// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OWNER/jyoshin/data"
)

func (m *Manager) collectNonDistro(ctx context.Context) []NonDistroPackage {
	var list []NonDistroPackage

	// 1. pip packages in standard locations
	pipPaths := []string{
		"/usr/local/lib/python3.*/dist-packages",
		"/usr/lib/python3.*/dist-packages",
		"/var/lib/pip",
	}
	for _, p := range pipPaths {
		matches, _ := filepath.Glob(m.fs.Path(p))
		for _, dir := range matches {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				name := e.Name()
				if strings.HasSuffix(name, ".dist-info") {
					pkgName := strings.TrimSuffix(name, ".dist-info")
					parts := strings.Split(pkgName, "-")
					v := ""
					if len(parts) > 1 {
						v = parts[len(parts)-1]
						pkgName = strings.Join(parts[:len(parts)-1], "-")
					}
					list = append(list, NonDistroPackage{
						Ecosystem: "pip",
						Name:      pkgName,
						Version:   v,
						Location:  filepath.Join(dir, name),
						ManagedBy: "global",
					})
				}
			}
		}
	}

	// 2. npm global packages
	npmGlobal := m.fs.Path("/usr/local/lib/node_modules")
	if entries, err := os.ReadDir(npmGlobal); err == nil {
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				list = append(list, NonDistroPackage{
					Ecosystem: "npm",
					Name:      e.Name(),
					Location:  filepath.Join(npmGlobal, e.Name()),
					ManagedBy: "global",
				})
			}
		}
	}

	// 3. cargo bin directory
	cargoBin := m.fs.Path("/root/.cargo/bin")
	if entries, err := os.ReadDir(cargoBin); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				list = append(list, NonDistroPackage{
					Ecosystem: "cargo",
					Name:      e.Name(),
					Location:  filepath.Join(cargoBin, e.Name()),
					ManagedBy: "cargo",
				})
			}
		}
	}

	// 4. Snap packages
	snapDir := m.fs.Path("/snap")
	if entries, err := os.ReadDir(snapDir); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name() != "bin" && e.Name() != "core" && !strings.HasPrefix(e.Name(), ".") {
				list = append(list, NonDistroPackage{
					Ecosystem: "snap",
					Name:      e.Name(),
					Location:  filepath.Join(snapDir, e.Name()),
				})
			}
		}
	}

	return list
}

func (m *Manager) collectRuntimes(ctx context.Context) []RuntimeVersion {
	var runtimes []RuntimeVersion
	eolMap := loadEOLMap()

	checkRuntime := func(name, binPath, verArg, manager string) {
		path := m.fs.Path(binPath)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			ver := extractBinaryVersion(path, verArg)
			isEOL, eolDate := checkEOL(name, ver, eolMap)
			runtimes = append(runtimes, RuntimeVersion{
				Name:    name,
				Version: ver,
				Path:    binPath,
				Manager: manager,
				EOLDate: eolDate,
				IsEOL:   isEOL,
			})
		}
	}

	// Common system runtime paths
	checkRuntime("python", "/usr/bin/python3", "--version", "system")
	checkRuntime("node", "/usr/bin/node", "--version", "system")
	checkRuntime("go", "/usr/bin/go", "version", "system")
	checkRuntime("java", "/usr/bin/java", "-version", "system")
	checkRuntime("ruby", "/usr/bin/ruby", "--version", "system")
	checkRuntime("php", "/usr/bin/php", "-v", "system")

	// Version manager paths (e.g. pyenv, nvm)
	nvmDir := m.fs.Path("/root/.nvm/versions/node")
	if entries, err := os.ReadDir(nvmDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				nodeBin := filepath.Join("/root/.nvm/versions/node", e.Name(), "bin/node")
				checkRuntime("node", nodeBin, "--version", "nvm")
			}
		}
	}

	return runtimes
}

func extractBinaryVersion(path, verArg string) string {
	// Simple string inspection or static file metadata
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}

	// Search for common version string patterns in the binary without exec
	s := string(data)
	if idx := strings.Index(s, "go1."); idx != -1 && idx+12 <= len(s) {
		return strings.Fields(s[idx : idx+12])[0]
	}
	if idx := strings.Index(s, "Python 3."); idx != -1 && idx+15 <= len(s) {
		return strings.Fields(s[idx : idx+15])[0]
	}
	if idx := strings.Index(s, "v18."); idx != -1 && idx+8 <= len(s) {
		return strings.Fields(s[idx : idx+8])[0]
	}
	if idx := strings.Index(s, "v20."); idx != -1 && idx+8 <= len(s) {
		return strings.Fields(s[idx : idx+8])[0]
	}

	return "installed"
}

func loadEOLMap() map[string]map[string]string {
	res := make(map[string]map[string]string)
	dataBytes, err := data.EOLData.ReadFile("eol.yaml")
	if err != nil {
		return res
	}

	scanner := bufio.NewScanner(bytes.NewReader(dataBytes))
	var currentRuntime string
	var currentVer string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasSuffix(line, ":") && !strings.Contains(line, "version") && !strings.Contains(line, "distros") && !strings.Contains(line, "runtimes") {
			currentRuntime = strings.TrimSuffix(line, ":")
			if _, ok := res[currentRuntime]; !ok {
				res[currentRuntime] = make(map[string]string)
			}
		}
		if strings.HasPrefix(line, "- version: ") {
			currentVer = strings.Trim(strings.TrimPrefix(line, "- version: "), `"'`)
		}
		if strings.HasPrefix(line, "eol: ") && currentRuntime != "" && currentVer != "" {
			eolDate := strings.Trim(strings.TrimPrefix(line, "eol: "), `"'`)
			res[currentRuntime][currentVer] = eolDate
		}
	}

	return res
}

func checkEOL(runtimeName, version string, eolMap map[string]map[string]string) (bool, string) {
	runtimeMap, ok := eolMap[runtimeName]
	if !ok {
		return false, ""
	}

	now := time.Now().Format("2006-01-02")
	for verPrefix, eolDate := range runtimeMap {
		if strings.Contains(version, verPrefix) {
			if eolDate < now {
				return true, eolDate
			}
			return false, eolDate
		}
	}
	return false, ""
}
