// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package inventory manages host package databases, non-distro ecosystems,
// and language runtime discoveries.
package inventory

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/graph"
)

// Package represents an installed software package from a system package manager.
type Package struct {
	Manager     string `json:"manager"` // dpkg, rpm, pacman, apk
	Name        string `json:"name"`
	Version     string `json:"version"`
	Arch        string `json:"arch,omitempty"`
	InstallTime string `json:"install_time,omitempty"`
}

// NonDistroPackage represents a package installed via language ecosystems or container tools.
type NonDistroPackage struct {
	Ecosystem string `json:"ecosystem"` // pip, npm, cargo, go, gem, snap, flatpak, docker
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Location  string `json:"location"`
	ManagedBy string `json:"managed_by,omitempty"` // venv path, global, etc.
}

// RuntimeVersion represents an installed language runtime.
type RuntimeVersion struct {
	Name    string `json:"name"` // python, node, java, go, ruby, php, dotnet
	Version string `json:"version"`
	Path    string `json:"path"`
	Manager string `json:"manager,omitempty"` // system, pyenv, nvm, sdkman, asdf
	EOLDate string `json:"eol_date,omitempty"`
	IsEOL   bool   `json:"is_eol"`
}

// Summary provides high-level counts and breakdown of the inventory.
type Summary struct {
	SystemPackages    int `json:"system_packages"`
	NonDistroPackages int `json:"non_distro_packages"`
	Runtimes          int `json:"runtimes"`
}

// Inventory encapsulates the entire software inventory of the host.
type Inventory struct {
	Timestamp         time.Time          `json:"timestamp"`
	Summary           Summary            `json:"summary"`
	Packages          []Package          `json:"packages"`
	NonDistroPackages []NonDistroPackage `json:"non_distro_packages"`
	Runtimes          []RuntimeVersion   `json:"runtimes"`
}

// Manager collects and indexes installed packages and ecosystems.
type Manager struct {
	fs        fs.FS
	mu        sync.RWMutex
	fileOwner map[string]string // bounded cache: file path -> package name
	maxCache  int
}

// NewManager creates a new inventory manager.
func NewManager(fs fs.FS) *Manager {
	return &Manager{
		fs:        fs,
		fileOwner: make(map[string]string),
		maxCache:  50000,
	}
}

// CollectInventory scans system package databases, non-distro ecosystems, and runtimes.
func (m *Manager) CollectInventory(ctx context.Context) (Inventory, error) {
	now := time.Now().UTC()
	inv := Inventory{
		Timestamp: now,
	}

	// 1. System packages
	pkgs := m.collectSystemPackages(ctx)
	inv.Packages = pkgs

	// 2. Non-distro ecosystems
	nonDistro := m.collectNonDistro(ctx)
	inv.NonDistroPackages = nonDistro

	// 3. Language runtimes
	runtimes := m.collectRuntimes(ctx)
	inv.Runtimes = runtimes

	inv.Summary = Summary{
		SystemPackages:    len(pkgs),
		NonDistroPackages: len(nonDistro),
		Runtimes:          len(runtimes),
	}

	return inv, nil
}

func (m *Manager) collectSystemPackages(ctx context.Context) []Package {
	var pkgs []Package

	// dpkg
	if dpkgPkgs, err := m.readDpkgStatus(); err == nil && len(dpkgPkgs) > 0 {
		pkgs = append(pkgs, dpkgPkgs...)
	}

	// pacman
	if pacPkgs, err := m.readPacmanLocal(); err == nil && len(pacPkgs) > 0 {
		pkgs = append(pkgs, pacPkgs...)
	}

	// apk
	if apkPkgs, err := m.readApkInstalled(); err == nil && len(apkPkgs) > 0 {
		pkgs = append(pkgs, apkPkgs...)
	}

	// rpm (read rpmdb or bounded exec)
	if rpmPkgs, err := m.readRPM(ctx); err == nil && len(rpmPkgs) > 0 {
		pkgs = append(pkgs, rpmPkgs...)
	}

	return pkgs
}

func (m *Manager) readDpkgStatus() ([]Package, error) {
	statusBytes, err := m.fs.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(statusBytes))

	var currentPkg Package
	var isInstalled bool

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if currentPkg.Name != "" && isInstalled {
				currentPkg.Manager = "dpkg"
				pkgs = append(pkgs, currentPkg)
			}
			currentPkg = Package{}
			isInstalled = false
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			currentPkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Version: ") {
			currentPkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		} else if strings.HasPrefix(line, "Architecture: ") {
			currentPkg.Arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture: "))
		} else if strings.HasPrefix(line, "Status: ") {
			// Status: install ok installed
			statusStr := strings.TrimPrefix(line, "Status: ")
			if strings.Contains(statusStr, "installed") && !strings.Contains(statusStr, "not-installed") {
				isInstalled = true
			}
		}
	}

	if currentPkg.Name != "" && isInstalled {
		currentPkg.Manager = "dpkg"
		pkgs = append(pkgs, currentPkg)
	}

	return pkgs, nil
}

func (m *Manager) readPacmanLocal() ([]Package, error) {
	localDir := "/var/lib/pacman/local"
	entries, err := m.fs.ReadDir(localDir)
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		descPath := filepath.Join(localDir, entry.Name(), "desc")
		data, err := m.fs.ReadFile(descPath)
		if err != nil {
			continue
		}

		pkg := parsePacmanDesc(data)
		if pkg.Name != "" {
			pkg.Manager = "pacman"
			pkgs = append(pkgs, pkg)
		}
	}

	return pkgs, nil
}

func parsePacmanDesc(data []byte) Package {
	var pkg Package
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var section string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") {
			section = line
			continue
		}
		if line == "" {
			continue
		}

		switch section {
		case "%NAME%":
			pkg.Name = line
		case "%VERSION%":
			pkg.Version = line
		case "%ARCH%":
			pkg.Arch = line
		}
	}
	return pkg
}

func (m *Manager) readApkInstalled() ([]Package, error) {
	data, err := m.fs.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var current Package

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if current.Name != "" {
				current.Manager = "apk"
				pkgs = append(pkgs, current)
			}
			current = Package{}
			continue
		}

		if strings.HasPrefix(line, "P:") {
			current.Name = strings.TrimPrefix(line, "P:")
		} else if strings.HasPrefix(line, "V:") {
			current.Version = strings.TrimPrefix(line, "V:")
		} else if strings.HasPrefix(line, "A:") {
			current.Arch = strings.TrimPrefix(line, "A:")
		}
	}

	if current.Name != "" {
		current.Manager = "apk"
		pkgs = append(pkgs, current)
	}

	return pkgs, nil
}

func (m *Manager) readRPM(ctx context.Context) ([]Package, error) {
	// If root is host, and /usr/bin/rpm exists, query rpm directly with fixed args and timeout
	if m.fs.Root() == "/" {
		if _, err := m.fs.Stat("/usr/bin/rpm"); err == nil {
			execCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(execCtx, "/usr/bin/rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n")
			out, err := cmd.Output()
			if err == nil {
				return parseRPMOutput(out), nil
			}
		}
	}
	return nil, errors.New("rpm database not available")
}

func parseRPMOutput(data []byte) []Package {
	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			pkgs = append(pkgs, Package{
				Manager: "rpm",
				Name:    fields[0],
				Version: fields[1],
				Arch:    fields[2],
			})
		}
	}
	return pkgs
}

// FindPackageOwner looks up which system package owns targetFile.
func (m *Manager) FindPackageOwner(targetFile string) (string, graph.Evidence, bool) {
	m.mu.RLock()
	if owner, found := m.fileOwner[targetFile]; found {
		m.mu.RUnlock()
		return owner, graph.Evidence{
			Source:    "cache",
			Collector: "inventory",
			Raw:       owner,
			Timestamp: time.Now().UTC(),
			Certainty: graph.CertaintyObserved,
		}, true
	}
	m.mu.RUnlock()

	// Check /var/lib/dpkg/info/<pkg>.list files if dpkg is present
	if _, err := m.fs.Stat("/var/lib/dpkg/info"); err == nil {
		entries, err := m.fs.ReadDir("/var/lib/dpkg/info")
		if err == nil {
			targetClean := filepath.Clean(targetFile)
			for _, entry := range entries {
				name := entry.Name()
				if !strings.HasSuffix(name, ".list") {
					continue
				}
				listBytes, err := m.fs.ReadFile(filepath.Join("/var/lib/dpkg/info", name))
				if err != nil {
					continue
				}

				if bytes.Contains(listBytes, []byte(targetClean)) {
					scanner := bufio.NewScanner(bytes.NewReader(listBytes))
					for scanner.Scan() {
						if strings.TrimSpace(scanner.Text()) == targetClean {
							pkgName := strings.TrimSuffix(name, ".list")
							if idx := strings.Index(pkgName, ":"); idx != -1 {
								pkgName = pkgName[:idx] // strip arch suffix
							}

							m.mu.Lock()
							if len(m.fileOwner) < m.maxCache {
								m.fileOwner[targetClean] = pkgName
							}
							m.mu.Unlock()

							return pkgName, graph.Evidence{
								Source:    filepath.Join("/var/lib/dpkg/info", name),
								Collector: "inventory",
								Raw:       fmt.Sprintf("%s owned by %s", targetClean, pkgName),
								Timestamp: time.Now().UTC(),
								Certainty: graph.CertaintyObserved,
							}, true
						}
					}
				}
			}
		}
	}

	return "", graph.Evidence{}, false
}
