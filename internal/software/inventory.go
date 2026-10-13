// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package software

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
)

// InventoryReader reads and assembles the complete software inventory from local
// filesystem caches only. No network calls are made.
type InventoryReader struct {
	fs     fs.FS
	mu     sync.RWMutex

	// mtime-based cache keys for dpkg
	dpkgMtime int64
	dpkgSize  int64
	dpkgCache []PackageEntry
}

// NewInventoryReader creates a new reader bound to the given rooted filesystem.
func NewInventoryReader(rfs fs.FS) *InventoryReader {
	return &InventoryReader{fs: rfs}
}

// Collect assembles the full InventoryResult. It reads dpkg status, apt candidate
// lists, hold/pin information, and maps entries to live graph nodes for running state.
// No network I/O is performed.
func (r *InventoryReader) Collect(nodes []graph.Node) *InventoryResult {
	now := time.Now().UTC()
	result := &InventoryResult{Timestamp: now}

	// 1. Parse installed packages from dpkg/status
	installed, dpkgMtime, err := r.readDpkgStatus()
	if err != nil {
		// Graceful degradation: return what we can
		result.Metadata = MetadataInfo{
			Available:     false,
			RefreshNeeded: true,
			RefreshCmd:    "sudo apt-get update",
			AgeHuman:      "unknown (dpkg status unreadable)",
		}
		return result
	}

	// 2. Determine holds from dpkg selections
	holds := r.readDpkgHolds()

	// 3. Parse pin preferences
	pins := r.readAptPins()

	// 4. Read apt candidate lists from /var/lib/apt/lists
	candidates, meta := r.readAptCandidates(dpkgMtime)
	result.Metadata = meta

	// 5. Parse reverse dependency index from installed packages
	revDeps := buildRevDepIndex(installed)

	// 6. Map live graph nodes to package names for running state
	runningMap := buildRunningMap(nodes)

	// 7. Assemble PackageEntry for each installed package
	pkgMap := make(map[string]dpkgPkg, len(installed))
	for _, p := range installed {
		pkgMap[p.name] = p
	}

	var entries []PackageEntry
	for _, p := range installed {
		entry := PackageEntry{
			Name:              p.name,
			Version:           p.version,
			Arch:              p.arch,
			Source:            SourceAPT,
			Status:            PackageStatusInstalled,
			Depends:           p.depends,
			ReverseDependents: revDeps[p.name],
			Section:           p.section,
			Description:       p.description,
		}

		// Hold status
		if holds[p.name] {
			entry.IsHeld = true
			entry.Status = PackageStatusHeld
		}

		// Pin status
		if pin, ok := pins[p.name]; ok {
			entry.IsPinned = true
			entry.PinReason = pin
			if entry.Status == PackageStatusInstalled {
				entry.Status = PackageStatusPinned
			}
		}

		// Candidate / upgradable
		if cand, ok := candidates[p.name]; ok {
			if cand.Version != p.version {
				entry.Candidate = &cand
				entry.IsUpgradable = true
				if entry.Status == PackageStatusInstalled {
					entry.Status = PackageStatusUpgradable
				}
			}
		}

		// Running mapping
		entry.Running = runningMap[p.name]

		entries = append(entries, entry)
	}

	// Sort deterministically by name
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	// Compute summary counts
	for _, e := range entries {
		result.TotalInstalled++
		if e.IsUpgradable {
			result.TotalUpgradable++
		}
		if e.Candidate != nil && e.Candidate.UpgradeKind == UpgradeKindSecurity {
			result.TotalSecurity++
		}
		if e.IsHeld {
			result.TotalHeld++
		}
		if e.IsEOL {
			result.TotalEOL++
		}
		if e.Running.IsRunning {
			result.TotalRunning++
		}
	}

	result.Packages = entries
	return result
}

// LookupPackage returns the full entry for a specific package name, or nil.
func (r *InventoryReader) LookupPackage(name string, nodes []graph.Node) *PackageEntry {
	inv := r.Collect(nodes)
	for i := range inv.Packages {
		if inv.Packages[i].Name == name {
			return &inv.Packages[i]
		}
	}
	return nil
}

// --- dpkg parsing ---

type dpkgPkg struct {
	name        string
	version     string
	arch        string
	depends     []string
	section     string
	description string
	installed   bool
}

func (r *InventoryReader) readDpkgStatus() ([]dpkgPkg, int64, error) {
	const statusPath = "/var/lib/dpkg/status"

	fi, err := r.fs.Stat(statusPath)
	if err != nil {
		return nil, 0, fmt.Errorf("dpkg status: %w", err)
	}

	mtime := fi.ModTime().UnixNano()
	r.mu.RLock()
	if r.dpkgMtime == mtime && r.dpkgSize == fi.Size() && len(r.dpkgCache) > 0 {
		// Cache valid
		r.mu.RUnlock()
	} else {
		r.mu.RUnlock()
	}

	data, err := r.fs.ReadFile(statusPath)
	if err != nil {
		return nil, 0, fmt.Errorf("reading dpkg status: %w", err)
	}

	var pkgs []dpkgPkg
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var cur dpkgPkg
	inDesc := false

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if cur.name != "" && cur.installed {
				pkgs = append(pkgs, cur)
			}
			cur = dpkgPkg{}
			inDesc = false
			continue
		}

		if inDesc {
			// continuation line of Description, skip
			continue
		}

		switch {
		case strings.HasPrefix(line, "Package: "):
			cur.name = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			cur.version = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Architecture: "):
			cur.arch = strings.TrimPrefix(line, "Architecture: ")
		case strings.HasPrefix(line, "Section: "):
			cur.section = strings.TrimPrefix(line, "Section: ")
		case strings.HasPrefix(line, "Status: "):
			s := strings.TrimPrefix(line, "Status: ")
			cur.installed = strings.Contains(s, "installed") && !strings.Contains(s, "not-installed")
		case strings.HasPrefix(line, "Depends: "):
			cur.depends = parseDependsList(strings.TrimPrefix(line, "Depends: "))
		case strings.HasPrefix(line, "Pre-Depends: "):
			cur.depends = append(cur.depends, parseDependsList(strings.TrimPrefix(line, "Pre-Depends: "))...)
		case strings.HasPrefix(line, "Description: "):
			cur.description = strings.TrimPrefix(line, "Description: ")
			inDesc = true
		}
	}

	if cur.name != "" && cur.installed {
		pkgs = append(pkgs, cur)
	}

	return pkgs, mtime, nil
}

// parseDependsList extracts bare package names from a Depends: field.
// e.g. "libc6 (>= 2.42), libpam0g (>= 0.99)" → ["libc6", "libpam0g"]
func parseDependsList(raw string) []string {
	var names []string
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Handle "pkg | alt" alternatives — take first
		alts := strings.SplitN(part, "|", 2)
		name := strings.TrimSpace(alts[0])
		// Strip version constraint "(>= x.y)"
		if idx := strings.Index(name, " ("); idx != -1 {
			name = name[:idx]
		}
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// buildRevDepIndex builds a map of package → packages that depend on it.
func buildRevDepIndex(pkgs []dpkgPkg) map[string][]string {
	rev := make(map[string][]string)
	for _, p := range pkgs {
		for _, dep := range p.depends {
			rev[dep] = append(rev[dep], p.name)
		}
	}
	return rev
}

// --- dpkg hold status ---

func (r *InventoryReader) readDpkgHolds() map[string]bool {
	holds := make(map[string]bool)
	const selectionsPath = "/var/lib/dpkg/status"

	data, err := r.fs.ReadFile(selectionsPath)
	if err != nil {
		return holds
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var curName string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Package: ") {
			curName = strings.TrimPrefix(line, "Package: ")
		}
		if strings.HasPrefix(line, "Status: ") && strings.Contains(line, "hold") {
			if curName != "" {
				holds[curName] = true
			}
		}
		if line == "" {
			curName = ""
		}
	}
	return holds
}

// --- apt pin preferences ---

func (r *InventoryReader) readAptPins() map[string]string {
	pins := make(map[string]string)
	prefDirs := []string{"/etc/apt/preferences", "/etc/apt/preferences.d"}

	for _, prefDir := range prefDirs {
		fi, err := r.fs.Stat(prefDir)
		if err != nil {
			continue
		}
		if !fi.IsDir() {
			r.parsePinFile(prefDir, pins)
			continue
		}
		entries, err := os.ReadDir(filepath.Join(r.fs.Root(), prefDir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			r.parsePinFile(filepath.Join(prefDir, e.Name()), pins)
		}
	}
	return pins
}

func (r *InventoryReader) parsePinFile(path string, pins map[string]string) {
	data, err := r.fs.ReadFile(path)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var pkg, pin string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Package: ") {
			pkg = strings.TrimPrefix(line, "Package: ")
		}
		if strings.HasPrefix(line, "Pin: ") {
			pin = strings.TrimPrefix(line, "Pin: ")
		}
		if line == "" && pkg != "" && pin != "" {
			if pkg != "*" {
				pins[pkg] = pin
			}
			pkg, pin = "", ""
		}
	}
	if pkg != "" && pin != "" && pkg != "*" {
		pins[pkg] = pin
	}
}

// --- apt candidate metadata from /var/lib/apt/lists ---

// readAptCandidates reads all *_binary-amd64_Packages files from /var/lib/apt/lists
// and builds a candidate map keyed by package name. It also computes metadata age.
func (r *InventoryReader) readAptCandidates(dpkgMtime int64) (map[string]CandidateInfo, MetadataInfo) {
	const listsDir = "/var/lib/apt/lists"

	dirFi, err := r.fs.Stat(listsDir)
	if err != nil || !dirFi.IsDir() {
		return nil, MetadataInfo{
			Available:     false,
			RefreshNeeded: true,
			RefreshCmd:    "sudo apt-get update",
			AgeHuman:      "unknown (apt lists directory not found)",
		}
	}

	// Scan for *_Packages files using real OS dir since fs.FS may not have ReadDir
	entries, err := os.ReadDir(filepath.Join(r.fs.Root(), listsDir))
	if err != nil {
		return nil, MetadataInfo{
			Available:     false,
			RefreshNeeded: true,
			RefreshCmd:    "sudo apt-get update",
			AgeHuman:      fmt.Sprintf("unknown (cannot read %s)", listsDir),
		}
	}

	candidates := make(map[string]CandidateInfo)
	var newestMtime time.Time
	var oldestPackagesMtime time.Time

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_Packages") {
			continue
		}

		fullPath := filepath.Join(listsDir, e.Name())
		fi, err := r.fs.Stat(fullPath)
		if err != nil {
			continue
		}

		if newestMtime.IsZero() || fi.ModTime().After(newestMtime) {
			newestMtime = fi.ModTime()
		}
		if oldestPackagesMtime.IsZero() || fi.ModTime().Before(oldestPackagesMtime) {
			oldestPackagesMtime = fi.ModTime()
		}

		// Determine if this is a security origin
		isSecurity := strings.Contains(e.Name(), "security")

		r.parsePackagesFile(fullPath, isSecurity, candidates)
	}

	now := time.Now().UTC()
	if newestMtime.IsZero() {
		return candidates, MetadataInfo{
			Available:     false,
			RefreshNeeded: true,
			RefreshCmd:    "sudo apt-get update",
			AgeHuman:      "unknown (no Packages files found) — run: sudo apt-get update",
		}
	}

	age := now.Sub(newestMtime)
	isStale := age > 7*24*time.Hour

	return candidates, MetadataInfo{
		Available:     true,
		Age:           age,
		AgeHuman:      humanDuration(age),
		IsStale:       isStale,
		RefreshNeeded: isStale,
		RefreshCmd:    "sudo apt-get update",
		LastRefreshed: newestMtime,
	}
}

func (r *InventoryReader) parsePackagesFile(path string, isSecurity bool, out map[string]CandidateInfo) {
	data, err := r.fs.ReadFile(path)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024) // 8MB max line buffer

	var curName, curVersion, curOrigin string

	flush := func() {
		if curName == "" || curVersion == "" {
			return
		}
		// Only keep the highest priority candidate.
		// Security origin always wins over regular when same name appears.
		existing, exists := out[curName]
		kind := UpgradeKindRegular
		if isSecurity {
			kind = UpgradeKindSecurity
		}
		if !exists || (kind == UpgradeKindSecurity && existing.UpgradeKind != UpgradeKindSecurity) {
			out[curName] = CandidateInfo{
				Version:     curVersion,
				Origin:      curOrigin,
				UpgradeKind: kind,
			}
		}
		curName, curVersion, curOrigin = "", "", ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package: "):
			flush()
			curName = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			curVersion = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Origin: "):
			curOrigin = strings.TrimPrefix(line, "Origin: ")
		}
	}
	flush()
}

// buildRunningMap scans graph nodes to build package-name → running state mapping.
// Uses process command names and service unit names from the provenance graph.
func buildRunningMap(nodes []graph.Node) map[string]RunningMapping {
	rm := make(map[string]RunningMapping)

	for _, n := range nodes {
		switch n.Type {
		case graph.NodeProcess:
			// Map process command to potential package names (best-effort via label)
			cmdName := ""
			if v, ok := n.Properties["cmd"].(string); ok {
				cmdName = filepath.Base(strings.Fields(v)[0])
			}
			if cmdName == "" {
				cmdName = n.Label
			}
			if cmdName != "" {
				m := rm[cmdName]
				m.IsRunning = true
				m.ProcessNames = appendUnique(m.ProcessNames, cmdName)
				rm[cmdName] = m
			}

		case graph.NodeService:
			// Service node label is usually the unit name: sshd.service → sshd
			svcName := strings.TrimSuffix(n.Label, ".service")
			m := rm[svcName]
			m.IsRunning = true
			m.ServiceNames = appendUnique(m.ServiceNames, n.Label)
			rm[svcName] = m

		case graph.NodePort:
			if v, ok := n.Properties["pid"].(float64); ok && v > 0 {
				port := n.Label
				// Find the owner process and attribute to package
				_ = port // attached to the process node linkage, best effort
			}
		}
	}
	return rm
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// humanDuration produces a concise human-readable duration.
func humanDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	if days > 0 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	if hours > 0 {
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	mins := int(d.Minutes())
	if mins > 0 {
		return fmt.Sprintf("%d minutes", mins)
	}
	return "less than a minute"
}

