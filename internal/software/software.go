// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package software provides read-only software inventory: installed packages from all
// package managers, candidate versions from local metadata caches only (no network),
// metadata age reporting, held/pinned status, mapping to running processes/services,
// and deterministic safety analysis for proposed changes.
//
// Principles:
//   - Principle 2/2': Read-only. No modifications. Exec only via strict allow-list.
//   - Principle 5/5': Local metadata caches only by default. Online refresh produces
//     a command for the user; it never fetches anything itself.
//   - Principle 11: Coverage honesty. Reports metadata age and says "unknown, refresh
//     needed" when caches are missing or unreadable.
//   - Principle 13: Exec allow-list enforced in dryrun.go.
package software

import (
	"time"
)

// Source identifies where a package came from.
type Source string

const (
	SourceAPT      Source = "apt"
	SourceDPKG     Source = "dpkg"
	SourceRPM      Source = "rpm"
	SourceDNF      Source = "dnf"
	SourcePacman   Source = "pacman"
	SourceAPK      Source = "apk"
	SourceZypper   Source = "zypper"
	SourceSnap     Source = "snap"
	SourceFlatpak  Source = "flatpak"
	SourcePip      Source = "pip"
	SourceNPM      Source = "npm"
	SourceCargo    Source = "cargo"
	SourceGo       Source = "go"
	SourceGem      Source = "gem"
	SourceBinary   Source = "binary"
	SourceUnknown  Source = "unknown"
)

// UpgradeKind classifies whether a candidate update is a security fix or regular update.
type UpgradeKind string

const (
	UpgradeKindSecurity UpgradeKind = "security"
	UpgradeKindRegular  UpgradeKind = "regular"
	UpgradeKindUnknown  UpgradeKind = "unknown"
)

// PackageStatus describes the current installation state.
type PackageStatus string

const (
	PackageStatusInstalled   PackageStatus = "installed"
	PackageStatusUpgradable  PackageStatus = "upgradable"
	PackageStatusHeld        PackageStatus = "held"
	PackageStatusPinned      PackageStatus = "pinned"
	PackageStatusOrphaned    PackageStatus = "orphaned"
)

// CandidateInfo describes what's available in the local metadata cache.
type CandidateInfo struct {
	Version       string      `json:"version"`
	Origin        string      `json:"origin"`        // e.g. "ubuntu resolute-security/main"
	UpgradeKind   UpgradeKind `json:"upgrade_kind"`  // "security" if from -security origin
	ChangelogPath string      `json:"changelog_path,omitempty"` // local changelog pointer if present
}

// MetadataInfo describes the freshness of local package cache data.
type MetadataInfo struct {
	Available     bool          `json:"available"`
	Age           time.Duration `json:"age_ns"` // time since last refresh
	AgeHuman      string        `json:"age_human"` // e.g. "9 days", "2 hours"
	IsStale       bool          `json:"is_stale"`   // true if > 7 days old
	RefreshNeeded bool          `json:"refresh_needed"` // true if cache missing or unreadable
	RefreshCmd    string        `json:"refresh_cmd,omitempty"` // e.g. "sudo apt-get update"
	LastRefreshed time.Time     `json:"last_refreshed,omitempty"`
}

// RunningMapping records whether the package has live processes/services.
type RunningMapping struct {
	IsRunning       bool     `json:"is_running"`
	ProcessNames    []string `json:"process_names,omitempty"`
	ServiceNames    []string `json:"service_names,omitempty"`
	ListeningPorts  []string `json:"listening_ports,omitempty"` // e.g. ["22/tcp"]
}

// PackageEntry is the complete view of one installed package.
type PackageEntry struct {
	// Identity
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Source  Source `json:"source"`

	// Status
	Status      PackageStatus `json:"status"`
	IsHeld      bool          `json:"is_held"`
	IsPinned    bool          `json:"is_pinned"`
	PinReason   string        `json:"pin_reason,omitempty"`

	// Availability from local cache
	Candidate     *CandidateInfo `json:"candidate,omitempty"`
	IsUpgradable  bool           `json:"is_upgradable"`
	IsEOL         bool           `json:"is_eol"`
	EOLDate       string         `json:"eol_date,omitempty"`

	// Dependency graph
	Depends         []string `json:"depends,omitempty"`          // packages this depends on
	ReverseDependents []string `json:"reverse_dependents,omitempty"` // packages that need this

	// Live state
	Running RunningMapping `json:"running"`

	// Meta
	Section     string `json:"section,omitempty"`
	Description string `json:"description,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

// InventoryResult is the full software inventory report.
type InventoryResult struct {
	Timestamp    time.Time      `json:"timestamp"`
	TotalInstalled int          `json:"total_installed"`
	TotalUpgradable int         `json:"total_upgradable"`
	TotalSecurity  int          `json:"total_security"`
	TotalHeld      int          `json:"total_held"`
	TotalEOL       int          `json:"total_eol"`
	TotalRunning   int          `json:"total_running"`
	Packages     []PackageEntry `json:"packages"`
	Metadata     MetadataInfo   `json:"metadata"`
	NonDistro    []NonDistroEntry `json:"non_distro,omitempty"`
}

// NonDistroEntry covers pip/npm/cargo/snap/flatpak packages.
type NonDistroEntry struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Source    Source `json:"source"`
	Location  string `json:"location,omitempty"`
}

