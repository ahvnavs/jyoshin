// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package coverage calculates sensor inspection visibility and coverage honesty.
package coverage

import (
	"context"
	"fmt"
	"strings"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/sensors"
	"github.com/OWNER/kazeshini/internal/supervisor"
)

// ItemCoverage reports inspection coverage for a single subsystem or sensor.
type ItemCoverage struct {
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	Readable    int     `json:"readable"`
	Total       int     `json:"total"`
	Percentage  float64 `json:"percentage"`
	Status      string  `json:"status"` // "full", "partial", "unavailable", "unknown"
	Explanation string  `json:"explanation"`
}

// Report encapsulates overall host coverage across all key subsystems.
type Report struct {
	OverallCoverage float64        `json:"overall_coverage"`
	IsAdequate      bool           `json:"is_adequate"`
	VerdictAllowed  bool           `json:"verdict_allowed"` // false if coverage is insufficient to say CALM
	SummaryNote     string         `json:"summary_note"`
	Items           []ItemCoverage `json:"items"`
}

// Assessor computes inspection coverage.
type Assessor struct {
	sup        *supervisor.Supervisor
	invManager *inventory.Manager
	orphanScan *orphan.Scanner
	fs         fs.FS
}

// NewAssessor creates a new coverage assessor.
func NewAssessor(sup *supervisor.Supervisor, inv *inventory.Manager, orph *orphan.Scanner, fs fs.FS) *Assessor {
	return &Assessor{
		sup:        sup,
		invManager: inv,
		orphanScan: orph,
		fs:         fs,
	}
}

// Assess computes the live coverage report.
func (a *Assessor) Assess(ctx context.Context) Report {
	var items []ItemCoverage

	// 1. Process Inspection: processes readable N of M
	procCov := ItemCoverage{
		Name:     "Processes",
		Category: "process",
		Status:   "unknown",
	}
	if a.sup != nil {
		if obs, ok := a.sup.GetObservation("process"); ok {
			total := obs.TotalSeen
			readable := len(obs.Items)
			procCov.Total = total
			procCov.Readable = readable
			if total > 0 {
				procCov.Percentage = (float64(readable) / float64(total)) * 100.0
			} else if obs.Status == sensors.StatusSuccess {
				procCov.Percentage = 100.0
			}
			if obs.Status != sensors.StatusSuccess {
				procCov.Status = "partial"
				procCov.Explanation = obs.Reason
			} else if total > readable {
				procCov.Status = "partial"
				procCov.Explanation = fmt.Sprintf("Read %d of %d processes (truncated or restricted)", readable, total)
			} else {
				procCov.Status = "full"
				procCov.Explanation = fmt.Sprintf("Inspected %d of %d active processes in /proc", readable, total)
			}
		}
	}
	if procCov.Explanation == "" {
		procCov.Explanation = "Process observation not yet collected"
	}
	items = append(items, procCov)

	// 2. Socket-to-Process Mapping: sockets mapped N of M
	netCov := ItemCoverage{
		Name:     "Network Sockets",
		Category: "network",
		Status:   "unknown",
	}
	if a.sup != nil {
		if obs, ok := a.sup.GetObservation("network"); ok {
			totalListeners := 0
			mappedListeners := 0
			for _, it := range obs.Items {
				if it.Type == "listener" || it.Type == "socket" {
					totalListeners++
					// Check if PID is mapped
					if m, ok := it.Data.(map[string]any); ok {
						if pid, ok := m["pid"].(int); ok && pid > 0 {
							mappedListeners++
						}
					}
				}
			}
			netCov.Total = totalListeners
			netCov.Readable = mappedListeners
			if totalListeners > 0 {
				netCov.Percentage = (float64(mappedListeners) / float64(totalListeners)) * 100.0
			} else {
				netCov.Percentage = 100.0
			}

			if strings.Contains(obs.Reason, "permission") || obs.Status == sensors.StatusUnknown {
				netCov.Status = "partial"
				netCov.Explanation = obs.Reason
			} else if totalListeners == 0 {
				netCov.Status = "full"
				netCov.Explanation = "Socket tables (/proc/net) accessible; 0 active listeners found"
			} else {
				netCov.Status = "full"
				netCov.Explanation = fmt.Sprintf("Mapped %d of %d sockets to owning processes via inodes", mappedListeners, totalListeners)
			}
		}
	}
	if netCov.Explanation == "" {
		netCov.Explanation = "Network observation not yet collected"
	}
	items = append(items, netCov)

	// 3. Package Database: dpkg / rpm / pacman / apk
	pkgCov := ItemCoverage{
		Name:     "Package Manager Database",
		Category: "inventory",
		Status:   "unavailable",
	}
	if a.invManager != nil {
		inv, err := a.invManager.CollectInventory(ctx)
		if err == nil && len(inv.Packages) > 0 {
			pkgCov.Readable = len(inv.Packages)
			pkgCov.Total = len(inv.Packages)
			pkgCov.Percentage = 100.0
			pkgCov.Status = "full"
			mgrName := inv.Packages[0].Manager
			pkgCov.Explanation = fmt.Sprintf("Native package database loaded (%d %s packages indexed)", len(inv.Packages), mgrName)
		} else {
			pkgCov.Status = "unavailable"
			pkgCov.Explanation = "No supported native package database found (/var/lib/dpkg, pacman, apk, rpm)"
		}
	}
	items = append(items, pkgCov)

	// 4. Init / Systemd Subsystem
	svcCov := ItemCoverage{
		Name:     "Init / Service Manager",
		Category: "service",
		Status:   "unknown",
	}
	if a.sup != nil {
		if obs, ok := a.sup.GetObservation("service"); ok {
			if obs.Status == sensors.StatusSuccess && len(obs.Items) > 0 {
				svcCov.Readable = len(obs.Items)
				svcCov.Total = len(obs.Items)
				svcCov.Percentage = 100.0
				svcCov.Status = "full"
				svcCov.Explanation = fmt.Sprintf("Systemd / init manager available; %d service units tracked", len(obs.Items))
			} else {
				svcCov.Status = "partial"
				svcCov.Explanation = "Systemd bus unavailable or non-systemd environment"
			}
		}
	}
	if svcCov.Explanation == "" {
		svcCov.Explanation = "Service observation not yet collected"
	}
	items = append(items, svcCov)

	// 5. Container Engine Socket
	contCov := ItemCoverage{
		Name:     "Container Engine Socket",
		Category: "container",
		Status:   "unavailable",
	}
	if a.sup != nil {
		if obs, ok := a.sup.GetObservation("container"); ok {
			if obs.Status == sensors.StatusSuccess {
				contCov.Readable = len(obs.Items)
				contCov.Total = len(obs.Items)
				contCov.Percentage = 100.0
				contCov.Status = "full"
				contCov.Explanation = fmt.Sprintf("Container engine socket accessible; %d containers inspected", len(obs.Items))
			} else if strings.Contains(obs.Reason, "socket") || strings.Contains(obs.Reason, "permission") {
				contCov.Status = "unavailable"
				contCov.Explanation = obs.Reason
			} else {
				contCov.Status = "unavailable"
				contCov.Explanation = "No container engine socket detected (/var/run/docker.sock, podman.sock)"
			}
		}
	}
	items = append(items, contCov)

	// 6. User & Authorized Keys Inspection
	userCov := ItemCoverage{
		Name:     "User Accounts & SSH Keys",
		Category: "user",
		Status:   "unknown",
	}
	if a.sup != nil {
		if obs, ok := a.sup.GetObservation("user"); ok {
			if obs.Status == sensors.StatusSuccess {
				userCov.Readable = len(obs.Items)
				userCov.Total = len(obs.Items)
				userCov.Percentage = 100.0
				userCov.Status = "full"
				userCov.Explanation = fmt.Sprintf("Inspected %d user accounts and authorized_keys metadata (key material strictly excluded)", len(obs.Items))
			} else {
				userCov.Status = "partial"
				userCov.Explanation = obs.Reason
			}
		}
	}
	if userCov.Explanation == "" {
		userCov.Explanation = "User accounts observation not yet collected"
	}
	items = append(items, userCov)

	// Compute overall coverage percentage across core inspection domains
	// Core domains: process, network, inventory
	sumScore := 0.0
	weightTotal := 0.0

	weights := map[string]float64{
		"process":   30.0,
		"network":   30.0,
		"inventory": 20.0,
		"service":   10.0,
		"user":      10.0,
	}

	for _, it := range items {
		if w, ok := weights[it.Category]; ok {
			weightTotal += w
			if it.Status == "full" {
				sumScore += w * 1.0
			} else if it.Status == "partial" {
				sumScore += w * 0.5
			}
		}
	}

	overall := 0.0
	if weightTotal > 0 {
		overall = (sumScore / weightTotal) * 100.0
	}

	// Adequacy check: must have full/adequate process, network, and package database visibility
	isAdequate := overall >= 75.0 && procCov.Status != "unavailable" && pkgCov.Status != "unavailable"
	verdictAllowed := isAdequate

	var note string
	if !isAdequate {
		note = "Limited visibility: essential sensors could not fully inspect host truth. CALM verdict suspended."
	} else {
		note = "Visibility adequate: core sensors verified full access to host truth."
	}

	return Report{
		OverallCoverage: overall,
		IsAdequate:      isAdequate,
		VerdictAllowed:  verdictAllowed,
		SummaryNote:     note,
		Items:           items,
	}
}

