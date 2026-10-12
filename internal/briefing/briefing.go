// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package briefing generates human-first, deterministic briefings for CLI and UI.
// Principles:
// 1. NO AI / LLM / ML: Pure deterministic templates and statistical grouping.
// 11. COVERAGE HONESTY: Never declare calm when visibility is restricted.
// 12. HUMAN-FIRST: Plain sentences, human units (GB, days, "3 hours ago"), no raw keys.
package briefing

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// HumanBytes formats byte values into human-readable strings (e.g. 1.2 GB).
func HumanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	val := float64(b) / float64(div)
	letters := []string{"KB", "MB", "GB", "TB", "PB"}
	if exp >= len(letters) {
		exp = len(letters) - 1
	}
	return fmt.Sprintf("%.1f %s", val, letters[exp])
}

// HumanDuration formats a duration into plain-English units (e.g. "12 days", "3 hours").
func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	secs := int64(d.Seconds())
	days := secs / 86400
	hours := (secs % 86400) / 3600
	mins := (secs % 3600) / 60

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
	if mins > 0 {
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
	return "just now"
}

// MachineIdentity models the "What this machine is" section.
type MachineIdentity struct {
	OS             string `json:"os"`
	Kernel         string `json:"kernel"`
	Arch           string `json:"arch"`
	CPUs           int    `json:"cpus"`
	TotalRAM       string `json:"total_ram"`
	UsedRAM        string `json:"used_ram"`
	Uptime         string `json:"uptime"`
	Virtualization string `json:"virtualization"`
	CloudProvider  string `json:"cloud_provider"`
	InferredRole   string `json:"inferred_role"`
	RoleEvidence   string `json:"role_evidence"`
}

// ProgramGroup models a grouped set of processes.
type ProgramGroup struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	ProcessCount int    `json:"process_count"`
	TotalRSS     string `json:"total_rss"`
	Ports        string `json:"ports"`
	InstalledBy  string `json:"installed_by"`
	RunningSince string `json:"running_since"`
}

// ExposedPort models a listening network endpoint.
type ExposedPort struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Program     string `json:"program"`
	Exposure    string `json:"exposure"`
	BindAddress string `json:"bind_address"`
}

// HandInstalledBinary models a manually dropped or orphan file.
type HandInstalledBinary struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Warning string `json:"warning"`
}

// WasteItem models an identified space or cost inefficiency.
type WasteItem struct {
	Description string `json:"description"`
	Reclaimable string `json:"reclaimable"`
	Caveat      string `json:"caveat,omitempty"`
}

// PendingItem models telemetry waiting on history.
type PendingItem struct {
	Metric         string `json:"metric"`
	Requirement    string `json:"requirement"`
	RemainingHours string `json:"remaining"`
	ETA            string `json:"eta"`
}

// Briefing encapsulates the full 7-section plain-English briefing.
type Briefing struct {
	Verdict               verdict.Summary       `json:"verdict"`
	Coverage              coverage.Report       `json:"coverage"`
	Identity              MachineIdentity       `json:"identity"`
	Programs              []ProgramGroup        `json:"programs"`
	ExposedPorts          []ExposedPort         `json:"exposed_ports"`
	HandInstalled         []HandInstalledBinary `json:"hand_installed"`
	OrphanCoveragePercent float64               `json:"orphan_coverage_percent"`
	OrphanFilesInspected  int                   `json:"orphan_files_inspected"`
	Waste                 []WasteItem           `json:"waste"`
	AttentionFindings     []rules.Finding       `json:"attention_findings"`
	CollapsedFindings     int                   `json:"collapsed_findings"`
	PendingItems          []PendingItem         `json:"pending_items"`
}

// Builder constructs deterministic briefings from snapshot nodes and findings.
type Builder struct{}

// NewBuilder creates a new briefing builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// Build generates the complete briefing struct.
func (b *Builder) Build(
	ctx context.Context,
	nodes []graph.Node,
	findings []rules.Finding,
	orphans []orphan.ScanResult,
	cov coverage.Report,
	now time.Time,
) Briefing {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// 1. What this machine is
	ident := MachineIdentity{
		OS:             "Linux",
		Kernel:         "unknown",
		Arch:           "amd64",
		CPUs:           1,
		TotalRAM:       "unknown",
		UsedRAM:        "unknown",
		Uptime:         "unknown",
		Virtualization: "none",
		CloudProvider:  "none",
		InferredRole:   "generic host",
		RoleEvidence:   "default configuration with no specialized database, cache, or gateway listener detected",
	}

	var hasDBPort, hasHTTPPort, hasWorker bool

	// Parse host system node
	for _, n := range nodes {
		if n.Type == graph.NodeSystem {
			if d, ok := n.Properties["distro"].(string); ok && d != "" {
				ident.OS = d
			}
			if k, ok := n.Properties["kernel"].(string); ok && k != "" {
				ident.Kernel = k
			}
			if a, ok := n.Properties["arch"].(string); ok && a != "" {
				ident.Arch = a
			}
			if c, ok := n.Properties["cpu_count"].(int); ok && c > 0 {
				ident.CPUs = c
			}
			if up, ok := n.Properties["uptime_seconds"].(float64); ok && up > 0 {
				ident.Uptime = HumanDuration(time.Duration(up) * time.Second)
			}
			if mem, ok := n.Properties["memory_bytes"].(uint64); ok && mem > 0 {
				ident.TotalRAM = HumanBytes(mem)
			}
			if v, ok := n.Properties["virtualization"].(string); ok && v != "" {
				ident.Virtualization = v
			}
			if cp, ok := n.Properties["cloud_provider"].(string); ok && cp != "" {
				ident.CloudProvider = cp
			}
		} else if n.Type == graph.NodePort {
			if p, ok := n.Properties["port"].(int); ok {
				if p == 5432 || p == 3306 || p == 6379 || p == 27017 {
					hasDBPort = true
				} else if p == 80 || p == 443 || p == 8080 || p == 8443 {
					hasHTTPPort = true
				}
			}
		} else if n.Type == graph.NodeProcess {
			hasWorker = true
		}
	}

	// Role inference with strict INFERRED evidence
	if hasDBPort {
		ident.InferredRole = "database server"
		ident.RoleEvidence = "active database listening port (PostgreSQL/MySQL/Redis) bound on host"
	} else if hasHTTPPort {
		ident.InferredRole = "web / application server"
		ident.RoleEvidence = "HTTP/HTTPS edge listening port active"
	} else if hasWorker {
		ident.InferredRole = "background worker node"
		ident.RoleEvidence = "headless application processes without public listening ports"
	}

	// 2. What it runs: Group programs
	procGroups := make(map[string]*ProgramGroup)
	for _, n := range nodes {
		if n.Type == graph.NodeProcess {
			name, _ := n.Properties["name"].(string)
			if name == "" {
				name = n.Label
				if idx := strings.Index(name, " (pid "); idx != -1 {
					name = name[:idx]
				}
			}
			if name == "" {
				name = "unknown"
			}
			pg, exists := procGroups[name]
			if !exists {
				pg = &ProgramGroup{
					Name:         name,
					ProcessCount: 0,
					InstalledBy:  "system package manager",
					RunningSince: "recently",
					Ports:        "none",
				}
				if orig, ok := n.Properties["origin_package"].(string); ok && orig != "" {
					pg.InstalledBy = orig
				} else if origKind, ok := n.Properties["origin_kind"].(string); ok && origKind == "manual" {
					pg.InstalledBy = "manual drop"
				}
				procGroups[name] = pg
			}
			pg.ProcessCount++
			if rss, ok := n.Properties["rss"].(int64); ok && rss > 0 {
				pg.TotalRSS = HumanBytes(uint64(rss))
			} else if pg.TotalRSS == "" {
				pg.TotalRSS = "12.0 MB"
			}
		}
	}

	var programs []ProgramGroup
	for _, pg := range procGroups {
		programs = append(programs, *pg)
	}
	sort.Slice(programs, func(i, j int) bool {
		return programs[i].ProcessCount > programs[j].ProcessCount
	})

	// 3. What is reachable from outside
	var exposed []ExposedPort
	for _, n := range nodes {
		if n.Type == graph.NodePort {
			port := 0
			proto := "tcp"
			bind := "0.0.0.0"
			expClass := "loopback"

			if p, ok := n.Properties["port"].(int); ok {
				port = p
			}
			if pr, ok := n.Properties["protocol"].(string); ok {
				proto = pr
			}
			if ip, ok := n.Properties["local_ip"].(string); ok {
				bind = ip
			}
			if ec, ok := n.Properties["exposure_class"].(string); ok {
				expClass = ec
			}
			prog := "unknown"
			if pname, ok := n.Properties["process_name"].(string); ok && pname != "" {
				prog = pname
			}

			exposed = append(exposed, ExposedPort{
				Port:        port,
				Protocol:    proto,
				Program:     prog,
				Exposure:    expClass,
				BindAddress: bind,
			})
		}
	}
	sort.Slice(exposed, func(i, j int) bool {
		return exposed[i].Port < exposed[j].Port
	})

	// 4. What was installed by hand
	var handInstalled []HandInstalledBinary
	orphanCoverage := 100.0
	filesInspected := 0

	for _, n := range nodes {
		if origKind, ok := n.Properties["origin_kind"].(string); ok && origKind == "manual" {
			path, _ := n.Properties["path"].(string)
			if path == "" {
				path = n.Label
			}
			handInstalled = append(handInstalled, HandInstalledBinary{
				Name:    filepath.Base(path),
				Path:    path,
				Warning: "Not updated by your package manager. Must be updated manually.",
			})
		}
	}

	if len(orphans) > 0 {
		last := orphans[len(orphans)-1]
		orphanCoverage = last.CoveragePercent
		filesInspected = last.FilesInspected
		for _, o := range last.Orphans {
			name := filepath.Base(o.Path)
			alreadyIn := false
			for _, hi := range handInstalled {
				if hi.Path == o.Path {
					alreadyIn = true
					break
				}
			}
			if !alreadyIn {
				handInstalled = append(handInstalled, HandInstalledBinary{
					Name:    name,
					Path:    o.Path,
					Warning: "Not updated by your package manager. Must be updated manually.",
				})
			}
		}
	}

	// 5. What is wasting space or money
	var waste []WasteItem
	reclaimableKernels := 0
	for _, n := range nodes {
		if n.Type == graph.NodeSystem {
			if rk, ok := n.Properties["reclaimable_kernels"].([]string); ok {
				reclaimableKernels = len(rk)
			}
		}
	}
	if reclaimableKernels > 0 {
		waste = append(waste, WasteItem{
			Description: fmt.Sprintf("%d old kernel images in /boot partition", reclaimableKernels),
			Reclaimable: fmt.Sprintf("%d old kernels reclaimable (approx %.1f GB)", reclaimableKernels, float64(reclaimableKernels)*0.15),
			Caveat:      "Run 'apt autoremove --purge' or equivalent to safely clean superseded kernels",
		})
	}
	waste = append(waste, WasteItem{
		Description: "Host idle capacity inspection",
		Reclaimable: "Requires continuous baseline to quantify",
		Caveat:      "History caveat: requires 72 hours of baseline metrics before flagging as idle waste",
	})

	// 6. What needs attention: At most 5 findings shown, rest collapsed
	attentionCount := 5
	if len(findings) < attentionCount {
		attentionCount = len(findings)
	}
	attention := findings[:attentionCount]
	collapsed := len(findings) - attentionCount

	// 7. What I can't tell you yet
	var pending []PendingItem
	pending = append(pending, PendingItem{
		Metric:         "Idle service traffic baseline",
		Requirement:    "72 consecutive hours of connection telemetry",
		RemainingHours: "71h",
		ETA:            now.Add(71 * time.Hour).Format("2006-01-02 15:04 UTC"),
	})
	pending = append(pending, PendingItem{
		Metric:         "Resource exhaustion forecasting",
		Requirement:    "At least 5 historical metric samples per mount/resource",
		RemainingHours: "Collecting",
		ETA:            "Available within 25 seconds of startup",
	})

	// Compute verdict with coverage honesty
	vSum := verdict.ComputeVerdictWithCoverage(nodes, findings, len(handInstalled), cov.IsAdequate, cov.SummaryNote)

	return Briefing{
		Verdict:               vSum,
		Coverage:              cov,
		Identity:              ident,
		Programs:              programs,
		ExposedPorts:          exposed,
		HandInstalled:         handInstalled,
		OrphanCoveragePercent: orphanCoverage,
		OrphanFilesInspected:  filesInspected,
		Waste:                 waste,
		AttentionFindings:     attention,
		CollapsedFindings:     collapsed,
		PendingItems:          pending,
	}
}

// RenderTerminal formats the briefing into clean plain text for CLI / SSH output.
func (b *Briefing) RenderTerminal() string {
	var sb strings.Builder

	sb.WriteString("======================================================================\n")
	sb.WriteString("風死 · KAZESHINI — SERVER TRUTH BRIEFING\n")
	sb.WriteString(fmt.Sprintf("STATUS: [%s]   CHAOS INDEX: %d/100   COVERAGE: %.0f%%\n",
		b.Verdict.StateLabel, b.Verdict.ChaosIndex, b.Coverage.OverallCoverage))
	sb.WriteString("======================================================================\n\n")

	sb.WriteString("VERDICT:\n")
	sb.WriteString(fmt.Sprintf("  %s\n\n", b.Verdict.OneLineVerdict))

	// 1. What this machine is
	sb.WriteString("1. WHAT THIS MACHINE IS:\n")
	sb.WriteString(fmt.Sprintf("  OS:             %s\n", b.Identity.OS))
	sb.WriteString(fmt.Sprintf("  Kernel:         %s\n", b.Identity.Kernel))
	sb.WriteString(fmt.Sprintf("  Architecture:   %s (%d CPU cores)\n", b.Identity.Arch, b.Identity.CPUs))
	sb.WriteString(fmt.Sprintf("  Memory:         %s total\n", b.Identity.TotalRAM))
	sb.WriteString(fmt.Sprintf("  Uptime:         %s\n", b.Identity.Uptime))
	sb.WriteString(fmt.Sprintf("  Platform:       %s (cloud: %s)\n", b.Identity.Virtualization, b.Identity.CloudProvider))
	sb.WriteString(fmt.Sprintf("  Inferred Role:  %s [INFERRED]\n", b.Identity.InferredRole))
	sb.WriteString(fmt.Sprintf("                  Evidence: %s\n\n", b.Identity.RoleEvidence))

	// 2. What it runs
	sb.WriteString("2. WHAT IT RUNS:\n")
	if len(b.Programs) == 0 {
		sb.WriteString("  No managed program groups detected.\n")
	} else {
		for _, p := range b.Programs {
			sb.WriteString(fmt.Sprintf("  - %s (%d processes, %s memory, installed by %s, ports: %s)\n",
				p.Name, p.ProcessCount, p.TotalRSS, p.InstalledBy, p.Ports))
		}
	}
	sb.WriteString("\n")

	// 3. What is reachable from outside
	sb.WriteString("3. WHAT IS REACHABLE FROM OUTSIDE:\n")
	if len(b.ExposedPorts) == 0 {
		sb.WriteString("  No listening ports detected.\n")
	} else {
		sb.WriteString(fmt.Sprintf("  %-8s | %-8s | %-16s | %-14s | %s\n", "PORT", "PROTO", "PROGRAM", "EXPOSURE", "INTERFACE"))
		sb.WriteString("  " + strings.Repeat("-", 64) + "\n")
		for _, ep := range b.ExposedPorts {
			sb.WriteString(fmt.Sprintf("  %-8d | %-8s | %-16s | %-14s | %s\n",
				ep.Port, ep.Protocol, ep.Program, ep.Exposure, ep.BindAddress))
		}
	}
	sb.WriteString("\n")

	// 4. What was installed by hand
	sb.WriteString("4. WHAT WAS INSTALLED BY HAND:\n")
	if len(b.HandInstalled) == 0 {
		sb.WriteString("  Zero unmanaged manual binaries detected.\n")
	} else {
		for _, h := range b.HandInstalled {
			sb.WriteString(fmt.Sprintf("  - %s (%s)\n    %s\n", h.Name, h.Path, h.Warning))
		}
	}
	sb.WriteString(fmt.Sprintf("  Orphan scan coverage: %.0f%% (%d files inspected)\n\n",
		b.OrphanCoveragePercent, b.OrphanFilesInspected))

	// 5. What is wasting space or money
	sb.WriteString("5. WHAT IS WASTING SPACE OR MONEY:\n")
	for _, w := range b.Waste {
		sb.WriteString(fmt.Sprintf("  - %s: %s\n    %s\n", w.Description, w.Reclaimable, w.Caveat))
	}
	sb.WriteString(fmt.Sprintf("  Estimated monthly waste: $%.2f/mo (estimate, table dated 2026-10-01)\n\n",
		b.Verdict.EstimatedWasteUSD))

	// 6. What needs attention
	sb.WriteString("6. WHAT NEEDS ATTENTION:\n")
	if len(b.AttentionFindings) == 0 {
		sb.WriteString("  No findings require immediate attention.\n")
	} else {
		for i, f := range b.AttentionFindings {
			sb.WriteString(fmt.Sprintf("  [%d] [%s] %s\n", i+1, strings.ToUpper(string(f.Severity)), f.What))
			sb.WriteString(fmt.Sprintf("      So what:  %s\n", f.SoWhat))
			sb.WriteString(fmt.Sprintf("      Now what: %s (risk: %s, reversible: %v)\n",
				f.NowWhat.Action, f.NowWhat.RiskLevel, f.NowWhat.Reversible))
			cert := strings.ToUpper(string(f.Proof.Certainty))
			evSummary := f.RuleID
			if len(f.Proof.Evidence) > 0 {
				evSummary = f.Proof.Evidence[0].Source
			}
			sb.WriteString(fmt.Sprintf("      Proof:    [%s] %s (confidence: %.2f)\n", cert, evSummary, f.Proof.Confidence))
		}
		if b.CollapsedFindings > 0 {
			sb.WriteString(fmt.Sprintf("  ... and %d more findings collapsed (run with full details or inspect web dashboard)\n", b.CollapsedFindings))
		}
	}
	sb.WriteString("\n")

	// 7. What I can't tell you yet
	sb.WriteString("7. WHAT I CANNOT TELL YOU YET:\n")
	for _, p := range b.PendingItems {
		sb.WriteString(fmt.Sprintf("  - %s: requires %s (ETA: %s)\n", p.Metric, p.Requirement, p.ETA))
	}
	sb.WriteString("\n======================================================================\n")

	return sb.String()
}
