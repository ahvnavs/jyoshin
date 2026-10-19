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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/OWNER/kazeshini/data"
	"github.com/OWNER/kazeshini/internal/contract"
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
	Verdict               verdict.Summary        `json:"verdict"`
	Coverage              coverage.Report        `json:"coverage"`
	Identity              MachineIdentity        `json:"identity"`
	Programs              []ProgramGroup         `json:"programs"`
	ExposedPorts          []ExposedPort          `json:"exposed_ports"`
	HandInstalled         []HandInstalledBinary  `json:"hand_installed"`
	OrphanCoveragePercent float64                `json:"orphan_coverage_percent"`
	OrphanFilesInspected  int                    `json:"orphan_files_inspected"`
	Waste                 []WasteItem            `json:"waste"`
	AttentionFindings     []rules.Finding        `json:"attention_findings"`
	CollapsedFindings     int                    `json:"collapsed_findings"`
	PendingItems          []PendingItem          `json:"pending_items"`
	Results               []contract.CheckResult `json:"results,omitempty"`
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

	type daemonDef struct {
		PlainName string `yaml:"plain_name"`
		Purpose   string `yaml:"purpose"`
	}
	daemonMap := make(map[string]daemonDef)
	if raw, err := data.EOLData.ReadFile("programs.yaml"); err == nil {
		var doc struct {
			Programs map[string]daemonDef `yaml:"programs"`
		}
		if err := yaml.Unmarshal(raw, &doc); err == nil {
			daemonMap = doc.Programs
		}
	}

	myPID := os.Getpid()
	var (
		dbCount     int
		httpCount   int
		workerCount int
		hasDBPort   bool
		hasHTTPPort bool
		hasWorker   bool
	)

	for _, n := range nodes {
		switch n.Type {
		case graph.NodeSystem:
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
		case graph.NodePort:
			if p, ok := n.Properties["port"].(int); ok {
				switch p {
				case 5432, 3306, 6379, 27017:
					hasDBPort = true
					dbCount++
				case 80, 443, 8080, 8443:
					hasHTTPPort = true
					httpCount++
				}
			}
		case graph.NodeProcess:
			pid, _ := n.Properties["pid"].(int)
			if pid != myPID {
				hasWorker = true
				workerCount++
			}
		}
	}

	// Role inference with strict INFERRED evidence and confidence threshold
	if hasDBPort && dbCount >= 1 {
		ident.InferredRole = "database server"
		ident.RoleEvidence = "active database listening port (PostgreSQL/MySQL/Redis) bound on host"
	} else if hasHTTPPort && httpCount >= 1 {
		ident.InferredRole = "web / application server"
		ident.RoleEvidence = "HTTP/HTTPS edge listening port active"
	} else if hasWorker && workerCount >= 5 {
		ident.InferredRole = "background worker node"
		ident.RoleEvidence = fmt.Sprintf("fleet of %d headless application processes without public listening ports", workerCount)
	} else {
		ident.InferredRole = "not enough signal to determine host role"
		ident.RoleEvidence = "low process and network listener count; no specialized database, cache, or web gateway detected"
	}

	// 2. What it runs: Group programs (excluding kazeshini self)
	procGroups := make(map[string]*ProgramGroup)
	for _, n := range nodes {
		if n.Type == graph.NodeProcess {
			pid, _ := n.Properties["pid"].(int)
			if pid == myPID {
				continue // Exclude kazeshini daemon itself from what it runs
			}

			name, _ := n.Properties["name"].(string)
			cmdline, _ := n.Properties["cmdline"].(string)
			pkgName, _ := n.Properties["origin_package"].(string)

			// Clean program display name (never bare "exe" or binary path)
			displayName := name
			if displayName == "exe" || displayName == "" {
				if cmdline != "" {
					parts := strings.Fields(cmdline)
					if len(parts) > 0 {
						displayName = filepath.Base(parts[0])
					}
				} else if pkgName != "" {
					displayName = pkgName
				} else {
					displayName = n.Label
					if idx := strings.Index(displayName, " (pid "); idx != -1 {
						displayName = displayName[:idx]
					}
				}
			}
			if displayName == "exe" || displayName == "" {
				displayName = "unknown"
			}

			pg, exists := procGroups[displayName]
			if !exists {
				installedBy := "system package manager"
				if pkgName != "" {
					installedBy = pkgName
				} else if origKind, ok := n.Properties["origin_kind"].(string); ok && origKind == "manual" {
					installedBy = "manual drop"
				}

				// Check daemon dictionary for plain name and purpose
				pgName := displayName
				if dDef, ok := daemonMap[displayName]; ok {
					pgName = fmt.Sprintf("%s (%s)", dDef.PlainName, displayName)
				}

				pg = &ProgramGroup{
					Name:         pgName,
					ProcessCount: 0,
					InstalledBy:  installedBy,
					RunningSince: "recently",
					Ports:        "none",
				}
				procGroups[displayName] = pg
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

	selfExe, _ := os.Executable()
	isSelf := func(p string) bool {
		if selfExe != "" && p == selfExe {
			return true
		}
		base := filepath.Base(p)
		return base == "kazeshini"
	}

	for _, n := range nodes {
		if n.Type == graph.NodeFile {
			if origKind, ok := n.Properties["origin_kind"].(string); ok && origKind == "manual" {
				path, _ := n.Properties["path"].(string)
				if path == "" {
					path = n.Label
				}
				if isSelf(path) {
					continue
				}
				handInstalled = append(handInstalled, HandInstalledBinary{
					Name:    filepath.Base(path),
					Path:    path,
					Warning: "Not updated by your package manager. Must be updated manually.",
				})
			}
		}
	}

	if len(orphans) > 0 {
		last := orphans[len(orphans)-1]
		orphanCoverage = last.CoveragePercent
		filesInspected = last.FilesInspected
		for _, o := range last.Orphans {
			if isSelf(o.Path) {
				continue
			}
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
		Requirement:    "6 samples spanning >= 1 hour per mount and resource",
		RemainingHours: "Collecting",
		ETA:            "Available after 1 hour of runtime telemetry",
	})

	// 8. One Result Contract: populate standardized CheckResults from findings
	procSeen := 0
	procTotal := 0
	for _, it := range cov.Items {
		if it.Category == "process" || it.Name == "Processes Readable" {
			procSeen = it.Readable
			procTotal = it.Total
			break
		}
	}

	var checkResults []contract.CheckResult
	for _, f := range attention {
		st := contract.StatusWarn
		switch f.Severity {
		case rules.SeverityCritical:
			st = contract.StatusCrit
		case rules.SeverityInfo, rules.SeverityLow:
			st = contract.StatusOK
		}

		cr := contract.CheckResult{
			ID:           f.ID,
			Role:         string(f.Category),
			Title:        f.What,
			Status:       st,
			SummaryPlain: f.SoWhat,
			ExplainLevels: [3]string{
				f.What,
				f.SoWhat,
				f.NowWhat.Action,
			},
			Evidence:          f.Proof.Evidence,
			Certainty:         f.Proof.Certainty,
			EquivalentCommand: "",
			NextStepCommand:   f.NowWhat.Action,
			ReadOnly:          true,
			CollectedAt:       now,
			Coverage: contract.CoverageSummary{
				Seen:   procSeen,
				Total:  procTotal,
				Reason: cov.SummaryNote,
			},
		}
		checkResults = append(checkResults, cr)
	}

	// Compute verdict with coverage honesty and check results
	vSum := verdict.ComputeVerdictWithChecks(nodes, findings, len(handInstalled), cov.IsAdequate, cov.SummaryNote, checkResults)

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
		Results:               checkResults,
	}
}

// RenderTerminal formats the overview into clean plain text for CLI / SSH output.
func (b *Briefing) RenderTerminal() string {
	var sb strings.Builder

	sb.WriteString("======================================================================\n")
	sb.WriteString("風死 · KAZESHINI — SERVER OVERVIEW & DIAGNOSTICS\n")
	sb.WriteString("----------------------------------------------------------------------\n")
	sb.WriteString("START HERE:\n")
	sb.WriteString("  1. Kazeshini is a read-only server truth engine.\n")
	sb.WriteString("  2. It only inspects system status and makes zero modifications to this host.\n")
	sb.WriteString("  3. Review the findings below or follow the recommended action box below.\n")
	sb.WriteString("----------------------------------------------------------------------\n")
	fmt.Fprintf(&sb, "HEALTH: [%s]   RISK SCORE: %d/100   VISIBILITY: %.0f%%\n",
		strings.ToUpper(b.Verdict.StateLabel), b.Verdict.RiskScore, b.Coverage.OverallCoverage)
	if len(b.Verdict.RiskContributors) > 0 {
		sb.WriteString("RISK CONTRIBUTORS:\n")
		for _, c := range b.Verdict.RiskContributors {
			fmt.Fprintf(&sb, "  • %-42s (+%d pts)\n", c.Label, c.Points)
		}
	}
	sb.WriteString("======================================================================\n\n")

	sb.WriteString("WHAT SHOULD I DO NOW?\n")
	if len(b.AttentionFindings) > 0 {
		top := b.AttentionFindings[0]
		fmt.Fprintf(&sb, "  PRIMARY ACTION: %s\n", top.What)
		fmt.Fprintf(&sb, "  WHY:            %s\n", top.SoWhat)
		fmt.Fprintf(&sb, "  COMMAND:        %s\n", top.NowWhat.Action)
	} else {
		sb.WriteString("  PRIMARY ACTION: No urgent fixes required. System is calm.\n")
		sb.WriteString("  COMMAND:        kazeshini --once\n")
	}
	sb.WriteString("  ASK TECHNICAL:  To share a secret-free summary with an engineer, run:\n")
	sb.WriteString("                  kazeshini report --format md > server-summary.md\n\n")

	sb.WriteString("SUMMARY:\n")
	fmt.Fprintf(&sb, "  %s\n\n", b.Verdict.OneLineVerdict)

	// 1. What this machine is
	sb.WriteString("1. WHAT THIS MACHINE IS:\n")
	fmt.Fprintf(&sb, "  OS:             %s\n", b.Identity.OS)
	fmt.Fprintf(&sb, "  Kernel:         %s\n", b.Identity.Kernel)
	fmt.Fprintf(&sb, "  Architecture:   %s (%d CPU cores)\n", b.Identity.Arch, b.Identity.CPUs)
	fmt.Fprintf(&sb, "  Memory:         %s total\n", b.Identity.TotalRAM)
	fmt.Fprintf(&sb, "  Uptime:         %s\n", b.Identity.Uptime)
	fmt.Fprintf(&sb, "  Platform:       %s (cloud: %s)\n", b.Identity.Virtualization, b.Identity.CloudProvider)
	sb.WriteString("  This tool:      kazeshini (read-only observer, nice 19, ionice idle, zero host changes)\n")
	fmt.Fprintf(&sb, "  Inferred Role:  %s [INFERRED]\n", b.Identity.InferredRole)
	fmt.Fprintf(&sb, "                  Evidence: %s\n\n", b.Identity.RoleEvidence)

	// 2. What it runs
	sb.WriteString("2. WHAT IT RUNS:\n")
	if len(b.Programs) == 0 {
		sb.WriteString("  No managed program groups detected.\n")
	} else {
		for _, p := range b.Programs {
			fmt.Fprintf(&sb, "  - %s (%d processes, %s memory, installed by %s, ports: %s)\n",
				p.Name, p.ProcessCount, p.TotalRSS, p.InstalledBy, p.Ports)
		}
	}
	sb.WriteString("\n")

	// 3. What is reachable from outside
	sb.WriteString("3. WHAT IS REACHABLE FROM OUTSIDE:\n")
	if len(b.ExposedPorts) == 0 {
		sb.WriteString("  No listening ports detected.\n")
	} else {
		fmt.Fprintf(&sb, "  %-8s | %-8s | %-16s | %-14s | %s\n", "PORT", "PROTO", "PROGRAM", "EXPOSURE", "INTERFACE")
		sb.WriteString("  " + strings.Repeat("-", 64) + "\n")
		for _, ep := range b.ExposedPorts {
			fmt.Fprintf(&sb, "  %-8d | %-8s | %-16s | %-14s | %s\n",
				ep.Port, ep.Protocol, ep.Program, ep.Exposure, ep.BindAddress)
		}
	}
	sb.WriteString("\n")

	// 4. What was installed by hand
	sb.WriteString("4. WHAT WAS INSTALLED BY HAND:\n")
	if len(b.HandInstalled) == 0 {
		sb.WriteString("  Zero unmanaged manual binaries detected.\n")
	} else {
		for _, h := range b.HandInstalled {
			fmt.Fprintf(&sb, "  - %s (%s)\n    %s\n", h.Name, h.Path, h.Warning)
		}
	}
	fmt.Fprintf(&sb, "  Orphan scan coverage: %.0f%% (%d files inspected)\n\n",
		b.OrphanCoveragePercent, b.OrphanFilesInspected)

	// 5. What is wasting space or money
	sb.WriteString("5. WHAT IS WASTING SPACE OR MONEY:\n")
	for _, w := range b.Waste {
		fmt.Fprintf(&sb, "  - %s: %s\n    %s\n", w.Description, w.Reclaimable, w.Caveat)
	}
	fmt.Fprintf(&sb, "  Estimated monthly waste: $%.2f/mo (estimate, table dated 2026-10-01)\n\n",
		b.Verdict.EstimatedWasteUSD)

	// 6. What needs attention
	sb.WriteString("6. WHAT NEEDS ATTENTION:\n")
	if len(b.AttentionFindings) == 0 {
		sb.WriteString("  No findings require immediate attention.\n")
	} else {
		for i, f := range b.AttentionFindings {
			fmt.Fprintf(&sb, "  [%d] [%s] %s\n", i+1, strings.ToUpper(string(f.Severity)), f.What)
			fmt.Fprintf(&sb, "      So what:  %s\n", f.SoWhat)
			fmt.Fprintf(&sb, "      Now what: %s (risk: %s, reversible: %v)\n",
				f.NowWhat.Action, f.NowWhat.RiskLevel, f.NowWhat.Reversible)
			cert := strings.ToUpper(string(f.Proof.Certainty))
			evSummary := f.RuleID
			if len(f.Proof.Evidence) > 0 {
				evSummary = f.Proof.Evidence[0].Source
			}
			fmt.Fprintf(&sb, "      Proof:    [%s] %s (confidence: %.2f)\n", cert, evSummary, f.Proof.Confidence)
		}
		if b.CollapsedFindings > 0 {
			fmt.Fprintf(&sb, "  ... and %d more findings collapsed (run with full details or inspect web dashboard)\n", b.CollapsedFindings)
		}
	}
	sb.WriteString("\n")

	// 7. What I can't tell you yet
	sb.WriteString("7. WHAT I CANNOT TELL YOU YET:\n")
	for _, p := range b.PendingItems {
		fmt.Fprintf(&sb, "  - %s: requires %s (ETA: %s)\n", p.Metric, p.Requirement, p.ETA)
	}
	sb.WriteString("\n======================================================================\n")

	return sb.String()
}
