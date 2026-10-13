// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package software

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/blastradius"
	"github.com/OWNER/kazeshini/internal/graph"
)

// SoftwarePlan is a deterministic, read-only upgrade/remove/install plan for a
// single package. It combines the dry-run simulation, safety analysis, and blast
// radius to give the operator a complete picture before acting.
// Nothing in this plan is ever executed automatically (Principles 2, 2', 17).
type SoftwarePlan struct {
	PackageName       string         `json:"package_name"`
	Kind              DryRunKind     `json:"kind"`
	FromVersion       string         `json:"from_version"`
	ToVersion         string         `json:"to_version,omitempty"`
	Manager           string         `json:"manager"`
	IsUpgradable      bool           `json:"is_upgradable"`

	// The raw unmodified dry-run output (Principle 6: fact vs inference)
	RawSimulation     string         `json:"raw_simulation"`

	// Parsed changes from the simulation
	WillInstall       []SimLine      `json:"will_install,omitempty"`
	WillRemove        []SimLine      `json:"will_remove,omitempty"`
	WillConfigure     []SimLine      `json:"will_configure,omitempty"`
	AdditionalPkgs    []string       `json:"additional_packages,omitempty"` // co-installed or co-removed
	ServicesRestarted []string       `json:"services_restarted,omitempty"`
	RequiresReboot    bool           `json:"requires_reboot"`
	IsReversible      bool           `json:"is_reversible"`

	// Safety analysis
	Safety            SafetyAnalysis `json:"safety"`

	// Blast radius
	BlastScore        int            `json:"blast_score"`
	BlastSummary      string         `json:"blast_summary"`

	// Equivalent command (shown only, never run automatically)
	EquivalentCommand string         `json:"equivalent_command"`
	RefreshCommand    string         `json:"refresh_command,omitempty"` // if metadata is stale

	// Metadata
	MetadataAge       string         `json:"metadata_age"`
	MetadataStale     bool           `json:"metadata_stale"`
	CreatedAt         time.Time      `json:"created_at"`
}

// Planner generates software plans combining dry-run, safety, and blast radius.
type Planner struct {
	reader        *InventoryReader
	blastAnalyzer *blastradius.Analyzer
	dryRunCfg     DryRunConfig
}

// NewPlanner creates a new software plan generator.
func NewPlanner(reader *InventoryReader, analyzer *blastradius.Analyzer) *Planner {
	return &Planner{
		reader:       reader,
		blastAnalyzer: analyzer,
		dryRunCfg:    DefaultDryRunConfig(),
	}
}

// CreatePlan generates a full SoftwarePlan for a package and operation kind.
// Uses apt-get -s for apt-managed packages. Fills in safety analysis and blast radius.
func (p *Planner) CreatePlan(ctx context.Context, pkgName string, kind DryRunKind, nodes []graph.Node, runningKernel string) (*SoftwarePlan, error) {
	if err := ValidatePackageName(pkgName); err != nil {
		return nil, fmt.Errorf("invalid package name: %w", err)
	}

	entry := p.reader.LookupPackage(pkgName, nodes)
	if entry == nil && kind != DryRunInstall {
		return nil, fmt.Errorf("package %q is not installed", pkgName)
	}

	// Run the dry-run simulation (exec allow-list enforced in dryrun.go)
	dryRun := RunAptDryRun(ctx, pkgName, kind, p.dryRunCfg)

	// Safety analysis
	safety := AnalyzeSafety(entry, kind, &dryRun, runningKernel)

	// Parse co-changes
	var instLines, remvLines, confLines []SimLine
	var additionalPkgs []string
	for _, line := range dryRun.Lines {
		switch line.Action {
		case "install":
			instLines = append(instLines, line)
			if line.Package != pkgName {
				additionalPkgs = appendUnique(additionalPkgs, line.Package)
			}
		case "remove":
			remvLines = append(remvLines, line)
			if line.Package != pkgName {
				additionalPkgs = appendUnique(additionalPkgs, line.Package)
			}
		case "configure":
			confLines = append(confLines, line)
		}
	}

	// Determine services that would restart (from running map)
	var servicesRestarted []string
	if entry != nil {
		servicesRestarted = entry.Running.ServiceNames
	}
	// Also check additional packages for running services
	for _, ap := range additionalPkgs {
		if ae := p.reader.LookupPackage(ap, nodes); ae != nil {
			servicesRestarted = append(servicesRestarted, ae.Running.ServiceNames...)
		}
	}

	// Reboot required: kernel or libc changes
	requiresReboot := strings.HasPrefix(pkgName, "linux-image-") ||
		strings.HasPrefix(pkgName, "linux-kernel-") ||
		pkgName == "libc6" || pkgName == "libc-bin" || pkgName == "glibc"

	// Reversible: installs and upgrades are reversible; purge of config files is not
	isReversible := kind != DryRunRemove

	// Blast radius (reuse Phase 25 engine)
	blastScore := 0
	blastSummary := "Blast radius data not available (no graph analyzer)."
	if p.blastAnalyzer != nil {
		nodeID := string(graph.NodePackage) + ":" + pkgName
		if rep, err := p.blastAnalyzer.Analyze(nodeID); err == nil {
			blastScore = rep.ImpactScore
			blastSummary = rep.VerdictSummary
		}
	}

	// Equivalent command
	eqCmd := buildEquivalentCommand(pkgName, kind)

	// Metadata info
	metadataAge := "unknown"
	metadataStale := false
	if entry != nil {
		inv := p.reader.Collect(nodes)
		metadataAge = inv.Metadata.AgeHuman
		metadataStale = inv.Metadata.IsStale
	}

	fromVer := ""
	toVer := ""
	if entry != nil {
		fromVer = entry.Version
		if entry.Candidate != nil {
			toVer = entry.Candidate.Version
		}
	}

	return &SoftwarePlan{
		PackageName:       pkgName,
		Kind:              kind,
		FromVersion:       fromVer,
		ToVersion:         toVer,
		Manager:           "apt",
		IsUpgradable:      entry != nil && entry.IsUpgradable,
		RawSimulation:     dryRun.RawOutput,
		WillInstall:       instLines,
		WillRemove:        remvLines,
		WillConfigure:     confLines,
		AdditionalPkgs:    additionalPkgs,
		ServicesRestarted: servicesRestarted,
		RequiresReboot:    requiresReboot,
		IsReversible:      isReversible,
		Safety:            safety,
		BlastScore:        blastScore,
		BlastSummary:      blastSummary,
		EquivalentCommand: eqCmd,
		MetadataAge:       metadataAge,
		MetadataStale:     metadataStale,
		CreatedAt:         time.Now().UTC(),
	}, nil
}

func buildEquivalentCommand(pkgName string, kind DryRunKind) string {
	switch kind {
	case DryRunUpgrade:
		return fmt.Sprintf("sudo apt-get install --only-upgrade -y %s", pkgName)
	case DryRunRemove:
		return fmt.Sprintf("sudo apt-get purge -y %s", pkgName)
	case DryRunInstall:
		return fmt.Sprintf("sudo apt-get install -y %s", pkgName)
	default:
		return ""
	}
}
