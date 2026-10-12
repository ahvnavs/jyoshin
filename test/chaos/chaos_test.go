// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package chaos_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/desired"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/policy"
	"github.com/OWNER/kazeshini/internal/resource"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
)

func TestChaosFixtureHost(t *testing.T) {
	tempDir := t.TempDir()

	cmd := exec.Command("sh", "../../test/chaos/setup_chaos.sh", tempDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup_chaos.sh failed: %v, out: %s", err, string(out))
	}

	rfs := fs.NewRootedFS(tempDir)
	invMgr := inventory.NewManager(rfs)
	inv, err := invMgr.CollectInventory(t.Context())
	if err != nil {
		t.Fatalf("failed to collect inventory: %v", err)
	}

	// Verify packages detected
	if len(inv.Packages) < 2 {
		t.Errorf("expected at least 2 dpkg packages, got %d", len(inv.Packages))
	}

	// Verify runtimes detected
	foundEOL := false
	for _, rt := range inv.Runtimes {
		if rt.IsEOL {
			foundEOL = true
		}
	}
	t.Logf("Detected %d runtimes, EOL present: %v", len(inv.Runtimes), foundEOL)

	// Build graph representing chaos host
	nodes := []graph.Node{
		{
			ID:        "host:chaos-demo",
			Type:      graph.NodeSystem,
			Label:     "chaos-demo-server",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"distro":    "Ubuntu 22.04 LTS",
				"cpu_count": 4,
			},
		},
		{
			ID:        "file:/usr/local/bin/custom-collector",
			Type:      graph.NodeFile,
			Label:     "custom-collector",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
		{
			ID:        "port:all:6379",
			Type:      graph.NodePort,
			Label:     "0.0.0.0:6379",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"local_port":     6379,
				"exposure_class": "all_interfaces",
			},
		},
		{
			ID:        "port:all:5432",
			Type:      graph.NodePort,
			Label:     "0.0.0.0:5432",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"local_port":     5432,
				"exposure_class": "all_interfaces",
			},
		},
		{
			ID:        "process:restart-looping",
			Type:      graph.NodeProcess,
			Label:     "restart-looping-svc",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		},
	}

	ruleEngine := rules.NewEngine(3 * time.Second)
	ruleCount, err := ruleEngine.LoadDirectory("../../rules")
	if err != nil {
		t.Fatalf("failed loading rules: %v", err)
	}
	t.Logf("Loaded %d declarative rules for chaos evaluation", ruleCount)

	// 1. Manual binary with a listener:
	// Process node with origin_kind: manual
	manualProcNode := graph.Node{
		ID:        "process:manual-api",
		Type:      graph.NodeProcess,
		Label:     "manual-api",
		Certainty: graph.CertaintyObserved,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Properties: map[string]any{
			"exe":         "/usr/local/bin/manual-api",
			"origin_kind": "manual",
		},
	}
	manualPortNode := graph.Node{
		ID:        "port:all:8088",
		Type:      graph.NodePort,
		Label:     "0.0.0.0:8088",
		Certainty: graph.CertaintyObserved,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Properties: map[string]any{
			"local_port":     8088,
			"exposure_class": "all_interfaces",
		},
	}
	// Edge connecting port -> process with relation "listens_on"
	edges := []graph.Edge{
		{
			ID:        "edge:port-to-proc",
			SourceID:  "process:manual-api",
			TargetID:  "port:all:8088",
			Relation:  "listens_on",
			Certainty: graph.CertaintyObserved,
		},
	}

	// 2. Process running from a deleted binary
	deletedProcNode := graph.Node{
		ID:        "process:deleted-daemon",
		Type:      graph.NodeProcess,
		Label:     "rogue-daemon",
		Certainty: graph.CertaintyObserved,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Properties: map[string]any{
			"exe": "/tmp/dropped-miner (deleted)",
		},
	}

	// 3. Leaking process (monotonic memory growth detected by forecaster)
	leakingResourceNode := graph.Node{
		ID:        "resource:leaking-ram",
		Type:      graph.NodeResource,
		Label:     "system_ram",
		Certainty: graph.CertaintyObserved,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Properties: map[string]any{
			"is_leak": true,
		},
	}

	// 4. EOL Runtime (Python 2.7, EOL since 2020)
	eolRuntimeNode := graph.Node{
		ID:        "origin:runtime:python-2.7",
		Type:      graph.NodeOrigin,
		Label:     "runtime:python 2.7",
		Certainty: graph.CertaintyObserved,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Properties: map[string]any{
			"kind":    "runtime",
			"source":  "python",
			"version": "2.7.18",
		},
	}

	nodes = append(nodes,
		manualProcNode,
		manualPortNode,
		deletedProcNode,
		leakingResourceNode,
		eolRuntimeNode,
	)

	// Add origin nodes for duplicate runtime detection
	nodes = append(nodes,
		graph.Node{
			ID:        "origin:runtime:python-3.8",
			Type:      graph.NodeOrigin,
			Label:     "runtime:python",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"kind":    "runtime",
				"source":  "python",
				"version": "3.8.10",
			},
		},
		graph.Node{
			ID:        "origin:runtime:python-3.11",
			Type:      graph.NodeOrigin,
			Label:     "runtime:python",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"kind":    "runtime",
				"source":  "python",
				"version": "3.11.8",
			},
		},
		graph.Node{
			ID:        "service:crash-loop.service",
			Type:      graph.NodeService,
			Label:     "crash-loop.service",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"active_state":  "failed",
				"restart_count": 8,
			},
		},
	)

	// Run rule engine against chaos host nodes
	findings, err := ruleEngine.Evaluate(t.Context(), nodes, edges)
	if err != nil {
		t.Fatalf("failed evaluating rules against chaos host: %v", err)
	}

	// Tally findings by severity and rule IDs
	firedRuleIDs := make(map[string]bool)
	severityCounts := make(map[rules.Severity]int)
	t.Logf("\n--- Chaos Host Fired Findings (%d total) ---", len(findings))
	for _, f := range findings {
		firedRuleIDs[f.RuleID] = true
		severityCounts[f.Severity]++
		t.Logf("Finding: [%s] ID=%s RuleID=%s Category=%s What=%s",
			f.Severity, f.ID, f.RuleID, f.Category, f.What)
	}

	t.Logf("\n--- Findings Count by Severity ---")
	t.Logf("CRITICAL: %d", severityCounts[rules.SeverityCritical])
	t.Logf("HIGH:     %d", severityCounts[rules.SeverityHigh])
	t.Logf("MEDIUM:   %d", severityCounts[rules.SeverityMedium])
	t.Logf("LOW:      %d", severityCounts[rules.SeverityLow])
	t.Logf("INFO:     %d", severityCounts[rules.SeverityInfo])

	// Assert exact expected rule IDs fired
	expectedRules := []string{
		"SEC-DB-EXPOSED",
		"EFF-SERVICE-RESTART-LOOP",
		"COST-DUPLICATE-RUNTIME",
		"SEC-MANUAL-BINARY-LISTENER",
		"SEC-DELETED-BINARY-EXEC",
		"EFF-MEMORY-LEAK-FORECAST",
		"OPS-EOL-SOFTWARE",
	}
	for _, expectedID := range expectedRules {
		if !firedRuleIDs[expectedID] {
			t.Errorf("expected chaos rule %s to fire, but it did not", expectedID)
		}
	}

	v := verdict.ComputeVerdict(nodes, findings, 10)
	if v.StateLabel != "MESSY" && v.StateLabel != "CRITICAL" {
		t.Errorf("expected chaos host verdict to be MESSY or CRITICAL, got: %s", v.StateLabel)
	}
	if v.ChaosIndex < 40 {
		t.Errorf("expected chaos index >= 40 for chaos host, got: %d", v.ChaosIndex)
	}

	// Verify unmanaged binary file exists
	if _, err := os.Stat(filepath.Join(tempDir, "usr/local/bin/custom-collector")); err != nil {
		t.Errorf("expected custom-collector binary in fixture: %v", err)
	}
}

func TestChaosFixture_DriftAndPlan(t *testing.T) {
	tempDir := t.TempDir()

	cmd := exec.Command("sh", "../../test/chaos/setup_chaos.sh", tempDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup_chaos.sh failed: %v, out: %s", err, string(out))
	}

	rfs := fs.NewRootedFS(tempDir)
	invMgr := inventory.NewManager(rfs)
	inv, err := invMgr.CollectInventory(t.Context())
	if err != nil {
		t.Fatalf("failed to collect inventory: %v", err)
	}

	// Build observed resources
	var observed []resource.Resource
	for _, p := range inv.Packages {
		observed = append(observed, resource.Resource{
			Kind: resource.KindPackage,
			Name: p.Name,
			Spec: map[string]any{"version": p.Version},
		})
	}
	// Add unexpected listening port and unmanaged service
	observed = append(observed,
		resource.Resource{
			Kind: resource.KindPort,
			Name: "23/tcp",
			Spec: map[string]any{"port": 23, "protocol": "tcp"},
		},
		resource.Resource{
			Kind: resource.KindService,
			Name: "telnetd",
			Spec: map[string]any{"active_state": "active"},
		},
	)

	// Desired specification: requires git, forbids openssl, allows only port 22
	desiredState := desired.DesiredState{
		RequiredPackages: []desired.PackageExpectation{
			{Name: "git", Version: "2.39"},
		},
		ForbiddenPackages: []string{"openssl"},
		RequiredServices: []desired.ServiceExpectation{
			{Name: "cron", State: "active"},
		},
		AllowedPorts: []desired.PortExpectation{
			{Port: 22, Protocol: "tcp"},
		},
	}

	adequateCov := coverage.Report{
		IsAdequate: true,
		Items: []coverage.ItemCoverage{
			{Name: "packages", Category: "packages", Status: "full", Readable: 10, Total: 10},
			{Name: "services", Category: "services", Status: "full", Readable: 10, Total: 10},
			{Name: "sockets", Category: "network", Status: "full", Readable: 10, Total: 10},
		},
	}

	engine := drift.NewEngine()
	driftItems, summary := engine.Evaluate(t.Context(), desiredState, observed, adequateCov)

	if summary.TotalDrift != 4 {
		t.Errorf("expected 4 drift items on chaos fixture, got %d (missing: %d, extra: %d, wrong_state: %d, ports: %d)",
			summary.TotalDrift, summary.Missing, summary.Extra, summary.WrongState, summary.Ports)
	}

	planner := plan.NewPlanner(nil)
	remediationPlan, err := planner.CreatePlan(driftItems)
	if err != nil {
		t.Fatalf("failed creating plan for chaos fixture: %v", err)
	}

	if remediationPlan.TotalSteps != 4 {
		t.Errorf("expected 4 steps in plan, got %d", remediationPlan.TotalSteps)
	}

	// Policy gate
	polEngine := policy.NewEngine(policy.DefaultConfig())
	decision := polEngine.EvaluatePlan(t.Context(), remediationPlan)
	if decision.IsBlocked {
		t.Errorf("unexpected policy blocking on chaos fixture: %+v", decision)
	}
}
