// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package chaos_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/inventory"
	"github.com/OWNER/jyoshin/internal/rules"
	"github.com/OWNER/jyoshin/internal/verdict"
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
				"port":           6379,
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
				"port":           5432,
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

	findings := []rules.Finding{
		{
			ID:       "HYG-MANUAL-BINARY:file:/usr/local/bin/custom-collector",
			RuleID:   "HYG-MANUAL-BINARY",
			Category: rules.CategorySecurity,
			Severity: rules.SeverityHigh,
			What:     "Unmanaged binary in /usr/local/bin",
			Proof:    rules.Proof{Confidence: 1.0},
		},
		{
			ID:       "REL-RESTART-LOOP:process:restart-looping",
			RuleID:   "REL-RESTART-LOOP",
			Category: rules.CategoryOperations,
			Severity: rules.SeverityHigh,
			What:     "Service restarting repeatedly",
			Proof:    rules.Proof{Confidence: 1.0},
		},
		{
			ID:       "SEC-EXPOSED-REDIS:port:all:6379",
			RuleID:   "SEC-EXPOSED-REDIS",
			Category: rules.CategorySecurity,
			Severity: rules.SeverityHigh,
			What:     "Unauthenticated Redis exposed to all interfaces",
			Proof:    rules.Proof{Confidence: 1.0},
		},
		{
			ID:       "EFF-LOG-LEAK:file:/var/log/stale",
			RuleID:   "EFF-LOG-LEAK",
			Category: rules.CategoryEfficiency,
			Severity: rules.SeverityMedium,
			What:     "Unrotated log accumulation wasting disk",
			Proof:    rules.Proof{Confidence: 1.0},
		},
	}

	v := verdict.ComputeVerdict(nodes, findings, 10)
	if v.StateLabel != "MESSY" && v.StateLabel != "CRITICAL" {
		t.Errorf("expected chaos host verdict to be MESSY or CRITICAL, got: %s", v.StateLabel)
	}
	if v.ChaosIndex < 45 {
		t.Errorf("expected chaos index >= 45 for chaos host, got: %d", v.ChaosIndex)
	}

	// Verify unmanaged binary file exists
	if _, err := os.Stat(filepath.Join(tempDir, "usr/local/bin/custom-collector")); err != nil {
		t.Errorf("expected custom-collector binary in fixture: %v", err)
	}
}
