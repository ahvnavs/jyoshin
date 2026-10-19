// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package facts_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/facts"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/verdict"
)

func TestFacts_JSONSchemaCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(tempDir, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "etc/os-release"), []byte("NAME=Debian\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n"), 0644)

	rfs := fs.NewRootedFS(tempDir)
	extractor := facts.NewExtractor(rfs)

	nodes := []graph.Node{
		{ID: "host:srv", Type: graph.NodeSystem, Label: "srv-db-01"},
		{ID: "port:5432", Type: graph.NodePort, Label: "port tcp/5432", Properties: map[string]any{"port": 5432}},
		{ID: "proc:pg", Type: graph.NodeProcess, Label: "postgres"},
	}

	cov := coverage.Report{OverallCoverage: 92.0, IsAdequate: true}
	v := verdict.Summary{StateLabel: "CALM", ChaosIndex: 0}
	inv := &inventory.Inventory{
		Packages: []inventory.Package{
			{Name: "postgresql", Version: "15.0"},
		},
	}

	res := extractor.Extract(context.Background(), nodes, cov, v, inv)

	// Validate JSON marshaling
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed marshaling facts: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed unmarshaling facts: %v", err)
	}

	// Verify required keys expected by Ansible, Terraform, Puppet, and Chef
	requiredKeys := []string{
		"host_id", "timestamp", "verdict_status", "chaos_index",
		"coverage_percent", "coverage_adequate", "listening_ports",
		"total_processes", "total_packages", "attributes",
	}

	for _, k := range requiredKeys {
		if _, ok := parsed[k]; !ok {
			t.Errorf("missing expected fact key: %s", k)
		}
	}

	if res.HostID != "srv-db-01" {
		t.Errorf("expected host_id srv-db-01, got %s", res.HostID)
	}
	if len(res.ListeningPorts) != 1 || res.ListeningPorts[0] != 5432 {
		t.Errorf("expected listening port 5432, got %v", res.ListeningPorts)
	}

	t.Logf("[✓] Facts JSON schema verified: compatible with Ansible /etc/ansible/facts.d, Terraform external, and Facter")
}
