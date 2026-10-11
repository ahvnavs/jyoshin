// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/graph"
)

func TestRules_LintValidAndInvalid(t *testing.T) {
	tmpDir := t.TempDir()

	validRule := `id: "SEC-TEST-VALID"
name: "Test Rule"
description: "A valid test rule"
category: "security"
severity: "high"
match:
  node_type: "port"
  properties:
    local_port:
      equals: 80
consequence: "Test consequence"
recommendation:
  action: "Test action"
  risk_level: "low"
  reversible: true
`
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validRule), 0644); err != nil {
		t.Fatal(err)
	}

	r, err := LintRule(validPath)
	if err != nil {
		t.Fatalf("expected valid rule to pass lint, got: %v", err)
	}
	if r.ID != "SEC-TEST-VALID" {
		t.Errorf("ID mismatch: %s", r.ID)
	}

	// Negative lint test: missing id and invalid category
	invalidRule := `name: "Invalid Rule"
category: "invalid_category"
severity: "high"
match:
  node_type: "port"
consequence: "Consequence"
recommendation:
  action: "Action"
  risk_level: "low"
`
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidRule), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LintRule(invalidPath)
	if err == nil {
		t.Fatal("expected invalid rule to fail linting, got nil")
	}
}

func TestRules_EngineEvaluationAndLifecycle(t *testing.T) {
	engine := NewEngine(2 * time.Second)

	ruleYAML := `id: "SEC-REDIS-PUBLIC"
name: "Redis Publicly Bound"
description: "Redis bound to 0.0.0.0"
category: "security"
severity: "critical"
match:
  node_type: "port"
  properties:
    local_port:
      equals: 6379
    exposure_class:
      equals: "all_interfaces"
consequence: "Unauthenticated Redis access"
recommendation:
  action: "Bind to localhost"
  risk_level: "low"
  reversible: true
`
	if _, err := engine.LoadRule([]byte(ruleYAML)); err != nil {
		t.Fatalf("failed to load rule: %v", err)
	}

	now := time.Now().UTC()
	matchingNode := graph.Node{
		ID:    "port:tcp:6379",
		Type:  graph.NodePort,
		Label: "port tcp/6379 (all_interfaces)",
		Properties: map[string]any{
			"local_port":     6379,
			"exposure_class": "all_interfaces",
		},
		Evidence: []graph.Evidence{
			{
				Source:    "/proc/net/tcp",
				Collector: "network",
				Timestamp: now,
				Certainty: graph.CertaintyObserved,
			},
		},
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}

	nonMatchingNode := graph.Node{
		ID:    "port:tcp:22",
		Type:  graph.NodePort,
		Label: "port tcp/22 (loopback)",
		Properties: map[string]any{
			"local_port":     22,
			"exposure_class": "loopback",
		},
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}

	nodes := []graph.Node{matchingNode, nonMatchingNode}

	// First evaluation pass -> LifecycleNew
	findings, err := engine.Evaluate(context.Background(), nodes, nil)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SEC-REDIS-PUBLIC" || f.Lifecycle != LifecycleNew {
		t.Errorf("finding mismatch: %+v", f)
	}
	if f.Score <= 0 {
		t.Errorf("expected positive score, got %f", f.Score)
	}

	// Second evaluation pass with same nodes -> LifecycleOngoing
	findings2, err := engine.Evaluate(context.Background(), nodes, nil)
	if err != nil {
		t.Fatalf("unexpected second eval error: %v", err)
	}
	if len(findings2) != 1 || findings2[0].Lifecycle != LifecycleOngoing {
		t.Errorf("expected LifecycleOngoing, got: %+v", findings2)
	}

	// Third evaluation pass with resolved node (no longer listening on 6379)
	findings3, err := engine.Evaluate(context.Background(), []graph.Node{nonMatchingNode}, nil)
	if err != nil {
		t.Fatalf("unexpected third eval error: %v", err)
	}
	if len(findings3) != 0 {
		t.Fatalf("expected 0 active findings, got %d", len(findings3))
	}
	if prev := engine.history[f.ID]; prev.Lifecycle != LifecycleResolved {
		t.Errorf("expected history to mark finding as LifecycleResolved, got %s", prev.Lifecycle)
	}
}

func TestRules_JoinEvaluation(t *testing.T) {
	engine := NewEngine(2 * time.Second)

	joinRule := `id: "SEC-ROOT-LISTENER-TEST"
name: "Root listener"
description: "Root listener on 0.0.0.0"
category: "security"
severity: "high"
match:
  node_type: "port"
  properties:
    exposure_class:
      equals: "all_interfaces"
  join:
    relation: "listens_on"
    direction: "in"
    node_type: "process"
    properties:
      uid:
        equals: 0
consequence: "Consequence"
recommendation:
  action: "Action"
  risk_level: "medium"
  reversible: true
`
	if _, err := engine.LoadRule([]byte(joinRule)); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	portNode := graph.Node{
		ID:         "port:1",
		Type:       graph.NodePort,
		Label:      "port 8080",
		Properties: map[string]any{"exposure_class": "all_interfaces"},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}

	// Positive test: process is root (uid 0)
	rootProcNode := graph.Node{
		ID:         "proc:1",
		Type:       graph.NodeProcess,
		Label:      "proc root",
		Properties: map[string]any{"uid": 0},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}
	edge1 := graph.Edge{
		ID:       "edge:1",
		SourceID: "proc:1",
		TargetID: "port:1",
		Relation: "listens_on",
	}

	findings, err := engine.Evaluate(context.Background(), []graph.Node{portNode, rootProcNode}, []graph.Edge{edge1})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("positive join test failed: expected 1 finding, got %d", len(findings))
	}

	// Negative test: process is unprivileged (uid 1000)
	unprivProcNode := graph.Node{
		ID:         "proc:2",
		Type:       graph.NodeProcess,
		Label:      "proc unpriv",
		Properties: map[string]any{"uid": 1000},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}
	edge2 := graph.Edge{
		ID:       "edge:2",
		SourceID: "proc:2",
		TargetID: "port:1",
		Relation: "listens_on",
	}

	findingsNeg, err := engine.Evaluate(context.Background(), []graph.Node{portNode, unprivProcNode}, []graph.Edge{edge2})
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsNeg) != 0 {
		t.Fatalf("negative join test failed: expected 0 findings, got %d", len(findingsNeg))
	}
}

func TestRules_AggregateEvaluation(t *testing.T) {
	engine := NewEngine(2 * time.Second)

	aggRule := `id: "COST-DUP-RUNTIME-TEST"
name: "Duplicate runtime"
description: "Duplicate runtime"
category: "cost"
severity: "low"
match:
  node_type: "origin"
  properties:
    kind:
      equals: "runtime"
  aggregate:
    group_by: "source"
    count_distinct: "version"
    greater_than: 1
consequence: "Consequence"
recommendation:
  action: "Action"
  risk_level: "low"
  reversible: true
`
	if _, err := engine.LoadRule([]byte(aggRule)); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	// Positive: two distinct versions for python
	pyNode1 := graph.Node{
		ID:         "orig:py1",
		Type:       graph.NodeOrigin,
		Label:      "python 3.10",
		Properties: map[string]any{"kind": "runtime", "source": "python", "version": "3.10"},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}
	pyNode2 := graph.Node{
		ID:         "orig:py2",
		Type:       graph.NodeOrigin,
		Label:      "python 3.12",
		Properties: map[string]any{"kind": "runtime", "source": "python", "version": "3.12"},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}

	findingsPos, err := engine.Evaluate(context.Background(), []graph.Node{pyNode1, pyNode2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsPos) != 1 {
		t.Fatalf("expected 1 aggregate finding for duplicate python, got %d", len(findingsPos))
	}

	// Negative: only 1 version for node
	nodeNode1 := graph.Node{
		ID:         "orig:node1",
		Type:       graph.NodeOrigin,
		Label:      "node 20",
		Properties: map[string]any{"kind": "runtime", "source": "node", "version": "20.10.0"},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}

	findingsNeg, err := engine.Evaluate(context.Background(), []graph.Node{nodeNode1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsNeg) != 0 {
		t.Fatalf("expected 0 aggregate findings for single node version, got %d", len(findingsNeg))
	}
}

func TestRules_EOLEvaluation(t *testing.T) {
	engine := NewEngine(2 * time.Second)

	eolRule := `id: "OPS-EOL-TEST"
name: "EOL OS"
description: "EOL OS"
category: "operations"
severity: "high"
match:
  node_type: "system"
  check_eol: true
consequence: "Consequence"
recommendation:
  action: "Action"
  risk_level: "high"
  reversible: false
`
	if _, err := engine.LoadRule([]byte(eolRule)); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	// Positive test: Ubuntu 20.04 is EOL (eol date: 2025-04-30)
	eolNode := graph.Node{
		ID:         "sys:eol",
		Type:       graph.NodeSystem,
		Label:      "Ubuntu 20.04",
		Properties: map[string]any{"distro_family": "ubuntu", "distro_version": "20.04"},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}
	findingsPos, err := engine.Evaluate(context.Background(), []graph.Node{eolNode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsPos) != 1 {
		t.Fatalf("expected 1 EOL finding for Ubuntu 20.04, got %d", len(findingsPos))
	}

	// Negative test: Ubuntu 24.04 is supported until 2029
	supportedNode := graph.Node{
		ID:         "sys:supported",
		Type:       graph.NodeSystem,
		Label:      "Ubuntu 24.04",
		Properties: map[string]any{"distro_family": "ubuntu", "distro_version": "24.04"},
		Certainty:  graph.CertaintyObserved,
		FirstSeen:  now,
		LastSeen:   now,
	}
	findingsNeg, err := engine.Evaluate(context.Background(), []graph.Node{supportedNode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsNeg) != 0 {
		t.Fatalf("expected 0 EOL findings for Ubuntu 24.04, got %d", len(findingsNeg))
	}
}

func TestRules_CalmHostZeroNoise(t *testing.T) {
	engine := NewEngine(2 * time.Second)
	count, err := engine.LoadDirectory("../../rules")
	if err != nil {
		t.Fatalf("failed loading rules: %v", err)
	}
	if count < 10 {
		t.Fatalf("expected at least 10 rules loaded, got %d", count)
	}

	now := time.Now().UTC()
	// Standard healthy Linux host
	calmNodes := []graph.Node{
		{
			ID:    "sys:host1",
			Type:  graph.NodeSystem,
			Label: "host:prod-web-01",
			Properties: map[string]any{
				"distro":            "Ubuntu 24.04.1 LTS",
				"distro_family":     "ubuntu",
				"distro_version":    "24.04",
				"virtualization":    "kvm",
				"cloud_provider":    "aws",
				"reboot_required":   false,
				"reclaimable_count": 0,
			},
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		},
		{
			ID:    "proc:1",
			Type:  graph.NodeProcess,
			Label: "systemd (pid 1)",
			Properties: map[string]any{
				"name":     "systemd",
				"uid":      0,
				"open_fds": 42,
				"vsize":    104857600,
			},
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		},
		{
			ID:    "port:22",
			Type:  graph.NodePort,
			Label: "port tcp/22 (loopback)",
			Properties: map[string]any{
				"local_port":     22,
				"exposure_class": "loopback",
			},
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		},
		{
			ID:    "res:mount-root",
			Type:  graph.NodeResource,
			Label: "mount / (ext4)",
			Properties: map[string]any{
				"mount_point": "/",
				"usage_ratio": 0.45,
			},
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		},
	}

	findings, err := engine.Evaluate(context.Background(), calmNodes, nil)
	if err != nil {
		t.Fatalf("evaluation error: %v", err)
	}

	// Must yield zero findings above info on calm host
	for _, f := range findings {
		if f.Severity != SeverityInfo {
			t.Errorf("calm host produced non-info finding: ID=%s, Sev=%s, What=%s", f.ID, f.Severity, f.What)
		}
	}
}

func TestRules_SuppressionFile(t *testing.T) {
	engine := NewEngine(2 * time.Second)

	ruleYAML := `id: "SEC-SUPPRESSED-1"
name: "Suppressed Rule"
description: "desc"
category: "security"
severity: "info"
match:
  node_type: "port"
consequence: "c"
recommendation:
  action: "a"
  risk_level: "none"
  reversible: true
`
	_, _ = engine.LoadRule([]byte(ruleYAML))

	tmpDir := t.TempDir()
	suppressPath := filepath.Join(tmpDir, "suppressions.txt")
	_ = os.WriteFile(suppressPath, []byte("# comment\nSEC-SUPPRESSED-1\n"), 0644)

	if err := engine.LoadSuppressionFile(suppressPath); err != nil {
		t.Fatal(err)
	}

	nodes := []graph.Node{{ID: "p1", Type: graph.NodePort}}
	findings, err := engine.Evaluate(context.Background(), nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected suppressed rule to produce 0 findings, got %d", len(findings))
	}
}

func TestRules_EvaluationTimeBudget(t *testing.T) {
	engine := NewEngine(1 * time.Nanosecond)
	ruleYAML := `id: "RULE-TIMEOUT"
name: "Timeout Rule"
description: "desc"
category: "security"
severity: "low"
match:
  node_type: "port"
consequence: "c"
recommendation:
  action: "a"
  risk_level: "low"
  reversible: true
`
	_, _ = engine.LoadRule([]byte(ruleYAML))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // instantly cancelled

	_, err := engine.Evaluate(ctx, []graph.Node{{ID: "p", Type: graph.NodePort}}, nil)
	if err == nil {
		t.Fatal("expected evaluation error when context budget cancelled")
	}
}
