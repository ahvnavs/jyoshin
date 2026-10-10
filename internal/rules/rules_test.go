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
	// Tiny budget to test timeout handling
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
