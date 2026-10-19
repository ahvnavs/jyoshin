// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package plan_test

import (
	"testing"

	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/resource"
)

func TestPlan_TopologicalSort_And_Cycles(t *testing.T) {
	steps := []plan.Step{
		{ID: "c", ResourceName: "c", Dependencies: []string{"b"}},
		{ID: "a", ResourceName: "a", Dependencies: []string{}},
		{ID: "b", ResourceName: "b", Dependencies: []string{"a"}},
	}

	sorted, err := plan.TopologicalSort(steps)
	if err != nil {
		t.Fatalf("TopologicalSort failed: %v", err)
	}

	if len(sorted) != 3 {
		t.Fatalf("expected 3 sorted steps, got %d", len(sorted))
	}
	if sorted[0].ID != "a" || sorted[1].ID != "b" || sorted[2].ID != "c" {
		t.Errorf("incorrect topological order: got %s, %s, %s; want a, b, c", sorted[0].ID, sorted[1].ID, sorted[2].ID)
	}

	// Cycle detection
	cyclicSteps := []plan.Step{
		{ID: "step-1", Dependencies: []string{"step-2"}},
		{ID: "step-2", Dependencies: []string{"step-1"}},
	}
	_, err = plan.TopologicalSort(cyclicSteps)
	if err == nil {
		t.Errorf("expected error on cyclic dependencies, but got nil")
	}
}

func TestPlan_DeterminismAndPlanner(t *testing.T) {
	driftItems := []drift.Item{
		{
			ID:           "drift:svc:wrong-state:nginx",
			ResourceKind: resource.KindService,
			Name:         "nginx",
			Kind:         drift.KindWrongState,
			Expected:     "active",
			Actual:       "inactive",
		},
		{
			ID:           "drift:pkg:missing:nginx",
			ResourceKind: resource.KindPackage,
			Name:         "nginx",
			Kind:         drift.KindMissing,
			Expected:     "installed",
			Actual:       "not installed",
		},
	}

	planner := plan.NewPlanner(nil)

	// Test run 1
	p1, err := planner.CreatePlan(driftItems)
	if err != nil {
		t.Fatalf("CreatePlan failed: %v", err)
	}

	// Test run 2
	p2, err := planner.CreatePlan(driftItems)
	if err != nil {
		t.Fatalf("CreatePlan failed: %v", err)
	}

	// Deterministic hash assert
	if p1.Hash != p2.Hash {
		t.Errorf("expected deterministic plan hash across identical inputs, got %q vs %q", p1.Hash, p2.Hash)
	}

	// Package install must precede service start in DAG
	if len(p1.Steps) != 2 {
		t.Fatalf("expected 2 steps in plan, got %d", len(p1.Steps))
	}
	if p1.Steps[0].Action != "install" || p1.Steps[1].Action != "start" {
		t.Errorf("dependency wiring failed: expected [install, start], got [%s, %s]", p1.Steps[0].Action, p1.Steps[1].Action)
	}
}
