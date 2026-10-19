// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package reconcile_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/events"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/policy"
	"github.com/OWNER/kazeshini/internal/reconcile"
	"github.com/OWNER/kazeshini/internal/state"
)

func TestReconcileLoop_ObserveMode(t *testing.T) {
	tmpDir := t.TempDir()
	desiredPath := filepath.Join(tmpDir, "desired.yaml")
	desiredContent := `
apiVersion: kazeshini.io/v1
kind: DesiredState
metadata:
  name: test-spec
rules:
  - state:
      requiredPackages:
        - name: nginx
          version: "1.18.0"
`
	if err := os.WriteFile(desiredPath, []byte(desiredContent), 0644); err != nil {
		t.Fatalf("failed writing desired state: %v", err)
	}

	cfg := reconcile.Config{
		Mode:        reconcile.ModeObserve,
		Interval:    10 * time.Millisecond,
		MaxJitter:   5 * time.Millisecond,
		DesiredPath: desiredPath,
	}

	driftEngine := drift.NewEngine()
	planner := plan.NewPlanner(nil)
	policyEngine := policy.NewEngine(policy.DefaultConfig())
	bus := events.NewBus(100)
	st := state.NewMemoryStore(10)

	loop := reconcile.NewLoop(cfg, driftEngine, planner, policyEngine, bus, st, nil)

	// Invariant: NextInterval should be between Interval and Interval + MaxJitter
	next := loop.NextInterval()
	if next < cfg.Interval || next > cfg.Interval+cfg.MaxJitter {
		t.Errorf("NextInterval out of expected jitter range: got %v", next)
	}

	// 1. Reconcile with empty nodes (should detect missing nginx)
	cov := coverage.Report{
		IsAdequate: true,
		Items: []coverage.ItemCoverage{
			{Name: "packages", Category: "packages", Status: "full"},
		},
	}
	items, p, dec, err := loop.ReconcileOnce(context.Background(), nil, cov)
	if err != nil {
		t.Fatalf("ReconcileOnce returned error: %v", err)
	}

	if len(items) == 0 {
		t.Fatalf("expected drift item for missing package 'nginx', got 0")
	}

	if p != nil || dec != nil {
		t.Errorf("expected plan and decision to be nil in observe mode, got p=%v, dec=%v", p, dec)
	}

	lastItems, lastPlan, lastDec, lastRun := loop.LastStatus()
	if len(lastItems) != len(items) || lastPlan != nil || lastDec != nil || lastRun.IsZero() {
		t.Errorf("LastStatus mismatch: items=%d, plan=%v, run=%v", len(lastItems), lastPlan, lastRun)
	}
}

func TestReconcileLoop_PlanMode(t *testing.T) {
	tmpDir := t.TempDir()
	desiredPath := filepath.Join(tmpDir, "desired.yaml")
	desiredContent := `
apiVersion: kazeshini.io/v1
kind: DesiredState
metadata:
  name: test-plan-spec
rules:
  - state:
      requiredPackages:
        - name: curl
`
	if err := os.WriteFile(desiredPath, []byte(desiredContent), 0644); err != nil {
		t.Fatalf("failed writing desired state: %v", err)
	}

	cfg := reconcile.Config{
		Mode:        reconcile.ModePlan,
		Interval:    10 * time.Millisecond,
		MaxJitter:   5 * time.Millisecond,
		DesiredPath: desiredPath,
	}

	driftEngine := drift.NewEngine()
	planner := plan.NewPlanner(nil)
	policyEngine := policy.NewEngine(policy.DefaultConfig())
	bus := events.NewBus(100)
	st := state.NewMemoryStore(10)

	loop := reconcile.NewLoop(cfg, driftEngine, planner, policyEngine, bus, st, nil)

	cov := coverage.Report{
		IsAdequate: true,
		Items: []coverage.ItemCoverage{
			{Name: "packages", Category: "packages", Status: "full"},
		},
	}
	items, p, dec, err := loop.ReconcileOnce(context.Background(), nil, cov)
	if err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 drift item, got %d", len(items))
	}
	if p == nil {
		t.Fatalf("expected non-nil plan in plan mode")
	}
	if dec == nil {
		t.Fatalf("expected non-nil policy decision in plan mode")
	}

	// Invariant: Checkpoint was stored in state store
	plans, err := st.ListPlans(context.Background(), 10)
	if err != nil || len(plans) != 1 {
		t.Errorf("expected plan checkpointed in store, got %d plans, err=%v", len(plans), err)
	}
}
