// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/rules"
)

// RunStoreConformanceSuite runs the canonical test suite against any Store implementation.
func RunStoreConformanceSuite(t *testing.T, newStore func() (Store, func())) {
	ctx := context.Background()

	t.Run("Snapshots", func(t *testing.T) {
		s, cleanup := newStore()
		defer cleanup()

		snap := Snapshot{
			ID:        "snap-1",
			Timestamp: time.Now().UTC(),
			Nodes: []graph.Node{
				{
					ID:        "host:main",
					Type:      graph.NodeSystem,
					Label:     "host",
					Certainty: graph.CertaintyObserved,
					FirstSeen: time.Now().UTC(),
					LastSeen:  time.Now().UTC(),
				},
			},
		}

		if err := s.SaveSnapshot(ctx, snap); err != nil {
			t.Fatalf("SaveSnapshot failed: %v", err)
		}

		latest, err := s.GetLatestSnapshot(ctx)
		if err != nil {
			t.Fatalf("GetLatestSnapshot failed: %v", err)
		}
		if latest.ID != "snap-1" || len(latest.Nodes) != 1 {
			t.Fatalf("unexpected snapshot returned: %+v", latest)
		}

		list, err := s.ListSnapshots(ctx, 10)
		if err != nil {
			t.Fatalf("ListSnapshots failed: %v", err)
		}
		if len(list) != 1 {
			t.Fatalf("expected 1 snapshot, got %d", len(list))
		}
	})

	t.Run("Findings", func(t *testing.T) {
		s, cleanup := newStore()
		defer cleanup()

		f := rules.Finding{
			ID:        "find-1",
			RuleID:    "RULE-1",
			Category:  rules.CategorySecurity,
			Severity:  rules.SeverityHigh,
			What:      "Security issue",
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
			Proof: rules.Proof{
				Certainty: graph.CertaintyObserved,
			},
		}

		if err := s.SaveFindings(ctx, []rules.Finding{f}); err != nil {
			t.Fatalf("SaveFindings failed: %v", err)
		}

		list, err := s.ListFindings(ctx, rules.CategorySecurity, 10)
		if err != nil {
			t.Fatalf("ListFindings failed: %v", err)
		}
		if len(list) != 1 || list[0].ID != "find-1" {
			t.Fatalf("unexpected findings returned: %+v", list)
		}
	})

	t.Run("Samples", func(t *testing.T) {
		s, cleanup := newStore()
		defer cleanup()

		now := time.Now().UTC()
		smp1 := forecast.Sample{Timestamp: now.Add(-1 * time.Minute), Value: 42.0}
		smp2 := forecast.Sample{Timestamp: now, Value: 43.5}

		if err := s.SaveSample(ctx, "system_ram", smp1); err != nil {
			t.Fatalf("SaveSample 1 failed: %v", err)
		}
		if err := s.SaveSample(ctx, "system_ram", smp2); err != nil {
			t.Fatalf("SaveSample 2 failed: %v", err)
		}

		smps, err := s.ListSamples(ctx, "system_ram", 10)
		if err != nil {
			t.Fatalf("ListSamples failed: %v", err)
		}
		if len(smps) != 2 {
			t.Fatalf("expected 2 samples, got %d", len(smps))
		}
	})

	t.Run("Activity", func(t *testing.T) {
		s, cleanup := newStore()
		defer cleanup()

		entry := ActivityEntry{
			Timestamp: time.Now().UTC(),
			CheckID:   "cpu-memory",
			Role:      "devops",
			Status:    "OK",
			Summary:   "CPU healthy",
			Duration:  "5ms",
		}

		if err := s.SaveActivity(ctx, entry); err != nil {
			t.Fatalf("SaveActivity failed: %v", err)
		}

		acts, err := s.ListActivity(ctx, 10)
		if err != nil {
			t.Fatalf("ListActivity failed: %v", err)
		}
		if len(acts) != 1 || acts[0].CheckID != "cpu-memory" {
			t.Fatalf("unexpected activity returned: %+v", acts)
		}
	})

	t.Run("DriftAndPlan", func(t *testing.T) {
		s, cleanup := newStore()
		defer cleanup()

		driftItems := []drift.Item{
			{
				ID:           "d-1",
				ResourceKind: "Package",
				Name:         "htop",
				Kind:         drift.KindMissing,
				Summary:      "Missing htop",
				Expected:     "installed",
				Actual:       "absent",
			},
		}

		if err := s.SaveDrift(ctx, driftItems); err != nil {
			t.Fatalf("SaveDrift failed: %v", err)
		}
		drifts, err := s.ListDrift(ctx, 5)
		if err != nil || len(drifts) != 1 {
			t.Fatalf("ListDrift failed: err=%v, count=%d", err, len(drifts))
		}

		p := plan.Plan{
			ID:         "plan-1",
			Hash:       "abc123hash",
			CreatedAt:  time.Now().UTC(),
			TotalSteps: 1,
			Summary:    "Test plan",
		}
		if err := s.SavePlan(ctx, p); err != nil {
			t.Fatalf("SavePlan failed: %v", err)
		}
		plans, err := s.ListPlans(ctx, 5)
		if err != nil || len(plans) != 1 || plans[0].ID != "plan-1" {
			t.Fatalf("ListPlans failed: err=%v, count=%d", err, len(plans))
		}
	})
}

func TestStore_Conformance(t *testing.T) {
	t.Run("MemoryStore", func(t *testing.T) {
		RunStoreConformanceSuite(t, func() (Store, func()) {
			m := NewMemoryStore(10)
			return m, func() { _ = m.Close() }
		})
	})

	t.Run("FileStore", func(t *testing.T) {
		RunStoreConformanceSuite(t, func() (Store, func()) {
			tmp := filepath.Join(t.TempDir(), "store.json")
			f, err := NewFileStore(tmp, 10)
			if err != nil {
				t.Fatalf("NewFileStore error: %v", err)
			}
			return f, func() { _ = f.Close() }
		})
	})

	t.Run("BoltStore", func(t *testing.T) {
		RunStoreConformanceSuite(t, func() (Store, func()) {
			tmpDir := t.TempDir()
			b, err := NewBoltStore(BoltConfig{DataDir: tmpDir, MaxSnapshots: 10}, nil)
			if err != nil {
				t.Fatalf("NewBoltStore error: %v", err)
			}
			return b, func() { _ = b.Close() }
		})
	})
}
