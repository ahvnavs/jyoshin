// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/graph"
)

func TestBoltStore_PersistenceAndRestart(t *testing.T) {
	dataDir := t.TempDir()
	cfg := DefaultConfig(dataDir)

	// Session 1: Open store and save snapshot
	s1, err := Open(cfg, nil)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	if s1.IsInMemory() {
		t.Fatal("expected persistent store, got in-memory")
	}

	now := time.Now().UTC()
	snap1 := Snapshot{
		ID:        "snap-1",
		Timestamp: now,
		Nodes: []graph.Node{
			{
				ID:        "node:1",
				Type:      graph.NodeProcess,
				Label:     "init",
				Certainty: graph.CertaintyObserved,
				FirstSeen: now,
				LastSeen:  now,
			},
		},
	}

	if err := s1.SaveSnapshot(context.Background(), snap1); err != nil {
		t.Fatalf("failed to save snapshot: %v", err)
	}
	_ = s1.Close()

	// Verify file permissions (0600)
	dbPath := filepath.Join(dataDir, "jyoshin.db")
	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("failed to stat db file: %v", err)
	}
	perm := fi.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected permissions 0600, got %#o", perm)
	}

	// Session 2: Reopen and verify data persisted across restart
	s2, err := Open(cfg, nil)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer s2.Close()

	latest, err := s2.GetLatestSnapshot(context.Background())
	if err != nil {
		t.Fatalf("failed to get latest snapshot after restart: %v", err)
	}
	if latest.ID != "snap-1" || len(latest.Nodes) != 1 || latest.Nodes[0].ID != "node:1" {
		t.Fatalf("snapshot mismatch after restart: %+v", latest)
	}
}

func TestBoltStore_RetentionCompaction(t *testing.T) {
	dataDir := t.TempDir()
	cfg := DefaultConfig(dataDir)
	cfg.MaxSnapshots = 5 // Keep at most 5

	s, err := Open(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	// Write 10 snapshots
	for i := 1; i <= 10; i++ {
		now := time.Now().UTC().Add(time.Duration(i) * time.Millisecond)
		_ = s.SaveSnapshot(ctx, Snapshot{
			ID:        fmt.Sprintf("snap-%d", i),
			Timestamp: now,
			Nodes:     []graph.Node{},
		})
	}

	list, err := s.ListSnapshots(ctx, 100)
	if err != nil {
		t.Fatalf("failed to list snapshots: %v", err)
	}

	if len(list) > 5 {
		t.Fatalf("retention not enforced: expected <= 5 snapshots, got %d", len(list))
	}
}

func TestBoltStore_DegradationToInMemory(t *testing.T) {
	// Point to invalid / read-only non-writable path to force fallback
	cfg := DefaultConfig("/dev/null/forbidden_data_dir")
	s, err := Open(cfg, nil)
	if err != nil {
		t.Fatalf("expected Open not to fatal on degraded fallback, got %v", err)
	}
	defer s.Close()

	if !s.IsInMemory() {
		t.Fatal("expected degraded in-memory mode")
	}

	// In-memory operations should still work safely
	snap := Snapshot{ID: "mem-1", Timestamp: time.Now().UTC()}
	if err := s.SaveSnapshot(context.Background(), snap); err != nil {
		t.Fatalf("in-memory save failed: %v", err)
	}

	got, err := s.GetLatestSnapshot(context.Background())
	if err != nil || got.ID != "mem-1" {
		t.Fatalf("in-memory retrieval failed: %v, got %+v", err, got)
	}
}
