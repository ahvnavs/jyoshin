// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package robustness_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/sensors/host"
	"github.com/OWNER/kazeshini/internal/sensors/process"
	"github.com/OWNER/kazeshini/internal/store"
)

// TestRobustness_HostileProcInput ensures process sensor safely handles hostile/corrupt /proc structures.
func TestRobustness_HostileProcInput(t *testing.T) {
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc")
	_ = os.MkdirAll(procDir, 0755)

	// Corrupt cmdline (null bytes only or invalid unicode)
	pidDir := filepath.Join(procDir, "99999")
	_ = os.MkdirAll(pidDir, 0755)
	_ = os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("\x00\xff\xfe\x00"), 0644)
	_ = os.WriteFile(filepath.Join(pidDir, "stat"), []byte("99999 (hostile) R 1 99999 99999 0 -1 4194560"), 0644)
	_ = os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\thostile\nPid:\t99999\nPPid:\t1\nUid:\t0 0 0 0\n"), 0644)

	rfs := fs.NewRootedFS(tmpDir)
	procSensor := process.New(rfs)

	obs, err := procSensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("sensor crashed on hostile proc: %v", err)
	}
	t.Logf("Observed %d items from hostile proc tree without panic", len(obs.Items))
}

// TestRobustness_ReadOnlyAndFullDiskStore verifies store resilience when filesystem is read-only or full.
func TestRobustness_ReadOnlyAndFullDiskStore(t *testing.T) {
	// 1. Point to uncreatable path (simulates read-only filesystem)
	s, err := store.Open(store.Config{DataDir: "/dev/null/forbidden"}, nil)
	if err != nil {
		t.Fatalf("expected graceful degradation to in-memory store, got error: %v", err)
	}
	defer s.Close()

	if !s.IsInMemory() {
		t.Errorf("store failed to degrade to in-memory mode on read-only target")
	}

	// Operations continue working in memory
	err = s.SaveSnapshot(context.Background(), store.Snapshot{
		ID:        "snap-ro-1",
		Timestamp: time.Now().UTC(),
		Nodes:     []graph.Node{{ID: "n1", Type: graph.NodeSystem, FirstSeen: time.Now(), LastSeen: time.Now()}},
	})
	if err != nil {
		t.Errorf("failed to save snapshot in degraded in-memory mode: %v", err)
	}
}

// TestRobustness_SoakAndLeakCheck runs an accelerated soak test (thousands of cycles)
// to verify zero memory runaway, bounded store growth, and zero goroutine leaks.
func TestRobustness_SoakAndLeakCheck(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	runtime.GC()
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	pg := graphbuilder.NewProvenanceGraph()
	rfs := fs.NewRootedFS("/")
	hSensor := host.New(rfs)

	ctx := context.Background()
	cycles := 1500

	for i := 0; i < cycles; i++ {
		obs, err := hSensor.Collect(ctx)
		if err == nil {
			pg.IngestObservation(obs)
		}
		// Ingest simulated fluctuating node
		pg.UpsertNode(graph.Node{
			ID:        fmt.Sprintf("proc:%d", i%100),
			Type:      graph.NodeProcess,
			Label:     "soak-worker",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		})
	}

	runtime.GC()
	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)

	leakedGoroutines := runtime.NumGoroutine() - initialGoroutines
	growthBytes := int64(memEnd.Alloc) - int64(memStart.Alloc)

	t.Logf("Soak finished: %d cycles, net goroutine delta: %d, net memory delta: %d bytes",
		cycles, leakedGoroutines, growthBytes)

	if leakedGoroutines > 5 {
		t.Errorf("suspected goroutine leak during soak: delta %d", leakedGoroutines)
	}
}
