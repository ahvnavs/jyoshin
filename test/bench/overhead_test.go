// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package bench_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/graphbuilder"
	"github.com/OWNER/jyoshin/internal/rules"
	"github.com/OWNER/jyoshin/internal/sensors/host"
	"github.com/OWNER/jyoshin/internal/verdict"
)

// BenchmarkHighLoadOverhead benchmarks graph reconstruction and node retrieval
// simulating a loaded host with 10,000 nodes.
func BenchmarkHighLoadOverhead(b *testing.B) {
	g := graphbuilder.NewProvenanceGraph()
	// Pre-populate with 10,000 simulated nodes
	for i := 0; i < 10000; i++ {
		g.UpsertNode(graph.Node{
			ID:        fmt.Sprintf("node:%d", i),
			Type:      graph.NodeProcess,
			Label:     fmt.Sprintf("worker-%d", i),
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"pid": i,
				"rss": 1024 * 1024,
			},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nodes, _ := g.Snapshot()
		if len(nodes) != 10000 {
			b.Fatalf("expected 10000 nodes, got %d", len(nodes))
		}
	}
}

// TestOverheadAndResourceCaps verifies that Jyōshin memory allocation under heavy
// graph building stays strictly below the 100 MB target and executes with bounded CPU.
func TestOverheadAndResourceCaps(t *testing.T) {
	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pg := graphbuilder.NewProvenanceGraph()
	rfs := fs.NewRootedFS("/")
	hSensor := host.New(rfs)

	// Simulate high rate observation ingests across concurrent workers
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				obs, _ := hSensor.Collect(ctx)
				pg.IngestObservation(obs)
			}
		}(w)
	}
	wg.Wait()

	runtime.GC()
	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	allocatedBytes := mAfter.Alloc - mBefore.Alloc
	allocatedMB := float64(allocatedBytes) / (1024 * 1024)

	t.Logf("Memory consumed by 4,000 ingest cycles: %.2f MB (Target: < 100 MB)", allocatedMB)
	if allocatedMB > 100.0 {
		t.Errorf("memory overhead exceeded 100 MB: %.2f MB", allocatedMB)
	}

	// Verify verdict calculation overhead with 500 findings
	findings := make([]rules.Finding, 500)
	for i := 0; i < 500; i++ {
		findings[i] = rules.Finding{
			ID:       fmt.Sprintf("find-%d", i),
			Severity: rules.SeverityMedium,
			Proof:    rules.Proof{Confidence: 1.0},
		}
	}
	start := time.Now()
	nodes, _ := pg.Snapshot()
	v := verdict.ComputeVerdict(nodes, findings, 20)
	elapsed := time.Since(start)

	t.Logf("Verdict computation time for %d nodes and 500 findings: %v", len(nodes), elapsed)
	if elapsed > 100*time.Millisecond {
		t.Errorf("verdict calculation too slow: %v (budget: 100ms)", elapsed)
	}
	if v.ChaosIndex <= 0 {
		t.Errorf("expected positive chaos index, got %d", v.ChaosIndex)
	}
}
