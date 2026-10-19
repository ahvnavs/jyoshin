// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package viz_test

import (
	"strings"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/viz"
)

func sampleNodesAndEdges() ([]graph.Node, []graph.Edge) {
	now := time.Now().UTC()
	nodes := []graph.Node{
		{
			ID:        "proc:100",
			Type:      graph.NodeProcess,
			Label:     "nginx: master process",
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
			Properties: map[string]any{
				"rss_bytes": float64(12 * 1024 * 1024),
			},
		},
		{
			ID:        "port:80",
			Type:      graph.NodePort,
			Label:     "0.0.0.0:80 (http)",
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
			Properties: map[string]any{
				"port": 80,
			},
		},
		{
			ID:        "svc:nginx",
			Type:      graph.NodeService,
			Label:     "nginx.service",
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
			Properties: map[string]any{
				"active": true,
			},
		},
		{
			ID:        "file:manual:tofu",
			Type:      graph.NodeFile,
			Label:     "/usr/local/bin/tofu",
			Certainty: graph.CertaintyInferred, // Unknown / inferred provenance
			FirstSeen: now,
			LastSeen:  now,
			Properties: map[string]any{
				"severity": "medium",
			},
		},
	}

	edges := []graph.Edge{
		{
			ID:         "svc:nginx->proc:100",
			SourceID:   "svc:nginx",
			TargetID:   "proc:100",
			Relation:   "supervises",
			Certainty:  graph.CertaintyObserved,
			Confidence: 1.0,
		},
		{
			ID:         "proc:100->port:80",
			SourceID:   "proc:100",
			TargetID:   "port:80",
			Relation:   "listens_on",
			Certainty:  graph.CertaintyObserved,
			Confidence: 1.0,
		},
	}
	return nodes, edges
}

func TestGrowthMap_ByteIdenticalReproducibility(t *testing.T) {
	nodes, edges := sampleNodesAndEdges()
	machineID := "machine-test-12345"

	gm1 := viz.BuildGrowthMap(machineID, nodes, edges, 1000, 700)
	svg1 := gm1.RenderSVG()

	gm2 := viz.BuildGrowthMap(machineID, nodes, edges, 1000, 700)
	svg2 := gm2.RenderSVG()

	if svg1 != svg2 {
		t.Fatalf("Growth map SVG is not byte-identical across identical runs!")
	}
	t.Logf("SVG output byte size: %d bytes (reproducible)", len(svg1))
}

func TestGrowthMap_EntityCountsInvariant(t *testing.T) {
	nodes, edges := sampleNodesAndEdges()
	gm := viz.BuildGrowthMap("mach-42", nodes, edges, 800, 600)

	if gm.DrawnEntities+gm.NotDrawnEntities != gm.TotalEntities {
		t.Fatalf("Entity count invariant violated: %d drawn + %d not drawn != %d total",
			gm.DrawnEntities, gm.NotDrawnEntities, gm.TotalEntities)
	}
	if gm.TotalEntities != 4 {
		t.Fatalf("expected 4 candidate entities, got %d", gm.TotalEntities)
	}
}

func TestGrowthMap_EmptyHost(t *testing.T) {
	gm := viz.BuildGrowthMap("empty-host", nil, nil, 800, 600)
	svg := gm.RenderSVG()

	if !strings.Contains(svg, "Empty server growth map") {
		t.Fatalf("expected empty description in SVG, got: %s", svg)
	}
	if len(gm.Branches) != 0 {
		t.Fatalf("expected 0 branches on empty host, got %d", len(gm.Branches))
	}
}

func TestGrowthMap_UnknownEntityDrawnAsExplicitShape(t *testing.T) {
	nodes, edges := sampleNodesAndEdges()
	gm := viz.BuildGrowthMap("test-unknown", nodes, edges, 800, 600)
	svg := gm.RenderSVG()

	// Principle 18: Unknown/not-visible data is drawn as explicit unknown shape (dashed rect)
	if !strings.Contains(svg, `class="attr-unknown"`) {
		t.Fatalf("expected attr-unknown class in SVG for inferred entity, got: %s", svg)
	}
	if !strings.Contains(svg, `aria-label="file: /usr/local/bin/tofu (unknown)"`) {
		t.Fatalf("expected aria-label with unknown marker, got: %s", svg)
	}
}

func TestGrowthMap_XSSSanitization(t *testing.T) {
	nodes := []graph.Node{
		{
			ID:        "proc:<script>alert(1)</script>",
			Type:      graph.NodeProcess,
			Label:     "<script>malicious()</script>",
			Certainty: graph.CertaintyObserved,
			FirstSeen: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
	}
	gm := viz.BuildGrowthMap("xss-host", nodes, nil, 800, 600)
	svg := gm.RenderSVG()

	if strings.Contains(svg, "<script>") {
		t.Fatalf("RAW XSS TAG DETECTED IN SVG: %s", svg)
	}
	if !strings.Contains(svg, "&lt;script&gt;") {
		t.Fatalf("expected escaped HTML entity in SVG, got: %s", svg)
	}
}

func TestGrowthMap_TerminalOutputWidth(t *testing.T) {
	nodes, edges := sampleNodesAndEdges()
	gm := viz.BuildGrowthMap("mach-term", nodes, edges, 800, 600)
	termText := gm.RenderTerminal(80, false)

	if !strings.Contains(termText, "風死 · KAZESHINI — PROVENANCE GROWTH MAP") {
		t.Fatalf("unexpected terminal output header: %s", termText)
	}
	if !strings.Contains(termText, "VISIBILITY: 4 of 4 entities shown") {
		t.Fatalf("expected visibility count in terminal output: %s", termText)
	}
}

func TestGrowthMap_LargeEntityFixturePerformance(t *testing.T) {
	// 50k-entity performance requirement: must complete in < 2.0s
	now := time.Now().UTC()
	const totalEntities = 50000
	nodes := make([]graph.Node, totalEntities)
	edges := make([]graph.Edge, 100)

	for i := 0; i < totalEntities; i++ {
		nodes[i] = graph.Node{
			ID:        "proc:" + string(rune(1000+i)),
			Type:      graph.NodeProcess,
			Label:     "synthetic-proc",
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		}
	}

	start := time.Now()
	gm := viz.BuildGrowthMap("perf-machine", nodes, edges, 1000, 700)
	svg := gm.RenderSVG()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("50k-entity growth map took %v (> 2.0s limit)", elapsed)
	}
	if gm.TotalEntities != totalEntities {
		t.Fatalf("expected %d total entities, got %d", totalEntities, gm.TotalEntities)
	}
	if gm.DrawnEntities != viz.DefaultNodeCap {
		t.Fatalf("expected %d drawn entities (capped), got %d", viz.DefaultNodeCap, gm.DrawnEntities)
	}
	if gm.NotDrawnEntities != totalEntities-viz.DefaultNodeCap {
		t.Fatalf("expected %d not drawn entities, got %d", totalEntities-viz.DefaultNodeCap, gm.NotDrawnEntities)
	}
	if len(svg) == 0 {
		t.Fatalf("rendered SVG is empty")
	}
	t.Logf("50k-entity growth map completed in %v (budget < 2.0s)", elapsed)
}

