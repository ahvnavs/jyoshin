// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package blastradius_test

import (
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/blastradius"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/graphbuilder"
)

func TestBlastRadius_SafeLeafNode(t *testing.T) {
	pGraph := graphbuilder.NewProvenanceGraph()
	now := time.Now().UTC()

	leafNode := graph.Node{
		ID:        "node:leaf:doc",
		Type:      graph.NodeFile,
		Label:     "/tmp/notes.txt",
		FirstSeen: now,
		LastSeen:  now,
		Certainty: graph.CertaintyObserved,
	}
	_ = pGraph.UpsertNode(leafNode)

	analyzer := blastradius.NewAnalyzer(pGraph)
	report, err := analyzer.Analyze(leafNode.ID)
	if err != nil {
		t.Fatalf("failed to analyze blast radius: %v", err)
	}

	if report.Verdict != blastradius.VerdictSafe {
		t.Errorf("expected VerdictSafe, got %s", report.Verdict)
	}
	if report.ImpactedCount != 0 {
		t.Errorf("expected 0 impacted dependencies, got %d", report.ImpactedCount)
	}
}

func TestBlastRadius_DangerousServiceWithPort(t *testing.T) {
	pGraph := graphbuilder.NewProvenanceGraph()
	now := time.Now().UTC()

	svcNode := graph.Node{
		ID:        "node:svc:postgres",
		Type:      graph.NodeService,
		Label:     "postgresql.service",
		FirstSeen: now,
		LastSeen:  now,
		Certainty: graph.CertaintyObserved,
	}
	procNode := graph.Node{
		ID:        "node:proc:postgres",
		Type:      graph.NodeProcess,
		Label:     "postgres (PID 1200)",
		FirstSeen: now,
		LastSeen:  now,
		Certainty: graph.CertaintyObserved,
	}
	portNode := graph.Node{
		ID:        "node:port:5432",
		Type:      graph.NodePort,
		Label:     "0.0.0.0:5432",
		FirstSeen: now,
		LastSeen:  now,
		Certainty: graph.CertaintyObserved,
	}

	_ = pGraph.UpsertNode(svcNode)
	_ = pGraph.UpsertNode(procNode)
	_ = pGraph.UpsertNode(portNode)

	// svc -> proc -> port
	_ = pGraph.UpsertEdge(graph.Edge{
		ID:        "edge:svc-proc",
		SourceID:  svcNode.ID,
		TargetID:  procNode.ID,
		Relation:  "spawns",
		Certainty: graph.CertaintyObserved,
	})
	_ = pGraph.UpsertEdge(graph.Edge{
		ID:        "edge:proc-port",
		SourceID:  procNode.ID,
		TargetID:  portNode.ID,
		Relation:  "listens_on",
		Certainty: graph.CertaintyObserved,
	})

	analyzer := blastradius.NewAnalyzer(pGraph)
	report, err := analyzer.Analyze(svcNode.ID)
	if err != nil {
		t.Fatalf("failed to analyze blast radius: %v", err)
	}

	if report.Verdict != blastradius.VerdictDangerous {
		t.Errorf("expected VerdictDangerous for core DB service, got %s", report.Verdict)
	}
	if report.ImpactedCount != 2 {
		t.Errorf("expected 2 downstream entities (proc + port), got %d", report.ImpactedCount)
	}
	if report.ImpactScore < 50 {
		t.Errorf("expected impact score >= 50, got %d", report.ImpactScore)
	}
}
