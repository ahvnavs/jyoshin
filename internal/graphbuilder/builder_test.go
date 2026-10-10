// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package graphbuilder

import (
	"fmt"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/sensors"
	"github.com/OWNER/jyoshin/internal/sensors/network"
	"github.com/OWNER/jyoshin/internal/sensors/process"
)

func TestProvenanceGraph_NodeIDStability(t *testing.T) {
	id1 := GenerateNodeID(graph.NodeProcess, "1024:nginx")
	id2 := GenerateNodeID(graph.NodeProcess, "1024:nginx")
	id3 := GenerateNodeID(graph.NodeProcess, "1025:nginx")

	if id1 != id2 {
		t.Fatalf("expected identical IDs for same key, got %s vs %s", id1, id2)
	}
	if id1 == id3 {
		t.Fatalf("expected different IDs for different keys, got identical %s", id1)
	}
}

func TestProvenanceGraph_ProvenanceWhyAndDependents(t *testing.T) {
	g := NewProvenanceGraph()
	now := time.Now().UTC()

	// Build chain: file -> process -> port
	fileNode := graph.Node{
		ID:        GenerateNodeID(graph.NodeFile, "/usr/sbin/nginx"),
		Type:      graph.NodeFile,
		Label:     "/usr/sbin/nginx",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}

	procNode := graph.Node{
		ID:        GenerateNodeID(graph.NodeProcess, "1024:nginx"),
		Type:      graph.NodeProcess,
		Label:     "nginx (pid 1024)",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}

	portNode := graph.Node{
		ID:        GenerateNodeID(graph.NodePort, "tcp:80"),
		Type:      graph.NodePort,
		Label:     "port tcp/80",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}

	_ = g.UpsertNode(fileNode)
	_ = g.UpsertNode(procNode)
	_ = g.UpsertNode(portNode)

	e1 := graph.Edge{
		ID:         GenerateEdgeID(fileNode.ID, procNode.ID, "executes"),
		SourceID:   fileNode.ID,
		TargetID:   procNode.ID,
		Relation:   "executes",
		Certainty:  graph.CertaintyObserved,
		Confidence: 1.0,
	}
	e2 := graph.Edge{
		ID:         GenerateEdgeID(procNode.ID, portNode.ID, "listens_on"),
		SourceID:   procNode.ID,
		TargetID:   portNode.ID,
		Relation:   "listens_on",
		Certainty:  graph.CertaintyObserved,
		Confidence: 1.0,
	}

	_ = g.UpsertEdge(e1)
	_ = g.UpsertEdge(e2)

	// Test Why portNode exists: should walk backwards: portNode -> procNode -> fileNode
	chain, err := g.Why(portNode.ID)
	if err != nil {
		t.Fatalf("unexpected error walking why: %v", err)
	}

	if len(chain.Chain) != 3 {
		t.Fatalf("expected chain length 3, got %d", len(chain.Chain))
	}
	if chain.Chain[0].ID != portNode.ID {
		t.Errorf("chain[0] should be portNode, got %s", chain.Chain[0].ID)
	}
	if chain.Chain[1].ID != procNode.ID {
		t.Errorf("chain[1] should be procNode, got %s", chain.Chain[1].ID)
	}
	if chain.Chain[2].ID != fileNode.ID {
		t.Errorf("chain[2] should be fileNode, got %s", chain.Chain[2].ID)
	}

	// Test Dependents of fileNode: should include procNode and portNode
	deps, depEdges, err := g.Dependents(fileNode.ID)
	if err != nil {
		t.Fatalf("unexpected error walking dependents: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependents, got %d", len(deps))
	}
	if len(depEdges) != 2 {
		t.Fatalf("expected 2 dependent edges, got %d", len(depEdges))
	}
}

func TestProvenanceGraph_IngestObservations(t *testing.T) {
	g := NewProvenanceGraph()
	now := time.Now().UTC()

	// Ingest process observation
	procObs := sensors.Observation{
		SensorName: "process",
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
		Items: []sensors.Item{
			{
				ID:   "proc:2048",
				Type: "process",
				Data: process.ProcessInfo{
					PID:     2048,
					Name:    "redis-server",
					Exe:     "/usr/bin/redis-server",
					Cmdline: "redis-server *:6379",
					UID:     1001,
				},
				Certainty: graph.CertaintyObserved,
			},
		},
	}
	g.IngestObservation(procObs)

	// Ingest network observation
	netObs := sensors.Observation{
		SensorName: "network",
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
		Items: []sensors.Item{
			{
				ID:   "port:tcp:6379",
				Type: "listening_port",
				Data: network.SocketInfo{
					Protocol:      "tcp",
					LocalIP:       "0.0.0.0",
					LocalPort:     6379,
					ExposureClass: network.ExposureAllInterfaces,
					PID:           2048,
					ProcessName:   "redis-server",
					State:         "LISTEN",
				},
				Certainty: graph.CertaintyObserved,
			},
		},
	}
	g.IngestObservation(netObs)

	portID := GenerateNodeID(graph.NodePort, "tcp:6379")
	chain, err := g.Why(portID)
	if err != nil {
		t.Fatalf("failed why query on ingested redis port: %v", err)
	}

	if len(chain.Chain) < 2 {
		t.Fatalf("expected at least 2 nodes in chain, got %d", len(chain.Chain))
	}
}

func BenchmarkProvenanceGraph_Synthetic50k(b *testing.B) {
	b.ReportAllocs()
	g := NewProvenanceGraph()
	now := time.Now().UTC()

	b.ResetTimer()
	for i := 0; i < 50000; i++ {
		procID := GenerateNodeID(graph.NodeProcess, fmt.Sprintf("%d:proc", i))
		_ = g.UpsertNode(graph.Node{
			ID:        procID,
			Type:      graph.NodeProcess,
			Label:     fmt.Sprintf("process-%d", i),
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}
