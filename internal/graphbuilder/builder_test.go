// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package graphbuilder

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/origin"
	"github.com/OWNER/kazeshini/internal/sensors"
	"github.com/OWNER/kazeshini/internal/sensors/network"
	"github.com/OWNER/kazeshini/internal/sensors/process"
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

	// Setup rooted FS and Origin resolver to test end-to-end provenance to origin
	tmpDir := t.TempDir()
	rfs := fs.NewRootedFS(tmpDir)
	invMgr := inventory.NewManager(rfs)
	origResolver := origin.NewResolver(rfs, invMgr)
	g.SetOriginResolver(origResolver)

	// Re-ingest process with origin resolver attached
	g.IngestObservation(procObs)
	g.IngestObservation(netObs)

	portID := GenerateNodeID(graph.NodePort, "tcp:6379")
	chain, err := g.Why(portID)
	if err != nil {
		t.Fatalf("failed why query on ingested redis port: %v", err)
	}

	if len(chain.Chain) < 4 {
		t.Fatalf("expected at least 4 nodes in full provenance chain (port->process->file->origin), got %d: %+v", len(chain.Chain), chain.Chain)
	}

	// 1. Port
	if chain.Chain[0].Type != graph.NodePort {
		t.Errorf("chain[0] type = %s, want port", chain.Chain[0].Type)
	}
	// 2. Process
	if chain.Chain[1].Type != graph.NodeProcess {
		t.Errorf("chain[1] type = %s, want process", chain.Chain[1].Type)
	}
	// 3. File
	if chain.Chain[2].Type != graph.NodeFile {
		t.Errorf("chain[2] type = %s, want file", chain.Chain[2].Type)
	}
	// 4. Origin
	if chain.Chain[3].Type != graph.NodeOrigin {
		t.Errorf("chain[3] type = %s, want origin", chain.Chain[3].Type)
	}
}

func TestProvenanceGraph_GoldenChainAndFaultInjection(t *testing.T) {
	g := NewProvenanceGraph()
	firstSeenTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	restartTime := firstSeenTime.Add(24 * time.Hour)

	// 1. Seed historical node with first-seen metadata
	histProcID := GenerateNodeID(graph.NodeProcess, "2048:web-daemon")
	g.SeedFromSnapshot([]graph.Node{
		{
			ID:        histProcID,
			Type:      graph.NodeProcess,
			Label:     "web-daemon (pid 2048)",
			Certainty: graph.CertaintyObserved,
			FirstSeen: firstSeenTime,
			LastSeen:  firstSeenTime,
		},
	})

	// 2. Ingest process observation with cgroup pointing to a systemd service
	procObs := sensors.Observation{
		SensorName: "process",
		Timestamp:  restartTime,
		Status:     sensors.StatusSuccess,
		Items: []sensors.Item{
			{
				ID:   "proc:2048",
				Type: "process",
				Data: process.ProcessInfo{
					PID:     2048,
					Name:    "web-daemon",
					Cmdline: "/usr/sbin/web-daemon",
					Exe:     "/usr/sbin/web-daemon",
					Cgroup:  "/system.slice/web-daemon.service",
					UID:     1000,
				},
				Certainty: graph.CertaintyObserved,
			},
		},
	}
	g.IngestObservation(procObs)

	// Assert first_seen was preserved from initial snapshot seeding
	node, ok := g.GetNode(histProcID)
	if !ok {
		t.Fatalf("expected process node %s to exist in graph", histProcID)
	}
	if !node.FirstSeen.Equal(firstSeenTime) {
		t.Errorf("first_seen not preserved: got %v, want %v", node.FirstSeen, firstSeenTime)
	}

	// Assert service node was automatically created via cgroup
	svcNodeID := GenerateNodeID(graph.NodeService, "web-daemon.service")
	svcNode, ok := g.GetNode(svcNodeID)
	if !ok {
		t.Fatalf("expected service node %s from cgroup to exist in graph", svcNodeID)
	}
	if svcNode.Type != graph.NodeService {
		t.Errorf("expected node type service, got %s", svcNode.Type)
	}

	// 3. Ingest network report containing connection groups
	netObs := sensors.Observation{
		SensorName: "network",
		Timestamp:  restartTime,
		Status:     sensors.StatusSuccess,
		Items: []sensors.Item{
			{
				ID:   "network:report",
				Type: "network_report",
				Data: network.NetworkReport{
					ConnectionGroups: []network.ConnectionGroup{
						{
							RemoteIP:    "10.0.0.50",
							PID:         2048,
							ProcessName: "web-daemon",
							Count:       42,
						},
					},
				},
				Certainty: graph.CertaintyObserved,
			},
		},
	}
	g.IngestObservation(netObs)

	// Assert connection node exists
	connNodeID := GenerateNodeID(graph.NodeConnection, "10.0.0.50:2048")
	connNode, ok := g.GetNode(connNodeID)
	if !ok {
		t.Fatalf("expected connection node %s to exist in graph", connNodeID)
	}
	if connNode.Type != graph.NodeConnection {
		t.Errorf("expected node type connection, got %s", connNode.Type)
	}

	// 4. Fault-injection test: Ingest fault observation (sensor degraded/unreadable)
	faultObs := sensors.Observation{
		SensorName: "storage",
		Timestamp:  restartTime,
		Status:     sensors.StatusUnknown,
		Reason:     "unknown, permission: statfs denied by security module",
		Items:      nil, // Zero items returned
	}
	g.IngestObservation(faultObs)

	// Graph should gracefully accept fault observation without crashing or corrupting existing nodes
	if g.NodeCount() < 3 {
		t.Errorf("graph corrupted after fault observation; node count = %d", g.NodeCount())
	}
}

var sinkGraph *ProvenanceGraph

func BenchmarkProvenanceGraph_Synthetic50k(b *testing.B) {
	b.ReportAllocs()
	now := time.Now().UTC()

	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		g := NewProvenanceGraph()
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
		sinkGraph = g
	}
	b.StopTimer()

	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)
	b.Logf("50k-node synthetic benchmark: Alloc=%d MB, TotalAlloc=%d MB, Sys=%d MB",
		memEnd.Alloc/(1024*1024), memEnd.TotalAlloc/(1024*1024), memEnd.Sys/(1024*1024))
}
