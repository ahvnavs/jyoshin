// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/blastradius"
	"github.com/OWNER/jyoshin/internal/config"
	"github.com/OWNER/jyoshin/internal/decisions"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/graphbuilder"
	"github.com/OWNER/jyoshin/internal/sensors"
	"github.com/OWNER/jyoshin/internal/sensors/network"
	"github.com/OWNER/jyoshin/internal/sensors/process"
)

func TestAPI_Phase8DecisionSupport(t *testing.T) {
	cfg := config.Default()
	pGraph := graphbuilder.NewProvenanceGraph()
	now := time.Now().UTC()

	// Ingest nodes: service -> port
	svc := graph.Node{
		ID:        "node:svc:web",
		Type:      graph.NodeService,
		Label:     "nginx.service",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}
	port := graph.Node{
		ID:        "node:port:80",
		Type:      graph.NodePort,
		Label:     "0.0.0.0:80",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
		Properties: map[string]any{
			"port":           80,
			"exposure_class": "all_interfaces",
		},
	}
	secretFile := graph.Node{
		ID:        "node:file:key",
		Type:      graph.NodeFile,
		Label:     "/etc/ssl/certs/key.pem",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
		Properties: map[string]any{
			"path": "/etc/ssl/certs/key.pem",
		},
	}

	_ = pGraph.UpsertNode(svc)
	_ = pGraph.UpsertNode(port)
	_ = pGraph.UpsertNode(secretFile)
	_ = pGraph.UpsertEdge(graph.Edge{
		ID:        "edge:svc-port",
		SourceID:  svc.ID,
		TargetID:  port.ID,
		Relation:  "listens_on",
		Certainty: graph.CertaintyObserved,
	})

	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pGraph, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	tok := srv.AuthManager().Token()

	// 1. GET /api/v1/blastradius/{id}
	reqBlast := httptest.NewRequest("GET", "/api/v1/blastradius/node:svc:web", nil)
	reqBlast.Header.Set("Authorization", "Bearer "+tok)
	wBlast := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wBlast, reqBlast)
	respBlast := wBlast.Result()
	defer respBlast.Body.Close()

	if respBlast.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for blastradius, got %d", respBlast.StatusCode)
	}
	var blastRep blastradius.Report
	if err := json.NewDecoder(respBlast.Body).Decode(&blastRep); err != nil {
		t.Fatalf("failed to decode blast radius report: %v", err)
	}
	if blastRep.ImpactedCount != 1 {
		t.Errorf("expected 1 downstream dependency, got %d", blastRep.ImpactedCount)
	}

	// 2. GET /api/v1/dependencies
	reqDeps := httptest.NewRequest("GET", "/api/v1/dependencies", nil)
	reqDeps.Header.Set("Authorization", "Bearer "+tok)
	wDeps := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wDeps, reqDeps)
	respDeps := wDeps.Result()
	defer respDeps.Body.Close()
	var depMap decisions.DependencyMap
	_ = json.NewDecoder(respDeps.Body).Decode(&depMap)
	if len(depMap.InboundEndpoints) != 1 {
		t.Errorf("expected 1 inbound endpoint, got %d", len(depMap.InboundEndpoints))
	}

	// 3. GET /api/v1/decommission
	reqDecom := httptest.NewRequest("GET", "/api/v1/decommission", nil)
	reqDecom.Header.Set("Authorization", "Bearer "+tok)
	wDecom := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wDecom, reqDecom)
	respDecom := wDecom.Result()
	defer respDecom.Body.Close()
	var decomRep decisions.DecommissionReport
	_ = json.NewDecoder(respDecom.Body).Decode(&decomRep)
	if decomRep.SafeToTurnOff {
		t.Errorf("expected SafeToTurnOff == false due to port 80")
	}

	// 4. GET /api/v1/migration
	reqMig := httptest.NewRequest("GET", "/api/v1/migration", nil)
	reqMig.Header.Set("Authorization", "Bearer "+tok)
	wMig := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wMig, reqMig)
	respMig := wMig.Result()
	defer respMig.Body.Close()
	var migPlan decisions.MigrationPlan
	_ = json.NewDecoder(respMig.Body).Decode(&migPlan)
	if len(migPlan.SecretsPaths) != 1 {
		t.Errorf("expected 1 secrets path, got %d", len(migPlan.SecretsPaths))
	}

	// 5. GET /api/v1/report?format=html & ?format=json
	reqReport := httptest.NewRequest("GET", "/api/v1/report?format=json", nil)
	reqReport.Header.Set("Authorization", "Bearer "+tok)
	wReport := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wReport, reqReport)
	respReport := wReport.Result()
	defer respReport.Body.Close()
	if respReport.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for report endpoint, got %d", respReport.StatusCode)
	}
	var repData map[string]any
	if err := json.NewDecoder(respReport.Body).Decode(&repData); err != nil {
		t.Fatalf("failed decoding json report: %v", err)
	}
	if !strings.Contains(repData["title"].(string), "Server Truth Engine") {
		t.Errorf("expected title in report data")
	}
}

func TestAPI_GraphWhyListeningPort(t *testing.T) {
	cfg := config.Default()
	pGraph := graphbuilder.NewProvenanceGraph()
	now := time.Now().UTC()

	// Ingest observations simulating process running redis and listening on port 6379
	pGraph.IngestObservation(sensors.Observation{
		SensorName: "process",
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
		Items: []sensors.Item{
			{
				ID:   "proc:redis:2048",
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
	})

	pGraph.IngestObservation(sensors.Observation{
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
	})

	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pGraph, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	tok := srv.AuthManager().Token()

	// 1. Fetch /api/v1/graph to discover listening port node ID dynamically
	reqGraph := httptest.NewRequest("GET", "/api/v1/graph", nil)
	reqGraph.Header.Set("Authorization", "Bearer "+tok)
	wGraph := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wGraph, reqGraph)
	respGraph := wGraph.Result()
	defer respGraph.Body.Close()

	if respGraph.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/graph, got %d", respGraph.StatusCode)
	}

	var graphData struct {
		NodeCount int          `json:"node_count"`
		EdgeCount int          `json:"edge_count"`
		Nodes     []graph.Node `json:"nodes"`
		Edges     []graph.Edge `json:"edges"`
	}
	if err := json.NewDecoder(respGraph.Body).Decode(&graphData); err != nil {
		t.Fatalf("failed decoding /api/v1/graph response: %v", err)
	}

	var portNode *graph.Node
	for _, n := range graphData.Nodes {
		if n.Type == graph.NodePort {
			portNode = &n
			break
		}
	}
	if portNode == nil {
		t.Fatalf("no listening port node found in /api/v1/graph response")
	}

	t.Logf("Dynamically picked port node ID from /api/v1/graph: %s (label: %s)", portNode.ID, portNode.Label)

	// 2. Query /api/v1/graph/why/{id} with the dynamically fetched ID
	reqWhy := httptest.NewRequest("GET", "/api/v1/graph/why/"+portNode.ID, nil)
	reqWhy.Header.Set("Authorization", "Bearer "+tok)
	wWhy := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wWhy, reqWhy)
	respWhy := wWhy.Result()
	defer respWhy.Body.Close()

	if respWhy.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/graph/why, got %d, body=%s", respWhy.StatusCode, wWhy.Body.String())
	}

	var chain graphbuilder.ProvenanceChain
	if err := json.NewDecoder(respWhy.Body).Decode(&chain); err != nil {
		t.Fatalf("failed decoding /api/v1/graph/why response: %v", err)
	}

	t.Logf("Provenance chain length: %d nodes, %d edges", len(chain.Chain), len(chain.Edges))
	for i, n := range chain.Chain {
		t.Logf("  chain[%d]: type=%s id=%s label=%s", i, n.Type, n.ID, n.Label)
	}

	// Assert the full chain: port -> process -> file
	if len(chain.Chain) < 3 {
		t.Fatalf("expected at least 3 nodes in provenance chain, got %d", len(chain.Chain))
	}
	if chain.Chain[0].Type != graph.NodePort {
		t.Errorf("chain[0] expected Port, got %s", chain.Chain[0].Type)
	}
	if chain.Chain[1].Type != graph.NodeProcess {
		t.Errorf("chain[1] expected Process, got %s", chain.Chain[1].Type)
	}
	if chain.Chain[2].Type != graph.NodeFile {
		t.Errorf("chain[2] expected File, got %s", chain.Chain[2].Type)
	}
}
