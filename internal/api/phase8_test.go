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

	// 1. GET /api/v1/blastradius/{id}
	reqBlast := httptest.NewRequest("GET", "/api/v1/blastradius/node:svc:web", nil)
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
