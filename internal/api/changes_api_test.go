// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/store"
)

func TestAPI_ChangesEndpoint(t *testing.T) {
	cfg := config.Default()
	bStore, err := store.Open(store.Config{DataDir: t.TempDir(), MaxSnapshots: 10}, nil)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer bStore.Close()

	now := time.Now().UTC()
	snap1 := store.Snapshot{
		ID:        "snap-001",
		Timestamp: now.Add(-5 * time.Minute),
		Nodes: []graph.Node{
			{
				ID:        "port:8080",
				Type:      graph.NodePort,
				Label:     "127.0.0.1:8080",
				FirstSeen: now.Add(-5 * time.Minute),
				LastSeen:  now.Add(-5 * time.Minute),
				Properties: map[string]any{
					"port":           8080,
					"exposure_class": "loopback",
				},
			},
		},
	}
	snap2 := store.Snapshot{
		ID:        "snap-002",
		Timestamp: now,
		Nodes: []graph.Node{
			{
				ID:        "port:8080",
				Type:      graph.NodePort,
				Label:     "0.0.0.0:8080",
				FirstSeen: now.Add(-5 * time.Minute),
				LastSeen:  now,
				Properties: map[string]any{
					"port":           8080,
					"exposure_class": "all_interfaces",
				},
			},
			{
				ID:        "file:manual",
				Type:      graph.NodeFile,
				Label:     "/usr/local/bin/agent",
				FirstSeen: now,
				LastSeen:  now,
				Properties: map[string]any{
					"path":        "/usr/local/bin/agent",
					"origin_kind": "manual",
				},
			},
		},
	}

	_ = bStore.SaveSnapshot(t.Context(), snap1)
	_ = bStore.SaveSnapshot(t.Context(), snap2)

	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, nil, bStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Request /api/v1/changes
	req := httptest.NewRequest("GET", "/api/v1/changes", nil)
	req.Header.Set("Authorization", "Bearer "+srv.AuthManager().Token())
	w := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var cs diff.ChangeSet
	if err := json.NewDecoder(resp.Body).Decode(&cs); err != nil {
		t.Fatalf("failed to decode ChangeSet: %v", err)
	}

	if cs.TotalChanges != 2 {
		t.Errorf("expected 2 changes, got %d", cs.TotalChanges)
	}
}

func TestAPI_ForecastsAndBaselinesEndpoints(t *testing.T) {
	cfg := config.Default()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Initial /forecasts request: insufficient data honest state
	reqFC := httptest.NewRequest("GET", "/api/v1/forecasts", nil)
	reqFC.Header.Set("Authorization", "Bearer "+srv.AuthManager().Token())
	wFC := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wFC, reqFC)
	respFC := wFC.Result()
	var fcResults []forecast.Result
	_ = json.NewDecoder(respFC.Body).Decode(&fcResults)
	_ = respFC.Body.Close()

	if len(fcResults) == 0 {
		t.Fatalf("expected forecast results array")
	}
	if fcResults[0].State != forecast.StateNotEnoughData {
		t.Errorf("expected StateNotEnoughData initially, got %s", fcResults[0].State)
	}

	// 2. Feed samples with distinct timestamps to create a valid trend spanning >= 1h
	t0 := time.Now().UTC().Add(-75 * time.Minute)
	for i := 0; i < 6; i++ {
		srv.RecordSampleAt("system_ram", float64(50+i*5), t0.Add(time.Duration(i*15)*time.Minute))
	}

	reqFC2 := httptest.NewRequest("GET", "/api/v1/forecasts", nil)
	reqFC2.Header.Set("Authorization", "Bearer "+srv.AuthManager().Token())
	wFC2 := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wFC2, reqFC2)
	respFC2 := wFC2.Result()
	var fcResults2 []forecast.Result
	_ = json.NewDecoder(respFC2.Body).Decode(&fcResults2)
	_ = respFC2.Body.Close()

	foundRAM := false
	for _, r := range fcResults2 {
		if r.Target == "system_ram" {
			foundRAM = true
			if r.State == forecast.StateNotEnoughData {
				t.Errorf("expected computed forecast after feeding samples, got not enough data")
			}
			if !r.IsLeak {
				t.Errorf("expected monotonic growth flagged as potential leak")
			}
		}
	}
	if !foundRAM {
		t.Errorf("system_ram forecast target not found in results")
	}

	// 3. /baselines endpoint
	reqBL := httptest.NewRequest("GET", "/api/v1/baselines", nil)
	reqBL.Header.Set("Authorization", "Bearer "+srv.AuthManager().Token())
	wBL := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wBL, reqBL)
	respBL := wBL.Result()
	var blResults []forecast.Baseline
	_ = json.NewDecoder(respBL.Body).Decode(&blResults)
	_ = respBL.Body.Close()

	if len(blResults) == 0 {
		t.Fatalf("expected baselines array")
	}
}
