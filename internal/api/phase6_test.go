// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/config"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/graphbuilder"
	"github.com/OWNER/jyoshin/internal/sensors"
	"github.com/OWNER/jyoshin/internal/sensors/host"
	"github.com/OWNER/jyoshin/internal/verdict"
)

func TestAPI_VerdictEndpoint(t *testing.T) {
	cfg := config.Default()
	pGraph := graphbuilder.NewProvenanceGraph()

	// Ingest a host observation
	pGraph.IngestObservation(sensors.Observation{
		SensorName: "host",
		Timestamp:  time.Now(),
		Status:     sensors.StatusSuccess,
		Items: []sensors.Item{
			{
				ID:        "host:info",
				Type:      "host_info",
				Certainty: graph.CertaintyObserved,
				Data: host.HostInfo{
					Hostname: "verdict-test-box",
					Distro:   "Debian GNU/Linux 12",
					Kernel:   "6.1.0-linux",
					CPUCount: 4,
				},
			},
		},
	})

	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pGraph, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/verdict", nil)
	w := httptest.NewRecorder()

	srv.server.Handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var sum verdict.Summary
	if err := json.NewDecoder(resp.Body).Decode(&sum); err != nil {
		t.Fatalf("failed to decode verdict summary: %v", err)
	}

	if sum.StateLabel != "CALM" {
		t.Errorf("expected CALM state, got %s", sum.StateLabel)
	}
	if sum.ChaosIndex < 0 || sum.ChaosIndex > 100 {
		t.Errorf("chaos index out of bounds: %d", sum.ChaosIndex)
	}
}

func TestAPI_StreamSSE(t *testing.T) {
	cfg := config.Default()
	pGraph := graphbuilder.NewProvenanceGraph()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pGraph, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, "GET", "/api/v1/stream", nil)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.server.Handler.ServeHTTP(w, req)
		close(done)
	}()

	<-done

	resp := w.Result()
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream content type, got %s", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	foundVerdictEvent := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: verdict") {
			foundVerdictEvent = true
			break
		}
	}

	if !foundVerdictEvent {
		t.Fatalf("did not find 'event: verdict' in SSE output")
	}
}

func TestAPI_StaticAssets(t *testing.T) {
	cfg := config.Default()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	paths := []string{"/css/style.css", "/js/app.js"}
	for _, p := range paths {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		srv.server.Handler.ServeHTTP(w, req)
		resp := w.Result()
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for %s, got %d", p, resp.StatusCode)
		}
	}
}

func TestAPI_AuthStatus(t *testing.T) {
	cfg := config.Default()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Unauthenticated request
	req := httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	w := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(w, req)
	resp := w.Result()
	var res map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&res)
	_ = resp.Body.Close()
	if res["authenticated"] != false {
		t.Errorf("expected unauthenticated, got %v", res["authenticated"])
	}

	// 2. Authenticated with valid token
	token := srv.AuthManager().Token()
	reqAuth := httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+token)
	wAuth := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wAuth, reqAuth)
	respAuth := wAuth.Result()
	var resAuth map[string]any
	_ = json.NewDecoder(respAuth.Body).Decode(&resAuth)
	_ = respAuth.Body.Close()
	if resAuth["authenticated"] != true {
		t.Errorf("expected authenticated with token, got %v", resAuth["authenticated"])
	}
}
