// Copyright 2026 Kazeshini Authors
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

	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/sensors"
	"github.com/OWNER/kazeshini/internal/sensors/host"
	"github.com/OWNER/kazeshini/internal/verdict"
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
	req.Header.Set("Authorization", "Bearer "+srv.AuthManager().Token())
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
	req.Header.Set("Authorization", "Bearer "+srv.AuthManager().Token())
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

func TestAPI_TokenAuthenticationBlocksUnauthenticated(t *testing.T) {
	cfg := config.Default()
	cfg.AuthRequired = true
	pGraph := graphbuilder.NewProvenanceGraph()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pGraph, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	token := srv.AuthManager().Token()

	// 1. Unauthenticated request to /api/v1/verdict -> MUST return 401
	reqUnauth := httptest.NewRequest("GET", "/api/v1/verdict", nil)
	wUnauth := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wUnauth, reqUnauth)
	respUnauth := wUnauth.Result()
	defer respUnauth.Body.Close()

	if respUnauth.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized without token, got: %d", respUnauth.StatusCode)
	}

	// 2. Request with wrong token -> MUST return 401
	reqWrong := httptest.NewRequest("GET", "/api/v1/verdict", nil)
	reqWrong.Header.Set("Authorization", "Bearer invalid-wrong-token")
	wWrong := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wWrong, reqWrong)
	respWrong := wWrong.Result()
	defer respWrong.Body.Close()

	if respWrong.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized with invalid token, got: %d", respWrong.StatusCode)
	}

	// 3. Request with valid Bearer token header -> MUST return 200
	reqValid := httptest.NewRequest("GET", "/api/v1/verdict", nil)
	reqValid.Header.Set("Authorization", "Bearer "+token)
	wValid := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wValid, reqValid)
	respValid := wValid.Result()
	defer respValid.Body.Close()

	if respValid.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK with valid token, got: %d", respValid.StatusCode)
	}

	// 4. Request with valid token in query param -> MUST return 401 (URL token parameter is rejected)
	reqQuery := httptest.NewRequest("GET", "/api/v1/verdict?token="+token, nil)
	wQuery := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wQuery, reqQuery)
	respQuery := wQuery.Result()
	defer respQuery.Body.Close()

	if respQuery.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized with URL query token, got: %d", respQuery.StatusCode)
	}

	// 5. Unauthenticated request to unauthenticated routes (/api/v1/health, /) -> MUST return 200
	reqHealth := httptest.NewRequest("GET", "/api/v1/health", nil)
	wHealth := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(wHealth, reqHealth)
	respHealth := wHealth.Result()
	defer respHealth.Body.Close()

	if respHealth.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /api/v1/health without token, got: %d", respHealth.StatusCode)
	}
}

