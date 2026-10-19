// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/config"
)

func TestAPI_Health(t *testing.T) {
	cfg := config.Default()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.0.1"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	srv.server.Handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["status"] != "ok" {
		t.Fatalf("expected status 'ok', got %v", body["status"])
	}
}

func TestAPI_Version(t *testing.T) {
	cfg := config.Default()
	v := VersionInfo{
		Version:   "v0.1.0-alpha",
		Commit:    "abcdef",
		BuildDate: "2026-10-10",
		GoVersion: "go1.26.0",
	}
	srv, err := NewServer(cfg, v, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	w := httptest.NewRecorder()

	srv.server.Handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var got VersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("failed to decode version: %v", err)
	}

	if got.Version != v.Version || got.Commit != v.Commit {
		t.Fatalf("version mismatch: %+v vs %+v", got, v)
	}
}

func TestAPI_EmbeddedUI(t *testing.T) {
	cfg := config.Default()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.0.1"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	srv.server.Handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if !strings.Contains(string(body), "KAZESHINI") {
		t.Fatalf("expected embedded html content with KAZESHINI, got: %s", string(body))
	}
}

func TestAPI_HostHeaderValidation(t *testing.T) {
	cfg := config.Default()
	cfg.AllowedHosts = []string{"monitor.local"}
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.0.1"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	tests := []struct {
		name       string
		host       string
		wantStatus int
	}{
		{"IPv4 loopback", "127.0.0.1:7777", http.StatusOK},
		{"IPv4 bare loopback", "127.0.0.1", http.StatusOK},
		{"localhost", "localhost:7777", http.StatusOK},
		{"IPv6 loopback", "[::1]:7777", http.StatusOK},
		{"Configured allowed host", "monitor.local:7777", http.StatusOK},
		{"Rebinding attacker host", "evil.attacker.com", http.StatusForbidden},
		{"Rebinding internal domain", "internal.corp.com:7777", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/health", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			srv.server.Handler.ServeHTTP(w, req)
			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Host %q: expected status %d, got %d", tt.host, tt.wantStatus, resp.StatusCode)
			}

			// Principle: No CORS headers allowed
			if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors != "" {
				t.Errorf("expected no Access-Control-Allow-Origin header, got %q", cors)
			}
		})
	}
}

func TestAPI_ResourceAbuse_OversizedBody(t *testing.T) {
	cfg := config.Default()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.0.1"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 5MB body exceeding the 2MB MaxBytesReader limit
	giantBody := strings.Repeat("A", 5<<20)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orphan/scan", strings.NewReader(giantBody))
	req.Header.Set("Authorization", "Bearer "+srv.auth.Token())
	w := httptest.NewRecorder()

	srv.server.Handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	// Should reject request with MaxBytes exceeded / BadRequest / InternalServerError without crashing
	t.Logf("Oversized body response status: %d", resp.StatusCode)
}

func TestAPI_ResourceAbuse_ConcurrentSSESubscribers(t *testing.T) {
	cfg := config.Default()
	srv, err := NewServer(cfg, VersionInfo{Version: "v0.0.1"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	token := srv.auth.Token()
	server := httptest.NewServer(srv.server.Handler)
	defer server.Close()

	// Launch 50 concurrent SSE subscribers and disconnect after 1 second
	var wg sync.WaitGroup
	subscribers := 50
	errCount := 0
	var mu sync.Mutex

	for i := 0; i < subscribers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/stream", nil)
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)

			client := &http.Client{Timeout: 1500 * time.Millisecond}
			resp, err := client.Do(req)
			if err != nil {
				// Context/timeout cancel is expected
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	if errCount > 0 {
		t.Errorf("encountered %d subscriber failures out of %d", errCount, subscribers)
	}
}

