// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
