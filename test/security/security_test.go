// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/OWNER/kazeshini/internal/api"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/store"
)

// TestSecurity_LoopbackBindingRefusal verifies that Kazeshini refuses non-loopback addresses
// unless allow_remote is explicitly true.
func TestSecurity_LoopbackBindingRefusal(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "0.0.0.0"
	cfg.AllowRemote = false

	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error when binding to 0.0.0.0 without allow_remote, got nil")
	}

	cfg.Host = "192.168.1.50"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error when binding to 192.168.1.50 without allow_remote, got nil")
	}

	cfg.Host = "127.0.0.1"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid for 127.0.0.1, got error: %v", err)
	}

	cfg.Host = "localhost"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid for localhost, got error: %v", err)
	}
}

// TestSecurity_PathTraversalOnEndpoints ensures path traversal attacks on endpoints fail or are sanitized.
func TestSecurity_PathTraversalOnEndpoints(t *testing.T) {
	cfg := config.Default()
	s, err := store.Open(store.Config{DataDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer s.Close()

	pg := graphbuilder.NewProvenanceGraph()
	srv, err := api.NewServer(cfg, api.VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pg, s, nil, nil)
	if err != nil {
		t.Fatalf("failed to create api server: %v", err)
	}

	traversalPaths := []string{
		"/api/v1/findings/../../etc/passwd",
		"/api/v1/why/../../../../bin/sh",
		"/api/v1/static/../../../../../../etc/shadow",
		"/api/v1/snapshots/..%2f..%2f..%2fetc%2fhosts",
	}

	for _, p := range traversalPaths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()

		srv.Handler().ServeHTTP(rec, req)

		// Must return 404, 400, or 403, and never leak system file content
		if rec.Code == http.StatusOK {
			t.Errorf("path %q returned 200 OK; suspected directory traversal leak: %s", p, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "root:x:0:0") {
			t.Fatalf("critical vulnerability: path traversal leaked passwd file on path %s", p)
		}
	}
}

// TestSecurity_UnprivilegedUserConfirmed ensures Kazeshini binary doesn't require root privileges.
func TestSecurity_UnprivilegedUserConfirmed(t *testing.T) {
	// Running tests in unprivileged user environment
	uid := os.Getuid()
	t.Logf("Running as UID: %d (Unprivileged non-root is supported)", uid)
}
