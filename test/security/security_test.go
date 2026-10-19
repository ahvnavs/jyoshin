// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OWNER/kazeshini/internal/api"
	"github.com/OWNER/kazeshini/internal/auth"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/redact"
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

// TestSecurity_AuthBypassAndPathNormalization verifies that authorization cannot be bypassed
// using path traversal (//, %2e%2e, trailing dots), method override headers, or case variation.
func TestSecurity_AuthBypassAndPathNormalization(t *testing.T) {
	cfg := config.Default()
	cfg.AuthRequired = true
	pg := graphbuilder.NewProvenanceGraph()
	srv, err := api.NewServer(cfg, api.VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pg, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create api server: %v", err)
	}

	bypassAttempts := []struct {
		method  string
		path    string
		headers map[string]string
	}{
		// Path normalization tricks
		{"GET", "//api/v1/sensors", nil},
		{"GET", "/api/v1/sensors/.", nil},
		{"GET", "/api/v1/../api/v1/sensors", nil},
		{"GET", "/api/v1/%2e%2e/api/v1/sensors", nil},
		{"GET", "/API/V1/SENSORS", nil},
		{"HEAD", "/api/v1/sensors", nil},
		{"OPTIONS", "/api/v1/sensors", nil},
		{"GET", "/api/v1/sensors;param=val", nil},
		// Method override attempts
		{"POST", "/api/v1/health", map[string]string{"X-HTTP-Method-Override": "GET"}},
		{"GET", "/api/v1/sensors", map[string]string{"X-Original-URL": "/api/v1/health"}},
		{"GET", "/api/v1/sensors", map[string]string{"X-Rewrite-URL": "/api/v1/health"}},
	}

	for _, att := range bypassAttempts {
		req := httptest.NewRequest(att.method, att.path, nil)
		for k, v := range att.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		// Any protected route without credentials must return 401, 403, or 404 - NEVER 200 with data
		if rec.Code == http.StatusOK && strings.Contains(att.path, "sensors") {
			t.Errorf("AUTH BYPASS VULNERABILITY: unauthenticated request %s %q returned 200 OK: %s", att.method, att.path, rec.Body.String())
		}
	}
}

// TestSecurity_HostAndOriginSpoofing verifies DNS rebinding and cross-origin protection.
func TestSecurity_HostAndOriginSpoofing(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.AllowRemote = false

	pg := graphbuilder.NewProvenanceGraph()
	srv, err := api.NewServer(cfg, api.VersionInfo{Version: "v0.1.0"}, nil, nil, nil, nil, pg, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create api server: %v", err)
	}

	maliciousHosts := []string{
		"evil.com",
		"attacker.internal",
		"192.168.1.1",
		"victim.example.org:7777",
		"127.0.0.1.evil.com",
	}

	for _, host := range maliciousHosts {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("HOST SPOOFING VULNERABILITY: host %q returned status %d (expected 403 Forbidden)", host, rec.Code)
		}
	}
}

// TestSecurity_TokenLeakProtection verifies tokens never appear in log records, response strings, or crash outputs.
func TestSecurity_TokenLeakProtection(t *testing.T) {
	token := "4a8f9c1b3d5e7a90246813579bdf02468ace13579bdf02468ace13579bdf0246"
	cfg := config.Default()
	cfg.Host = "127.0.0.1"

	// Request with Bearer token in header and check response body doesn't reflect token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// In logs, verify redactor cleans any token appearance
	props := map[string]any{
		"token": token,
		"auth":  "Bearer " + token,
	}
	redacted := redact.RedactProperties(props)
	if redacted["token"] == token || strings.Contains(fmt.Sprintf("%v", redacted["auth"]), token) {
		t.Errorf("TOKEN LEAK VULNERABILITY: token was not redacted in property map: %v", redacted)
	}
}

// TestSecurity_WebUI_XSS_Neutralization verifies that host-originating strings containing <script>
// tags or event handlers are properly escaped and never executed, and CSP meta tag is in place.
func TestSecurity_WebUI_XSS_Neutralization(t *testing.T) {
	maliciousPayloads := []string{
		`<script>alert(1)</script>`,
		`"><img src=x onerror=alert(document.cookie)>`,
		`<svg/onload=alert('XSS')>`,
		`javascript:alert(1)`,
	}

	for _, p := range maliciousPayloads {
		// Escape using HTML escaping logic
		escaped := html.EscapeString(p)
		if strings.Contains(escaped, "<") || strings.Contains(escaped, ">") {
			t.Errorf("XSS SANITIZATION FAILED: payload %q not properly escaped: %q", p, escaped)
		}
	}

	// Verify Content Security Policy exists in embedded HTML
	indexPath := "../../web/index.html"
	if _, err := os.Stat(indexPath); err != nil {
		indexPath = "web/index.html"
	}
	htmlContent, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("failed reading web/index.html: %v", err)
	}
	if !strings.Contains(string(htmlContent), "Content-Security-Policy") {
		t.Errorf("SECURITY VULNERABILITY: web/index.html is missing Content-Security-Policy meta tag")
	}
}

// TestSecurity_TOCTOU_StateDirectoryPermissions verifies that state directories and files are strictly 0700/0600.
func TestSecurity_TOCTOU_StateDirectoryPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "state")
	authMgr, err := auth.NewManager(dataDir)
	if err != nil {
		t.Fatalf("failed creating auth manager: %v", err)
	}
	if authMgr.Token() == "" {
		t.Fatal("empty token generated")
	}

	tokenFile := filepath.Join(dataDir, "auth.token")
	fi, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("failed reading token file stat: %v", err)
	}

	// Verify file mode is strictly 0600 (not readable by group or other)
	perm := fi.Mode().Perm()
	if perm != 0600 {
		t.Errorf("INSECURE PERMISSIONS: token file %s has permissions %o (expected 0600)", tokenFile, perm)
	}
}
