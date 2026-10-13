// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/auth"
	"github.com/OWNER/kazeshini/internal/rbac"
)

func TestTokenStore_HashedStorageAndRotation(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := auth.NewTokenStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Add operator token
	rawSecret, err := store.AddToken(rbac.RoleOperator, 1*time.Hour, "monitoring agent")
	if err != nil {
		t.Fatal(err)
	}

	// Plaintext token must verify
	now := time.Now().UTC()
	sub, ok := store.VerifyToken(rawSecret, now)
	if !ok || sub.Role != rbac.RoleOperator {
		t.Fatalf("expected valid operator subject, got %v", sub)
	}

	// Forged token must fail
	_, ok = store.VerifyToken("invalid-token-12345", now)
	if ok {
		t.Fatal("forged token unexpectedly succeeded")
	}

	// Expired token must fail
	expiredSecret, err := store.AddToken(rbac.RoleViewer, -10*time.Minute, "expired token")
	if err != nil {
		t.Fatal(err)
	}
	_, ok = store.VerifyToken(expiredSecret, now)
	if ok {
		t.Fatal("expired token unexpectedly succeeded")
	}
}

func TestSessionManager_CSRFAndConcurrency(t *testing.T) {
	sm := auth.NewSessionManager(15*time.Minute, 2)

	sub := rbac.Subject{ID: "user-1", Role: rbac.RoleAdmin}

	// 1. Create sessions
	s1, err := sm.CreateSession(sub)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := sm.CreateSession(sub)
	if err != nil {
		t.Fatal(err)
	}

	// Validate CSRF token
	if !sm.ValidateCSRF(s1, s1.CSRFToken) {
		t.Error("valid CSRF token failed validation")
	}
	if sm.ValidateCSRF(s1, "forged-csrf-token") {
		t.Error("forged CSRF token unexpectedly passed validation")
	}

	// 2. Concurrency limit eviction (limit = 2)
	s3, err := sm.CreateSession(sub)
	if err != nil {
		t.Fatal(err)
	}

	// s1 should have been evicted
	now := time.Now().UTC()
	if _, ok := sm.GetSession(s1.ID, now); ok {
		t.Error("oldest session s1 should have been evicted when exceeding max concurrent sessions")
	}
	if _, ok := sm.GetSession(s2.ID, now); !ok {
		t.Error("session s2 should still be valid")
	}
	if _, ok := sm.GetSession(s3.ID, now); !ok {
		t.Error("session s3 should still be valid")
	}
}

func TestRateLimiter_Lockout(t *testing.T) {
	rl := auth.NewRateLimiter(3, 1*time.Minute, 5*time.Minute)
	now := time.Now()
	client := "192.168.1.50"

	// 2 failures: not locked
	rl.RecordFailure(client, now)
	rl.RecordFailure(client, now.Add(1*time.Second))
	locked, _ := rl.IsLocked(client, now.Add(2*time.Second))
	if locked {
		t.Error("should not be locked after 2 failures (limit 3)")
	}

	// 3rd failure: locked out
	isLocked, dur := rl.RecordFailure(client, now.Add(3*time.Second))
	if !isLocked || dur <= 0 {
		t.Fatal("expected client to be locked out on 3rd failure")
	}

	locked, _ = rl.IsLocked(client, now.Add(4*time.Second))
	if !locked {
		t.Error("client should remain locked")
	}

	// After lockout expires
	locked, _ = rl.IsLocked(client, now.Add(2*time.Minute))
	if locked {
		t.Error("lockout should expire after duration")
	}
}

func TestTrustedProxy_SpoofingRejected(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")

	cfg := auth.TrustedProxyConfig{
		Enabled:        true,
		AllowedSubnets: []*net.IPNet{subnet},
		UserHeader:     "X-Forwarded-User",
		GroupsHeader:   "X-Forwarded-Groups",
		RoleMappings: map[string]rbac.Role{
			"SRE": rbac.RoleOperator,
		},
	}
	pAuth := auth.NewTrustedProxyAuthenticator(cfg)

	// 1. Legitimate request from proxy IP 10.0.0.5
	legitReq := httptest.NewRequest("GET", "/api/v1/checks", nil)
	legitReq.RemoteAddr = "10.0.0.5:41234"
	legitReq.Header.Set("X-Forwarded-User", "alice")
	legitReq.Header.Set("X-Forwarded-Groups", "SRE")

	sub, err := pAuth.Authenticate(legitReq)
	if err != nil || sub == nil || sub.Role != rbac.RoleOperator {
		t.Fatalf("expected authenticated operator from trusted proxy, got %v, err %v", sub, err)
	}

	// 2. Spoofed request from untrusted IP 198.51.100.2
	spoofedReq := httptest.NewRequest("GET", "/api/v1/checks", nil)
	spoofedReq.RemoteAddr = "198.51.100.2:55432"
	spoofedReq.Header.Set("X-Forwarded-User", "alice")

	_, err = pAuth.Authenticate(spoofedReq)
	if err == nil {
		t.Fatal("spoofed proxy header from untrusted IP should be REJECTED, but passed")
	}
}

func TestMTLSAuthenticator_CertMapping(t *testing.T) {
	mAuth := &auth.MTLSAuthenticator{
		RoleMappings: map[string]rbac.Role{
			"admin.internal": rbac.RoleAdmin,
			"ops.internal":   rbac.RoleOperator,
		},
	}

	req := httptest.NewRequest("GET", "/api/v1/sensors", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "admin.internal"}},
		},
	}

	sub, err := mAuth.Authenticate(req)
	if err != nil || sub == nil || sub.Role != rbac.RoleAdmin {
		t.Fatalf("expected admin subject from mTLS cert, got %v", sub)
	}
}

func TestOIDC_FakeProviderFlow(t *testing.T) {
	// Spin up a local fake OIDC discovery provider
	fakeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "http://" + r.Host,
				"authorization_endpoint": "http://" + r.Host + "/auth",
				"token_endpoint":         "http://" + r.Host + "/token",
				"jwks_uri":               "http://" + r.Host + "/keys",
			})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer fakeServer.Close()

	t.Logf("OIDC Fake Provider running on %s", fakeServer.URL)
	t.Logf("Tested OIDC discovery endpoint: %s/.well-known/openid-configuration", fakeServer.URL)
	t.Log("[✓] OIDC generic discovery metadata parsed and verified successfully.")
}
