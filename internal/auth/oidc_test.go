//go:build experimental
// +build experimental

package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OWNER/kazeshini/internal/auth"
)

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

	mgr, err := auth.NewOIDCManager(context.Background(), auth.OIDCConfig{
		IssuerURL:    fakeServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  fakeServer.URL + "/callback",
	})
	if err != nil {
		t.Fatalf("failed to init OIDC manager: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil OIDC manager")
	}

	t.Logf("OIDC Fake Provider running on %s", fakeServer.URL)
	t.Logf("Tested OIDC discovery endpoint: %s/.well-known/openid-configuration", fakeServer.URL)
	t.Log("[✓] OIDC generic discovery metadata parsed and verified successfully.")
}
