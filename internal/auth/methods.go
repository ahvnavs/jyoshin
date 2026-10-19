// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/rbac"
)

// Authenticator provides a unified interface for credential verification.
type Authenticator interface {
	Authenticate(r *http.Request) (*rbac.Subject, error)
}

// TokenRecord stores token metadata with sha256 hash (never plain text).
type TokenRecord struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"` // sha256 hex digest
	Role      rbac.Role `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Comment   string    `json:"comment,omitempty"`
}

// TokenStore manages rotatable, hashed token persistence.
type TokenStore struct {
	mu     sync.RWMutex
	path   string
	tokens []TokenRecord
}

// NewTokenStore initializes or loads token database from dataDir/tokens.json.
func NewTokenStore(dataDir string) (*TokenStore, error) {
	ts := &TokenStore{
		path: filepath.Join(dataDir, "tokens.json"),
	}
	if err := ts.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading token store: %w", err)
	}
	return ts, nil
}

// HashToken calculates the SHA-256 hex digest of a raw token.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// AddToken generates a new random token, stores its hash, and returns the raw secret.
func (ts *TokenStore) AddToken(role rbac.Role, ttl time.Duration, comment string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	rawToken := hex.EncodeToString(b)
	hash := HashToken(rawToken)

	now := time.Now().UTC()
	rec := TokenRecord{
		ID:        fmt.Sprintf("tok-%d", now.UnixNano()),
		Hash:      hash,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Comment:   comment,
	}

	ts.mu.Lock()
	ts.tokens = append(ts.tokens, rec)
	err := ts.saveLocked()
	ts.mu.Unlock()

	if err != nil {
		return "", err
	}
	return rawToken, nil
}

// VerifyToken checks whether a raw token matches any non-expired stored hash.
func (ts *TokenStore) VerifyToken(raw string, now time.Time) (*rbac.Subject, bool) {
	hash := HashToken(raw)

	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, t := range ts.tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(hash)) == 1 {
			if !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) {
				return nil, false // Expired
			}
			return &rbac.Subject{
				ID:     t.ID,
				Role:   t.Role,
				Method: "token",
			}, true
		}
	}
	return nil, false
}

func (ts *TokenStore) load() error {
	data, err := os.ReadFile(ts.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &ts.tokens)
}

func (ts *TokenStore) saveLocked() error {
	if ts.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(ts.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ts.tokens, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ts.path, data, 0600)
}

// MTLSAuthenticator authenticates clients via TLS Client Certificate CN/SAN.
type MTLSAuthenticator struct {
	RoleMappings map[string]rbac.Role // CN or SAN -> Role
}

// Authenticate extracts client cert and maps to role.
func (m *MTLSAuthenticator) Authenticate(r *http.Request) (*rbac.Subject, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, nil // No client cert provided
	}
	cert := r.TLS.PeerCertificates[0]
	cn := cert.Subject.CommonName

	role, exists := m.RoleMappings[cn]
	if !exists {
		// Check email SANs
		for _, email := range cert.EmailAddresses {
			if r, ok := m.RoleMappings[email]; ok {
				role = r
				exists = true
				cn = email
				break
			}
		}
	}

	if !exists {
		role = rbac.RoleViewer
	}

	return &rbac.Subject{
		ID:     fmt.Sprintf("mtls:%s", cn),
		Role:   role,
		Method: "mtls",
	}, nil
}

// TrustedProxyConfig configures reverse proxy header authentication.
type TrustedProxyConfig struct {
	Enabled        bool
	AllowedSubnets []*net.IPNet
	UserHeader     string // e.g. "X-Forwarded-User"
	GroupsHeader   string // e.g. "X-Forwarded-Groups"
	SigHeader      string // e.g. "X-Forwarded-Signature"
	SharedSecret   string
	RoleMappings   map[string]rbac.Role
}

// TrustedProxyAuthenticator validates proxy authentication headers.
type TrustedProxyAuthenticator struct {
	cfg TrustedProxyConfig
}

// NewTrustedProxyAuthenticator creates an authenticator for reverse proxy headers.
func NewTrustedProxyAuthenticator(cfg TrustedProxyConfig) *TrustedProxyAuthenticator {
	return &TrustedProxyAuthenticator{cfg: cfg}
}

// Authenticate verifies client IP against allow-list and extracts user/role.
func (p *TrustedProxyAuthenticator) Authenticate(r *http.Request) (*rbac.Subject, error) {
	if !p.cfg.Enabled {
		return nil, nil
	}

	user := r.Header.Get(p.cfg.UserHeader)
	if user == "" {
		return nil, nil // No proxy header present
	}

	// 1. Verify RemoteAddr is from allowed proxy subnet
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("trusted proxy error: invalid remote IP %q", host)
	}

	allowed := false
	for _, subnet := range p.cfg.AllowedSubnets {
		if subnet.Contains(ip) {
			allowed = true
			break
		}
	}
	if !allowed {
		// Spoofing attempt from untrusted address: REJECT IMMEDIATELY
		return nil, fmt.Errorf("trusted proxy rejected: request with %s from unauthorized IP %s", p.cfg.UserHeader, host)
	}

	// 2. Optional HMAC Signature Verification
	if p.cfg.SharedSecret != "" && p.cfg.SigHeader != "" {
		sig := r.Header.Get(p.cfg.SigHeader)
		mac := hmac.New(sha256.New, []byte(p.cfg.SharedSecret))
		mac.Write([]byte(user))
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
			return nil, fmt.Errorf("trusted proxy signature mismatch")
		}
	}

	// 3. Map Groups to Role
	role := rbac.RoleViewer
	groupsRaw := r.Header.Get(p.cfg.GroupsHeader)
	var groups []string
	if groupsRaw != "" {
		for _, g := range strings.Split(groupsRaw, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				groups = append(groups, g)
				if mappedRole, ok := p.cfg.RoleMappings[g]; ok {
					if mappedRole.Satisfies(role) {
						role = mappedRole
					}
				}
			}
		}
	}

	return &rbac.Subject{
		ID:     fmt.Sprintf("proxy:%s", user),
		Role:   role,
		Method: "proxy",
		Groups: groups,
	}, nil
}
