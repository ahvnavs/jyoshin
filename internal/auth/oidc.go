//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/OWNER/kazeshini/internal/rbac"
)

// OIDCConfig specifies settings for generic OpenID Connect authentication.
type OIDCConfig struct {
	Enabled      bool
	IssuerURL    string // e.g. "https://accounts.google.com" or Okta/Keycloak issuer
	ClientID     string
	ClientSecret string
	RedirectURL  string
	RoleClaim    string // e.g. "groups" or "roles" (default: "groups")
	RoleMappings map[string]rbac.Role
}

// OIDCManager handles OIDC discovery, PKCE auth code exchange, and token verification.
type OIDCManager struct {
	cfg          OIDCConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauthConfig  oauth2.Config
	statesMu     sync.Mutex
	activeStates map[string]oidcState
}

type oidcState struct {
	codeVerifier string
	createdAt    time.Time
}

// NewOIDCManager initializes the OIDC provider via auto-discovery.
func NewOIDCManager(ctx context.Context, cfg OIDCConfig) (*OIDCManager, error) {
	if !cfg.Enabled {
		return &OIDCManager{cfg: cfg}, nil
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed for %s: %w", cfg.IssuerURL, err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	return &OIDCManager{
		cfg:          cfg,
		provider:     provider,
		verifier:     verifier,
		oauthConfig:  oauthCfg,
		activeStates: make(map[string]oidcState),
	}, nil
}

// AuthCodeURL produces an authorization URL with PKCE code challenge.
func (m *OIDCManager) AuthCodeURL() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	state := hex.EncodeToString(b)

	// PKCE code_verifier (random) and code_challenge (S256)
	cvBytes := make([]byte, 32)
	if _, err := rand.Read(cvBytes); err != nil {
		return "", "", err
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(cvBytes)
	challengeSum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])

	m.statesMu.Lock()
	m.activeStates[state] = oidcState{
		codeVerifier: codeVerifier,
		createdAt:    time.Now(),
	}
	m.statesMu.Unlock()

	url := m.oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return url, state, nil
}

// ExchangeAndVerify exchanges the authorization code for an ID token and verifies it.
func (m *OIDCManager) ExchangeAndVerify(ctx context.Context, code, state string) (*rbac.Subject, error) {
	m.statesMu.Lock()
	savedState, exists := m.activeStates[state]
	if exists {
		delete(m.activeStates, state)
	}
	m.statesMu.Unlock()

	if !exists {
		return nil, fmt.Errorf("invalid or expired OIDC state parameter")
	}

	token, err := m.oauthConfig.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", savedState.codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("exchanging oidc code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := m.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verifying id_token: %w", err)
	}

	var claims struct {
		Subject string   `json:"sub"`
		Email   string   `json:"email"`
		Groups  []string `json:"groups"`
		Roles   []string `json:"roles"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing id_token claims: %w", err)
	}

	userIdent := claims.Email
	if userIdent == "" {
		userIdent = claims.Subject
	}

	// Map claims/groups to roles
	role := rbac.RoleViewer
	combinedGroups := append(claims.Groups, claims.Roles...)
	for _, g := range combinedGroups {
		if mappedRole, ok := m.cfg.RoleMappings[g]; ok {
			if mappedRole.Satisfies(role) {
				role = mappedRole
			}
		}
	}

	return &rbac.Subject{
		ID:     fmt.Sprintf("oidc:%s", userIdent),
		Role:   role,
		Method: "oidc",
		Groups: combinedGroups,
	}, nil
}
