// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package auth manages local API authentication tokens with strict 0600 file permissions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Manager handles API access token generation, persistence, and verification.
type Manager struct {
	mu        sync.RWMutex
	tokenPath string
	token     string
}

// NewManager creates an auth manager storing the local token in dataDir/auth.token.
func NewManager(dataDir string) (*Manager, error) {
	if dataDir == "" {
		dataDir = "/var/lib/kazeshini"
	}
	m := &Manager{
		tokenPath: filepath.Join(dataDir, "auth.token"),
	}

	if err := m.loadOrGenerate(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) loadOrGenerate() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if token exists
	if data, err := os.ReadFile(m.tokenPath); err == nil {
		tok := strings.TrimSpace(string(data))
		if len(tok) >= 32 {
			m.token = tok
			return nil
		}
	}

	// Generate 32-byte secure random token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("failed generating random token: %w", err)
	}
	newToken := hex.EncodeToString(b)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(m.tokenPath), 0700); err != nil {
		// Fallback in memory if dir creation fails
		m.token = newToken
		return nil
	}

	// Write token with 0600 permissions
	if err := os.WriteFile(m.tokenPath, []byte(newToken+"\n"), 0600); err != nil {
		m.token = newToken
		return nil
	}

	m.token = newToken
	return nil
}

// Token returns the current auth token string.
func (m *Manager) Token() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.token
}

// Validate checks whether the provided token matches using constant-time comparison.
func (m *Manager) Validate(candidate string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if candidate == "" || m.token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(m.token)) == 1
}
