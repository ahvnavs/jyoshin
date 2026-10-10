// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuthManager_GenerateAndPersist(t *testing.T) {
	tmpDir := t.TempDir()

	m1, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	tok1 := m1.Token()
	if len(tok1) < 32 {
		t.Fatalf("token too short: %s", tok1)
	}

	// Verify file permissions 0600
	tokenFile := filepath.Join(tmpDir, "auth.token")
	fi, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("token file not found: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected permissions 0600, got %#o", perm)
	}

	// Re-open and verify persistence
	m2, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("failed to re-open auth manager: %v", err)
	}
	if m2.Token() != tok1 {
		t.Errorf("tokens mismatch after reopen: %s vs %s", m2.Token(), tok1)
	}

	// Validation check
	if !m2.Validate(tok1) {
		t.Error("expected valid token to pass")
	}
	if m2.Validate("wrong-token") {
		t.Error("expected invalid token to fail")
	}
}
