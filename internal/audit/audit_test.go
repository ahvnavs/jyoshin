// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/audit"
	"github.com/OWNER/kazeshini/internal/rbac"
)

func TestRequestLogger_AuditChainTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "requests_audit.log")

	logger, err := audit.NewRequestLogger(auditFile)
	if err != nil {
		t.Fatal(err)
	}

	sub := rbac.Subject{
		ID:     "operator-bob",
		Role:   rbac.RoleOperator,
		Method: "token",
	}

	// 1. Log 3 requests
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/checks/chk-%d/run", i), nil)
		req.RemoteAddr = "127.0.0.1:51234"
		err := logger.LogRequest(sub, req, 200, 15*time.Millisecond, fmt.Sprintf("chk-%d", i), "")
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify valid chain
	count, err := audit.VerifyChain(auditFile)
	if err != nil {
		t.Fatalf("clean audit chain should verify, got error: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 verified records, got %d", count)
	}

	// 2. Tamper with file
	data, _ := os.ReadFile(auditFile)
	tampered := []byte(string(data) + `{"timestamp":"2026-01-01T00:00:00Z","caller_id":"attacker","prev_hash":"bad","entry_hash":"fake"}` + "\n")
	_ = os.WriteFile(auditFile, tampered, 0600)

	_, err = audit.VerifyChain(auditFile)
	if err == nil {
		t.Fatal("tampered audit chain should be detected, but passed")
	}
}

