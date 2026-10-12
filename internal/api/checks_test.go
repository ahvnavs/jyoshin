// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OWNER/kazeshini/internal/api"
	"github.com/OWNER/kazeshini/internal/checks"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/contract"
)

func TestAPI_ChecksAndActivityEndpoints(t *testing.T) {
	cfg := config.Default()
	cfg.AuthRequired = false // Test endpoints directly
	cfg.DataDir = t.TempDir()

	srv, err := api.NewServer(cfg, api.VersionInfo{Version: "v0.0.1"}, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	handler := srv.Handler()

	// 1. GET /api/v1/checks
	reqChecks := httptest.NewRequest("GET", "/api/v1/checks", nil)
	wChecks := httptest.NewRecorder()
	handler.ServeHTTP(wChecks, reqChecks)

	if wChecks.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/checks returned %d", wChecks.Code)
	}

	var checksList []map[string]any
	if err := json.Unmarshal(wChecks.Body.Bytes(), &checksList); err != nil {
		t.Fatalf("failed to unmarshal checks response: %v", err)
	}
	if len(checksList) < 20 {
		t.Fatalf("expected >= 20 checks, got %d", len(checksList))
	}

	// 2. GET /api/v1/checks?role=infrastructure
	reqRole := httptest.NewRequest("GET", "/api/v1/checks?role=infrastructure", nil)
	wRole := httptest.NewRecorder()
	handler.ServeHTTP(wRole, reqRole)

	if wRole.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/checks?role=infrastructure returned %d", wRole.Code)
	}
	var infraList []map[string]any
	if err := json.Unmarshal(wRole.Body.Bytes(), &infraList); err != nil {
		t.Fatalf("failed to unmarshal infra checks: %v", err)
	}
	if len(infraList) != 3 {
		t.Fatalf("expected 3 infrastructure checks, got %d", len(infraList))
	}

	// 3. POST /api/v1/checks/disk-inodes/run
	reqRun := httptest.NewRequest("POST", "/api/v1/checks/disk-inodes/run", nil)
	wRun := httptest.NewRecorder()
	handler.ServeHTTP(wRun, reqRun)

	if wRun.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/checks/disk-inodes/run returned %d", wRun.Code)
	}
	var runResult contract.CheckResult
	if err := json.Unmarshal(wRun.Body.Bytes(), &runResult); err != nil {
		t.Fatalf("failed to unmarshal check result: %v", err)
	}
	if runResult.ID != "disk-inodes" || !runResult.ReadOnly {
		t.Errorf("unexpected check result: %+v", runResult)
	}

	// 4. POST /api/v1/checks/app-logs/run with path traversal attack -> expect 400 Bad Request
	reqAttack := httptest.NewRequest("POST", "/api/v1/checks/app-logs/run?file=../../etc/shadow", nil)
	wAttack := httptest.NewRecorder()
	handler.ServeHTTP(wAttack, reqAttack)

	if wAttack.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for path traversal attack, got %d", wAttack.Code)
	}

	// 5. POST /api/v1/checks/connectivity-probe/run with injection attack -> expect 400
	reqInject := httptest.NewRequest("POST", "/api/v1/checks/connectivity-probe/run?target=127.0.0.1%3A80%3Breboot", nil)
	wInject := httptest.NewRecorder()
	handler.ServeHTTP(wInject, reqInject)

	if wInject.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for command injection attack, got %d: %s", wInject.Code, wInject.Body.String())
	}

	// 6. GET /api/v1/activity -> verify activity log recorded the runs
	reqAct := httptest.NewRequest("GET", "/api/v1/activity", nil)
	wAct := httptest.NewRecorder()
	handler.ServeHTTP(wAct, reqAct)

	if wAct.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/activity returned %d", wAct.Code)
	}

	var actData struct {
		Disclaimer string                 `json:"disclaimer"`
		Entries    []checks.ActivityEntry `json:"entries"`
	}
	if err := json.Unmarshal(wAct.Body.Bytes(), &actData); err != nil {
		t.Fatalf("failed to unmarshal activity log: %v", err)
	}
	if !strings.Contains(actData.Disclaimer, "Local audit activity log") {
		t.Errorf("missing activity disclaimer: %s", actData.Disclaimer)
	}
	if len(actData.Entries) == 0 {
		t.Errorf("expected activity entries, got 0")
	}
}
