//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package fleet_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/actuator"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/fleet"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// TestFleet_MultiAgentAndControllerLifecycle verifies 2 agents, 1 controller,
// killing one agent, stale detection, plan isolation, and controller outage resilience.
func TestFleet_MultiAgentAndControllerLifecycle(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize Controller with short 200ms stale timeout for testing
	ctrl := fleet.NewController(fleet.ControllerConfig{
		StaleTimeout: 200 * time.Millisecond,
	})

	// 2. Setup HTTP test server exposing Controller endpoints
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/fleet/snapshot":
			certID := r.Header.Get("X-Cert-ID")
			var snap fleet.AgentSnapshot
			if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := ctrl.IngestSnapshot(r.Context(), certID, snap); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)

		case "/api/v1/fleet/plans":
			hostID := r.URL.Query().Get("host_id")
			env := ctrl.PullPlanForHost(hostID)
			if env == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(env)

		default:
			http.NotFound(w, r)
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// 3. Setup Agent A and Agent B keypairs
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)

	// Enroll agents
	tokA, _ := ctrl.IssueEnrollmentToken(5*time.Minute, "host-alpha")
	_ = ctrl.Enroll(tokA, "host-alpha", pubA)

	tokB, _ := ctrl.IssueEnrollmentToken(5*time.Minute, "host-bravo")
	_ = ctrl.Enroll(tokB, "host-bravo", pubB)

	agentA := fleet.NewAgent(fleet.AgentConfig{
		HostID:        "host-alpha",
		ControllerURL: server.URL,
		PrivateKey:    privA,
	}, nil)

	agentB := fleet.NewAgent(fleet.AgentConfig{
		HostID:        "host-bravo",
		ControllerURL: server.URL,
		PrivateKey:    privB,
	}, nil)

	// 4. Push snapshots from both agents
	snapA, _ := agentA.BuildSnapshot(
		verdict.Summary{StateLabel: "CALM", ChaosIndex: 0},
		coverage.Report{OverallCoverage: 95.0, IsAdequate: true},
		nil,
		drift.Summary{TotalDrift: 0},
	)
	if err := agentA.PushSnapshot(ctx, snapA); err != nil {
		t.Fatalf("agent A push failed: %v", err)
	}

	snapB, _ := agentB.BuildSnapshot(
		verdict.Summary{StateLabel: "MESSY", ChaosIndex: 25},
		coverage.Report{OverallCoverage: 80.0, IsAdequate: true},
		nil,
		drift.Summary{TotalDrift: 3},
	)
	if err := agentB.PushSnapshot(ctx, snapB); err != nil {
		t.Fatalf("agent B push failed: %v", err)
	}

	// Verify both active in fleet table
	table, summary := ctrl.GetFleetTable()
	if len(table) != 2 || summary.ActiveHosts != 2 {
		t.Fatalf("expected 2 active hosts, got table=%d, active=%d", len(table), summary.ActiveHosts)
	}
	t.Logf("[✓] Initial fleet view: %d hosts active (Alpha: CALM, Bravo: MESSY)", summary.ActiveHosts)

	// 5. Simulate Agent B killed: Agent A keeps reporting, Agent B stops
	time.Sleep(300 * time.Millisecond) // Exceed 200ms stale timeout

	// Agent A heartbeats again
	snapA2, _ := agentA.BuildSnapshot(
		verdict.Summary{StateLabel: "CALM", ChaosIndex: 0},
		coverage.Report{OverallCoverage: 95.0, IsAdequate: true},
		nil,
		drift.Summary{TotalDrift: 0},
	)
	_ = agentA.PushSnapshot(ctx, snapA2)

	// Inspect fleet table: Agent B must be marked UNKNOWN (STALE)
	tableAfter, summaryAfter := ctrl.GetFleetTable()
	if summaryAfter.StaleHosts != 1 || summaryAfter.ActiveHosts != 1 {
		t.Fatalf("expected 1 active and 1 stale host, got active=%d, stale=%d", summaryAfter.ActiveHosts, summaryAfter.StaleHosts)
	}

	foundStaleBravo := false
	for _, rec := range tableAfter {
		if rec.HostID == "host-bravo" && rec.IsStale && rec.StatusLabel == "UNKNOWN (STALE)" {
			foundStaleBravo = true
		}
	}
	if !foundStaleBravo {
		t.Errorf("expected host-bravo to be marked UNKNOWN (STALE)")
	}
	t.Logf("[✓] Killed agent properly detected: host-bravo is UNKNOWN (STALE), host-alpha remains CALM")

	// 6. Plan targeted to Host A rejected by Agent B
	planForA := &actuator.ExecutionEnvelope{
		HostID: "host-alpha",
		Plan: actuator.RemediationPlan{
			ID:           "plan-001",
			TargetHostID: "host-alpha",
		},
	}
	ctrl.QueuePlan(planForA)

	// Agent B attempts to pull for host-bravo -> receives no plan
	envB, err := agentB.PullAndVerifyPlan(ctx)
	if err != nil {
		t.Fatalf("unexpected error pulling for agent B: %v", err)
	}
	if envB != nil {
		t.Fatalf("agent B received plan targeted to host-alpha!")
	}

	// Agent A pulls for host-alpha -> receives plan cleanly
	envA, err := agentA.PullAndVerifyPlan(ctx)
	if err != nil {
		t.Fatalf("agent A failed pulling its own plan: %v", err)
	}
	if envA == nil || envA.HostID != "host-alpha" {
		t.Fatalf("expected plan for host-alpha, got %v", envA)
	}
	t.Logf("[✓] Plan envelope isolation verified: host-alpha pulled its plan, host-bravo received nothing")

	// 7. Revoked cert rejected
	ctrl.RevokeCert("cert-compromised-99")
	errRev := ctrl.IngestSnapshot(ctx, "cert-compromised-99", *snapA)
	if errRev != fleet.ErrCertRevoked {
		t.Errorf("expected ErrCertRevoked, got %v", errRev)
	}
	t.Logf("[✓] Revoked client cert rejected by controller: %v", errRev)

	// 8. Controller outage leaves local agent fully functional
	server.Close()
	errOutage := agentA.PushSnapshot(ctx, snapA)
	if errOutage == nil {
		t.Errorf("expected error connecting to closed controller server")
	}
	// Local agent functions independently without crashing
	t.Logf("[✓] Controller outage gracefully handled: local agent functions independently (%v)", errOutage)
}
