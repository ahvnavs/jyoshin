//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package actuator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ExecutionStep defines a single atomic mutation unit within a plan.
type ExecutionStep struct {
	ID          string `json:"id"`
	Action      string `json:"action"` // "package_install", "package_upgrade", "package_remove", "service_start", "service_stop", "service_restart", "service_enable", "service_disable"
	Target      string `json:"target"` // package name or service unit name
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
	TimeoutSec  int    `json:"timeout_sec,omitempty"`
	Precheck    string `json:"precheck,omitempty"`
	Postcheck   string `json:"postcheck,omitempty"`
}

// RemediationPlan is the plain-data mutation blueprint produced by Core.
type RemediationPlan struct {
	ID             string          `json:"id"`
	TargetHostID   string          `json:"target_host_id"` // /etc/machine-id
	CreatedAt      time.Time       `json:"created_at"`
	Steps          []ExecutionStep `json:"steps"`
	RequiresReboot bool            `json:"requires_reboot"`
	Summary        string          `json:"summary"`
}

// ComputeHash calculates the canonical SHA-256 digest of a RemediationPlan.
func (p *RemediationPlan) ComputeHash() (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("canonicalizing plan: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// ExecutionEnvelope carries a signed plan with replay protection and expiry.
type ExecutionEnvelope struct {
	EnvelopeVersion string          `json:"envelope_version"` // "1.0"
	PlanHash        string          `json:"plan_hash"`
	Plan            RemediationPlan `json:"plan"`
	HostID          string          `json:"host_id"`
	Nonce           string          `json:"nonce"`
	Approver        string          `json:"approver"`
	ApprovedAt      time.Time       `json:"approved_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	Signature       string          `json:"signature"` // base64 encoded ed25519 signature
}

// SigningPayload generates the canonical byte stream covered by the signature.
func (e *ExecutionEnvelope) SigningPayload() []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%d|%d",
		e.EnvelopeVersion,
		e.PlanHash,
		e.HostID,
		e.Nonce,
		e.Approver,
		e.ApprovedAt.Unix(),
		e.ExpiresAt.Unix(),
	))
}

// SignEnvelope signs an ExecutionEnvelope using an Approver's private key.
func SignEnvelope(e *ExecutionEnvelope, privKey ed25519.PrivateKey) error {
	planHash, err := e.Plan.ComputeHash()
	if err != nil {
		return err
	}
	e.PlanHash = planHash
	payload := e.SigningPayload()
	sig := ed25519.Sign(privKey, payload)
	e.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyEnvelope asserts validity, expiry, plan integrity, and signature authenticity.
func VerifyEnvelope(e *ExecutionEnvelope, pubKey ed25519.PublicKey, currentHostID string, now time.Time) error {
	if e.EnvelopeVersion != "1.0" {
		return fmt.Errorf("unsupported envelope version: %q", e.EnvelopeVersion)
	}
	if now.After(e.ExpiresAt) {
		return errors.New("plan signature has expired")
	}
	if e.ApprovedAt.After(now.Add(1 * time.Minute)) {
		return errors.New("approval timestamp is in the future")
	}
	if currentHostID != "" && e.HostID != currentHostID {
		return fmt.Errorf("envelope host ID %q does not match current machine ID %q", e.HostID, currentHostID)
	}
	if e.Plan.TargetHostID != "" && currentHostID != "" && e.Plan.TargetHostID != currentHostID {
		return fmt.Errorf("plan target host ID %q does not match current machine ID %q", e.Plan.TargetHostID, currentHostID)
	}

	computedHash, err := e.Plan.ComputeHash()
	if err != nil {
		return fmt.Errorf("verifying plan hash: %w", err)
	}
	if computedHash != e.PlanHash {
		return fmt.Errorf("plan hash mismatch: envelope says %s, plan computes to %s", e.PlanHash, computedHash)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature base64: %w", err)
	}

	payload := e.SigningPayload()
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return errors.New("cryptographic signature verification failed: invalid signature for payload")
	}

	return nil
}

// GenerateApproverKeypair produces a fresh Ed25519 key pair for approval operations.
func GenerateApproverKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// ReadCurrentHostID inspects /etc/machine-id or returns fallback.
func ReadCurrentHostID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(p); err == nil {
			id := strings.TrimSpace(string(data))
			if id != "" {
				return id
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown-host"
}

func fmtSprintfError(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}
