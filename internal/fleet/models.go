// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package fleet implements multi-host Agent and Controller capabilities for Kazeshini.
// This mode is optional and disabled by default. Single-host operation remains 100% autonomous.
//
// Principles:
// 1. Outbound-only agent connection over mTLS (no inbound ports required on managed host).
// 2. Agents push signed read-only snapshots and pull approved plan envelopes strictly for their own host ID.
// 3. Controller cannot bypass local agent policy or force unapproved mutations.
// 4. Stale agents (>60s) report UNKNOWN in the fleet table, never healthy.
package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/OWNER/kazeshini/internal/actuator"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/resource"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
)

var (
	ErrEnrollmentExpired   = errors.New("enrollment token has expired")
	ErrEnrollmentUsed      = errors.New("enrollment token has already been consumed")
	ErrCertRevoked         = errors.New("client certificate has been revoked")
	ErrHostMismatch        = errors.New("plan envelope target host ID does not match agent machine-id")
	ErrSignatureInvalid    = errors.New("cryptographic signature verification failed")
	ErrHaltThresholdExceeded = errors.New("batch execution halted due to failure threshold")
)

// AgentSnapshot contains read-only telemetry pushed by an agent to the controller.
type AgentSnapshot struct {
	HostID          string              `json:"host_id"`           // Machine ID / hostname
	AgentVersion    string              `json:"agent_version"`
	Timestamp       time.Time           `json:"timestamp"`
	Verdict         verdict.Summary     `json:"verdict"`
	Coverage        coverage.Report     `json:"coverage"`
	Findings        []rules.Finding     `json:"findings"`
	DriftSummary    drift.Summary       `json:"drift_summary"`
	Resources       []resource.Resource `json:"resources,omitempty"`
	Signature       string              `json:"signature"`         // ed25519 signature of payload bytes
}

// ComputeDigest calculates canonical SHA-256 digest of AgentSnapshot data.
func (s *AgentSnapshot) ComputeDigest() ([]byte, error) {
	clone := *s
	clone.Signature = ""
	bytes, err := json.Marshal(clone)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(bytes)
	return h[:], nil
}

// Sign signs snapshot with agent's ed25519 private key.
func (s *AgentSnapshot) Sign(privKey ed25519.PrivateKey) error {
	digest, err := s.ComputeDigest()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(privKey, digest)
	s.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify verifies snapshot against agent's ed25519 public key.
func (s *AgentSnapshot) Verify(pubKey ed25519.PublicKey) bool {
	if s.Signature == "" {
		return false
	}
	sigBytes, err := hex.DecodeString(s.Signature)
	if err != nil {
		return false
	}
	digest, err := s.ComputeDigest()
	if err != nil {
		return false
	}
	return ed25519.Verify(pubKey, digest, sigBytes)
}

// HostRecord stores the latest known fleet state of a registered host.
type HostRecord struct {
	HostID          string          `json:"host_id"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
	IsStale         bool            `json:"is_stale"`          // True if LastSeen > 60s ago
	StatusLabel     string          `json:"status_label"`      // "CALM", "MESSY", "CRITICAL", "UNKNOWN (STALE)"
	ChaosIndex      int             `json:"chaos_index"`
	CoverageRatio   float64         `json:"coverage_ratio"`
	CriticalCount   int             `json:"critical_count"`
	TotalDrift      int             `json:"total_drift"`
	PendingPlanID   string          `json:"pending_plan_id,omitempty"`
	LatestSnapshot  *AgentSnapshot  `json:"latest_snapshot,omitempty"`
}

// FleetSummary aggregates rollups across all enrolled hosts.
type FleetSummary struct {
	TotalHosts      int `json:"total_hosts"`
	ActiveHosts     int `json:"active_hosts"`
	StaleHosts      int `json:"stale_hosts"`
	CriticalHosts   int `json:"critical_hosts"`
	MessyHosts      int `json:"messy_hosts"`
	CalmHosts       int `json:"calm_hosts"`
	TotalDrift      int `json:"total_drift"`
	TotalFindings   int `json:"total_findings"`
}

// EnrollmentToken defines a single-use expiring token to onboard a new agent.
type EnrollmentToken struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Consumed  bool      `json:"consumed"`
	HostID    string    `json:"host_id,omitempty"`
}

// GenerateEnrollmentToken creates a cryptographically random token expiring after duration.
func GenerateEnrollmentToken(ttl time.Duration, hostID string) (EnrollmentToken, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return EnrollmentToken{}, err
	}
	now := time.Now().UTC()
	return EnrollmentToken{
		Token:     hex.EncodeToString(bytes),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Consumed:  false,
		HostID:    hostID,
	}, nil
}

// BatchRolloutConfig controls multi-host plan rollout with concurrency & safety bounds.
type BatchRolloutConfig struct {
	MaxConcurrency int     `json:"max_concurrency"`
	HaltThreshold  float64 `json:"halt_threshold"` // e.g. 0.20 = halt if >20% fail
}

// BatchRollout tracks execution across multiple hosts.
type BatchRollout struct {
	ID             string                         `json:"id"`
	PlanID         string                         `json:"plan_id"`
	Hosts          []string                       `json:"hosts"`
	Completed      map[string]bool                `json:"completed"`
	Failed         map[string]error               `json:"failed"`
	Config         BatchRolloutConfig             `json:"config"`
	Halted         bool                           `json:"halted"`
	HaltReason     string                         `json:"halt_reason,omitempty"`
}

// EnvelopesQueue holds pending signed plans targeted to specific host IDs.
type EnvelopesQueue struct {
	envelopes map[string][]*actuator.ExecutionEnvelope // hostID -> queue
}

func NewEnvelopesQueue() *EnvelopesQueue {
	return &EnvelopesQueue{
		envelopes: make(map[string][]*actuator.ExecutionEnvelope),
	}
}

func (q *EnvelopesQueue) Push(env *actuator.ExecutionEnvelope) {
	host := env.HostID
	if host == "" {
		host = env.Plan.TargetHostID
	}
	q.envelopes[host] = append(q.envelopes[host], env)
}

func (q *EnvelopesQueue) PopForHost(hostID string) *actuator.ExecutionEnvelope {
	list := q.envelopes[hostID]
	if len(list) == 0 {
		return nil
	}
	item := list[0]
	q.envelopes[hostID] = list[1:]
	return item
}
