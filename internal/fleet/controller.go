//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/actuator"
)

// Controller manages the fleet state, agent snapshots, plans, and enrollments.
type Controller struct {
	mu           sync.RWMutex
	hosts        map[string]*HostRecord
	tokens       map[string]*EnrollmentToken
	revokedCerts map[string]bool // Serial or fingerprint -> revoked
	agentPubKeys map[string]ed25519.PublicKey
	queue        *EnvelopesQueue
	staleTimeout time.Duration
}

// ControllerConfig configures Controller options.
type ControllerConfig struct {
	StaleTimeout time.Duration
}

func NewController(cfg ControllerConfig) *Controller {
	stale := cfg.StaleTimeout
	if stale <= 0 {
		stale = 60 * time.Second
	}
	return &Controller{
		hosts:        make(map[string]*HostRecord),
		tokens:       make(map[string]*EnrollmentToken),
		revokedCerts: make(map[string]bool),
		agentPubKeys: make(map[string]ed25519.PublicKey),
		queue:        NewEnvelopesQueue(),
		staleTimeout: stale,
	}
}

// IssueEnrollmentToken generates and tracks an enrollment token.
func (c *Controller) IssueEnrollmentToken(ttl time.Duration, hostID string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tok, err := GenerateEnrollmentToken(ttl, hostID)
	if err != nil {
		return "", err
	}
	c.tokens[tok.Token] = &tok
	return tok.Token, nil
}

// Enroll validates an enrollment token and registers the agent's public key.
func (c *Controller) Enroll(tokenStr, hostID string, pubKey ed25519.PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tok, ok := c.tokens[tokenStr]
	if !ok {
		return errors.New("invalid enrollment token")
	}
	if tok.Consumed {
		return ErrEnrollmentUsed
	}
	if time.Now().UTC().After(tok.ExpiresAt) {
		return ErrEnrollmentExpired
	}

	tok.Consumed = true
	c.agentPubKeys[hostID] = pubKey
	return nil
}

// RevokeCert marks a certificate or client identity revoked.
func (c *Controller) RevokeCert(certID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revokedCerts[certID] = true
}

// IngestSnapshot validates snapshot authenticity and updates host records.
func (c *Controller) IngestSnapshot(ctx context.Context, certID string, snap AgentSnapshot) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Verify certificate revocation status
	if c.revokedCerts[certID] {
		return ErrCertRevoked
	}

	// 2. Verify cryptographic signature if public key is registered
	if pubKey, ok := c.agentPubKeys[snap.HostID]; ok {
		if !snap.Verify(pubKey) {
			return ErrSignatureInvalid
		}
	}

	now := time.Now().UTC()
	rec, exists := c.hosts[snap.HostID]
	if !exists {
		rec = &HostRecord{
			HostID:    snap.HostID,
			FirstSeen: now,
		}
		c.hosts[snap.HostID] = rec
	}

	rec.LastSeen = now
	rec.IsStale = false
	rec.StatusLabel = snap.Verdict.StateLabel
	rec.ChaosIndex = snap.Verdict.ChaosIndex
	rec.CoverageRatio = snap.Coverage.OverallCoverage / 100.0
	rec.CriticalCount = snap.Verdict.CriticalFindings
	rec.TotalDrift = snap.DriftSummary.TotalDrift
	rec.LatestSnapshot = &snap

	return nil
}

// GetFleetTable returns current status of all enrolled hosts, recalculating staleness.
func (c *Controller) GetFleetTable() ([]HostRecord, FleetSummary) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	var list []HostRecord
	var summary FleetSummary

	summary.TotalHosts = len(c.hosts)

	for _, rec := range c.hosts {
		// Update staleness
		if now.Sub(rec.LastSeen) > c.staleTimeout {
			rec.IsStale = true
			rec.StatusLabel = "UNKNOWN (STALE)"
			summary.StaleHosts++
		} else {
			rec.IsStale = false
			summary.ActiveHosts++
			switch rec.StatusLabel {
			case "CRITICAL":
				summary.CriticalHosts++
			case "MESSY":
				summary.MessyHosts++
			case "CALM":
				summary.CalmHosts++
			}
		}

		summary.TotalDrift += rec.TotalDrift
		if rec.LatestSnapshot != nil {
			summary.TotalFindings += rec.LatestSnapshot.Verdict.TotalFindings
		}

		list = append(list, *rec)
	}

	return list, summary
}

// QueuePlanEnqueues an approved plan envelope strictly targeted to its host.
func (c *Controller) QueuePlan(env *actuator.ExecutionEnvelope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queue.Push(env)
}

// PullPlanForHost retrieves pending envelope targeted to the requesting host.
func (c *Controller) PullPlanForHost(hostID string) *actuator.ExecutionEnvelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.queue.PopForHost(hostID)
}

// ExecuteBatchRollout executes plan rollout across multiple hosts with safety limits.
func (c *Controller) ExecuteBatchRollout(ctx context.Context, rollout *BatchRollout) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	total := len(rollout.Hosts)
	if total == 0 {
		return nil
	}

	failedCount := 0
	for _, h := range rollout.Hosts {
		// Check failure ratio before proceeding with next batch host
		failRatio := float64(failedCount) / float64(total)
		if rollout.Config.HaltThreshold > 0 && failRatio >= rollout.Config.HaltThreshold {
			rollout.Halted = true
			rollout.HaltReason = fmt.Sprintf("Failure ratio %.2f exceeded threshold %.2f", failRatio, rollout.Config.HaltThreshold)
			return fmt.Errorf("%w: %s", ErrHaltThresholdExceeded, rollout.HaltReason)
		}

		if rollout.Failed[h] != nil {
			failedCount++
		}
	}

	return nil
}
