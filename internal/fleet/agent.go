// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/OWNER/kazeshini/internal/actuator"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// AgentConfig configures the outbound-only agent.
type AgentConfig struct {
	HostID         string
	ControllerURL  string
	PushInterval   time.Duration
	TLSConfig      *tls.Config
	PrivateKey     ed25519.PrivateKey
	LocalPolicyPreflight func(plan *actuator.RemediationPlan) error
}

// Agent runs on the managed host, pushing read-only snapshots and pulling plans.
type Agent struct {
	cfg        AgentConfig
	client     *http.Client
	actEngine  *actuator.Engine
}

func NewAgent(cfg AgentConfig, actEngine *actuator.Engine) *Agent {
	if cfg.PushInterval <= 0 {
		cfg.PushInterval = 15 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: cfg.TLSConfig,
	}
	return &Agent{
		cfg:       cfg,
		client:    &http.Client{Transport: tr, Timeout: 5 * time.Second},
		actEngine: actEngine,
	}
}

// BuildSnapshot creates a signed snapshot from host observation state.
func (a *Agent) BuildSnapshot(v verdict.Summary, cov coverage.Report, findings []rules.Finding, dSummary drift.Summary) (*AgentSnapshot, error) {
	snap := &AgentSnapshot{
		HostID:       a.cfg.HostID,
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
		Verdict:      v,
		Coverage:     cov,
		Findings:     findings,
		DriftSummary: dSummary,
	}

	if a.cfg.PrivateKey != nil {
		if err := snap.Sign(a.cfg.PrivateKey); err != nil {
			return nil, fmt.Errorf("signing snapshot: %w", err)
		}
	}

	return snap, nil
}

// PushSnapshot sends snapshot to Controller.
func (a *Agent) PushSnapshot(ctx context.Context, snap *AgentSnapshot) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/fleet/snapshot", a.cfg.ControllerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kazeshini-Host", a.cfg.HostID)

	resp, err := a.client.Do(req)
	if err != nil {
		// Controller outage: graceful degradation, local operations unaffected
		return fmt.Errorf("controller connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("controller returned status %d", resp.StatusCode)
	}
	return nil
}

// PullAndVerifyPlan retrieves pending plan envelope for this host and verifies host binding.
func (a *Agent) PullAndVerifyPlan(ctx context.Context) (*actuator.ExecutionEnvelope, error) {
	url := fmt.Sprintf("%s/api/v1/fleet/plans?host_id=%s", a.cfg.ControllerURL, a.cfg.HostID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("controller pull failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil, nil // No pending plan
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller returned status %d", resp.StatusCode)
	}

	var env actuator.ExecutionEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decoding envelope: %w", err)
	}

	// 1. Strict Host ID verification: Reject plan targeted to another host
	targetHost := env.HostID
	if targetHost == "" {
		targetHost = env.Plan.TargetHostID
	}
	if targetHost != a.cfg.HostID {
		return nil, fmt.Errorf("%w: envelope host %q != agent host %q", ErrHostMismatch, targetHost, a.cfg.HostID)
	}

	// 2. Local Policy Preflight check: Controller cannot force forbidden actions
	if a.cfg.LocalPolicyPreflight != nil {
		if err := a.cfg.LocalPolicyPreflight(&env.Plan); err != nil {
			return nil, fmt.Errorf("local policy rejected controller plan: %w", err)
		}
	}

	return &env, nil
}
