// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package reconcile coordinates the level-triggered reconciliation loop:
// observe actual -> compare against desired -> plan remediation DAG -> publish events.
// Modes are strictly observe and plan in this phase (Principle 17).
package reconcile

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/desired"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/events"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/policy"
	"github.com/OWNER/kazeshini/internal/resource"
	"github.com/OWNER/kazeshini/internal/state"
)

// Mode controls loop behavior: "observe" (drift only) or "plan" (drift + plan).
type Mode string

const (
	ModeObserve Mode = "observe"
	ModePlan    Mode = "plan"
)

// Config configures loop intervals, jitter, and execution mode.
type Config struct {
	Mode        Mode          `json:"mode"`
	Interval    time.Duration `json:"interval"`
	MaxJitter   time.Duration `json:"max_jitter"`
	DesiredPath string        `json:"desired_path"`
	LabelsPath  string        `json:"labels_path"`
}

// Loop runs periodic level-triggered reconciliation.
type Loop struct {
	mu           sync.RWMutex
	cfg          Config
	driftEngine  *drift.Engine
	planner      *plan.Planner
	policyEngine *policy.Engine
	bus          *events.Bus
	store        state.Store
	logger       *slog.Logger

	lastDrift    []drift.Item
	lastPlan     *plan.Plan
	lastDecision *policy.EvaluationResult
	lastRun      time.Time
}

// NewLoop creates a new reconciliation loop coordinator.
func NewLoop(
	cfg Config,
	driftEngine *drift.Engine,
	planner *plan.Planner,
	policyEngine *policy.Engine,
	bus *events.Bus,
	st state.Store,
	logger *slog.Logger,
) *Loop {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.MaxJitter <= 0 {
		cfg.MaxJitter = 5 * time.Second
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeObserve
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Loop{
		cfg:          cfg,
		driftEngine:  driftEngine,
		planner:      planner,
		policyEngine: policyEngine,
		bus:          bus,
		store:        st,
		logger:       logger,
	}
}

// ReconcileOnce performs a single pass of observe -> compare -> plan.
func (l *Loop) ReconcileOnce(
	ctx context.Context,
	nodes []graph.Node,
	cov coverage.Report,
) ([]drift.Item, *plan.Plan, *policy.EvaluationResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.lastRun = time.Now().UTC()

	// 1. Load desired state manifest
	if l.cfg.DesiredPath == "" {
		return nil, nil, nil, nil
	}
	manifest, err := desired.LoadFile(l.cfg.DesiredPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("desired manifest load error: %w", err)
	}

	labels, _ := desired.LoadHostLabels(l.cfg.LabelsPath)
	desiredState := manifest.ForHost(labels)

	// 2. Map observed graph nodes to unified Resource model
	resources := make([]resource.Resource, len(nodes))
	for i, n := range nodes {
		resources[i] = resource.FromGraphNode(n)
	}

	// 3. Compare (Drift Engine)
	driftItems, _ := l.driftEngine.Evaluate(ctx, desiredState, resources, cov)
	l.lastDrift = driftItems

	// Checkpoint drift items in store
	if l.store != nil {
		_ = l.store.SaveDrift(ctx, driftItems)
	}

	// Publish drift event to bus
	if l.bus != nil && len(driftItems) > 0 {
		_ = l.bus.Publish(ctx, events.Event{
			ID:        fmt.Sprintf("drift-%d", time.Now().UnixNano()),
			Type:      events.TypeState,
			Timestamp: time.Now().UTC(),
			Payload:   driftItems,
		})
	}

	// In observe mode, stop at drift
	if l.cfg.Mode == ModeObserve || len(driftItems) == 0 {
		l.lastPlan = nil
		l.lastDecision = nil
		return driftItems, nil, nil, nil
	}

	// 4. Plan (Planner DAG)
	p, err := l.planner.CreatePlan(driftItems)
	if err != nil {
		return driftItems, nil, nil, fmt.Errorf("plan generation failed: %w", err)
	}
	l.lastPlan = p

	// 5. Policy Check
	decision := l.policyEngine.EvaluatePlan(ctx, p)
	l.lastDecision = &decision

	// Checkpoint plan in store
	if l.store != nil {
		_ = l.store.SavePlan(ctx, *p)
	}

	// Publish plan event to bus
	if l.bus != nil {
		_ = l.bus.Publish(ctx, events.Event{
			ID:        fmt.Sprintf("plan-%s", p.ID),
			Type:      events.TypeState,
			Timestamp: time.Now().UTC(),
			Payload:   p,
		})
	}

	return driftItems, p, &decision, nil
}

// LastStatus returns the most recent evaluation outcomes.
func (l *Loop) LastStatus() ([]drift.Item, *plan.Plan, *policy.EvaluationResult, time.Time) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastDrift, l.lastPlan, l.lastDecision, l.lastRun
}

// NextInterval calculates jittered sleep duration.
func (l *Loop) NextInterval() time.Duration {
	if l.cfg.MaxJitter <= 0 {
		return l.cfg.Interval
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(l.cfg.MaxJitter)))
	if err != nil {
		return l.cfg.Interval
	}
	return l.cfg.Interval + time.Duration(n.Int64())
}
