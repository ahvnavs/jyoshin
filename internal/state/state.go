// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package state defines the pluggable Store interface and providers:
// Memory (default), File (atomic JSON), and Bolt.
package state

import (
	"context"
	"time"

	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/rules"
)

// ActivityEntry models a check run audit record.
type ActivityEntry struct {
	Timestamp time.Time `json:"timestamp"`
	CheckID   string    `json:"check_id"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	Summary   string    `json:"summary"`
	Duration  string    `json:"duration"`
}

// Snapshot represents a full point-in-time capture of the server provenance graph.
type Snapshot struct {
	ID        string       `json:"id"`
	Timestamp time.Time    `json:"timestamp"`
	Nodes     []graph.Node `json:"nodes"`
	Edges     []graph.Edge `json:"edges"`
}

// Store defines persistence operations for local server truth, findings, samples, and activity.
type Store interface {
	SaveSnapshot(ctx context.Context, snap Snapshot) error
	GetLatestSnapshot(ctx context.Context) (*Snapshot, error)
	ListSnapshots(ctx context.Context, limit int) ([]Snapshot, error)

	SaveFindings(ctx context.Context, findings []rules.Finding) error
	ListFindings(ctx context.Context, category rules.Category, limit int) ([]rules.Finding, error)

	SaveSample(ctx context.Context, target string, sample forecast.Sample) error
	ListSamples(ctx context.Context, target string, limit int) ([]forecast.Sample, error)

	SaveActivity(ctx context.Context, entry ActivityEntry) error
	ListActivity(ctx context.Context, limit int) ([]ActivityEntry, error)

	SaveDrift(ctx context.Context, driftItems []drift.Item) error
	ListDrift(ctx context.Context, limit int) ([][]drift.Item, error)

	SavePlan(ctx context.Context, p plan.Plan) error
	ListPlans(ctx context.Context, limit int) ([]plan.Plan, error)

	// IsPersistent returns false for pure in-memory stores and true for durable stores.
	IsPersistent() bool

	Close() error
}

