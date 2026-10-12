// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"errors"
	"sync"

	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/rules"
)

// MemoryStore implements a strictly zero-disk, zero-write Store.
// Adheres strictly to Principle 15 (STATELESS BY DEFAULT).
type MemoryStore struct {
	mu           sync.RWMutex
	maxSnapshots int
	snapshots    []Snapshot
	findings     []rules.Finding
	samples      map[string][]forecast.Sample
	activities   []ActivityEntry
	drifts       [][]drift.Item
	plans        []plan.Plan
}

// NewMemoryStore creates a pure in-memory store.
func NewMemoryStore(maxSnapshots int) *MemoryStore {
	if maxSnapshots <= 0 {
		maxSnapshots = 100
	}
	return &MemoryStore{
		maxSnapshots: maxSnapshots,
		samples:      make(map[string][]forecast.Sample),
	}
}

func (m *MemoryStore) IsPersistent() bool {
	return false
}

func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshots = nil
	m.findings = nil
	m.samples = nil
	m.activities = nil
	return nil
}

func (m *MemoryStore) SaveSnapshot(ctx context.Context, snap Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshots = append(m.snapshots, snap)
	if len(m.snapshots) > m.maxSnapshots {
		m.snapshots = m.snapshots[1:]
	}
	return nil
}

func (m *MemoryStore) GetLatestSnapshot(ctx context.Context) (*Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.snapshots) == 0 {
		return nil, errors.New("no snapshots available")
	}
	latest := m.snapshots[len(m.snapshots)-1]
	return &latest, nil
}

func (m *MemoryStore) ListSnapshots(ctx context.Context, limit int) ([]Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.snapshots)
	if limit <= 0 || limit > n {
		limit = n
	}
	res := make([]Snapshot, limit)
	copy(res, m.snapshots[n-limit:])
	return res, nil
}

func (m *MemoryStore) SaveFindings(ctx context.Context, findings []rules.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = append(m.findings, findings...)
	if len(m.findings) > 500 {
		m.findings = m.findings[len(m.findings)-500:]
	}
	return nil
}

func (m *MemoryStore) ListFindings(ctx context.Context, category rules.Category, limit int) ([]rules.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []rules.Finding
	for i := len(m.findings) - 1; i >= 0; i-- {
		f := m.findings[i]
		if category == "" || f.Category == category {
			res = append(res, f)
		}
		if limit > 0 && len(res) >= limit {
			break
		}
	}
	return res, nil
}

func (m *MemoryStore) SaveSample(ctx context.Context, target string, sample forecast.Sample) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.samples[target]
	list = append(list, sample)
	if len(list) > 1000 {
		list = list[1:]
	}
	m.samples[target] = list
	return nil
}

func (m *MemoryStore) ListSamples(ctx context.Context, target string, limit int) ([]forecast.Sample, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list, ok := m.samples[target]
	if !ok || len(list) == 0 {
		return nil, nil
	}
	n := len(list)
	if limit <= 0 || limit > n {
		limit = n
	}
	res := make([]forecast.Sample, limit)
	copy(res, list[n-limit:])
	return res, nil
}

func (m *MemoryStore) SaveActivity(ctx context.Context, entry ActivityEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activities = append(m.activities, entry)
	if len(m.activities) > 1000 {
		m.activities = m.activities[1:]
	}
	return nil
}

func (m *MemoryStore) ListActivity(ctx context.Context, limit int) ([]ActivityEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.activities)
	if limit <= 0 || limit > n {
		limit = n
	}
	res := make([]ActivityEntry, 0, limit)
	for i := n - 1; i >= 0 && len(res) < limit; i-- {
		res = append(res, m.activities[i])
	}
	return res, nil
}

func (m *MemoryStore) SaveDrift(ctx context.Context, driftItems []drift.Item) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drifts = append(m.drifts, driftItems)
	if len(m.drifts) > 100 {
		m.drifts = m.drifts[1:]
	}
	return nil
}

func (m *MemoryStore) ListDrift(ctx context.Context, limit int) ([][]drift.Item, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.drifts)
	if limit <= 0 || limit > n {
		limit = n
	}
	res := make([][]drift.Item, 0, limit)
	for i := n - 1; i >= 0 && len(res) < limit; i-- {
		res = append(res, m.drifts[i])
	}
	return res, nil
}

func (m *MemoryStore) SavePlan(ctx context.Context, p plan.Plan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plans = append(m.plans, p)
	if len(m.plans) > 50 {
		m.plans = m.plans[1:]
	}
	return nil
}

func (m *MemoryStore) ListPlans(ctx context.Context, limit int) ([]plan.Plan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.plans)
	if limit <= 0 || limit > n {
		limit = n
	}
	res := make([]plan.Plan, 0, limit)
	for i := n - 1; i >= 0 && len(res) < limit; i-- {
		res = append(res, m.plans[i])
	}
	return res, nil
}

