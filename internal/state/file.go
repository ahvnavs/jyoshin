// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/rules"
)

// FileStore persists state to a single structured JSON file via atomic write (temp + rename).
type FileStore struct {
	mu       sync.RWMutex
	filePath string
	mem      *MemoryStore
}

type filePayload struct {
	Snapshots  []Snapshot                   `json:"snapshots"`
	Findings   []rules.Finding              `json:"findings"`
	Samples    map[string][]forecast.Sample `json:"samples"`
	Activities []ActivityEntry              `json:"activities"`
	Drifts     [][]drift.Item               `json:"drifts"`
	Plans      []plan.Plan                  `json:"plans"`
}

// NewFileStore creates or opens an atomic file store.
func NewFileStore(filePath string, maxSnapshots int) (*FileStore, error) {
	if filePath == "" {
		return nil, errors.New("file path required")
	}

	fs := &FileStore{
		filePath: filePath,
		mem:      NewMemoryStore(maxSnapshots),
	}

	// Load existing file if present
	if data, err := os.ReadFile(filePath); err == nil && len(data) > 0 {
		var payload filePayload
		if err := json.Unmarshal(data, &payload); err == nil {
			fs.mem.snapshots = payload.Snapshots
			fs.mem.findings = payload.Findings
			if payload.Samples != nil {
				fs.mem.samples = payload.Samples
			}
			fs.mem.activities = payload.Activities
		}
	}

	return fs, nil
}

func (f *FileStore) IsPersistent() bool {
	return true
}

func (f *FileStore) persistLocked() error {
	payload := filePayload{
		Snapshots:  f.mem.snapshots,
		Findings:   f.mem.findings,
		Samples:    f.mem.samples,
		Activities: f.mem.activities,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(f.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", f.filePath, os.Getpid())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, f.filePath)
}

func (f *FileStore) SaveSnapshot(ctx context.Context, snap Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mem.SaveSnapshot(ctx, snap); err != nil {
		return err
	}
	return f.persistLocked()
}

func (f *FileStore) GetLatestSnapshot(ctx context.Context) (*Snapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mem.GetLatestSnapshot(ctx)
}

func (f *FileStore) ListSnapshots(ctx context.Context, limit int) ([]Snapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mem.ListSnapshots(ctx, limit)
}

func (f *FileStore) SaveFindings(ctx context.Context, findings []rules.Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mem.SaveFindings(ctx, findings); err != nil {
		return err
	}
	return f.persistLocked()
}

func (f *FileStore) ListFindings(ctx context.Context, category rules.Category, limit int) ([]rules.Finding, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mem.ListFindings(ctx, category, limit)
}

func (f *FileStore) SaveSample(ctx context.Context, target string, sample forecast.Sample) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mem.SaveSample(ctx, target, sample); err != nil {
		return err
	}
	return f.persistLocked()
}

func (f *FileStore) ListSamples(ctx context.Context, target string, limit int) ([]forecast.Sample, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mem.ListSamples(ctx, target, limit)
}

func (f *FileStore) SaveActivity(ctx context.Context, entry ActivityEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mem.SaveActivity(ctx, entry); err != nil {
		return err
	}
	return f.persistLocked()
}

func (f *FileStore) ListActivity(ctx context.Context, limit int) ([]ActivityEntry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mem.ListActivity(ctx, limit)
}

func (f *FileStore) SaveDrift(ctx context.Context, driftItems []drift.Item) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mem.SaveDrift(ctx, driftItems); err != nil {
		return err
	}
	return f.persistLocked()
}

func (f *FileStore) ListDrift(ctx context.Context, limit int) ([][]drift.Item, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mem.ListDrift(ctx, limit)
}

func (f *FileStore) SavePlan(ctx context.Context, p plan.Plan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mem.SavePlan(ctx, p); err != nil {
		return err
	}
	return f.persistLocked()
}

func (f *FileStore) ListPlans(ctx context.Context, limit int) ([]plan.Plan, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mem.ListPlans(ctx, limit)
}

func (f *FileStore) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.persistLocked()
	return f.mem.Close()
}

