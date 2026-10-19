// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	bbolt "go.etcd.io/bbolt"

	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/rules"
)

var (
	bucketSnapshots  = []byte("snapshots")
	bucketFindings   = []byte("findings")
	bucketSamples    = []byte("samples")
	bucketActivities = []byte("activities")
	bucketDrifts     = []byte("drifts")
	bucketPlans      = []byte("plans")
	bucketMeta       = []byte("metadata")
)

// BoltConfig configures embedded store retention and file storage limits.
type BoltConfig struct {
	DataDir      string
	MaxDiskBytes int64
	MaxSnapshots int
}

// BoltStore implements Store using embedded pure-Go bbolt.
type BoltStore struct {
	mu       sync.RWMutex
	cfg      BoltConfig
	db       *bbolt.DB
	dbPath   string
	inMemory bool
	mem      *MemoryStore
	logger   *slog.Logger
}

// NewBoltStore initializes or migrates the embedded bbolt database with 0600 file permissions.
func NewBoltStore(cfg BoltConfig, logger *slog.Logger) (*BoltStore, error) {
	if logger == nil {
		logger = slog.Default()
	}

	bs := &BoltStore{
		cfg:    cfg,
		logger: logger,
		mem:    NewMemoryStore(cfg.MaxSnapshots),
	}

	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/kazeshini"
	}

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		logger.Warn("failed to create data dir; degrading to in-memory store", "error", err)
		bs.inMemory = true
		return bs, nil
	}

	dbPath := filepath.Join(cfg.DataDir, "kazeshini.db")
	bs.dbPath = dbPath

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		logger.Warn("failed to open bbolt database; degrading to in-memory store", "error", err)
		bs.inMemory = true
		return bs, nil
	}

	bs.db = db

	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketSnapshots, bucketFindings, bucketSamples, bucketActivities, bucketDrifts, bucketPlans, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		bs.inMemory = true
		bs.db = nil
		return bs, nil
	}

	return bs, nil
}

func (s *BoltStore) IsPersistent() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.inMemory
}

func (s *BoltStore) SaveSnapshot(ctx context.Context, snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory {
		return s.mem.SaveSnapshot(ctx, snap)
	}

	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	key := []byte(fmt.Sprintf("%s_%s", snap.Timestamp.Format(time.RFC3339Nano), snap.ID))

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSnapshots)
		if err := b.Put(key, data); err != nil {
			return err
		}

		c := b.Cursor()
		count := 0
		var keysToDelete [][]byte
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			count++
		}
		if count > s.cfg.MaxSnapshots {
			excess := count - s.cfg.MaxSnapshots
			for k, _ := c.First(); k != nil && excess > 0; k, _ = c.Next() {
				keysToDelete = append(keysToDelete, append([]byte{}, k...))
				excess--
			}
			for _, k := range keysToDelete {
				_ = b.Delete(k)
			}
		}
		return nil
	})
}

func (s *BoltStore) GetLatestSnapshot(ctx context.Context) (*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		return s.mem.GetLatestSnapshot(ctx)
	}

	var latest Snapshot
	found := false

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSnapshots)
		c := b.Cursor()
		k, v := c.Last()
		if k == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &latest)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no snapshots available")
	}

	return &latest, nil
}

func (s *BoltStore) ListSnapshots(ctx context.Context, limit int) ([]Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		return s.mem.ListSnapshots(ctx, limit)
	}

	var list []Snapshot
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSnapshots)
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var snap Snapshot
			if err := json.Unmarshal(v, &snap); err == nil {
				list = append(list, snap)
			}
			if limit > 0 && len(list) >= limit {
				break
			}
		}
		return nil
	})

	return list, err
}

func (s *BoltStore) SaveFindings(ctx context.Context, findings []rules.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory {
		return s.mem.SaveFindings(ctx, findings)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketFindings)
		for _, f := range findings {
			data, err := json.Marshal(f)
			if err != nil {
				continue
			}
			key := []byte(fmt.Sprintf("%s_%s", f.FirstSeen.Format(time.RFC3339Nano), f.ID))
			_ = b.Put(key, data)
		}
		return nil
	})
}

func (s *BoltStore) ListFindings(ctx context.Context, category rules.Category, limit int) ([]rules.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		return s.mem.ListFindings(ctx, category, limit)
	}

	var list []rules.Finding
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketFindings)
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var f rules.Finding
			if err := json.Unmarshal(v, &f); err == nil {
				if category == "" || f.Category == category {
					list = append(list, f)
				}
			}
			if limit > 0 && len(list) >= limit {
				break
			}
		}
		return nil
	})

	return list, err
}

func (s *BoltStore) SaveSample(ctx context.Context, target string, sample forecast.Sample) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory || s.db == nil {
		return s.mem.SaveSample(ctx, target, sample)
	}

	key := fmt.Sprintf("%s:%020d", target, sample.Timestamp.UnixNano())
	data, err := json.Marshal(sample)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSamples)
		if b == nil {
			return nil
		}
		return b.Put([]byte(key), data)
	})
}

func (s *BoltStore) ListSamples(ctx context.Context, target string, limit int) ([]forecast.Sample, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory || s.db == nil {
		return s.mem.ListSamples(ctx, target, limit)
	}

	var samples []forecast.Sample
	prefix := []byte(target + ":")

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSamples)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var smp forecast.Sample
			if err := json.Unmarshal(v, &smp); err == nil {
				samples = append(samples, smp)
			}
			if limit > 0 && len(samples) >= limit {
				break
			}
		}
		return nil
	})

	return samples, err
}

func (s *BoltStore) SaveActivity(ctx context.Context, entry ActivityEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory || s.db == nil {
		return s.mem.SaveActivity(ctx, entry)
	}

	key := fmt.Sprintf("%020d_%s", entry.Timestamp.UnixNano(), entry.CheckID)
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketActivities)
		if b == nil {
			return nil
		}
		return b.Put([]byte(key), data)
	})
}

func (s *BoltStore) ListActivity(ctx context.Context, limit int) ([]ActivityEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory || s.db == nil {
		return s.mem.ListActivity(ctx, limit)
	}

	var list []ActivityEntry
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketActivities)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var ent ActivityEntry
			if err := json.Unmarshal(v, &ent); err == nil {
				list = append(list, ent)
			}
			if limit > 0 && len(list) >= limit {
				break
			}
		}
		return nil
	})

	return list, err
}

func (s *BoltStore) SaveDrift(ctx context.Context, driftItems []drift.Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory || s.db == nil {
		return s.mem.SaveDrift(ctx, driftItems)
	}

	key := fmt.Sprintf("%020d", time.Now().UnixNano())
	data, err := json.Marshal(driftItems)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketDrifts)
		if b == nil {
			return nil
		}
		return b.Put([]byte(key), data)
	})
}

func (s *BoltStore) ListDrift(ctx context.Context, limit int) ([][]drift.Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory || s.db == nil {
		return s.mem.ListDrift(ctx, limit)
	}

	var list [][]drift.Item
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketDrifts)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var d []drift.Item
			if err := json.Unmarshal(v, &d); err == nil {
				list = append(list, d)
			}
			if limit > 0 && len(list) >= limit {
				break
			}
		}
		return nil
	})

	return list, err
}

func (s *BoltStore) SavePlan(ctx context.Context, p plan.Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory || s.db == nil {
		return s.mem.SavePlan(ctx, p)
	}

	key := fmt.Sprintf("%020d_%s", p.CreatedAt.UnixNano(), p.ID)
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketPlans)
		if b == nil {
			return nil
		}
		return b.Put([]byte(key), data)
	})
}

func (s *BoltStore) ListPlans(ctx context.Context, limit int) ([]plan.Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory || s.db == nil {
		return s.mem.ListPlans(ctx, limit)
	}

	var list []plan.Plan
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketPlans)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var p plan.Plan
			if err := json.Unmarshal(v, &p); err == nil {
				list = append(list, p)
			}
			if limit > 0 && len(list) >= limit {
				break
			}
		}
		return nil
	})

	return list, err
}

func (s *BoltStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}
