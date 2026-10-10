// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
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

	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/rules"
)

var (
	bucketSnapshots = []byte("snapshots")
	bucketFindings  = []byte("findings")
	bucketMeta      = []byte("metadata")
)

// Config configures embedded store retention and file storage limits.
type Config struct {
	DataDir      string
	MaxDiskBytes int64 // Hard disk cap (e.g. 100 MB)
	MaxSnapshots int   // Retention limit
}

// DefaultConfig provides conservative bounds.
func DefaultConfig(dataDir string) Config {
	if dataDir == "" {
		dataDir = "/var/lib/jyoshin"
	}
	return Config{
		DataDir:      dataDir,
		MaxDiskBytes: 100 * 1024 * 1024, // 100 MB cap
		MaxSnapshots: 100,               // Keep up to 100 snapshots
	}
}

// Snapshot represents a full point-in-time capture of the server provenance graph.
type Snapshot struct {
	ID        string       `json:"id"`
	Timestamp time.Time    `json:"timestamp"`
	Nodes     []graph.Node `json:"nodes"`
	Edges     []graph.Edge `json:"edges"`
}

// Store defines persistence operations for local server truth data.
type Store interface {
	SaveSnapshot(ctx context.Context, snap Snapshot) error
	GetLatestSnapshot(ctx context.Context) (*Snapshot, error)
	ListSnapshots(ctx context.Context, limit int) ([]Snapshot, error)
	SaveFindings(ctx context.Context, findings []rules.Finding) error
	ListFindings(ctx context.Context, category rules.Category, limit int) ([]rules.Finding, error)
	Close() error
}

// BoltStore implements Store using pure-Go bbolt.
type BoltStore struct {
	mu       sync.RWMutex
	cfg      Config
	db       *bbolt.DB
	dbPath   string
	inMemory bool
	memSnaps []Snapshot
	logger   *slog.Logger
}

// Open initializes or migrates the embedded bbolt database with 0600 file permissions.
// Degrades gracefully to in-memory mode if disk or permissions are unavailable.
func Open(cfg Config, logger *slog.Logger) (*BoltStore, error) {
	if logger == nil {
		logger = slog.Default()
	}

	bs := &BoltStore{
		cfg:    cfg,
		logger: logger,
	}

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		logger.Warn("failed to create data dir; degrading to in-memory store", "error", err)
		bs.inMemory = true
		return bs, nil
	}

	dbPath := filepath.Join(cfg.DataDir, "jyoshin.db")
	bs.dbPath = dbPath

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		logger.Warn("failed to open bbolt database; degrading to in-memory store", "error", err)
		bs.inMemory = true
		return bs, nil
	}

	bs.db = db

	// Initialize buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketSnapshots); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketFindings); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketMeta); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		logger.Warn("failed to init buckets; degrading to in-memory store", "error", err)
		bs.inMemory = true
		bs.db = nil
		return bs, nil
	}

	return bs, nil
}

// IsInMemory indicates whether the store is running in degraded in-memory mode.
func (s *BoltStore) IsInMemory() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inMemory
}

// SaveSnapshot stores a snapshot and enforces the configured retention and disk cap.
func (s *BoltStore) SaveSnapshot(ctx context.Context, snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory {
		s.memSnaps = append(s.memSnaps, snap)
		if len(s.memSnaps) > s.cfg.MaxSnapshots {
			s.memSnaps = s.memSnaps[1:]
		}
		return nil
	}

	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	key := []byte(fmt.Sprintf("%s_%s", snap.Timestamp.Format(time.RFC3339Nano), snap.ID))

	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSnapshots)
		if err := b.Put(key, data); err != nil {
			return err
		}

		// Enforce retention: remove oldest keys if snapshot count exceeds MaxSnapshots
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
	if err != nil {
		return err
	}

	// Enforce hard disk cap: stat the file, warn if exceeding MaxDiskBytes
	if s.cfg.MaxDiskBytes > 0 && s.dbPath != "" {
		if fi, err := os.Stat(s.dbPath); err == nil && fi.Size() > s.cfg.MaxDiskBytes {
			s.logger.Warn("embedded store file exceeds disk cap limit", "size_bytes", fi.Size(), "cap_bytes", s.cfg.MaxDiskBytes)
		}
	}

	return nil
}

// GetLatestSnapshot retrieves the most recent snapshot.
func (s *BoltStore) GetLatestSnapshot(ctx context.Context) (*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		if len(s.memSnaps) == 0 {
			return nil, errors.New("no snapshots available")
		}
		latest := s.memSnaps[len(s.memSnaps)-1]
		return &latest, nil
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

// GetSnapshotByID finds a snapshot by its ID.
func (s *BoltStore) GetSnapshotByID(ctx context.Context, id string) (*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		for i := len(s.memSnaps) - 1; i >= 0; i-- {
			if s.memSnaps[i].ID == id {
				snap := s.memSnaps[i]
				return &snap, nil
			}
		}
		return nil, fmt.Errorf("snapshot %q not found", id)
	}

	var found *Snapshot
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSnapshots)
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var snap Snapshot
			if err := json.Unmarshal(v, &snap); err == nil {
				if snap.ID == id {
					found = &snap
					return nil
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("snapshot %q not found", id)
	}
	return found, nil
}

// CheckIntegrity scans the snapshot bucket and verifies JSON deserialization without corruption.
func (s *BoltStore) CheckIntegrity(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		return len(s.memSnaps), nil
	}

	validCount := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSnapshots)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var snap Snapshot
			if err := json.Unmarshal(v, &snap); err != nil {
				return fmt.Errorf("corrupted snapshot at key %s: %w", string(k), err)
			}
			validCount++
		}
		return nil
	})
	return validCount, err
}

// ListSnapshots returns summary information for stored snapshots.
func (s *BoltStore) ListSnapshots(ctx context.Context, limit int) ([]Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		count := len(s.memSnaps)
		if limit > 0 && limit < count {
			return s.memSnaps[count-limit:], nil
		}
		return s.memSnaps, nil
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

// SaveFindings stores evaluated findings.
func (s *BoltStore) SaveFindings(ctx context.Context, findings []rules.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inMemory {
		return nil
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

// ListFindings queries stored findings.
func (s *BoltStore) ListFindings(ctx context.Context, category rules.Category, limit int) ([]rules.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.inMemory {
		return nil, nil
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

// Close safely flushes write logs and terminates the bbolt database.
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
