//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package actuator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NonceStore guards against replay attacks by tracking all seen nonces.
type NonceStore struct {
	mu       sync.Mutex
	path     string
	seen     map[string]time.Time
	maxAge   time.Duration
}

// NewNonceStore creates or loads a persistent nonce cache.
func NewNonceStore(path string, maxAge time.Duration) (*NonceStore, error) {
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	ns := &NonceStore{
		path:   path,
		seen:   make(map[string]time.Time),
		maxAge: maxAge,
	}
	if path != "" {
		if err := ns.load(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading nonce cache: %w", err)
		}
	}
	return ns, nil
}

// CheckAndRecord asserts the nonce has never been seen, then commits it.
func (ns *NonceStore) CheckAndRecord(nonce string, now time.Time) error {
	if nonce == "" {
		return fmt.Errorf("empty nonce provided")
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Evict expired entries
	cutoff := now.Add(-ns.maxAge)
	for k, t := range ns.seen {
		if t.Before(cutoff) {
			delete(ns.seen, k)
		}
	}

	if _, exists := ns.seen[nonce]; exists {
		return fmt.Errorf("replay rejected: nonce %q was already executed", nonce)
	}

	ns.seen[nonce] = now
	return ns.save()
}

func (ns *NonceStore) load() error {
	data, err := os.ReadFile(ns.path)
	if err != nil {
		return err
	}
	var raw map[string]int64
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, sec := range raw {
		ns.seen[k] = time.Unix(sec, 0)
	}
	return nil
}

func (ns *NonceStore) save() error {
	if ns.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(ns.path), 0700); err != nil {
		return err
	}
	raw := make(map[string]int64, len(ns.seen))
	for k, t := range ns.seen {
		raw[k] = t.Unix()
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(ns.path, data, 0600)
}

