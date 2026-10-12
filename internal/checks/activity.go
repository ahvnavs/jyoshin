// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	DefaultActivityLogFile = "activity.log"
	MaxActivityLogBytes    = 2 * 1024 * 1024 // 2 MB size cap
	MaxActivityEntries     = 1000
)

// ActivityLog manages an append-only local activity log.
// Security note: Local audit file; not tamper-proof against root or compromised host.
type ActivityLog struct {
	mu       sync.Mutex
	filePath string
}

// NewActivityLog initializes an activity logger storing entries in logDir/activity.log with 0600 permissions.
func NewActivityLog(logDir string) *ActivityLog {
	if logDir == "" {
		logDir = os.TempDir()
	}
	return &ActivityLog{
		filePath: filepath.Join(logDir, DefaultActivityLogFile),
	}
}

// Log records a new check execution entry.
func (a *ActivityLog) Log(entry ActivityEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Check size cap; rotate/truncate if exceeding 2 MB
	if fi, err := os.Stat(a.filePath); err == nil && fi.Size()+int64(len(data)) > MaxActivityLogBytes {
		// Truncate to keep the most recent entries
		_ = os.WriteFile(a.filePath, []byte{}, 0600)
	}

	f, err := os.OpenFile(a.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

// Entries returns up to limit recent activity entries (most recent first).
func (a *ActivityLog) Entries(limit int) ([]ActivityEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if limit <= 0 || limit > MaxActivityEntries {
		limit = MaxActivityEntries
	}

	data, err := os.ReadFile(a.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []ActivityEntry{}, nil
		}
		return nil, err
	}

	var all []ActivityEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry ActivityEntry
		if err := json.Unmarshal(line, &entry); err == nil {
			all = append(all, entry)
		}
	}

	// Reverse order for most recent first
	n := len(all)
	res := make([]ActivityEntry, 0, n)
	for i := n - 1; i >= 0; i-- {
		res = append(res, all[i])
		if len(res) >= limit {
			break
		}
	}
	return res, nil
}
