// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/rbac"
)

// RequestRecord captures one authenticated API request in the hash chain.
type RequestRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	CallerID   string    `json:"caller_id"`
	Role       string    `json:"role"`
	Method     string    `json:"method"`
	Route      string    `json:"route"`
	RemoteIP   string    `json:"remote_ip"`
	Status     int       `json:"status"`
	Target     string    `json:"target,omitempty"`
	PlanID     string    `json:"plan_id,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	PrevHash   string    `json:"prev_hash"`
	EntryHash  string    `json:"entry_hash"`
}

// ComputeHash calculates the cryptographic SHA-256 digest over the entry.
func (r *RequestRecord) ComputeHash() string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%s|%s|%d|%s",
		r.Timestamp.Format(time.RFC3339Nano),
		r.CallerID,
		r.Role,
		r.Method,
		r.Route,
		r.RemoteIP,
		r.Status,
		r.Target,
		r.PlanID,
		r.DurationMs,
		r.PrevHash,
	)
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

// RequestLogger maintains an append-only, hash-chained log of API calls.
type RequestLogger struct {
	mu       sync.Mutex
	path     string
	lastHash string
	file     *os.File
}

// NewRequestLogger opens or initializes the audit log file.
func NewRequestLogger(path string) (*RequestLogger, error) {
	if path == "" {
		return &RequestLogger{lastHash: "genesis"}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating audit dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	rl := &RequestLogger{
		path:     path,
		file:     f,
		lastHash: "genesis",
	}

	if err := rl.recoverLastHash(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("recovering audit chain hash: %w", err)
	}

	return rl, nil
}

func (rl *RequestLogger) recoverLastHash() error {
	if rl.file == nil {
		return nil
	}
	_, err := rl.file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(rl.file)
	for decoder.More() {
		var rec RequestRecord
		if err := decoder.Decode(&rec); err != nil {
			break
		}
		rl.lastHash = rec.EntryHash
	}

	_, err = rl.file.Seek(0, io.SeekEnd)
	return err
}

// LogRequest records an API request, skipping health probes.
func (rl *RequestLogger) LogRequest(sub rbac.Subject, r *http.Request, status int, dur time.Duration, target, planID string) error {
	// Skip health/liveness probes from generating noise
	if r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/version" {
		return nil
	}

	remoteIP := r.RemoteAddr
	if host, _, err := strings.Cut(r.RemoteAddr, ":"); err {
		remoteIP = host
	}

	callerID := sub.ID
	if callerID == "" {
		callerID = "anonymous"
	}
	roleStr := string(sub.Role)
	if roleStr == "" {
		roleStr = "unauthenticated"
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec := RequestRecord{
		Timestamp:  time.Now().UTC(),
		CallerID:   callerID,
		Role:       roleStr,
		Method:     r.Method,
		Route:      r.URL.Path,
		RemoteIP:   remoteIP,
		Status:     status,
		Target:     target,
		PlanID:     planID,
		DurationMs: dur.Milliseconds(),
		PrevHash:   rl.lastHash,
	}

	rec.EntryHash = rec.ComputeHash()
	rl.lastHash = rec.EntryHash

	if rl.file == nil {
		return nil
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := rl.file.Write(data); err != nil {
		return err
	}
	return rl.file.Sync()
}

// VerifyChain checks cryptographic integrity of the API request audit log.
func VerifyChain(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	decoder := json.NewDecoder(f)
	expectedPrev := "genesis"
	count := 0

	for decoder.More() {
		var rec RequestRecord
		if err := decoder.Decode(&rec); err != nil {
			return count, fmt.Errorf("record %d decode error: %w", count+1, err)
		}
		count++

		if rec.PrevHash != expectedPrev {
			return count, fmt.Errorf("chain broken at record %d: expected prev_hash %s, got %s", count, expectedPrev, rec.PrevHash)
		}

		computed := rec.ComputeHash()
		if rec.EntryHash != computed {
			return count, fmt.Errorf("tamper detected at record %d: hash mismatch (stored %s, computed %s)", count, rec.EntryHash, computed)
		}

		expectedPrev = rec.EntryHash
	}

	return count, nil
}
