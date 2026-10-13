// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package actuator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditRecord represents one executed step or action in the hash chain.
type AuditRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	PlanID     string    `json:"plan_id"`
	PlanHash   string    `json:"plan_hash"`
	Approver   string    `json:"approver"`
	Nonce      string    `json:"nonce"`
	StepIndex  int       `json:"step_index"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	Argv       []string  `json:"argv"`
	ExitCode   int       `json:"exit_code"`
	DurationMs int64     `json:"duration_ms"`
	Status     string    `json:"status"` // "SUCCEEDED", "FAILED", "UNCERTAIN", "SKIPPED", "ABORTED"
	OutputTail string    `json:"output_tail,omitempty"`
	PrevHash   string    `json:"prev_hash"`
	EntryHash  string    `json:"entry_hash"`
}

// ComputeHash calculates the SHA-256 over record content and its PrevHash.
func (r *AuditRecord) ComputeHash() string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s|%s|%v|%d|%d|%s|%s",
		r.Timestamp.Format(time.RFC3339Nano),
		r.PlanID,
		r.PlanHash,
		r.Approver,
		r.Nonce,
		r.StepIndex,
		r.Action,
		r.Target,
		r.Argv,
		r.ExitCode,
		r.DurationMs,
		r.Status,
		r.PrevHash,
	)
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

// AuditLogger records append-only hash-chained JSON Lines audit events.
type AuditLogger struct {
	mu       sync.Mutex
	path     string
	lastHash string
	file     *os.File
}

// NewAuditLogger opens or initializes the hash-chained audit log file.
func NewAuditLogger(path string) (*AuditLogger, error) {
	if path == "" {
		return &AuditLogger{lastHash: "genesis"}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating audit dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	al := &AuditLogger{
		path:     path,
		file:     f,
		lastHash: "genesis",
	}

	// Read existing log to establish lastHash
	if err := al.recoverLastHash(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("recovering audit chain hash: %w", err)
	}

	return al, nil
}

func (al *AuditLogger) recoverLastHash() error {
	if al.file == nil {
		return nil
	}
	_, err := al.file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(al.file)
	for decoder.More() {
		var rec AuditRecord
		if err := decoder.Decode(&rec); err != nil {
			break
		}
		al.lastHash = rec.EntryHash
	}

	// Seek to end for future appends
	_, err = al.file.Seek(0, io.SeekEnd)
	return err
}

// LogStep commits an execution record to the audit chain.
func (al *AuditLogger) LogStep(rec AuditRecord) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	rec.PrevHash = al.lastHash
	rec.EntryHash = rec.ComputeHash()
	al.lastHash = rec.EntryHash

	if al.file == nil {
		return nil
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := al.file.Write(data); err != nil {
		return err
	}
	return al.file.Sync()
}

// VerifyAuditChain inspects an audit log file and validates cryptographic integrity.
func VerifyAuditChain(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	expectedPrev := "genesis"
	count := 0

	for decoder.More() {
		var rec AuditRecord
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

