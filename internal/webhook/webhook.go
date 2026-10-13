// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package webhook implements secure, HMAC-signed, retry-capable webhook dispatch
// for findings and drift events. Webhook destinations are strictly allow-listed.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrDestinationNotAllowed = errors.New("webhook destination URL is not in configured allow-list")
)

// EventType identifies the nature of the outbound notification.
type EventType string

const (
	EventFinding EventType = "finding.detected"
	EventDrift   EventType = "drift.detected"
)

// Event is the standardized notification payload sent to webhooks.
type Event struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	HostID    string    `json:"host_id"`
	Data      any       `json:"data"`
}

// Config configures the webhook dispatcher.
type Config struct {
	Enabled       bool          `json:"enabled"`
	Destinations  []string      `json:"destinations"`  // Allow-listed destination URLs
	SecretKey     string        `json:"-"`             // HMAC-SHA256 signature key
	MaxRetries    int           `json:"max_retries"`    // Default 3
	RetryBackoff  time.Duration `json:"retry_backoff"` // Initial backoff (e.g. 50ms)
}

// DispatchLog records outbound transmission history.
type DispatchLog struct {
	EventID     string        `json:"event_id"`
	Destination string        `json:"destination"`
	StatusCode  int           `json:"status_code"`
	Attempts    int           `json:"attempts"`
	Success     bool          `json:"success"`
	Duration    time.Duration `json:"duration"`
	Error       string        `json:"error,omitempty"`
}

// Dispatcher sends HMAC-signed notifications to destinations in the allow-list.
type Dispatcher struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	logs   []DispatchLog
}

func NewDispatcher(cfg Config) *Dispatcher {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	return &Dispatcher{
		cfg:    cfg,
		client: &http.Client{Timeout: 3 * time.Second},
	}
}

// ComputeSignature calculates HMAC-SHA256 of payload using secret key.
func ComputeSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature validates a received signature.
func VerifySignature(payload []byte, secret, signature string) bool {
	expected := ComputeSignature(payload, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// isAllowed checks whether destination URL is in configured allow-list.
func (d *Dispatcher) isAllowed(destURL string) bool {
	dest, err := url.Parse(destURL)
	if err != nil {
		return false
	}

	for _, allowed := range d.cfg.Destinations {
		a, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		if strings.EqualFold(dest.Host, a.Host) && strings.HasPrefix(dest.Path, a.Path) {
			return true
		}
	}
	return false
}

// Dispatch sends the event to targetURL with retries, exponential backoff, and HMAC signing.
func (d *Dispatcher) Dispatch(ctx context.Context, targetURL string, ev Event) (*DispatchLog, error) {
	if !d.cfg.Enabled {
		return nil, nil
	}

	if !d.isAllowed(targetURL) {
		return nil, ErrDestinationNotAllowed
	}

	bodyBytes, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	sig := ComputeSignature(bodyBytes, d.cfg.SecretKey)

	start := time.Now()
	var lastErr error
	statusCode := 0
	attempts := 0

	backoff := d.cfg.RetryBackoff

	for attempt := 1; attempt <= d.cfg.MaxRetries; attempt++ {
		attempts = attempt
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			break
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Kazeshini-Signature", "sha256="+sig)
		req.Header.Set("X-Kazeshini-Event", string(ev.Type))

		resp, err := d.client.Do(req)
		if err == nil {
			statusCode = resp.StatusCode
			_ = resp.Body.Close()
			if statusCode >= 200 && statusCode < 300 {
				lastErr = nil
				break
			}
			lastErr = fmt.Errorf("server returned status %d", statusCode)
		} else {
			lastErr = err
		}

		if attempt < d.cfg.MaxRetries {
			select {
			case <-ctx.Done():
				lastErr = ctx.Err()
				break
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}

	entry := DispatchLog{
		EventID:     ev.ID,
		Destination: targetURL,
		StatusCode:  statusCode,
		Attempts:    attempts,
		Success:     lastErr == nil,
		Duration:    time.Since(start),
	}
	if lastErr != nil {
		entry.Error = lastErr.Error()
	}

	d.mu.Lock()
	d.logs = append(d.logs, entry)
	d.mu.Unlock()

	return &entry, lastErr
}

// Logs returns a copy of dispatch history.
func (d *Dispatcher) Logs() []DispatchLog {
	d.mu.Lock()
	defer d.mu.Unlock()
	res := make([]DispatchLog, len(d.logs))
	copy(res, d.logs)
	return res
}

