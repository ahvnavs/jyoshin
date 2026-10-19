// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package webhook_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/webhook"
)

func TestWebhook_HMACSigningAndRetry(t *testing.T) {
	var attempts int32
	var receivedBody []byte
	var receivedSig string
	var mu sync.Mutex

	secret := "super-secure-shared-key-999"

	// Mock webhook server that fails twice then succeeds
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := atomic.AddInt32(&attempts, 1)
		if att < 3 {
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		mu.Lock()
		receivedSig = r.Header.Get("X-Kazeshini-Signature")
		receivedBody, _ = io.ReadAll(r.Body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := webhook.Config{
		Enabled:      true,
		Destinations: []string{ts.URL},
		SecretKey:    secret,
		MaxRetries:   3,
		RetryBackoff: 10 * time.Millisecond,
	}

	dispatcher := webhook.NewDispatcher(cfg)

	ev := webhook.Event{
		ID:        "evt-12345",
		Type:      webhook.EventFinding,
		Timestamp: time.Now().UTC(),
		HostID:    "prod-worker-01",
		Data: map[string]string{
			"finding_id": "SEC-ROOT-SSH",
		},
	}

	ctx := context.Background()
	logEntry, err := dispatcher.Dispatch(ctx, ts.URL, ev)
	if err != nil {
		t.Fatalf("dispatch failed unexpectedly: %v", err)
	}

	if logEntry.Attempts != 3 {
		t.Errorf("expected 3 retry attempts before success, got %d", logEntry.Attempts)
	}
	if !logEntry.Success {
		t.Errorf("expected dispatch to succeed on 3rd attempt")
	}

	mu.Lock()
	defer mu.Unlock()
	expectedSig := "sha256=" + webhook.ComputeSignature(receivedBody, secret)
	if receivedSig != expectedSig {
		t.Errorf("HMAC signature mismatch: got %s, want %s", receivedSig, expectedSig)
	}

	t.Logf("[✓] Webhook retry and HMAC signature verified: %d attempts, signature matches", logEntry.Attempts)
}

func TestWebhook_AllowListRejection(t *testing.T) {
	cfg := webhook.Config{
		Enabled:      true,
		Destinations: []string{"https://hooks.slack.com/services/allowlisted"},
		SecretKey:    "test-secret",
	}

	dispatcher := webhook.NewDispatcher(cfg)
	ev := webhook.Event{
		ID:        "evt-reject",
		Type:      webhook.EventDrift,
		Timestamp: time.Now().UTC(),
	}

	_, err := dispatcher.Dispatch(context.Background(), "https://evil.attacker.com/sink", ev)
	if err != webhook.ErrDestinationNotAllowed {
		t.Fatalf("expected ErrDestinationNotAllowed, got %v", err)
	}
	t.Logf("[✓] Destination not in allow-list safely rejected: %v", err)
}
