// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBus_PublishAndSubscribe(t *testing.T) {
	bus := NewBus(10)
	sub := bus.Subscribe()
	defer sub.Unsubscribe()

	ev := Event{
		ID:        "ev-1",
		Type:      TypeAlert,
		Timestamp: time.Now().UTC(),
		Payload:   "test alert",
	}

	if err := bus.Publish(context.Background(), ev); err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	select {
	case received := <-sub.Channel():
		if received.ID != "ev-1" || received.Type != TypeAlert {
			t.Fatalf("unexpected event: %+v", received)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBus_NeverBlocksSlowSubscriber(t *testing.T) {
	// Tiny buffer of 2
	bus := NewBus(2)
	slowSub := bus.Subscribe()
	defer slowSub.Unsubscribe()

	var wg sync.WaitGroup
	start := time.Now()

	// Rapidly publish 20 events without slowSub reading
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = bus.Publish(context.Background(), Event{
				ID:   "ev",
				Type: TypeState,
			})
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Invariant: Publishing 20 events should be instantaneous (< 100ms) even with a full buffer
	if elapsed > 100*time.Millisecond {
		t.Fatalf("publishing blocked slow subscriber! took %v", elapsed)
	}

	// Dropped count must be greater than zero
	dropped := bus.DroppedCount()
	if dropped == 0 {
		t.Fatalf("expected dropped events for buffer overflow, got 0")
	}
	t.Logf("Successfully dropped %d events without blocking publisher", dropped)
}
