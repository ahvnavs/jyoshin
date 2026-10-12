// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package events provides an in-process, typed, bounded, drop-counted event bus.
package events

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Type identifies the kind of event emitted across the bus.
type Type string

const (
	TypeAlert    Type = "alert"
	TypeState    Type = "state"
	TypeForecast Type = "forecast"
	TypeCheck    Type = "check"
)

// Event is the envelope for all bus notifications.
type Event struct {
	ID        string    `json:"id"`
	Type      Type      `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Payload   any       `json:"payload"`
}

// Subscription is an active subscriber handle.
type Subscription struct {
	id     int64
	bus    *Bus
	ch     chan Event
	closed atomic.Bool
}

// Channel returns the receive-only event channel.
func (s *Subscription) Channel() <-chan Event {
	return s.ch
}

// Unsubscribe unregisters the subscriber from future event dispatches.
func (s *Subscription) Unsubscribe() {
	if s.closed.CompareAndSwap(false, true) {
		s.bus.unsubscribe(s.id)
	}
}

// Bus is a non-blocking in-process event hub with per-subscriber bounded buffering.
type Bus struct {
	mu           sync.RWMutex
	nextID       atomic.Int64
	subs         map[int64]*Subscription
	bufferSize   int
	droppedCount atomic.Uint64
}

// NewBus creates a new bounded event bus.
func NewBus(bufferSize int) *Bus {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	return &Bus{
		subs:       make(map[int64]*Subscription),
		bufferSize: bufferSize,
	}
}

// Subscribe registers a new subscriber with a bounded channel buffer.
func (b *Bus) Subscribe() *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := b.nextID.Add(1)
	sub := &Subscription{
		id:  id,
		bus: b,
		ch:  make(chan Event, b.bufferSize),
	}
	b.subs[id] = sub
	return sub
}

func (b *Bus) unsubscribe(id int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if sub, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(sub.ch)
	}
}

// Publish distributes an event to all subscribers.
// Non-blocking: if a subscriber's buffer is full, the event is dropped and
// the dropped counter is incremented so slow subscribers never block sensors.
func (b *Bus) Publish(ctx context.Context, ev Event) error {
	if ev.Type == "" {
		return errors.New("event type required")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range b.subs {
		if sub.closed.Load() {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			// Non-blocking drop: sensor work cycle continues without pause
			b.droppedCount.Add(1)
		}
	}
	return nil
}

// DroppedCount returns the cumulative number of dropped events across slow subscribers.
func (b *Bus) DroppedCount() uint64 {
	return b.droppedCount.Load()
}

