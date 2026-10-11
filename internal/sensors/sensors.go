// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package sensors defines the interface, models, and registry for read-only collectors.
//
// Non-negotiable principles:
// 2. READ-ONLY. Never modify the host.
// 3. NEVER HARM THE HOST. Low priority, bounded work per cycle.
// 4. ISOLATION. Each sensor is independent; one crashing or hanging must never affect others.
// 6. FACT vs INFERENCE. Every item carries evidence + certainty.
// 10. Graceful degradation: missing permission or unsupported kernel feature is
// reported as "unknown, here's why", never a crash or a silent gap.
package sensors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/OWNER/jyoshin/internal/graph"
)

// ObservationStatus represents the outcome of an observation.
type ObservationStatus string

const (
	StatusSuccess ObservationStatus = "ok"
	StatusUnknown ObservationStatus = "unknown"
	StatusError   ObservationStatus = "error"
)

// Item represents a typed observation item with discrete evidence and certainty.
type Item struct {
	ID        string           `json:"id"`
	Type      string           `json:"type"`
	Data      any              `json:"data"`
	Evidence  []graph.Evidence `json:"evidence"`
	Certainty graph.Certainty  `json:"certainty"`
}

// Observation represents the full result emitted by a single sensor collection cycle.
type Observation struct {
	SensorName string            `json:"sensor_name"`
	Timestamp  time.Time         `json:"timestamp"`
	Duration   time.Duration     `json:"duration"`
	Status     ObservationStatus `json:"status"`
	Reason     string            `json:"reason,omitempty"` // Explanation if status == "unknown" or "error"
	Truncated  bool              `json:"truncated,omitempty"`
	TotalSeen  int               `json:"total_seen,omitempty"`
	Items      []Item            `json:"items,omitempty"`
}

// Sensor is the interface implemented by all read-only collectors.
type Sensor interface {
	// Name returns the unique identifier for the sensor.
	Name() string

	// Interval returns the default polling frequency.
	Interval() time.Duration

	// Collect gathers system observations bounded by ctx.
	Collect(ctx context.Context) (Observation, error)
}

// BreakerState models the circuit breaker lifecycle for a sensor.
type BreakerState string

const (
	BreakerClosed   BreakerState = "closed"    // Operating normally
	BreakerOpen     BreakerState = "open"      // Tripped due to repeated errors; skipping runs
	BreakerHalfOpen BreakerState = "half_open" // Testing single execution
)

// SensorState tracks the live operational health and statistics of a sensor.
type SensorState struct {
	Name            string        `json:"name"`
	Interval        time.Duration `json:"interval"`
	LastRun         time.Time     `json:"last_run"`
	LastDuration    time.Duration `json:"last_duration"`
	ConsecutiveFail int           `json:"consecutive_failures"`
	TotalRuns       int64         `json:"total_runs"`
	TotalFailures   int64         `json:"total_failures"`
	BreakerState    BreakerState  `json:"breaker_state"`
	NextAllowedRun  time.Time     `json:"next_allowed_run"`
	LastError       string        `json:"last_error,omitempty"`
}

// Registry manages sensor discovery and storage.
type Registry struct {
	mu      sync.RWMutex
	sensors map[string]Sensor
}

// NewRegistry creates a new sensor registry.
func NewRegistry() *Registry {
	return &Registry{
		sensors: make(map[string]Sensor),
	}
}

// Register adds a sensor to the registry.
func (r *Registry) Register(s Sensor) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := s.Name()
	if _, exists := r.sensors[name]; exists {
		return fmt.Errorf("sensor %q already registered", name)
	}
	r.sensors[name] = s
	return nil
}

// Get retrieves a sensor by name.
func (r *Registry) Get(name string) (Sensor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sensors[name]
	return s, ok
}

// All returns a slice of registered sensors.
func (r *Registry) All() []Sensor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]Sensor, 0, len(r.sensors))
	for _, s := range r.sensors {
		list = append(list, s)
	}
	return list
}
