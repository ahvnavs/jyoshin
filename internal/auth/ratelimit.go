// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"sync"
	"time"
)

// RateLimiter tracks auth failures per client IP and enforces temporary lockouts.
type RateLimiter struct {
	mu          sync.Mutex
	maxFailures int
	lockoutTime time.Duration
	window      time.Duration
	failures    map[string][]time.Time
	lockedUntil map[string]time.Time
}

// NewRateLimiter creates a failure rate limiter.
func NewRateLimiter(maxFailures int, lockoutTime, window time.Duration) *RateLimiter {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if lockoutTime <= 0 {
		lockoutTime = 5 * time.Minute
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &RateLimiter{
		maxFailures: maxFailures,
		lockoutTime: lockoutTime,
		window:      window,
		failures:    make(map[string][]time.Time),
		lockedUntil: make(map[string]time.Time),
	}
}

// IsLocked checks whether the given key (IP address) is currently locked out.
func (rl *RateLimiter) IsLocked(key string, now time.Time) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	until, locked := rl.lockedUntil[key]
	if locked {
		if now.Before(until) {
			return true, until.Sub(now)
		}
		// Lockout expired
		delete(rl.lockedUntil, key)
		delete(rl.failures, key)
	}
	return false, 0
}

// RecordFailure notes an authentication failure and engages lockout if threshold exceeded.
func (rl *RateLimiter) RecordFailure(key string, now time.Time) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Clean out failures older than window
	cutoff := now.Add(-rl.window)
	var active []time.Time
	for _, t := range rl.failures[key] {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}
	active = append(active, now)
	rl.failures[key] = active

	if len(active) >= rl.maxFailures {
		lockUntil := now.Add(rl.lockoutTime)
		rl.lockedUntil[key] = lockUntil
		return true, rl.lockoutTime
	}
	return false, 0
}

// RecordSuccess clears failure records upon successful authentication.
func (rl *RateLimiter) RecordSuccess(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.failures, key)
	delete(rl.lockedUntil, key)
}
