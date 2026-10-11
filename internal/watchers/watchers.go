// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package watchers implements proactive event evaluation and rate-limited alert generation
// for critical host state mutations.
package watchers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/rules"
)

// EventAlert represents an alert emitted by an event watcher.
type EventAlert struct {
	ID        string         `json:"id"`
	RuleID    string         `json:"rule_id"`
	Severity  rules.Severity `json:"severity"`
	Title     string         `json:"title"`
	Message   string         `json:"message"`
	Target    string         `json:"target"`
	Timestamp time.Time      `json:"timestamp"`
}

// Manager coordinates event watchers, deduplication, and rate limiting.
type Manager struct {
	mu           sync.Mutex
	recentAlerts map[string]time.Time // key -> last fired
	cooldown     time.Duration
	alerts       []EventAlert
	maxHistory   int
}

// NewManager creates a new watchers manager with deduplication cooldown.
func NewManager(cooldown time.Duration) *Manager {
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Manager{
		recentAlerts: make(map[string]time.Time),
		cooldown:     cooldown,
		maxHistory:   50,
	}
}

// ProcessChangeSet evaluates diff changes against proactive watcher rules:
// - New listening port (especially newly exposed)
// - New manual binary in exec paths
// - Version drift
// - Restart loops
func (m *Manager) ProcessChangeSet(ctx context.Context, cs diff.ChangeSet) []EventAlert {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	var newAlerts []EventAlert

	for _, ch := range cs.Changes {
		var (
			ruleID    string
			sev       rules.Severity
			title     string
			dedupeKey string
		)

		switch ch.Kind {
		case diff.ChangeNewlyExposed:
			ruleID = "WATCH-PORT-EXPOSED"
			sev = rules.SeverityCritical
			title = fmt.Sprintf("Critical: Port %s exposed publicly", ch.Label)
			dedupeKey = fmt.Sprintf("%s:%s", ruleID, ch.NodeID)

		case diff.ChangeNewListener:
			ruleID = "WATCH-NEW-PORT"
			sev = rules.SeverityMedium
			title = fmt.Sprintf("New listening port: %s", ch.Label)
			dedupeKey = fmt.Sprintf("%s:%s", ruleID, ch.NodeID)

		case diff.ChangeNewManualBinary:
			ruleID = "WATCH-MANUAL-BINARY"
			sev = rules.SeverityHigh
			title = fmt.Sprintf("New unmanaged binary dropped: %s", ch.Label)
			dedupeKey = fmt.Sprintf("%s:%s", ruleID, ch.NodeID)

		case diff.ChangeVersionChanged:
			ruleID = "WATCH-VERSION-DRIFT"
			sev = rules.SeverityLow
			title = fmt.Sprintf("Software version drift: %s", ch.Label)
			dedupeKey = fmt.Sprintf("%s:%s", ruleID, ch.NodeID)

		case diff.ChangeStateChanged:
			if state, ok := ch.After["active_state"].(string); ok && state == "failed" {
				ruleID = "WATCH-SERVICE-CRASH"
				sev = rules.SeverityHigh
				title = fmt.Sprintf("Service unit failure: %s", ch.Label)
				dedupeKey = fmt.Sprintf("%s:%s", ruleID, ch.NodeID)
			}
		}

		if ruleID == "" {
			continue
		}

		// Check rate limiting / deduplication
		if last, exists := m.recentAlerts[dedupeKey]; exists && now.Sub(last) < m.cooldown {
			continue // Rate limited
		}

		m.recentAlerts[dedupeKey] = now
		alert := EventAlert{
			ID:        fmt.Sprintf("alert-%d-%s", now.UnixNano(), ch.NodeID),
			RuleID:    ruleID,
			Severity:  sev,
			Title:     title,
			Message:   ch.Description,
			Target:    ch.Label,
			Timestamp: now,
		}
		newAlerts = append(newAlerts, alert)
		m.alerts = append(m.alerts, alert)
	}

	if len(m.alerts) > m.maxHistory {
		m.alerts = m.alerts[len(m.alerts)-m.maxHistory:]
	}

	return newAlerts
}

// ProcessForecast evaluates resource exhaustion risks and leak detections:
func (m *Manager) ProcessForecast(res forecast.Result) *EventAlert {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	var (
		ruleID    string
		sev       rules.Severity
		title     string
		dedupeKey string
	)

	if res.State == forecast.StateExhaustionRisk {
		ruleID = "WATCH-FORECAST-EXHAUSTION"
		sev = rules.SeverityCritical
		title = fmt.Sprintf("Imminent exhaustion of %s (%s)", res.Resource, res.Target)
		dedupeKey = fmt.Sprintf("%s:%s:%s", ruleID, res.Resource, res.Target)
	} else if res.IsLeak {
		ruleID = "WATCH-RESOURCE-LEAK"
		sev = rules.SeverityHigh
		title = fmt.Sprintf("Resource leak detected on %s (%s)", res.Resource, res.Target)
		dedupeKey = fmt.Sprintf("%s:%s:%s", ruleID, res.Resource, res.Target)
	}

	if ruleID == "" {
		return nil
	}

	if last, exists := m.recentAlerts[dedupeKey]; exists && now.Sub(last) < m.cooldown {
		return nil
	}

	m.recentAlerts[dedupeKey] = now
	alert := EventAlert{
		ID:        fmt.Sprintf("alert-%d-%s-%s", now.UnixNano(), res.Resource, res.Target),
		RuleID:    ruleID,
		Severity:  sev,
		Title:     title,
		Message:   res.Message,
		Target:    res.Target,
		Timestamp: now,
	}
	m.alerts = append(m.alerts, alert)
	if len(m.alerts) > m.maxHistory {
		m.alerts = m.alerts[len(m.alerts)-m.maxHistory:]
	}

	return &alert
}

// RecentAlerts returns the recorded history of event alerts.
func (m *Manager) RecentAlerts(limit int) []EventAlert {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 || limit > len(m.alerts) {
		limit = len(m.alerts)
	}
	res := make([]EventAlert, limit)
	copy(res, m.alerts[len(m.alerts)-limit:])
	return res
}
