// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package contract defines the single unified result contract across all outputs:
// CLI terminal text, API JSON, and embedded Web UI.
package contract

import (
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
)

// Status represents the standard check result severity/state.
type Status string

const (
	StatusOK            Status = "OK"
	StatusWarn          Status = "WARN"
	StatusCrit          Status = "CRIT"
	StatusUnknown       Status = "UNKNOWN"
	StatusNotApplicable Status = "NOT_APPLICABLE"
)

// CoverageSummary captures the sensor visibility context for a check.
type CoverageSummary struct {
	Seen   int    `json:"seen"`
	Total  int    `json:"total"`
	Reason string `json:"reason,omitempty"`
}

// CheckResult represents a single standardized inspection statement.
type CheckResult struct {
	ID                string           `json:"id"`
	Role              string           `json:"role"` // e.g. "security", "efficiency", "operations", "cost", "coverage"
	Title             string           `json:"title"`
	Status            Status           `json:"status"` // OK, WARN, CRIT, UNKNOWN, NOT_APPLICABLE
	SummaryPlain      string           `json:"summary_plain"`
	ExplainLevels     [3]string        `json:"explain_levels"` // [0] What, [1] So what, [2] Now what
	Evidence          []graph.Evidence `json:"evidence"`
	Certainty         graph.Certainty  `json:"certainty"` // OBSERVED, DERIVED, INFERRED
	Coverage          CoverageSummary  `json:"coverage"`
	EquivalentCommand string           `json:"equivalent_command,omitempty"`
	NextStepCommand   string           `json:"next_step_command,omitempty"` // Shown to user, NEVER executed by Kazeshini
	ReadOnly          bool             `json:"read_only"`                   // Invariant: always true
	CollectedAt       time.Time        `json:"collected_at"`
	RawRedacted       string           `json:"raw_redacted,omitempty"`
}

// NewCheckResult initializes a valid CheckResult maintaining read-only and timestamp invariants.
func NewCheckResult(id, role, title string, status Status, summary string) CheckResult {
	return CheckResult{
		ID:           id,
		Role:         role,
		Title:        title,
		Status:       status,
		SummaryPlain: summary,
		ReadOnly:     true,
		CollectedAt:  time.Now().UTC(),
	}
}

