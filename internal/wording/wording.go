// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package wording provides the single, canonical wording constants and dictionaries
// used by the CLI, API, UI, and report generators per Phase 34 specifications.
package wording

const (
	// Domains
	DomainOverview  = "Overview"
	DomainSoftware  = "Software"
	DomainServices  = "Services"
	DomainNetwork   = "Network"
	DomainStorage   = "Storage"
	DomainSecurity  = "Security"
	DomainLogs      = "Logs"
	DomainPlatforms = "Platforms"
	DomainDrift     = "Drift"
	DomainAudit     = "Audit Log"
	DomainSettings  = "Settings"

	// Health States
	StateHealthy           = "Healthy"
	StateDegraded          = "Degraded"
	StateCritical          = "Critical"
	StatePartialVisibility = "Partial visibility"
	StateUnknown           = "Unknown"

	// Scoring & Diagnostics
	TermRiskScore         = "Risk Score"
	TermRiskContributors  = "Risk Contributors"
	TermSummary           = "Summary"
	TermDiagnostics       = "Diagnostics and Visibility"
	TermGuidedTriage      = "Guided triage"
	TermUnmanagedSoftware = "Unmanaged software"
	TermImpactAnalysis    = "Impact analysis"

	// Severities
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"

	// Certainty
	CertaintyObserved = "Observed"
	CertaintyDerived  = "Derived"
	CertaintyInferred = "Inferred"
)
