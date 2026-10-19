// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package consistency_test

import (
	"fmt"
	"testing"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
	"github.com/OWNER/kazeshini/internal/wording"
)

// TestProperty_HealthyNeverReturnedOnInadequateCoverage asserts the invariant:
// A verdict of Healthy must NEVER be returned if coverage is inadequate or checks are unknown/failed.
func TestProperty_HealthyNeverReturnedOnInadequateCoverage(t *testing.T) {
	testCases := []struct {
		name                string
		nodes               []graph.Node
		findings            []rules.Finding
		coverageAdequate    bool
		coverageExplanation string
		checkResults        []contract.CheckResult
	}{
		{
			name:                "Empty nodes and findings with inadequate coverage",
			nodes:               nil,
			findings:            nil,
			coverageAdequate:    false,
			coverageExplanation: "sensors uncollected",
		},
		{
			name: "Nodes exist but coverage is inadequate",
			nodes: []graph.Node{
				{ID: "host:srv", Type: graph.NodeSystem, Label: "srv", Certainty: graph.CertaintyObserved},
			},
			findings:            nil,
			coverageAdequate:    false,
			coverageExplanation: "permission denied reading /proc/net",
		},
		{
			name: "Critical check failed with adequate coverage",
			nodes: []graph.Node{
				{ID: "host:srv", Type: graph.NodeSystem, Label: "srv", Certainty: graph.CertaintyObserved},
			},
			findings:         nil,
			coverageAdequate: true,
			checkResults: []contract.CheckResult{
				{ID: "chk-disk", Title: "Disk Space", Status: contract.StatusCrit, SummaryPlain: "99% full"},
			},
		},
		{
			name: "Critical check failed with inadequate coverage",
			nodes: []graph.Node{
				{ID: "host:srv", Type: graph.NodeSystem, Label: "srv", Certainty: graph.CertaintyObserved},
			},
			findings:            nil,
			coverageAdequate:    false,
			coverageExplanation: "missing root permissions",
			checkResults: []contract.CheckResult{
				{ID: "chk-ssh", Title: "SSH Root Login", Status: contract.StatusCrit, SummaryPlain: "PermitRootLogin yes"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			summary := verdict.ComputeVerdictWithChecks(
				tc.nodes,
				tc.findings,
				0,
				tc.coverageAdequate,
				tc.coverageExplanation,
				tc.checkResults,
			)

			if summary.StateLabel == wording.StateHealthy {
				t.Fatalf("INVARIANT VIOLATION: ComputeVerdictWithChecks returned StateHealthy (%s) under condition: %s",
					summary.StateLabel, tc.name)
			}
			t.Logf("Passed: under '%s', state is %q (Verdict: %s)", tc.name, summary.StateLabel, summary.OneLineVerdict)
		})
	}
}

// TestMetamorphic_SensorsAndGraph verifies metamorphic relations:
// - Adding an open port node must monotonically increase or maintain listening port count
// - Adding a critical finding must monotonically increase or maintain Risk Score
func TestMetamorphic_SensorsAndGraph(t *testing.T) {
	baseNodes := []graph.Node{
		{
			ID:        "host:meta",
			Type:      graph.NodeSystem,
			Label:     "meta-host",
			Certainty: graph.CertaintyObserved,
		},
		{
			ID:        "port:tcp:80",
			Type:      graph.NodePort,
			Label:     "0.0.0.0:80",
			Certainty: graph.CertaintyObserved,
			Properties: map[string]any{
				"exposure_class": "all_interfaces",
			},
		},
	}

	v1 := verdict.ComputeVerdict(baseNodes, nil, 0)
	if v1.ListeningPortCount != 1 || v1.PublicPortCount != 1 {
		t.Fatalf("expected 1 port, got %d", v1.ListeningPortCount)
	}

	// Metamorphic transform 1: Add another listening port
	extendedNodes := append([]graph.Node{}, baseNodes...)
	extendedNodes = append(extendedNodes, graph.Node{
		ID:        "port:tcp:443",
		Type:      graph.NodePort,
		Label:     "0.0.0.0:443",
		Certainty: graph.CertaintyObserved,
		Properties: map[string]any{
			"exposure_class": "all_interfaces",
		},
	})

	v2 := verdict.ComputeVerdict(extendedNodes, nil, 0)
	if v2.ListeningPortCount <= v1.ListeningPortCount {
		t.Fatalf("Metamorphic invariant failed: adding port did not increase count (%d <= %d)",
			v2.ListeningPortCount, v1.ListeningPortCount)
	}
	if v2.RiskScore < v1.RiskScore {
		t.Fatalf("Metamorphic invariant failed: adding exposed port reduced Risk Score (%d < %d)",
			v2.RiskScore, v1.RiskScore)
	}

	// Metamorphic transform 2: Add critical findings
	findings := []rules.Finding{
		{
			ID:       "FIND-001",
			RuleID:   "RUL-001",
			Category: rules.CategorySecurity,
			Severity: rules.SeverityCritical,
			What:     "CVE Detected",
			SoWhat:   "System vulnerable",
			NowWhat: rules.NowWhat{
				Action:    "Patch package",
				RiskLevel: rules.RiskLow,
			},
			Proof: rules.Proof{
				Certainty:  graph.CertaintyObserved,
				Confidence: 1.0,
			},
		},
	}

	v3 := verdict.ComputeVerdict(extendedNodes, findings, 0)
	if v3.RiskScore <= v2.RiskScore {
		t.Fatalf("Metamorphic invariant failed: adding critical finding did not increase Risk Score (%d <= %d)",
			v3.RiskScore, v2.RiskScore)
	}
	if v3.StateLabel != wording.StateCritical {
		t.Fatalf("expected StateCritical, got %s", v3.StateLabel)
	}
	fmt.Printf("Metamorphic tests verified: base risk=%d, +port risk=%d, +cve risk=%d\n",
		v1.RiskScore, v2.RiskScore, v3.RiskScore)
}
