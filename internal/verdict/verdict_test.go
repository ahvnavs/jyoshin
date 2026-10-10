// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package verdict

import (
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/rules"
)

func TestComputeVerdict_Scenarios(t *testing.T) {
	t.Run("Calm scenario", func(t *testing.T) {
		nodes := []graph.Node{
			{
				ID:        "host:debian",
				Type:      graph.NodeSystem,
				Label:     "calm-node-01",
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Properties: map[string]any{
					"distro":    "Debian GNU/Linux 12 (bookworm)",
					"cpu_count": 8,
				},
			},
			{
				ID:        "port:loopback:8080",
				Type:      graph.NodePort,
				Label:     "127.0.0.1:8080",
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Properties: map[string]any{
					"port":           8080,
					"exposure_class": "loopback",
				},
			},
		}
		var findings []rules.Finding // zero findings
		orphanCount := 0

		summary := ComputeVerdict(nodes, findings, orphanCount)
		if summary.StateLabel != "CALM" {
			t.Errorf("expected CALM state, got %s", summary.StateLabel)
		}
		if summary.ChaosIndex > 15 {
			t.Errorf("expected low ChaosIndex (<=15), got %d", summary.ChaosIndex)
		}
		if summary.CriticalFindings != 0 || summary.HighFindings != 0 {
			t.Errorf("expected 0 critical and high findings, got %d, %d", summary.CriticalFindings, summary.HighFindings)
		}
		if summary.EstimatedWasteUSD != 0 {
			t.Errorf("expected $0 waste, got %f", summary.EstimatedWasteUSD)
		}
	})

	t.Run("Messy scenario", func(t *testing.T) {
		nodes := []graph.Node{
			{
				ID:        "host:ubuntu",
				Type:      graph.NodeSystem,
				Label:     "staging-box",
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Properties: map[string]any{
					"distro":    "Ubuntu 22.04 LTS",
					"cpu_count": 4,
				},
			},
			{
				ID:        "port:all:8080",
				Type:      graph.NodePort,
				Label:     "0.0.0.0:8080",
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Properties: map[string]any{
					"port":           8080,
					"exposure_class": "all_interfaces",
				},
			},
		}
		findings := []rules.Finding{
			{
				ID:       "rule-med-1",
				Severity: rules.SeverityMedium,
				Proof:    rules.Proof{Confidence: 1.0},
			},
			{
				ID:       "rule-med-2",
				Severity: rules.SeverityMedium,
				Proof:    rules.Proof{Confidence: 1.0},
			},
			{
				ID:       "rule-low-1",
				Severity: rules.SeverityLow,
				Proof:    rules.Proof{Confidence: 1.0},
			},
		}
		orphanCount := 10 // high orphan penalty: 15 max

		summary := ComputeVerdict(nodes, findings, orphanCount)
		if summary.ChaosIndex < 16 {
			t.Errorf("expected higher ChaosIndex for messy scenario, got %d", summary.ChaosIndex)
		}
		if summary.EstimatedWasteUSD <= 0 {
			t.Errorf("expected estimated waste > 0, got %f", summary.EstimatedWasteUSD)
		}
	})

	t.Run("Critical scenario", func(t *testing.T) {
		nodes := []graph.Node{
			{
				ID:        "host:rhel",
				Type:      graph.NodeSystem,
				Label:     "prod-db-01",
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Properties: map[string]any{
					"distro":    "RHEL 9",
					"cpu_count": 16,
				},
			},
			{
				ID:        "port:all:5432",
				Type:      graph.NodePort,
				Label:     "0.0.0.0:5432",
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Properties: map[string]any{
					"port":           5432,
					"exposure_class": "all_interfaces",
				},
			},
		}
		findings := []rules.Finding{
			{
				ID:       "crit-postgres",
				Severity: rules.SeverityCritical,
				Proof:    rules.Proof{Confidence: 1.0},
			},
			{
				ID:       "crit-telnet",
				Severity: rules.SeverityCritical,
				Proof:    rules.Proof{Confidence: 1.0},
			},
		}
		orphanCount := 2

		summary := ComputeVerdict(nodes, findings, orphanCount)
		if summary.StateLabel != "CRITICAL" {
			t.Errorf("expected CRITICAL state, got %s", summary.StateLabel)
		}
		if summary.ChaosIndex < 45 {
			t.Errorf("expected elevated ChaosIndex for critical scenario, got %d", summary.ChaosIndex)
		}
		if summary.CriticalFindings != 2 {
			t.Errorf("expected 2 critical findings, got %d", summary.CriticalFindings)
		}
	})
}
