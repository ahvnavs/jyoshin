// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package briefing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/rules"
)

func TestBriefing_RenderQualityAndNoPlaceholders(t *testing.T) {
	b := NewBuilder()

	nodes := []graph.Node{
		{
			ID:        "host:prod-01",
			Type:      graph.NodeSystem,
			Label:     "prod-01",
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"distro":         "Ubuntu 24.04 LTS",
				"kernel":         "6.8.0-generic",
				"arch":           "amd64",
				"cpu_count":      4,
				"uptime_seconds": 86400.0,
				"memory_bytes":   uint64(16 * 1024 * 1024 * 1024),
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
				"protocol":       "tcp",
				"local_ip":       "0.0.0.0",
				"exposure_class": "all_interfaces",
				"process_name":   "postgres",
			},
		},
		{
			ID:        "proc:100",
			Type:      graph.NodeProcess,
			Label:     "postgres",
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Properties: map[string]any{
				"pid":            100,
				"rss":            int64(512 * 1024 * 1024),
				"origin_package": "postgresql-16",
			},
		},
	}

	findings := []rules.Finding{
		{
			ID:       "sec-postgres",
			RuleID:   "SEC-DB-EXPOSED",
			Category: rules.CategorySecurity,
			Severity: rules.SeverityCritical,
			What:     "Database listening publicly on port 5432",
			SoWhat:   "Accessible by unauthorized remote clients",
			NowWhat: rules.NowWhat{
				Action:    "Bind to 127.0.0.1 in postgresql.conf",
				RiskLevel: rules.RiskLow,
			},
			Proof: rules.Proof{
				Certainty:  graph.CertaintyObserved,
				Confidence: 1.0,
			},
		},
	}

	cov := coverage.Report{
		OverallCoverage: 100.0,
		IsAdequate:      true,
		VerdictAllowed:  true,
		SummaryNote:     "All sensors operating normally",
	}

	br := b.Build(context.Background(), nodes, findings, []orphan.ScanResult{}, cov, time.Now())
	rendered := br.RenderTerminal()

	// Assertions for Task item 3 (WORDING):
	// No empty strings, no "<nil>", no raw JSON keys, no unreplaced {placeholders}
	prohibitedTokens := []string{
		"<nil>",
		"null",
		"{",
		"}",
		"NaN",
	}

	for _, token := range prohibitedTokens {
		if strings.Contains(rendered, token) {
			t.Errorf("rendered briefing contained prohibited token %q:\n%s", token, rendered)
		}
	}

	// Verify required sections exist
	requiredSections := []string{
		"1. WHAT THIS MACHINE IS:",
		"2. WHAT IT RUNS:",
		"3. WHAT IS REACHABLE FROM OUTSIDE:",
		"4. WHAT WAS INSTALLED BY HAND:",
		"5. WHAT IS WASTING SPACE OR MONEY:",
		"6. WHAT NEEDS ATTENTION:",
		"7. WHAT I CANNOT TELL YOU YET:",
		"INFERRED",
	}

	for _, sec := range requiredSections {
		if !strings.Contains(rendered, sec) {
			t.Errorf("rendered briefing missing required section %q", sec)
		}
	}
}
