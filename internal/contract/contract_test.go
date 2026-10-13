// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package contract_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/graph"
)

func TestCheckResult_UnifiedAgreement(t *testing.T) {
	// Golden test asserting that CLI terminal rendering, API JSON serialization,
	// and HTML rendering agree on fields and values.
	fixedTime := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	res := contract.CheckResult{
		ID:           "test-ssh-exposure",
		Role:         "security",
		Title:        "Unrestricted SSH listening on 0.0.0.0:22",
		Status:       contract.StatusWarn,
		SummaryPlain: "SSH daemon is exposed to all network interfaces.",
		ExplainLevels: [3]string{
			"sshd listening on 0.0.0.0:22",
			"Permits network brute-force attempts from any routable subnet",
			"Bind sshd to internal bastion interface or apply firewall",
		},
		Evidence: []graph.Evidence{
			{
				Source:    "/proc/net/tcp",
				Collector: "network",
				Details:   "Inode 12345 bound to 0.0.0.0:22",
				Timestamp: fixedTime,
				Certainty: graph.CertaintyObserved,
			},
		},
		Certainty: graph.CertaintyObserved,
		Coverage: contract.CoverageSummary{
			Seen:   50,
			Total:  50,
			Reason: "All listening sockets inspected",
		},
		EquivalentCommand: "ss -tulpn | grep :22",
		NextStepCommand:   "ufw allow from 10.0.0.0/8 to any port 22",
		ReadOnly:          true,
		CollectedAt:       fixedTime,
	}

	// 1. JSON Agreement
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var unmarshaled contract.CheckResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if unmarshaled.ID != res.ID || unmarshaled.Status != res.Status || !unmarshaled.ReadOnly {
		t.Errorf("JSON mismatch: got %+v, want %+v", unmarshaled, res)
	}

	// 2. Terminal Text Agreement (Phase 34 Standardized 8-Field Card)
	termText := res.RenderTerminal()
	if !strings.Contains(termText, "Severity:           High") {
		t.Errorf("terminal text missing status: %s", termText)
	}
	if !strings.Contains(termText, res.Title) {
		t.Errorf("terminal text missing title: %s", termText)
	}
	if !strings.Contains(termText, res.SummaryPlain) {
		t.Errorf("terminal text missing result explanation: %s", termText)
	}
	if !strings.Contains(termText, res.NextStepCommand) {
		t.Errorf("terminal text missing next step command: %s", termText)
	}

	// 3. HTML Agreement
	htmlSnippet := res.RenderHTML()
	if !strings.Contains(htmlSnippet, `data-severity="High"`) {
		t.Errorf("HTML snippet missing status attribute: %s", htmlSnippet)
	}
	if !strings.Contains(htmlSnippet, res.Title) {
		t.Errorf("HTML snippet missing title: %s", htmlSnippet)
	}
	if !strings.Contains(htmlSnippet, res.ExplainLevels[1]) {
		t.Errorf("HTML snippet missing impact explanation: %s", htmlSnippet)
	}
}
