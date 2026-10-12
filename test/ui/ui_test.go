// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package ui_test

import (
	"strings"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
	"github.com/OWNER/kazeshini/web"
)

// TestUI_StaticAssetIntegrity checks bundle size budget (< 300 KB) and assets presence.
func TestUI_StaticAssetIntegrity(t *testing.T) {
	entries, err := web.Assets.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to read embedded web assets: %v", err)
	}

	totalBytes := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("failed reading file info for %s: %v", entry.Name(), err)
		}
		if !entry.IsDir() {
			totalBytes += int(info.Size())
		}
	}

	// Check css and js
	cssEntries, err := web.Assets.ReadDir("css")
	if err == nil {
		for _, e := range cssEntries {
			info, _ := e.Info()
			totalBytes += int(info.Size())
		}
	}

	jsEntries, err := web.Assets.ReadDir("js")
	if err == nil {
		for _, e := range jsEntries {
			info, _ := e.Info()
			totalBytes += int(info.Size())
		}
	}

	const maxBudget = 300 * 1024 // 300 KB
	if totalBytes > maxBudget {
		t.Fatalf("bundle size %d exceeds 300 KB budget", totalBytes)
	}
	t.Logf("Total UI embedded bundle size: %d bytes (budget: %d bytes)", totalBytes, maxBudget)
}

// TestUI_DOMContract validates required semantic elements, tokens, and WCAG accessibility contracts.
func TestUI_DOMContract(t *testing.T) {
	indexHTML, err := web.Assets.ReadFile("index.html")
	if err != nil {
		t.Fatalf("failed to read embedded index.html: %v", err)
	}
	html := string(indexHTML)

	// Invariants: Monospace grid & zero external network fonts
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		t.Fatalf("prohibited external HTTP/HTTPS asset links found in index.html (violates local-first zero-egress)")
	}

	requiredElements := []string{
		"verdict-banner",
		"verdict-lead",
		"chaos-score",
		"chaos-badge",
		"identity-line",
		"pulse-title",
		"danger-title",
		"waste-title",
		"changes-title",
		"styleguide-view",
		"auth-modal",
	}

	for _, elemID := range requiredElements {
		if !strings.Contains(html, elemID) {
			t.Errorf("missing critical UI DOM element ID: %q", elemID)
		}
	}

	// Check box drawing characters presence
	if !strings.Contains(html, "+---") && !strings.Contains(html, "|") {
		t.Errorf("expected box-drawing character header in index.html")
	}

	// Verify CSS stylesheet contract
	cssContent, err := web.Assets.ReadFile("css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	css := string(cssContent)

	requiredTokens := []string{
		"--bg: #0B0C10",
		"--panel: #11131A",
		"--panel-border: #1E2230",
		"--text: #D8DEE9",
		"--dim: #7D8597",
		"--mint: #8FFFC8",
		"--cyan: #8FE9FF",
		"--lavender: #B9A7FF",
		"--peach: #FFB89A",
		"--rose: #FF9EC7",
		"prefers-reduced-motion",
		":focus-visible",
	}

	for _, token := range requiredTokens {
		if !strings.Contains(css, token) {
			t.Errorf("missing design system CSS token or rule: %q", token)
		}
	}

	// Font stack test: monospace first, never sans-serif before monospace
	fontLine := ""
	for _, line := range strings.Split(css, "\n") {
		if strings.Contains(line, "--font:") {
			fontLine = line
			break
		}
	}
	if fontLine == "" {
		t.Fatalf("missing --font in style.css")
	}
	if !strings.Contains(fontLine, "ui-monospace, 'JetBrains Mono'") {
		t.Errorf("expected ui-monospace and 'JetBrains Mono' first in font stack, got: %s", fontLine)
	}
	sansIdx := strings.Index(fontLine, "sans-serif")
	monoIdx := strings.Index(fontLine, "monospace")
	if sansIdx != -1 && (monoIdx == -1 || sansIdx < monoIdx) {
		t.Errorf("sans-serif placed before monospace in --font: %s", fontLine)
	}

	// Phase 22 App Shell assertions: Left rail, Key hint bar, Symptom picker, Pet isolation
	shellElements := []string{
		"left-rail",
		"nav-overview",
		"nav-briefing",
		"nav-devops",
		"nav-cloud",
		"nav-cloud-platform",
		"nav-infrastructure",
		"nav-devsecops",
		"nav-platform",
		"nav-network",
		"nav-activity",
		"quick-filter",
		"command-palette-modal",
		"help-modal",
		"symptom-picker-panel",
		"key-hint-bar",
	}
	for _, elemID := range shellElements {
		if !strings.Contains(html, elemID) {
			t.Errorf("missing App Shell UI DOM element ID: %q", elemID)
		}
	}

	// Verify Pet JS module has zero network egress (no fetch, XMLHttpRequest, WebSocket)
	petJS, err := web.Assets.ReadFile("js/pet.js")
	if err != nil {
		t.Fatalf("failed to read embedded js/pet.js: %v", err)
	}
	petContent := string(petJS)
	for _, forbidden := range []string{"fetch(", "XMLHttpRequest", "WebSocket", "EventSource"} {
		if strings.Contains(petContent, forbidden) {
			t.Errorf("forbidden network egress mechanism %q found in TSUMUJI pet module", forbidden)
		}
	}

	// Check if web/fonts/JetBrainsMono-Regular.woff2 is present
	if _, err := web.Assets.ReadFile("fonts/JetBrainsMono-Regular.woff2"); err != nil {
		t.Logf("web/fonts/JetBrainsMono-Regular.woff2 is absent (%v); font stack gracefully uses system monospaces", err)
	}
}

// TestUI_Scenarios validates deterministic verdict and chaos index outcomes across 3 canonical host scenarios.
func TestUI_Scenarios(t *testing.T) {
	t.Run("Calm Host Scenario", func(t *testing.T) {
		nodes := []graph.Node{
			{
				ID:        "host:calm",
				Type:      graph.NodeSystem,
				Label:     "calm-prod-01",
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Properties: map[string]any{
					"distro":    "Debian GNU/Linux 12",
					"cpu_count": 8,
				},
			},
			{
				ID:        "port:loopback",
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
		var findings []rules.Finding
		summary := verdict.ComputeVerdict(nodes, findings, 0)

		if summary.StateLabel != "CALM" {
			t.Errorf("expected CALM state, got %s", summary.StateLabel)
		}
		if summary.ChaosIndex > 15 {
			t.Errorf("expected ChaosIndex <= 15 for calm server, got %d", summary.ChaosIndex)
		}
		if summary.CriticalFindings != 0 || summary.HighFindings != 0 {
			t.Errorf("expected 0 critical/high findings, got %d / %d", summary.CriticalFindings, summary.HighFindings)
		}
	})

	t.Run("Messy Host Scenario", func(t *testing.T) {
		nodes := []graph.Node{
			{
				ID:        "host:messy",
				Type:      graph.NodeSystem,
				Label:     "staging-drift-02",
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
		}
		summary := verdict.ComputeVerdict(nodes, findings, 8)

		if summary.StateLabel != "MESSY" && summary.StateLabel != "MODERATE" {
			t.Errorf("expected MESSY or MODERATE state, got %s", summary.StateLabel)
		}
		if summary.ChaosIndex < 16 {
			t.Errorf("expected ChaosIndex >= 16 for messy server, got %d", summary.ChaosIndex)
		}
		if summary.EstimatedWasteUSD <= 0 {
			t.Errorf("expected waste > 0, got %f", summary.EstimatedWasteUSD)
		}
	})

	t.Run("Critical Host Scenario", func(t *testing.T) {
		nodes := []graph.Node{
			{
				ID:        "host:crit",
				Type:      graph.NodeSystem,
				Label:     "exposed-db-prod",
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
				ID:       "crit-postgres-exposed",
				Severity: rules.SeverityCritical,
				Proof:    rules.Proof{Confidence: 1.0},
			},
		}
		summary := verdict.ComputeVerdict(nodes, findings, 5)

		if summary.StateLabel != "CRITICAL" {
			t.Errorf("expected CRITICAL state, got %s", summary.StateLabel)
		}
		if summary.CriticalFindings != 1 {
			t.Errorf("expected 1 critical finding, got %d", summary.CriticalFindings)
		}
		if summary.PublicPortCount != 1 {
			t.Errorf("expected 1 public port, got %d", summary.PublicPortCount)
		}
	})
}
