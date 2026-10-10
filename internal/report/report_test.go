// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"strings"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/diff"
	"github.com/OWNER/jyoshin/internal/forecast"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/graphbuilder"
	"github.com/OWNER/jyoshin/internal/report"
	"github.com/OWNER/jyoshin/internal/rules"
	"github.com/OWNER/jyoshin/internal/verdict"
)

func TestReport_GenerationAndFormats(t *testing.T) {
	pGraph := graphbuilder.NewProvenanceGraph()
	now := time.Now().UTC()

	// Ingest test port
	_ = pGraph.UpsertNode(graph.Node{
		ID:        "port:80",
		Type:      graph.NodePort,
		Label:     "0.0.0.0:80",
		FirstSeen: now,
		LastSeen:  now,
		Certainty: graph.CertaintyObserved,
		Properties: map[string]any{
			"port":           80,
			"exposure_class": "all_interfaces",
		},
	})

	vSum := verdict.Summary{
		OneLineVerdict:    "Server operating under normal operational baseline.",
		StateLabel:        "CALM",
		ChaosIndex:        8,
		IdentityLine:      "prod-box (Debian 12, 8 cores)",
		EstimatedWasteUSD: 15.0,
	}

	gen := report.NewGenerator(
		pGraph,
		"v0.1.0-dev",
		vSum,
		[]rules.Finding{},
		[]forecast.Result{},
		diff.ChangeSet{},
	)

	// 1. Test JSON Rendering
	jsonData, err := gen.RenderJSON()
	if err != nil {
		t.Fatalf("failed to render JSON report: %v", err)
	}
	if !strings.Contains(string(jsonData), "State of this Server Handoff Report") {
		t.Errorf("expected title in JSON report")
	}

	// 2. Test Markdown Rendering
	mdData := gen.RenderMarkdown()
	if !strings.Contains(mdData, "## Decommissioning Readiness") {
		t.Errorf("expected decommission header in markdown report")
	}
	if !strings.Contains(mdData, "## Certainty Legend") {
		t.Errorf("expected certainty legend in markdown report")
	}

	// 3. Test HTML Rendering
	htmlData := gen.RenderHTML()
	if !strings.Contains(htmlData, "<title>Jyōshin Server Truth Engine") {
		t.Errorf("expected html title tag")
	}
	if strings.Contains(htmlData, "http://") || strings.Contains(htmlData, "https://") {
		t.Errorf("report HTML must not include external network assets")
	}
}
