// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package report generates deterministic, standalone handoff reports
// in HTML, JSON, and Markdown formats without external network dependencies.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/blastradius"
	"github.com/OWNER/kazeshini/internal/decisions"
	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/redact"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// ServerHandoff aggregates full server state into a structured handoff document.
type ServerHandoff struct {
	Title        string                       `json:"title"`
	ToolVersion  string                       `json:"tool_version"`
	GeneratedAt  time.Time                    `json:"generated_at"`
	Verdict      verdict.Summary              `json:"verdict"`
	Decommission decisions.DecommissionReport `json:"decommission"`
	Migration    decisions.MigrationPlan      `json:"migration"`
	Dependencies decisions.DependencyMap      `json:"dependencies"`
	Forecasts    []forecast.Result            `json:"forecasts"`
	TopFindings  []rules.Finding              `json:"top_findings"`
	RecentDiff   diff.ChangeSet               `json:"recent_diff"`
	BlastRadius  []blastradius.Report         `json:"blast_radius"`
}

// Generator builds deterministic reports across multiple formats.
type Generator struct {
	pGraph     *graphbuilder.ProvenanceGraph
	decisions  *decisions.Engine
	version    string
	verdictSum verdict.Summary
	findings   []rules.Finding
	forecasts  []forecast.Result
	diffSet    diff.ChangeSet
}

// NewGenerator constructs a report generator.
func NewGenerator(
	pGraph *graphbuilder.ProvenanceGraph,
	version string,
	verdictSum verdict.Summary,
	findings []rules.Finding,
	forecasts []forecast.Result,
	diffSet diff.ChangeSet,
) *Generator {
	return &Generator{
		pGraph:     pGraph,
		decisions:  decisions.NewEngine(pGraph),
		version:    version,
		verdictSum: verdictSum,
		findings:   findings,
		forecasts:  forecasts,
		diffSet:    diffSet,
	}
}

// Generate creates the structured handoff report with secret redaction enforced.
func (g *Generator) Generate() ServerHandoff {
	decom := g.decisions.EvaluateDecommission()
	mig := g.decisions.PlanMigration()
	deps := g.decisions.GetDependencies()

	// Compute sample blast radii for top exposed ports
	var blastReports []blastradius.Report
	analyzer := blastradius.NewAnalyzer(g.pGraph)
	if g.pGraph != nil {
		nodes, _ := g.pGraph.Snapshot()
		count := 0
		for _, n := range nodes {
			if n.Type == "service" || n.Type == "port" {
				if r, err := analyzer.Analyze(n.ID); err == nil {
					blastReports = append(blastReports, *r)
					count++
					if count >= 5 {
						break
					}
				}
			}
		}
	}

	// Redact findings
	cleanFindings := make([]rules.Finding, len(g.findings))
	for i, f := range g.findings {
		f.What = redact.RedactString(f.What)
		f.SoWhat = redact.RedactString(f.SoWhat)
		f.NowWhat.Action = redact.RedactString(f.NowWhat.Action)
		cleanFindings[i] = f
	}

	return ServerHandoff{
		Title:        "Kazeshini Server Truth Engine — State of this Server Handoff Report",
		ToolVersion:  g.version,
		GeneratedAt:  time.Now().UTC(),
		Verdict:      g.verdictSum,
		Decommission: decom,
		Migration:    mig,
		Dependencies: deps,
		Forecasts:    g.forecasts,
		TopFindings:  cleanFindings,
		RecentDiff:   g.diffSet,
		BlastRadius:  blastReports,
	}
}

// RenderJSON serializes the report to indented JSON.
func (g *Generator) RenderJSON() ([]byte, error) {
	handoff := g.Generate()
	return json.MarshalIndent(handoff, "", "  ")
}

// RenderMarkdown formats the report as clean, portable GitHub-flavored Markdown.
func (g *Generator) RenderMarkdown() string {
	h := g.Generate()
	var sb strings.Builder

	fmt.Fprintf(&sb, "# %s\n\n", h.Title)
	fmt.Fprintf(&sb, "**Generated At**: %s | **Tool Version**: %s\n\n", h.GeneratedAt.Format(time.RFC3339), h.ToolVersion)
	fmt.Fprintf(&sb, "## Verdict: %s\n", h.Verdict.OneLineVerdict)
	fmt.Fprintf(&sb, "- **Chaos Index**: %d / 100 (%s)\n", h.Verdict.ChaosIndex, h.Verdict.StateLabel)
	fmt.Fprintf(&sb, "- **Identity**: %s\n", h.Verdict.IdentityLine)
	fmt.Fprintf(&sb, "- **Monthly Waste**: $%.2f\n\n", h.Verdict.EstimatedWasteUSD)

	sb.WriteString("## Decommissioning Readiness\n")
	fmt.Fprintf(&sb, "> %s\n\n", h.Decommission.Verdict)
	if len(h.Decommission.Blockers) > 0 {
		sb.WriteString("### Blockers:\n")
		for _, b := range h.Decommission.Blockers {
			fmt.Fprintf(&sb, "- [!] %s\n", b)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## What Must Move (Migration Plan)\n")
	fmt.Fprintf(&sb, "- **Active Services**: %s\n", strings.Join(h.Migration.Services, ", "))
	fmt.Fprintf(&sb, "- **Listening Ports**: %s\n", strings.Join(h.Migration.Ports, ", "))
	fmt.Fprintf(&sb, "- **Unique Data Paths**: %s\n", strings.Join(h.Migration.DataPaths, ", "))
	fmt.Fprintf(&sb, "- **Secrets Paths (Redacted Metadata)**: %s\n\n", strings.Join(h.Migration.SecretsPaths, ", "))

	sb.WriteString("## Dependency Topology\n```\n")
	sb.WriteString(h.Dependencies.ASCIIMap)
	sb.WriteString("```\n\n")

	sb.WriteString("## Certainty Legend\n")
	sb.WriteString("- `[✓] OBSERVED`: Direct factual evidence from `/proc`, `/sys`, or package databases.\n")
	sb.WriteString("- `[≈] DERIVED`: Deterministically calculated fact from observed states.\n")
	sb.WriteString("- `[?] INFERRED`: Statistical or heuristic inference accompanied by confidence score.\n")

	return sb.String()
}

// RenderHTML formats a self-contained, offline HTML report suitable for printing to PDF.
func (g *Generator) RenderHTML() string {
	h := g.Generate()
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>%s</title>
  <style>
    @media print {
      body { background: #fff !important; color: #000 !important; font-size: 11pt; }
      .no-print { display: none !important; }
      .page-break { page-break-after: always; }
      .box { border: 1px solid #333 !important; }
    }
    body {
      background-color: #0B0C10;
      color: #D8DEE9;
      font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace;
      padding: 32px;
      line-height: 1.5;
      max-width: 900px;
      margin: 0 auto;
    }
    h1, h2, h3 { color: #8FFFC8; }
    .box { background: #11131A; border: 1px solid #1E2230; padding: 16px; margin: 16px 0; }
    .badge { border: 1px solid currentColor; padding: 2px 6px; font-size: 12px; font-weight: bold; }
    .badge-rose { color: #FF9EC7; }
    .badge-mint { color: #8FFFC8; }
    .badge-cyan { color: #8FE9FF; }
    pre { background: #07080B; padding: 12px; border: 1px solid #1E2230; overflow-x: auto; color: #8FE9FF; }
  </style>
</head>
<body>
  <h1>%s</h1>
  <div><strong>Generated:</strong> %s | <strong>Tool Version:</strong> %s</div>
  <hr style="border-color: #1E2230; margin: 16px 0;">

  <div class="box">
    <h2>VERDICT & CHAOS INDEX</h2>
    <div style="font-size: 18px; font-weight: bold; margin-bottom: 8px;">%s</div>
    <div>Chaos Index: <span class="badge badge-mint">%d/100 (%s)</span> | Identity: %s</div>
    <div>Estimated Monthly Waste: $%.2f</div>
  </div>

  <div class="box">
    <h2>DECOMMISSIONING VERDICT</h2>
    <div>%s</div>
  </div>

  <div class="box">
    <h2>WHAT MUST MOVE (MIGRATION INVENTORY)</h2>
    <div><strong>Services:</strong> %s</div>
    <div><strong>Ports:</strong> %s</div>
    <div><strong>Data Volumes:</strong> %s</div>
    <div><strong>Secrets (Paths only, zero values):</strong> %s</div>
  </div>

  <div class="box">
    <h2>TOPOLOGICAL DEPENDENCIES</h2>
    <pre>%s</pre>
  </div>

  <div class="box">
    <h3>CERTAINTY LEGEND</h3>
    <div>[✓] OBSERVED: Directly gathered facts from kernel & host databases.</div>
    <div>[≈] DERIVED: Deterministically calculated from observed properties.</div>
    <div>[?] INFERRED: Structural heuristic or statistical projection.</div>
  </div>
</body>
</html>`,
		h.Title,
		h.Title,
		h.GeneratedAt.Format(time.RFC3339),
		h.ToolVersion,
		h.Verdict.OneLineVerdict,
		h.Verdict.ChaosIndex,
		h.Verdict.StateLabel,
		h.Verdict.IdentityLine,
		h.Verdict.EstimatedWasteUSD,
		h.Decommission.Verdict,
		strings.Join(h.Migration.Services, ", "),
		strings.Join(h.Migration.Ports, ", "),
		strings.Join(h.Migration.DataPaths, ", "),
		strings.Join(h.Migration.SecretsPaths, ", "),
		h.Dependencies.ASCIIMap,
	)
}
