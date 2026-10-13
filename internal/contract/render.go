// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"fmt"
	"strings"
)

// RenderTerminal formats a CheckResult into the single standardized Phase 34 card layout:
// Severity | Title | Result (one sentence) | Impact | Recommended action | Evidence | Confidence | Visibility
func (c CheckResult) RenderTerminal() string {
	var sb strings.Builder

	// Map internal Status to canonical Severity
	severity := "Info"
	switch c.Status {
	case StatusCrit:
		severity = "Critical"
	case StatusWarn:
		severity = "High"
	case StatusOK:
		severity = "Low"
	case StatusUnknown, StatusNotApplicable:
		severity = "Info"
	}

	confidence := "Observed"
	if c.Certainty != "" {
		confidence = strings.Title(strings.ToLower(string(c.Certainty)))
	}

	visibility := "Full"
	if c.Coverage.Total > 0 {
		visibility = fmt.Sprintf("%d of %d", c.Coverage.Seen, c.Coverage.Total)
	} else if c.Coverage.Reason != "" {
		visibility = c.Coverage.Reason
	}

	resultSentence := c.SummaryPlain
	if resultSentence == "" && c.ExplainLevels[0] != "" {
		resultSentence = c.ExplainLevels[0]
	}

	impact := c.ExplainLevels[1]
	if impact == "" {
		impact = "None detected under current operational conditions."
	}

	recommendedAction := c.NextStepCommand
	if recommendedAction == "" && c.ExplainLevels[2] != "" {
		recommendedAction = c.ExplainLevels[2]
	}
	if recommendedAction == "" {
		recommendedAction = "No action needed (system healthy)."
	}

	var evidenceList []string
	if len(c.Evidence) > 0 {
		for _, ev := range c.Evidence {
			detail := ev.Details
			if detail == "" {
				detail = ev.Raw
			}
			if detail != "" {
				evidenceList = append(evidenceList, fmt.Sprintf("%s (%s)", ev.Source, detail))
			} else {
				evidenceList = append(evidenceList, ev.Source)
			}
		}
	} else if c.EquivalentCommand != "" {
		evidenceList = append(evidenceList, c.EquivalentCommand)
	} else {
		evidenceList = append(evidenceList, c.ID)
	}

	fmt.Fprintf(&sb, "Severity:           %s\n", severity)
	fmt.Fprintf(&sb, "Title:              %s\n", c.Title)
	fmt.Fprintf(&sb, "Result:             %s\n", resultSentence)
	fmt.Fprintf(&sb, "Impact:             %s\n", impact)
	fmt.Fprintf(&sb, "Recommended action: %s\n", recommendedAction)
	fmt.Fprintf(&sb, "Evidence:           %s\n", strings.Join(evidenceList, "; "))
	fmt.Fprintf(&sb, "Confidence:         %s\n", confidence)
	fmt.Fprintf(&sb, "Visibility:         %s\n", visibility)

	return sb.String()
}

// RenderHTML formats a CheckResult into an accessible, standardized card following Phase 34 layout.
func (c CheckResult) RenderHTML() string {
	severity := "Info"
	statusClass := "badge-dim"
	switch c.Status {
	case StatusCrit:
		severity = "Critical"
		statusClass = "badge-rose"
	case StatusWarn:
		severity = "High"
		statusClass = "badge-peach"
	case StatusOK:
		severity = "Low"
		statusClass = "badge-mint"
	case StatusUnknown, StatusNotApplicable:
		severity = "Info"
		statusClass = "badge-dim"
	}

	confidence := "Observed"
	if c.Certainty != "" {
		confidence = strings.Title(strings.ToLower(string(c.Certainty)))
	}

	visibility := "Full"
	if c.Coverage.Total > 0 {
		visibility = fmt.Sprintf("%d of %d", c.Coverage.Seen, c.Coverage.Total)
	} else if c.Coverage.Reason != "" {
		visibility = c.Coverage.Reason
	}

	resultSentence := c.SummaryPlain
	if resultSentence == "" && c.ExplainLevels[0] != "" {
		resultSentence = c.ExplainLevels[0]
	}

	impact := c.ExplainLevels[1]
	if impact == "" {
		impact = "None detected."
	}

	recommendedAction := c.NextStepCommand
	if recommendedAction == "" && c.ExplainLevels[2] != "" {
		recommendedAction = c.ExplainLevels[2]
	}
	if recommendedAction == "" {
		recommendedAction = "None."
	}

	evidenceSummary := c.ID
	if len(c.Evidence) > 0 {
		evidenceSummary = c.Evidence[0].Source
	}

	return fmt.Sprintf(`<div class="check-result-card" data-id="%s" data-severity="%s">
  <div class="card-row"><span class="badge %s">%s</span> <strong class="card-title">%s</strong></div>
  <div class="card-field"><span class="field-label">Result:</span> %s</div>
  <div class="card-field"><span class="field-label">Impact:</span> %s</div>
  <div class="card-field"><span class="field-label">Recommended action:</span> <code>%s</code></div>
  <div class="card-meta">
    <span><strong>Evidence:</strong> %s</span> |
    <span><strong>Confidence:</strong> %s</span> |
    <span><strong>Visibility:</strong> %s</span>
  </div>
</div>`,
		c.ID, severity,
		statusClass, severity, c.Title,
		resultSentence,
		impact,
		recommendedAction,
		evidenceSummary,
		confidence,
		visibility,
	)
}
