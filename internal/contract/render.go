// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"fmt"
	"strings"
)

// RenderTerminal formats a CheckResult into plain terminal text.
func (c CheckResult) RenderTerminal() string {
	var sb strings.Builder
	statusTag := fmt.Sprintf("[%s]", c.Status)
	sb.WriteString(fmt.Sprintf("%-6s %s (%s)\n", statusTag, c.Title, c.Role))
	sb.WriteString(fmt.Sprintf("       Summary:  %s\n", c.SummaryPlain))
	if c.ExplainLevels[0] != "" {
		sb.WriteString(fmt.Sprintf("       What:     %s\n", c.ExplainLevels[0]))
	}
	if c.ExplainLevels[1] != "" {
		sb.WriteString(fmt.Sprintf("       So what:  %s\n", c.ExplainLevels[1]))
	}
	if c.ExplainLevels[2] != "" {
		sb.WriteString(fmt.Sprintf("       Now what: %s\n", c.ExplainLevels[2]))
	}
	if c.NextStepCommand != "" {
		sb.WriteString(fmt.Sprintf("       Next cmd: %s\n", c.NextStepCommand))
	}
	if c.Certainty != "" {
		sb.WriteString(fmt.Sprintf("       Certainty: [%s]\n", strings.ToUpper(string(c.Certainty))))
	}
	return sb.String()
}

// RenderHTML formats a CheckResult into an accessible HTML snippet for the embedded web UI.
func (c CheckResult) RenderHTML() string {
	statusClass := "badge-mint"
	switch c.Status {
	case StatusCrit:
		statusClass = "badge-rose"
	case StatusWarn:
		statusClass = "badge-peach"
	case StatusUnknown, StatusNotApplicable:
		statusClass = "badge-dim"
	}

	return fmt.Sprintf(`<div class="check-result" data-id="%s" data-status="%s">
  <div class="check-header">
    <span class="badge %s">[%s]</span>
    <strong class="check-title">%s</strong>
    <span class="check-role">(%s)</span>
  </div>
  <div class="check-summary">%s</div>
  <div class="check-explains">
    <div class="explain-what"><span class="label">What:</span> %s</div>
    <div class="explain-so-what"><span class="label">So what:</span> %s</div>
    <div class="explain-now-what"><span class="label">Now what:</span> %s</div>
  </div>
</div>`,
		c.ID, c.Status,
		statusClass, c.Status,
		c.Title,
		c.Role,
		c.SummaryPlain,
		c.ExplainLevels[0],
		c.ExplainLevels[1],
		c.ExplainLevels[2],
	)
}

