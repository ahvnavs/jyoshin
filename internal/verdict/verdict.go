// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package verdict computes deterministic server health verdicts and the Risk Score.
package verdict

import (
	"fmt"
	"math"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/wording"
)

// RiskContributor explains a specific factor increasing the Risk Score.
type RiskContributor struct {
	Label  string `json:"label"`  // e.g. "+12 unmanaged programs"
	Points int    `json:"points"` // Points added to Risk Score
}

// ChaosContributor is an alias for RiskContributor for backwards compatibility.
type ChaosContributor = RiskContributor

// Summary captures the server-computed verdict for the UI and CLI.
type Summary struct {
	Timestamp          time.Time         `json:"timestamp"`
	OneLineVerdict     string            `json:"one_line_verdict"`
	StateLabel         string            `json:"state_label"` // Healthy, Degraded, Critical, Partial visibility, Unknown
	RiskScore          int               `json:"risk_score"`  // 0 - 100
	ChaosIndex         int               `json:"chaos_index"` // Backwards-compatibility alias
	IdentityLine       string            `json:"identity_line"`
	TotalFindings      int               `json:"total_findings"`
	CriticalFindings   int               `json:"critical_findings"`
	HighFindings       int               `json:"high_findings"`
	EstimatedWasteUSD  float64           `json:"estimated_waste_usd_monthly"`
	ListeningPortCount int               `json:"listening_port_count"`
	PublicPortCount    int               `json:"public_port_count"`
	OrphanCount        int               `json:"orphan_count"`
	CoverageHonest     bool              `json:"coverage_honest"`
	CoverageNote       string            `json:"coverage_note,omitempty"`
	RiskContributors   []RiskContributor `json:"risk_contributors,omitempty"`
	ChaosContributors  []RiskContributor `json:"chaos_contributors,omitempty"` // Alias
	TopFindings        []rules.Finding   `json:"top_findings"`
}

// ComputeVerdict calculates the overall server verdict and Risk Score from graph and findings.
func ComputeVerdict(nodes []graph.Node, findings []rules.Finding, orphanCount int) Summary {
	now := time.Now().UTC()
	var (
		critCount   int
		highCount   int
		medCount    int
		lowCount    int
		pubPorts    int
		totalPorts  int
		failedUnits int
		hostname    = "server"
		distro      = "Linux"
		cpuCount    = 0
	)

	for _, n := range nodes {
		switch n.Type {
		case graph.NodeSystem:
			if h, ok := n.Properties["distro"].(string); ok && h != "" {
				distro = h
			}
			if c, ok := n.Properties["cpu_count"].(int); ok {
				cpuCount = c
			}
			if l := n.Label; l != "" {
				hostname = l
			}
		case graph.NodePort:
			totalPorts++
			if exp, ok := n.Properties["exposure_class"].(string); ok && exp == "all_interfaces" {
				pubPorts++
			}
		case graph.NodeService:
			if st, ok := n.Properties["active_state"].(string); ok && st == "failed" {
				failedUnits++
			}
		}
	}

	scoreSum := 0.0
	for _, f := range findings {
		conf := f.Proof.Confidence
		if conf <= 0 {
			conf = 1.0
		}
		switch f.Severity {
		case rules.SeverityCritical:
			critCount++
			scoreSum += 20.0 * conf
		case rules.SeverityHigh:
			highCount++
			scoreSum += 10.0 * conf
		case rules.SeverityMedium:
			medCount++
			scoreSum += 4.0 * conf
		case rules.SeverityLow:
			lowCount++
			scoreSum += 1.0 * conf
		}
	}

	// System risk penalties and contributors tracking
	var contributors []RiskContributor
	orphanPenalty := math.Min(15.0, float64(orphanCount)*2.0)
	if orphanPenalty > 0 {
		contributors = append(contributors, RiskContributor{
			Label:  fmt.Sprintf("+%d unmanaged software programs", orphanCount),
			Points: int(math.Round(orphanPenalty)),
		})
	}

	exposurePenalty := math.Min(20.0, float64(pubPorts)*5.0)
	if exposurePenalty > 0 {
		contributors = append(contributors, RiskContributor{
			Label:  fmt.Sprintf("+%d public listening sockets exposed", pubPorts),
			Points: int(math.Round(exposurePenalty)),
		})
	}

	failedPenalty := float64(failedUnits) * 8.0
	if failedPenalty > 0 {
		contributors = append(contributors, RiskContributor{
			Label:  fmt.Sprintf("+%d failed units", failedUnits),
			Points: int(math.Round(failedPenalty)),
		})
	}

	if critCount > 0 {
		contributors = append(contributors, RiskContributor{
			Label:  fmt.Sprintf("+%d critical security or reliability findings", critCount),
			Points: int(math.Round(float64(critCount) * 20.0)),
		})
	}
	if highCount > 0 {
		contributors = append(contributors, RiskContributor{
			Label:  fmt.Sprintf("+%d high severity findings", highCount),
			Points: int(math.Round(float64(highCount) * 10.0)),
		})
	}

	rawRisk := scoreSum + orphanPenalty + exposurePenalty + failedPenalty
	riskScore := int(math.Min(100.0, math.Round(rawRisk)))

	stateLabel := wording.StateHealthy
	verdict := "Server is healthy with low operational risk."

	switch {
	case riskScore >= 75 || critCount > 0:
		stateLabel = wording.StateCritical
		verdict = fmt.Sprintf("Critical exposure detected: %d critical and %d high findings require review.", critCount, highCount)
	case riskScore >= 16:
		stateLabel = wording.StateDegraded
		verdict = fmt.Sprintf("Server configuration exhibits degraded state: %d findings present.", len(findings))
	}

	// Estimated monthly waste based on findings
	wasteUSD := float64(medCount)*15.0 + float64(lowCount)*5.0

	identity := fmt.Sprintf("%s (%s, %d CPU cores)", hostname, distro, cpuCount)

	topCount := 5
	if len(findings) < topCount {
		topCount = len(findings)
	}

	return Summary{
		Timestamp:          now,
		OneLineVerdict:     verdict,
		StateLabel:         stateLabel,
		RiskScore:          riskScore,
		ChaosIndex:         riskScore,
		IdentityLine:       identity,
		TotalFindings:      len(findings),
		CriticalFindings:   critCount,
		HighFindings:       highCount,
		EstimatedWasteUSD:  wasteUSD,
		ListeningPortCount: totalPorts,
		PublicPortCount:    pubPorts,
		OrphanCount:        orphanCount,
		CoverageHonest:     true,
		RiskContributors:   contributors,
		ChaosContributors:  contributors,
		TopFindings:        findings[:topCount],
	}
}

// ComputeVerdictWithCoverage calculates verdict enforcing coverage honesty.
// If coverage is inadequate, Healthy is suspended and state becomes Partial visibility or Unknown.
func ComputeVerdictWithCoverage(nodes []graph.Node, findings []rules.Finding, orphanCount int, coverageAdequate bool, coverageExplanation string) Summary {
	return ComputeVerdictWithChecks(nodes, findings, orphanCount, coverageAdequate, coverageExplanation, nil)
}

// ComputeVerdictWithChecks calculates verdict incorporating active CheckResults.
// A critical check result forces Critical or Partial visibility with critical findings.
func ComputeVerdictWithChecks(nodes []graph.Node, findings []rules.Finding, orphanCount int, coverageAdequate bool, coverageExplanation string, checkResults []contract.CheckResult) Summary {
	summary := ComputeVerdict(nodes, findings, orphanCount)
	summary.CoverageHonest = coverageAdequate
	summary.CoverageNote = coverageExplanation

	// Inspect check results
	critChecks := 0
	warnChecks := 0
	for _, cr := range checkResults {
		switch cr.Status {
		case contract.StatusCrit:
			critChecks++
			contrib := RiskContributor{
				Label:  fmt.Sprintf("+critical check finding: %s", cr.ID),
				Points: 20,
			}
			summary.RiskContributors = append(summary.RiskContributors, contrib)
			summary.ChaosContributors = append(summary.ChaosContributors, contrib)
		case contract.StatusWarn:
			warnChecks++
			contrib := RiskContributor{
				Label:  fmt.Sprintf("+warning check finding: %s", cr.ID),
				Points: 10,
			}
			summary.RiskContributors = append(summary.RiskContributors, contrib)
			summary.ChaosContributors = append(summary.ChaosContributors, contrib)
		}
	}

	if critChecks > 0 {
		summary.RiskScore = int(math.Min(100.0, float64(summary.RiskScore+critChecks*20+warnChecks*10)))
		summary.ChaosIndex = summary.RiskScore
		summary.CriticalFindings += critChecks
		if !coverageAdequate {
			summary.StateLabel = "Partial visibility (Critical findings)"
			summary.OneLineVerdict = fmt.Sprintf("Critical issue detected (%d critical checks failed) with limited sensor visibility: %s", critChecks, coverageExplanation)
		} else {
			summary.StateLabel = wording.StateCritical
			summary.OneLineVerdict = fmt.Sprintf("Critical exposure detected: %d critical check findings require immediate action.", critChecks)
		}
		return summary
	}

	if len(nodes) == 0 && len(findings) == 0 && !coverageAdequate {
		summary.StateLabel = wording.StateUnknown
		summary.OneLineVerdict = "Host truth unknown: sensors have not yet collected system observations."
		return summary
	}

	if !coverageAdequate && summary.StateLabel == wording.StateHealthy {
		summary.StateLabel = wording.StatePartialVisibility
		summary.OneLineVerdict = fmt.Sprintf("Limited visibility: %s. Cannot certify healthy state.", coverageExplanation)
	}
	return summary
}
