// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package verdict computes deterministic server health verdicts and the Chaos Index.
package verdict

import (
	"fmt"
	"math"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/rules"
)

// Summary captures the server-computed verdict for the UI.
type Summary struct {
	Timestamp          time.Time       `json:"timestamp"`
	OneLineVerdict     string          `json:"one_line_verdict"`
	StateLabel         string          `json:"state_label"` // CALM, MODERATE, MESSY, CRITICAL
	ChaosIndex         int             `json:"chaos_index"` // 0 - 100
	IdentityLine       string          `json:"identity_line"`
	TotalFindings      int             `json:"total_findings"`
	CriticalFindings   int             `json:"critical_findings"`
	HighFindings       int             `json:"high_findings"`
	EstimatedWasteUSD  float64         `json:"estimated_waste_usd_monthly"`
	ListeningPortCount int             `json:"listening_port_count"`
	PublicPortCount    int             `json:"public_port_count"`
	OrphanCount        int             `json:"orphan_count"`
	TopFindings        []rules.Finding `json:"top_findings"`
}

// ComputeVerdict calculates the overall server verdict and Chaos Index from graph and findings.
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

	// System entropy penalties
	orphanPenalty := math.Min(15.0, float64(orphanCount)*2.0)
	exposurePenalty := math.Min(20.0, float64(pubPorts)*5.0)
	failedPenalty := float64(failedUnits) * 8.0

	rawChaos := scoreSum + orphanPenalty + exposurePenalty + failedPenalty
	chaosIndex := int(math.Min(100.0, math.Round(rawChaos)))

	stateLabel := "CALM"
	verdict := "Server is calm, predictable, and healthy with low operational risk."

	switch {
	case chaosIndex >= 75 || critCount > 0:
		stateLabel = "CRITICAL"
		verdict = fmt.Sprintf("Critical exposure detected: %d critical and %d high findings require review.", critCount, highCount)
	case chaosIndex >= 45:
		stateLabel = "MESSY"
		verdict = fmt.Sprintf("Server configuration exhibits disorder: %d issues and unmanaged entropy present.", len(findings))
	case chaosIndex >= 16:
		stateLabel = "MODERATE"
		verdict = fmt.Sprintf("Server operating moderately: %d minor findings, low immediate risk.", len(findings))
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
		ChaosIndex:         chaosIndex,
		IdentityLine:       identity,
		TotalFindings:      len(findings),
		CriticalFindings:   critCount,
		HighFindings:       highCount,
		EstimatedWasteUSD:  wasteUSD,
		ListeningPortCount: totalPorts,
		PublicPortCount:    pubPorts,
		OrphanCount:        orphanCount,
		TopFindings:        findings[:topCount],
	}
}
