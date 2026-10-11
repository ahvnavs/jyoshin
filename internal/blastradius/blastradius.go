// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package blastradius evaluates downstream impact and safe-to-touch verdicts
// when a node (service, package, port, file, container) is stopped, removed, or changed.
package blastradius

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
)

// Verdict classifies the operational risk of modifying or stopping a node.
type Verdict string

const (
	VerdictSafe      Verdict = "SAFE"
	VerdictCareful   Verdict = "CAREFUL"
	VerdictDangerous Verdict = "DANGEROUS"
	VerdictUnknown   Verdict = "UNKNOWN"
)

// ImpactedEntity represents a single downstream dependency that would be affected.
type ImpactedEntity struct {
	NodeID      string          `json:"node_id"`
	NodeType    graph.NodeType  `json:"node_type"`
	Label       string          `json:"label"`
	Relation    string          `json:"relation"`
	ImpactLevel string          `json:"impact_level"` // "critical", "high", "medium", "low"
	Reason      string          `json:"reason"`
	Certainty   graph.Certainty `json:"certainty"`
}

// Report captures the full blast radius analysis for a target node.
type Report struct {
	TargetNodeID   string           `json:"target_node_id"`
	TargetLabel    string           `json:"target_label"`
	TargetType     graph.NodeType   `json:"target_type"`
	Verdict        Verdict          `json:"verdict"`
	VerdictSummary string           `json:"verdict_summary"`
	Reasons        []string         `json:"reasons"`
	ImpactScore    int              `json:"impact_score"` // 0-100
	ImpactedCount  int              `json:"impacted_count"`
	ImpactedList   []ImpactedEntity `json:"impacted_list"`
}

// Analyzer calculates blast radius from the Provenance Graph.
type Analyzer struct {
	graph *graphbuilder.ProvenanceGraph
}

// NewAnalyzer creates a new blast radius analyzer.
func NewAnalyzer(pGraph *graphbuilder.ProvenanceGraph) *Analyzer {
	return &Analyzer{graph: pGraph}
}

// Analyze computes what breaks if targetID is stopped or removed.
func (a *Analyzer) Analyze(targetID string) (*Report, error) {
	if a.graph == nil {
		return nil, fmt.Errorf("provenance graph unavailable")
	}

	targetNode, exists := a.graph.GetNode(targetID)
	if !exists {
		return nil, fmt.Errorf("node %q not found in graph", targetID)
	}

	depNodes, depEdges, err := a.graph.Dependents(targetID)
	if err != nil {
		return nil, err
	}

	rep := &Report{
		TargetNodeID: targetNode.ID,
		TargetLabel:  targetNode.Label,
		TargetType:   targetNode.Type,
		Verdict:      VerdictSafe,
	}

	edgeMap := make(map[string]graph.Edge, len(depEdges))
	for _, e := range depEdges {
		edgeMap[fmt.Sprintf("%s->%s", e.SourceID, e.TargetID)] = e
	}

	var reasons []string
	impactScore := 0
	var impacted []ImpactedEntity

	for _, dep := range depNodes {
		rel := "depends_on"
		if e, ok := edgeMap[fmt.Sprintf("%s->%s", targetID, dep.ID)]; ok {
			rel = e.Relation
		}

		item := ImpactedEntity{
			NodeID:    dep.ID,
			NodeType:  dep.Type,
			Label:     dep.Label,
			Relation:  rel,
			Certainty: dep.Certainty,
		}

		switch dep.Type {
		case graph.NodePort:
			item.ImpactLevel = "critical"
			item.Reason = fmt.Sprintf("Network port %s will cease accepting connections", dep.Label)
			impactScore += 30
			reasons = append(reasons, fmt.Sprintf("Terminates listening network port %s", dep.Label))

		case graph.NodeService:
			item.ImpactLevel = "high"
			item.Reason = fmt.Sprintf("Service %s depends on this entity", dep.Label)
			impactScore += 25
			reasons = append(reasons, fmt.Sprintf("Downstream service %s will be impacted", dep.Label))

		case graph.NodeProcess:
			item.ImpactLevel = "high"
			item.Reason = fmt.Sprintf("Process %s is actively running from this resource", dep.Label)
			impactScore += 20
			reasons = append(reasons, fmt.Sprintf("Running process %s will terminate", dep.Label))

		case graph.NodeConnection:
			item.ImpactLevel = "critical"
			item.Reason = fmt.Sprintf("Active client connection %s will be dropped", dep.Label)
			impactScore += 35
			reasons = append(reasons, fmt.Sprintf("Active client session %s will be abruptly disconnected", dep.Label))

		default:
			item.ImpactLevel = "medium"
			item.Reason = fmt.Sprintf("Dependent %s entity %s affected", dep.Type, dep.Label)
			impactScore += 10
		}

		impacted = append(impacted, item)
	}

	// Rank impacted entities: critical > high > medium > low
	sort.Slice(impacted, func(i, j int) bool {
		rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		if rank[impacted[i].ImpactLevel] != rank[impacted[j].ImpactLevel] {
			return rank[impacted[i].ImpactLevel] > rank[impacted[j].ImpactLevel]
		}
		return impacted[i].Label < impacted[j].Label
	})

	rep.ImpactedList = impacted
	rep.ImpactedCount = len(impacted)
	if impactScore > 100 {
		impactScore = 100
	}
	rep.ImpactScore = impactScore

	// Determine plain-language verdict
	switch {
	case impactScore >= 50:
		rep.Verdict = VerdictDangerous
		rep.VerdictSummary = fmt.Sprintf("DANGEROUS: Modifying %s will cause immediate outages to %d downstream components.", targetNode.Label, len(impacted))
	case impactScore >= 20:
		rep.Verdict = VerdictCareful
		rep.VerdictSummary = fmt.Sprintf("CAREFUL: Modifying %s impacts %d dependent entities; schedule maintenance window.", targetNode.Label, len(impacted))
	case len(impacted) == 0:
		rep.Verdict = VerdictSafe
		rep.VerdictSummary = fmt.Sprintf("SAFE: No active downstream dependencies observed for %s. Safe to touch or stop.", targetNode.Label)
		reasons = append(reasons, "Zero running processes, open ports, or dependent services rely on this node.")
	default:
		rep.Verdict = VerdictCareful
		rep.VerdictSummary = fmt.Sprintf("CAREFUL: Minor localized impact to %d non-critical entities.", len(impacted))
	}

	rep.Reasons = dedupeStrings(reasons)
	return rep, nil
}

func dedupeStrings(list []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range list {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	return out
}
