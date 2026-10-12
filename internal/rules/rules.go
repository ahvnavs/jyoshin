// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules defines the declarative rule file schema, query conditions,
// the deterministic rule evaluation engine, and finding ranking logic.
package rules

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/OWNER/kazeshini/data"
	"github.com/OWNER/kazeshini/internal/graph"
)

// Category classifies findings by operational domain.
type Category string

const (
	CategoryCost       Category = "cost"
	CategorySecurity   Category = "security"
	CategoryEfficiency Category = "efficiency"
	CategoryOperations Category = "operations"
	CategoryChange     Category = "change"
)

func (c Category) IsValid() bool {
	switch c {
	case CategoryCost, CategorySecurity, CategoryEfficiency, CategoryOperations, CategoryChange:
		return true
	default:
		return false
	}
}

// Severity rates the impact of a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// RiskLevel represents the risk of taking a recommended action.
type RiskLevel string

const (
	RiskNone   RiskLevel = "none"
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

func (r RiskLevel) IsValid() bool {
	switch r {
	case RiskNone, RiskLow, RiskMedium, RiskHigh:
		return true
	default:
		return false
	}
}

// FindingLifecycle models finding progression over time.
type FindingLifecycle string

const (
	LifecycleNew      FindingLifecycle = "new"
	LifecycleOngoing  FindingLifecycle = "ongoing"
	LifecycleResolved FindingLifecycle = "resolved"
)

// NowWhat conveys the actionable recommendation.
type NowWhat struct {
	Action      string    `json:"action" yaml:"action"`
	RiskLevel   RiskLevel `json:"risk_level" yaml:"risk_level"`
	Reversible  bool      `json:"reversible" yaml:"reversible"`
	Explanation string    `json:"explanation,omitempty" yaml:"explanation,omitempty"`
}

func (nw NowWhat) Validate() error {
	if nw.Action == "" {
		return errors.New("now_what action is required")
	}
	if !nw.RiskLevel.IsValid() {
		return fmt.Errorf("invalid risk_level: %q", nw.RiskLevel)
	}
	return nil
}

// Proof provides deterministic provenance and certainty guarantees.
type Proof struct {
	Evidence   []graph.Evidence `json:"evidence" yaml:"evidence"`
	Certainty  graph.Certainty  `json:"certainty" yaml:"certainty"`
	Confidence float64          `json:"confidence" yaml:"confidence"`
}

func (p Proof) Validate() error {
	if !p.Certainty.IsValid() {
		return fmt.Errorf("invalid proof certainty: %q", p.Certainty)
	}
	if p.Confidence < 0.0 || p.Confidence > 1.0 {
		return fmt.Errorf("proof confidence %f out of range [0.0, 1.0]", p.Confidence)
	}
	for i, ev := range p.Evidence {
		if err := ev.Validate(); err != nil {
			return fmt.Errorf("invalid proof evidence at index %d: %w", i, err)
		}
	}
	return nil
}

// Finding represents an evaluated rule result.
type Finding struct {
	ID              string           `json:"id" yaml:"id"`
	RuleID          string           `json:"rule_id" yaml:"rule_id"`
	Category        Category         `json:"category" yaml:"category"`
	Severity        Severity         `json:"severity" yaml:"severity"`
	What            string           `json:"what" yaml:"what"`
	SoWhat          string           `json:"so_what" yaml:"so_what"`
	NowWhat         NowWhat          `json:"now_what" yaml:"now_what"`
	Proof           Proof            `json:"proof" yaml:"proof"`
	Score           float64          `json:"score"`
	Lifecycle       FindingLifecycle `json:"lifecycle"`
	FirstSeen       time.Time        `json:"first_seen"`
	LastSeen        time.Time        `json:"last_seen"`
	AffectedNodeIDs []string         `json:"affected_node_ids,omitempty"`
}

func (f Finding) Validate() error {
	if f.ID == "" {
		return errors.New("finding id is required")
	}
	if !f.Category.IsValid() {
		return fmt.Errorf("invalid category: %q", f.Category)
	}
	if !f.Severity.IsValid() {
		return fmt.Errorf("invalid severity: %q", f.Severity)
	}
	if f.What == "" {
		return errors.New("what is required")
	}
	if f.SoWhat == "" {
		return errors.New("so_what is required")
	}
	if err := f.NowWhat.Validate(); err != nil {
		return fmt.Errorf("invalid now_what: %w", err)
	}
	if err := f.Proof.Validate(); err != nil {
		return fmt.Errorf("invalid proof: %w", err)
	}
	if f.FirstSeen.IsZero() {
		return errors.New("first_seen timestamp must not be zero")
	}
	return nil
}

// MatchProperty represents attribute match conditions on a node.
type MatchProperty struct {
	Equals      any      `yaml:"equals,omitempty"`
	Contains    string   `yaml:"contains,omitempty"`
	StartsWith  string   `yaml:"starts_with,omitempty"`
	In          []any    `yaml:"in,omitempty"`
	GreaterThan *float64 `yaml:"greater_than,omitempty"`
	LessThan    *float64 `yaml:"less_than,omitempty"`
}

// MatchJoin specifies a traversal join along graph edges.
type MatchJoin struct {
	Relation   string                   `yaml:"relation,omitempty"`   // Edge relation name (e.g. "installed_by", "executes", "listens_on")
	Direction  string                   `yaml:"direction,omitempty"`  // "in" (target<-source) or "out" (source->target). Default "in".
	NodeType   graph.NodeType           `yaml:"node_type,omitempty"`  // Target node type to match along the edge
	Properties map[string]MatchProperty `yaml:"properties,omitempty"` // Attribute match on joined node
}

// MatchAggregate specifies grouping and aggregate threshold conditions across graph nodes.
type MatchAggregate struct {
	GroupBy       string   `yaml:"group_by,omitempty"`       // Property name to group by
	CountDistinct string   `yaml:"count_distinct,omitempty"` // Property name to count unique values of
	GreaterThan   *float64 `yaml:"greater_than,omitempty"`   // Minimum threshold for group count
}

// MatchDuration specifies time duration conditions.
type MatchDuration struct {
	MinHours   float64 `yaml:"min_hours,omitempty"`   // Sustained time in hours
	MinSeconds float64 `yaml:"min_seconds,omitempty"` // Sustained time in seconds
}

// MatchCondition specifies how a node, join, aggregate, or dataset match is evaluated.
type MatchCondition struct {
	NodeType   graph.NodeType           `yaml:"node_type"`
	Properties map[string]MatchProperty `yaml:"properties,omitempty"`
	Join       *MatchJoin               `yaml:"join,omitempty"`
	Aggregate  *MatchAggregate          `yaml:"aggregate,omitempty"`
	Duration   *MatchDuration           `yaml:"duration,omitempty"`
	CheckEOL   bool                     `yaml:"check_eol,omitempty"` // Match against data/eol.yaml
}

// RuleDefinition represents a declarative YAML rule file.
type RuleDefinition struct {
	ID             string          `yaml:"id"`
	Name           string          `yaml:"name"`
	Description    string          `yaml:"description"`
	Category       Category        `yaml:"category"`
	Severity       Severity        `yaml:"severity"`
	Match          MatchCondition  `yaml:"match"`
	Consequence    string          `yaml:"consequence"`
	Recommendation NowWhat         `yaml:"recommendation"`
	Certainty      graph.Certainty `yaml:"certainty,omitempty"`
	Confidence     float64         `yaml:"confidence,omitempty"`
}

// Validate validates rule structure and fields for linting.
func (r *RuleDefinition) Validate() error {
	if r.ID == "" {
		return errors.New("rule field 'id' is required")
	}
	if r.Name == "" {
		return errors.New("rule field 'name' is required")
	}
	if !r.Category.IsValid() {
		return fmt.Errorf("invalid category %q (must be cost, security, efficiency, operations, change)", r.Category)
	}
	if !r.Severity.IsValid() {
		return fmt.Errorf("invalid severity %q (must be info, low, medium, high, critical)", r.Severity)
	}
	if r.Match.NodeType == "" {
		return errors.New("rule field 'match.node_type' is required")
	}
	if r.Consequence == "" {
		return errors.New("rule field 'consequence' is required")
	}
	if err := r.Recommendation.Validate(); err != nil {
		return fmt.Errorf("invalid recommendation: %w", err)
	}
	if r.Certainty == "" {
		r.Certainty = graph.CertaintyObserved
	}
	if !r.Certainty.IsValid() {
		return fmt.Errorf("invalid certainty: %q", r.Certainty)
	}
	if r.Confidence == 0 {
		r.Confidence = 1.0
	}
	return nil
}

// CalculateScore calculates finding score according to docs/RANKING.md.
func CalculateScore(f Finding, exposureMultiplier float64) float64 {
	base := 5.0
	switch f.Severity {
	case SeverityCritical:
		base = 40.0
	case SeverityHigh:
		base = 30.0
	case SeverityMedium:
		base = 20.0
	case SeverityLow:
		base = 10.0
	}

	blastRadius := 1.0
	n := len(f.AffectedNodeIDs)
	if n > 5 {
		blastRadius = 1.4
	} else if n >= 2 {
		blastRadius = 1.2
	}

	conf := f.Proof.Confidence
	if conf <= 0 {
		conf = 1.0
	}

	score := base * exposureMultiplier * blastRadius * conf
	return math.Min(100.0, math.Round(score*100)/100)
}

// SortFindings orders findings deterministically (score desc, severity desc, id asc).
func SortFindings(list []Finding) {
	sevWeight := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	sort.Slice(list, func(i, j int) bool {
		if list[i].Score != list[j].Score {
			return list[i].Score > list[j].Score
		}
		if sevWeight[list[i].Severity] != sevWeight[list[j].Severity] {
			return sevWeight[list[i].Severity] > sevWeight[list[j].Severity]
		}
		return list[i].ID < list[j].ID
	})
}

// Engine loads and deterministically evaluates rules with time budgets and lifecycle tracking.
type Engine struct {
	mu           sync.RWMutex
	rules        []RuleDefinition
	suppressions map[string]bool // ruleID -> suppressed
	history      map[string]*Finding
	timeBudget   time.Duration
	eolMap       map[string]map[string]string // runtime -> version -> eolDate
	pricingTable map[string]float64           // "aws:t3.medium" -> monthly_usd
}

// NewEngine creates a new Engine with the specified time evaluation budget.
func NewEngine(budget time.Duration) *Engine {
	if budget <= 0 {
		budget = 5 * time.Second
	}
	eng := &Engine{
		suppressions: make(map[string]bool),
		history:      make(map[string]*Finding),
		timeBudget:   budget,
		eolMap:       loadEmbeddedEOLMap(),
		pricingTable: loadEmbeddedPricingTable(),
	}
	return eng
}

// LoadRule loads a single YAML rule definition.
func (e *Engine) LoadRule(data []byte) (*RuleDefinition, error) {
	var r RuleDefinition
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("yaml parse error: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
	return &r, nil
}

// LoadDirectory loads all YAML rule files from dir.
func (e *Engine) LoadDirectory(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if _, err := e.LoadRule(data); err == nil {
			count++
		}
	}
	return count, nil
}

// LoadSuppressionFile loads a list of suppressed rule IDs from a text file.
func (e *Engine) LoadSuppressionFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			e.suppressions[trimmed] = true
		}
	}
	return nil
}

// Evaluate runs all loaded rules against nodes and edges within the time budget.
func (e *Engine) Evaluate(ctx context.Context, nodes []graph.Node, edges []graph.Edge) ([]Finding, error) {
	evalCtx, cancel := context.WithTimeout(ctx, e.timeBudget)
	defer cancel()

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().UTC()
	var currentFindings []Finding
	matchedKeys := make(map[string]bool)

	// Pre-index graph nodes and edges for joins
	nodeMap := make(map[string]graph.Node, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	inEdges := make(map[string][]graph.Edge)
	outEdges := make(map[string][]graph.Edge)
	for _, edge := range edges {
		inEdges[edge.TargetID] = append(inEdges[edge.TargetID], edge)
		outEdges[edge.SourceID] = append(outEdges[edge.SourceID], edge)
	}

	for _, rule := range e.rules {
		select {
		case <-evalCtx.Done():
			return currentFindings, errors.New("rule evaluation budget exceeded")
		default:
		}

		if e.suppressions[rule.ID] {
			continue
		}

		// Handle Aggregate Rules
		if rule.Match.Aggregate != nil {
			aggFindings := e.evaluateAggregateRule(rule, nodes, nodeMap, now)
			for _, f := range aggFindings {
				matchedKeys[f.ID] = true
				if prev, exists := e.history[f.ID]; exists {
					f.FirstSeen = prev.FirstSeen
					f.Lifecycle = LifecycleOngoing
				} else {
					f.FirstSeen = now
					f.Lifecycle = LifecycleNew
				}
				e.history[f.ID] = &f
				currentFindings = append(currentFindings, f)
			}
			continue
		}

		// Handle Standard, Join, Duration, and EOL Node Rules
		for _, node := range nodes {
			if rule.Match.CheckEOL {
				if node.Type != rule.Match.NodeType && node.Type != graph.NodeOrigin {
					continue
				}
			} else if node.Type != rule.Match.NodeType {
				continue
			}

			if !matchesProperties(node.Properties, rule.Match.Properties) {
				continue
			}

			// Duration condition check
			if rule.Match.Duration != nil {
				if !matchesDuration(node, rule.Match.Duration, now) {
					continue
				}
			}

			// EOL Condition check
			if rule.Match.CheckEOL {
				isEOL, _ := e.checkNodeEOL(node)
				if !isEOL {
					continue
				}
			}

			// Join condition check
			joinedNodes := []graph.Node{}
			if rule.Match.Join != nil {
				matched, joins := matchesJoin(node, rule.Match.Join, inEdges, outEdges, nodeMap)
				if !matched {
					continue
				}
				joinedNodes = joins
			}

			findingID := fmt.Sprintf("%s:%s", rule.ID, node.ID)
			matchedKeys[findingID] = true

			// Collect affected node IDs and combined proof evidence
			affectedIDs := []string{node.ID}
			evidence := make([]graph.Evidence, 0, len(node.Evidence))
			evidence = append(evidence, node.Evidence...)
			for _, jn := range joinedNodes {
				affectedIDs = append(affectedIDs, jn.ID)
				evidence = append(evidence, jn.Evidence...)
			}

			f := Finding{
				ID:       findingID,
				RuleID:   rule.ID,
				Category: rule.Category,
				Severity: rule.Severity,
				What:     fmt.Sprintf("%s on %s", rule.Name, node.Label),
				SoWhat:   rule.Consequence,
				NowWhat:  rule.Recommendation,
				Proof: Proof{
					Evidence:   evidence,
					Certainty:  rule.Certainty,
					Confidence: rule.Confidence,
				},
				AffectedNodeIDs: affectedIDs,
				LastSeen:        now,
			}

			// Enhance Cost Findings with pricing table reference
			if rule.Category == CategoryCost {
				f.What = e.enrichCostDescription(f.What, node)
			}

			// Exposure multiplier
			expMultiplier := 1.0
			if expClass, ok := node.Properties["exposure_class"].(string); ok {
				switch expClass {
				case "all_interfaces":
					expMultiplier = 1.5
				case "private":
					expMultiplier = 1.2
				}
			}

			f.Score = CalculateScore(f, expMultiplier)

			// Lifecycle tracking
			if prev, exists := e.history[findingID]; exists {
				f.FirstSeen = prev.FirstSeen
				f.Lifecycle = LifecycleOngoing
			} else {
				f.FirstSeen = now
				f.Lifecycle = LifecycleNew
			}

			e.history[findingID] = &f
			currentFindings = append(currentFindings, f)
		}
	}

	// Deduplicate overlapping findings on the same process node
	// (e.g. SEC-DELETED-BINARY-EXEC and SEC-PROC-TMP-EXEC)
	var dedupedFindings []Finding
	procTmpIndex := make(map[string]int) // nodeID -> index in dedupedFindings

	for _, f := range currentFindings {
		nodeID := ""
		if len(f.AffectedNodeIDs) > 0 {
			nodeID = f.AffectedNodeIDs[0]
		}

		if (f.RuleID == "SEC-DELETED-BINARY-EXEC" || f.RuleID == "SEC-PROC-TMP-EXEC") && nodeID != "" {
			if existingIdx, exists := procTmpIndex[nodeID]; exists {
				// Merge into existing finding
				existing := &dedupedFindings[existingIdx]
				existing.What = fmt.Sprintf("Process executing deleted binary from temporary path on %s", nodeID)
				existing.SoWhat = fmt.Sprintf("%s Additionally, %s", existing.SoWhat, f.SoWhat)
				existing.Proof.Evidence = append(existing.Proof.Evidence, f.Proof.Evidence...)
				continue
			}
			procTmpIndex[nodeID] = len(dedupedFindings)
		}

		dedupedFindings = append(dedupedFindings, f)
	}

	// Lifecycle: identify resolved findings
	for id, prev := range e.history {
		if !matchedKeys[id] && prev.Lifecycle != LifecycleResolved {
			prev.Lifecycle = LifecycleResolved
			prev.LastSeen = now
		}
	}

	SortFindings(dedupedFindings)
	return dedupedFindings, nil
}

func matchesDuration(node graph.Node, dur *MatchDuration, now time.Time) bool {
	if dur == nil {
		return true
	}

	// Check uptime_seconds property first if present
	if dur.MinSeconds > 0 {
		if uptime, ok := node.Properties["uptime_seconds"]; ok {
			var uSec float64
			switch v := uptime.(type) {
			case float64:
				uSec = v
			case int:
				uSec = float64(v)
			case int64:
				uSec = float64(v)
			}
			if uSec < dur.MinSeconds {
				return false
			}
		}
	}

	// Check time elapsed since first seen
	if dur.MinHours > 0 {
		elapsedHours := now.Sub(node.FirstSeen).Hours()
		if elapsedHours < dur.MinHours {
			// Also check if uptime_seconds satisfies it
			if uptime, ok := node.Properties["uptime_seconds"]; ok {
				var uSec float64
				switch v := uptime.(type) {
				case float64:
					uSec = v
				case int:
					uSec = float64(v)
				case int64:
					uSec = float64(v)
				}
				if uSec < dur.MinHours*3600 {
					return false
				}
			} else {
				return false
			}
		}
	}

	return true
}

func matchesJoin(node graph.Node, join *MatchJoin, inEdges, outEdges map[string][]graph.Edge, nodeMap map[string]graph.Node) (bool, []graph.Node) {
	if join == nil {
		return true, nil
	}

	var candidateEdges []graph.Edge
	if join.Direction == "out" {
		candidateEdges = outEdges[node.ID]
	} else {
		// Default to "in"
		candidateEdges = inEdges[node.ID]
	}

	var matchedNodes []graph.Node
	for _, e := range candidateEdges {
		if join.Relation != "" && e.Relation != join.Relation {
			continue
		}

		targetID := e.SourceID
		if join.Direction == "out" {
			targetID = e.TargetID
		}

		targetNode, exists := nodeMap[targetID]
		if !exists {
			continue
		}

		if join.NodeType != "" && targetNode.Type != join.NodeType {
			continue
		}

		if matchesProperties(targetNode.Properties, join.Properties) {
			matchedNodes = append(matchedNodes, targetNode)
		}
	}

	return len(matchedNodes) > 0, matchedNodes
}

func (e *Engine) evaluateAggregateRule(rule RuleDefinition, nodes []graph.Node, nodeMap map[string]graph.Node, now time.Time) []Finding {
	agg := rule.Match.Aggregate
	if agg == nil {
		return nil
	}

	var findings []Finding
	// Group matching nodes
	groups := make(map[string][]graph.Node)

	for _, n := range nodes {
		if n.Type != rule.Match.NodeType {
			continue
		}
		if !matchesProperties(n.Properties, rule.Match.Properties) {
			continue
		}

		groupKey := "all"
		if agg.GroupBy != "" {
			if val, ok := n.Properties[agg.GroupBy]; ok {
				groupKey = fmt.Sprintf("%v", val)
			}
		}
		groups[groupKey] = append(groups[groupKey], n)
	}

	for groupKey, groupNodes := range groups {
		count := float64(len(groupNodes))
		if agg.CountDistinct != "" {
			distinctVals := make(map[string]bool)
			for _, gn := range groupNodes {
				if v, ok := gn.Properties[agg.CountDistinct]; ok {
					distinctVals[fmt.Sprintf("%v", v)] = true
				}
			}
			count = float64(len(distinctVals))
		}

		threshold := 1.0
		if agg.GreaterThan != nil {
			threshold = *agg.GreaterThan
		}

		if count > threshold {
			findingID := fmt.Sprintf("%s:%s", rule.ID, groupKey)
			var affectedIDs []string
			var evidence []graph.Evidence
			for _, gn := range groupNodes {
				affectedIDs = append(affectedIDs, gn.ID)
				evidence = append(evidence, gn.Evidence...)
			}

			f := Finding{
				ID:       findingID,
				RuleID:   rule.ID,
				Category: rule.Category,
				Severity: rule.Severity,
				What:     fmt.Sprintf("%s (%s: count=%.0f)", rule.Name, groupKey, count),
				SoWhat:   rule.Consequence,
				NowWhat:  rule.Recommendation,
				Proof: Proof{
					Evidence:   evidence,
					Certainty:  rule.Certainty,
					Confidence: rule.Confidence,
				},
				AffectedNodeIDs: affectedIDs,
				LastSeen:        now,
			}
			f.Score = CalculateScore(f, 1.0)
			findings = append(findings, f)
		}
	}

	return findings
}

func (e *Engine) checkNodeEOL(node graph.Node) (bool, string) {
	if node.Properties == nil {
		return false, ""
	}

	// Check distro
	if distro, ok := node.Properties["distro_family"].(string); ok {
		if ver, ok := node.Properties["distro_version"].(string); ok {
			if eolDate, found := e.eolLookup(distro, ver); found {
				return true, eolDate
			}
		}
	}

	// Check runtime / package / origin
	name := ""
	if n, ok := node.Properties["name"].(string); ok {
		name = n
	} else if src, ok := node.Properties["source"].(string); ok {
		name = src
	}
	if name != "" {
		if ver, ok := node.Properties["version"].(string); ok {
			if eolDate, found := e.eolLookup(name, ver); found {
				return true, eolDate
			}
		}
	}

	return false, ""
}

func (e *Engine) eolLookup(name, version string) (string, bool) {
	table, ok := e.eolMap[strings.ToLower(name)]
	if !ok {
		return "", false
	}
	now := time.Now().Format("2006-01-02")
	for verPrefix, eolDate := range table {
		if strings.Contains(version, verPrefix) && eolDate < now {
			return eolDate, true
		}
	}
	return "", false
}

func (e *Engine) enrichCostDescription(what string, node graph.Node) string {
	provider := "aws"
	if p, ok := node.Properties["cloud_provider"].(string); ok && p != "" && p != "none" {
		provider = p
	}
	instType := "t3.medium"
	if it, ok := node.Properties["instance_type"].(string); ok && it != "" {
		instType = it
	}

	key := fmt.Sprintf("%s:%s", provider, instType)
	cost, ok := e.pricingTable[key]
	if !ok {
		cost = 30.00 // Default reference
	}

	return fmt.Sprintf("%s (~$%.2f/mo estimate, table dated 2026-01-01)", what, cost)
}

func matchesProperties(nodeProps map[string]any, matchProps map[string]MatchProperty) bool {
	if len(matchProps) == 0 {
		return true
	}
	if nodeProps == nil {
		return false
	}

	for key, cond := range matchProps {
		val, exists := nodeProps[key]
		if !exists {
			return false
		}

		if cond.Equals != nil {
			if fmt.Sprintf("%v", val) != fmt.Sprintf("%v", cond.Equals) {
				return false
			}
		}
		if cond.Contains != "" {
			if !strings.Contains(fmt.Sprintf("%v", val), cond.Contains) {
				return false
			}
		}
		if cond.StartsWith != "" {
			if !strings.HasPrefix(fmt.Sprintf("%v", val), cond.StartsWith) {
				return false
			}
		}
		if len(cond.In) > 0 {
			matchedIn := false
			valStr := fmt.Sprintf("%v", val)
			for _, item := range cond.In {
				if valStr == fmt.Sprintf("%v", item) {
					matchedIn = true
					break
				}
			}
			if !matchedIn {
				return false
			}
		}
		if cond.GreaterThan != nil {
			fVal, ok := toFloat(val)
			if !ok || fVal <= *cond.GreaterThan {
				return false
			}
		}
		if cond.LessThan != nil {
			fVal, ok := toFloat(val)
			if !ok || fVal >= *cond.LessThan {
				return false
			}
		}
	}
	return true
}

func toFloat(val any) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case uint32:
		return float64(v), true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// LintRule parses and checks a rule file, reporting descriptive syntax/schema errors.
func LintRule(path string) (*RuleDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file %q: %w", path, err)
	}
	var r RuleDefinition
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("yaml syntax error: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("rule schema violation: %w", err)
	}
	return &r, nil
}

func loadEmbeddedEOLMap() map[string]map[string]string {
	res := make(map[string]map[string]string)
	dataBytes, err := data.EOLData.ReadFile("eol.yaml")
	if err != nil {
		return res
	}

	scanner := bufio.NewScanner(bytes.NewReader(dataBytes))
	var currentItem string
	var currentVer string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasSuffix(line, ":") && !strings.Contains(line, "version") && !strings.Contains(line, "distros") && !strings.Contains(line, "runtimes") {
			currentItem = strings.TrimSuffix(line, ":")
			if _, ok := res[currentItem]; !ok {
				res[currentItem] = make(map[string]string)
			}
		}
		if strings.HasPrefix(line, "- version: ") {
			currentVer = strings.Trim(strings.TrimPrefix(line, "- version: "), `"'`)
		}
		if strings.HasPrefix(line, "eol: ") && currentItem != "" && currentVer != "" {
			eolDate := strings.Trim(strings.TrimPrefix(line, "eol: "), `"'`)
			res[currentItem][currentVer] = eolDate
		}
	}
	return res
}

func loadEmbeddedPricingTable() map[string]float64 {
	res := make(map[string]float64)
	dataBytes, err := data.EOLData.ReadFile("prices.yaml")
	if err != nil {
		return res
	}

	var doc struct {
		Providers map[string]map[string]struct {
			HourlyUSD  float64 `yaml:"hourly_usd"`
			MonthlyUSD float64 `yaml:"monthly_usd"`
		} `yaml:"providers"`
	}

	if err := yaml.Unmarshal(dataBytes, &doc); err == nil {
		for prov, instances := range doc.Providers {
			for inst, price := range instances {
				key := fmt.Sprintf("%s:%s", prov, inst)
				res[key] = price.MonthlyUSD
			}
		}
	}
	return res
}
