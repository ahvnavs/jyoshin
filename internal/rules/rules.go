// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules defines the declarative rule file schema, query conditions,
// the deterministic rule evaluation engine, and finding ranking logic.
package rules

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/OWNER/jyoshin/internal/graph"
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

// MatchCondition specifies how a node or join is matched.
type MatchCondition struct {
	NodeType   graph.NodeType           `yaml:"node_type"`
	Properties map[string]MatchProperty `yaml:"properties,omitempty"`
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
}

// NewEngine creates a new Engine with the specified time evaluation budget.
func NewEngine(budget time.Duration) *Engine {
	if budget <= 0 {
		budget = 5 * time.Second
	}
	return &Engine{
		suppressions: make(map[string]bool),
		history:      make(map[string]*Finding),
		timeBudget:   budget,
	}
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

	for _, rule := range e.rules {
		select {
		case <-evalCtx.Done():
			return currentFindings, errors.New("rule evaluation budget exceeded")
		default:
		}

		if e.suppressions[rule.ID] {
			continue
		}

		for _, node := range nodes {
			if node.Type != rule.Match.NodeType {
				continue
			}

			if matchesProperties(node.Properties, rule.Match.Properties) {
				findingID := fmt.Sprintf("%s:%s", rule.ID, node.ID)
				matchedKeys[findingID] = true

				f := Finding{
					ID:       findingID,
					RuleID:   rule.ID,
					Category: rule.Category,
					Severity: rule.Severity,
					What:     fmt.Sprintf("%s on %s", rule.Name, node.Label),
					SoWhat:   rule.Consequence,
					NowWhat:  rule.Recommendation,
					Proof: Proof{
						Evidence:   node.Evidence,
						Certainty:  rule.Certainty,
						Confidence: rule.Confidence,
					},
					AffectedNodeIDs: []string{node.ID},
					LastSeen:        now,
				}

				// Exposure multiplier
				expMultiplier := 1.0
				if expClass, ok := node.Properties["exposure_class"].(string); ok {
					if expClass == "all_interfaces" {
						expMultiplier = 1.5
					} else if expClass == "private" {
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
	}

	// Lifecycle: identify resolved findings
	for id, prev := range e.history {
		if !matchedKeys[id] && prev.Lifecycle != LifecycleResolved {
			prev.Lifecycle = LifecycleResolved
			prev.LastSeen = now
		}
	}

	SortFindings(currentFindings)
	return currentFindings, nil
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
	}
	return true
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
