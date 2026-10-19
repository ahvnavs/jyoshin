// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy evaluates remediation plans against declarative safety policies.
// Determines whether plans are plannable, require operator approval, or are blocked.
package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/OWNER/kazeshini/internal/plan"
)

// Decision defines the operational verdict for a proposed plan.
type Decision string

const (
	DecisionPlannable       Decision = "plannable"
	DecisionRequireApproval Decision = "require_approval"
	DecisionBlocked         Decision = "blocked"
)

// PolicyRule defines an individual policy constraint.
type PolicyRule struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `yaml:"description" json:"description"`
	Action      string   `yaml:"action" json:"action"` // "deny", "require_approval", "warn"
	MatchKind   string   `yaml:"matchKind,omitempty" json:"matchKind,omitempty"`
	MatchNames  []string `yaml:"matchNames,omitempty" json:"matchNames,omitempty"`
	MaxBlast    int      `yaml:"maxBlast,omitempty" json:"maxBlast,omitempty"`
}

// Config defines active policy constraints including freeze periods and protected resources.
type Config struct {
	FreezePeriodActive bool         `yaml:"freezePeriodActive" json:"freezePeriodActive"`
	ProtectedResources []string     `yaml:"protectedResources" json:"protectedResources"`
	MaxAllowedBlast    int          `yaml:"maxAllowedBlast" json:"maxAllowedBlast"`
	Rules              []PolicyRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// DefaultConfig provides conservative host protections (sshd, kernel, init).
func DefaultConfig() Config {
	return Config{
		ProtectedResources: []string{
			"sshd", "ssh", "systemd", "kernel", "linux-image", "libc6", "kazeshini",
		},
		MaxAllowedBlast: 60,
	}
}

// EvaluationResult captures the policy decision and rationale.
type EvaluationResult struct {
	Decision         Decision `json:"decision"`
	IsBlocked        bool     `json:"is_blocked"`
	RequiresApproval bool     `json:"requires_approval"`
	Summary          string   `json:"summary"`
	Violations       []string `json:"violations,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// Engine evaluates plans against safety policies.
type Engine struct {
	cfg Config
}

func NewEngine(cfg Config) *Engine {
	if len(cfg.ProtectedResources) == 0 {
		cfg = DefaultConfig()
	}
	return &Engine{cfg: cfg}
}

// EvaluatePlan checks whether a plan violates safety policies or freeze windows.
func (e *Engine) EvaluatePlan(ctx context.Context, p *plan.Plan) EvaluationResult {
	if p == nil || len(p.Steps) == 0 {
		return EvaluationResult{
			Decision: DecisionPlannable,
			Summary:  "Plan is empty; no operations proposed.",
		}
	}

	var violations []string
	var warnings []string

	// 1. Check Freeze Period
	if e.cfg.FreezePeriodActive {
		violations = append(violations, "Change freeze period is currently active: all mutations are blocked")
	}

	// 2. Check Protected Resources
	for _, step := range p.Steps {
		// Removal of protected resources is strictly denied
		if step.Action == "remove" || step.Action == "purge" || step.Action == "stop" {
			nameLower := strings.ToLower(step.ResourceName)
			for _, prot := range e.cfg.ProtectedResources {
				if strings.Contains(nameLower, strings.ToLower(prot)) {
					violations = append(violations, fmt.Sprintf(
						"Step %q targets protected resource %q: removal or stopping of critical system components is strictly forbidden",
						step.ID, step.ResourceName,
					))
				}
			}
		}

		// 3. Check Blast Radius Caps
		if e.cfg.MaxAllowedBlast > 0 && step.BlastRadiusScore > e.cfg.MaxAllowedBlast {
			violations = append(violations, fmt.Sprintf(
				"Step %q blast radius (%d) exceeds max policy limit (%d)",
				step.ID, step.BlastRadiusScore, e.cfg.MaxAllowedBlast,
			))
		}

		// High risk steps require approval
		if step.Risk == "high" {
			warnings = append(warnings, fmt.Sprintf("Step %q is classified as HIGH risk", step.ID))
		}
	}

	if len(violations) > 0 {
		return EvaluationResult{
			Decision:   DecisionBlocked,
			IsBlocked:  true,
			Summary:    fmt.Sprintf("Plan is BLOCKED by safety policy (%d violation(s)): %s", len(violations), violations[0]),
			Violations: violations,
			Warnings:   warnings,
		}
	}

	if len(warnings) > 0 || p.MaxRisk == "high" || p.RequiresReboot {
		return EvaluationResult{
			Decision:         DecisionRequireApproval,
			RequiresApproval: true,
			Summary:          "Plan is SAFE TO PLAN but REQUIRES OPERATOR APPROVAL (high risk or reboot requirement)",
			Warnings:         warnings,
		}
	}

	return EvaluationResult{
		Decision: DecisionPlannable,
		Summary:  fmt.Sprintf("Plan conforms to all safety policies and is plannable without blockers (%d steps evaluated)", len(p.Steps)),
	}
}
