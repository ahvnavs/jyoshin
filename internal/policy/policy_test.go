// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"context"
	"testing"

	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/policy"
	"github.com/OWNER/kazeshini/internal/resource"
)

func TestPolicyEngine_Matrix(t *testing.T) {
	ctx := context.Background()

	t.Run("plannable clean plan", func(t *testing.T) {
		eng := policy.NewEngine(policy.DefaultConfig())
		p := &plan.Plan{
			Steps: []plan.Step{
				{
					ID:           "pkg-install-curl",
					ResourceName: "curl",
					Action:       "install",
					Risk:         "low",
				},
			},
		}

		res := eng.EvaluatePlan(ctx, p)
		if res.Decision != policy.DecisionPlannable || res.IsBlocked {
			t.Errorf("expected DecisionPlannable, got %v (blocked: %v)", res.Decision, res.IsBlocked)
		}
	})

	t.Run("blocks removal of protected resources (sshd, kernel, systemd)", func(t *testing.T) {
		eng := policy.NewEngine(policy.DefaultConfig())
		p := &plan.Plan{
			Steps: []plan.Step{
				{
					ID:           "pkg-remove-sshd",
					ResourceKind: resource.KindPackage,
					ResourceName: "openssh-server",
					Action:       "remove",
					Risk:         "high",
				},
			},
		}

		res := eng.EvaluatePlan(ctx, p)
		if res.Decision != policy.DecisionBlocked || !res.IsBlocked {
			t.Errorf("expected DecisionBlocked for removing sshd, got %v", res.Decision)
		}
	})

	t.Run("blocks when change freeze period is active", func(t *testing.T) {
		cfg := policy.DefaultConfig()
		cfg.FreezePeriodActive = true
		eng := policy.NewEngine(cfg)

		p := &plan.Plan{
			Steps: []plan.Step{
				{
					ID:           "pkg-install-htop",
					ResourceName: "htop",
					Action:       "install",
					Risk:         "low",
				},
			},
		}

		res := eng.EvaluatePlan(ctx, p)
		if res.Decision != policy.DecisionBlocked {
			t.Errorf("expected DecisionBlocked during freeze period, got %v", res.Decision)
		}
	})

	t.Run("blocks when blast radius score exceeds max allowed cap", func(t *testing.T) {
		cfg := policy.DefaultConfig()
		cfg.MaxAllowedBlast = 50
		eng := policy.NewEngine(cfg)

		p := &plan.Plan{
			Steps: []plan.Step{
				{
					ID:               "high-blast-action",
					ResourceName:     "custom-lib",
					Action:           "remove",
					BlastRadiusScore: 75,
				},
			},
		}

		res := eng.EvaluatePlan(ctx, p)
		if res.Decision != policy.DecisionBlocked {
			t.Errorf("expected DecisionBlocked when blast score (75) > limit (50), got %v", res.Decision)
		}
	})

	t.Run("requires operator approval for high risk actions", func(t *testing.T) {
		eng := policy.NewEngine(policy.DefaultConfig())
		p := &plan.Plan{
			MaxRisk: "high",
			Steps: []plan.Step{
				{
					ID:           "risky-action",
					ResourceName: "generic-app",
					Action:       "restart",
					Risk:         "high",
				},
			},
		}

		res := eng.EvaluatePlan(ctx, p)
		if res.Decision != policy.DecisionRequireApproval || !res.RequiresApproval {
			t.Errorf("expected DecisionRequireApproval, got %v", res.Decision)
		}
	})
}

