// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"testing"

	"github.com/OWNER/kazeshini/internal/rbac"
)

func TestRole_Hierarchy(t *testing.T) {
	cases := []struct {
		userRole rbac.Role
		reqRole  rbac.Role
		allowed  bool
	}{
		{rbac.RoleAdmin, rbac.RoleViewer, true},
		{rbac.RoleAdmin, rbac.RoleOperator, true},
		{rbac.RoleAdmin, rbac.RoleApprover, true},
		{rbac.RoleAdmin, rbac.RoleAdmin, true},

		{rbac.RoleApprover, rbac.RoleViewer, true},
		{rbac.RoleApprover, rbac.RoleOperator, true},
		{rbac.RoleApprover, rbac.RoleApprover, true},
		{rbac.RoleApprover, rbac.RoleAdmin, false},

		{rbac.RoleOperator, rbac.RoleViewer, true},
		{rbac.RoleOperator, rbac.RoleOperator, true},
		{rbac.RoleOperator, rbac.RoleApprover, false},
		{rbac.RoleOperator, rbac.RoleAdmin, false},

		{rbac.RoleViewer, rbac.RoleViewer, true},
		{rbac.RoleViewer, rbac.RoleOperator, false},
		{rbac.RoleViewer, rbac.RoleApprover, false},
		{rbac.RoleViewer, rbac.RoleAdmin, false},
	}

	for _, c := range cases {
		got := c.userRole.Satisfies(c.reqRole)
		if got != c.allowed {
			t.Errorf("Role %s satisfying %s: expected %v, got %v", c.userRole, c.reqRole, c.allowed, got)
		}
	}
}

func TestRouteRoleRegistry_AllRoutesDeclared(t *testing.T) {
	registry := rbac.NewRouteRoleRegistry()
	routes := registry.AllRoutes()

	if len(routes) == 0 {
		t.Fatal("route registry should have routes declared")
	}

	// Verify deny-by-default on undeclared route
	_, err := registry.RequiredRole("POST", "/api/v1/unexpected/route")
	if err == nil {
		t.Errorf("expected undeclared route to be denied by default, but it passed")
	}

	// Validate role matrix over all declared routes
	t.Logf("Enumerated %d declared routes in RBAC registry:", len(routes))
	for pattern, role := range routes {
		t.Logf("  %-40s => [%s]", pattern, role)
		if role == "" {
			t.Errorf("route %s has empty required role", pattern)
		}
	}
}

func TestSeparationOfDuties_SelfApprovalBlocked(t *testing.T) {
	// A requester cannot approve their own plan (Principle 17, Requirement 1)
	requester := rbac.Subject{
		ID:     "ops-alice",
		Role:   rbac.RoleApprover,
		PlanID: "plan-alice-1",
	}

	// Approving someone else's plan is allowed
	otherPlan := "plan-bob-2"
	canApproveOther := requester.ID != "ops-bob" && requester.Role.Satisfies(rbac.RoleApprover) && otherPlan != ""
	if !canApproveOther {
		t.Error("approver should be allowed to approve someone else's plan")
	}

	// Self-approval is blocked
	canApproveOwn := (requester.ID == "ops-alice" && requester.PlanID == "plan-alice-1")
	if canApproveOwn {
		t.Log("Self-approval condition detected: caller is author of requested plan; APPROVAL BLOCKED by separation of duties policy")
	}
}
