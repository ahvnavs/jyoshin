// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"fmt"
	"strings"
)

// Role defines the authorization tier for API operations.
type Role string

const (
	// RoleViewer can inspect observations, findings, and read-only telemetry.
	RoleViewer Role = "viewer"

	// RoleOperator can run diagnostics, orphan scans, and generate remediation plans.
	RoleOperator Role = "operator"

	// RoleApprover can cryptographically approve remediation plans (separation of duties).
	RoleApprover Role = "approver"

	// RoleAdmin can modify configuration, rotate authentication keys/tokens, and access debug profiles.
	RoleAdmin Role = "admin"
)

// Hierarchy ranks: viewer (1) < operator (2) < approver (3) < admin (4).
// However, separation of duties overrides hierarchy for plan approval:
// A user cannot approve a plan they requested (Principle 17, Requirement 1).
var roleRank = map[Role]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleApprover: 3,
	RoleAdmin:    4,
}

// Satisfies checks whether the current role has at least the required role's permission level.
func (r Role) Satisfies(required Role) bool {
	return roleRank[r] >= roleRank[required]
}

// Subject represents an authenticated caller identity.
type Subject struct {
	ID     string   `json:"id"`
	Role   Role     `json:"role"`
	Method string   `json:"auth_method"` // "token", "oidc", "mtls", "proxy", "session"
	Groups []string `json:"groups,omitempty"`
	PlanID string   `json:"current_plan_id,omitempty"`
}

type contextKey struct{}

var subjectContextKey = contextKey{}

// WithSubject injects an authenticated Subject into context.
func WithSubject(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, subjectContextKey, s)
}

// FromContext extracts the authenticated Subject, or returns an empty subject with RoleViewer.
func FromContext(ctx context.Context) (Subject, bool) {
	s, ok := ctx.Value(subjectContextKey).(Subject)
	return s, ok
}

// RouteRoleRegistry maps every registered HTTP route pattern to its required Role.
// Deny-by-default: if a route is not declared, access is blocked.
type RouteRoleRegistry struct {
	routes map[string]Role
}

// NewRouteRoleRegistry constructs a registry with all declared API routes.
func NewRouteRoleRegistry() *RouteRoleRegistry {
	r := &RouteRoleRegistry{
		routes: make(map[string]Role),
	}
	r.registerDefaults()
	return r
}

func (r *RouteRoleRegistry) registerDefaults() {
	// Public / Unauthenticated routes (special handling in middleware)
	r.routes["GET /api/v1/health"] = RoleViewer
	r.routes["GET /api/v1/version"] = RoleViewer
	r.routes["GET /api/v1/auth/status"] = RoleViewer

	// Viewer tier: Read-only observations, graph, briefing, coverage, reports
	r.routes["GET /api/v1/sensors"] = RoleViewer
	r.routes["GET /api/v1/observations/{sensor}"] = RoleViewer
	r.routes["GET /api/v1/self"] = RoleViewer
	r.routes["GET /api/v1/inventory"] = RoleViewer
	r.routes["GET /api/v1/origins"] = RoleViewer
	r.routes["GET /api/v1/runtimes"] = RoleViewer
	r.routes["GET /api/v1/graph"] = RoleViewer
	r.routes["GET /api/v1/graph/node/{id}"] = RoleViewer
	r.routes["GET /api/v1/graph/why/{id}"] = RoleViewer
	r.routes["GET /api/v1/graph/dependents/{id}"] = RoleViewer
	r.routes["GET /api/v1/snapshots"] = RoleViewer
	r.routes["GET /api/v1/findings"] = RoleViewer
	r.routes["GET /api/v1/verdict"] = RoleViewer
	r.routes["GET /api/v1/stream"] = RoleViewer
	r.routes["GET /api/v1/changes"] = RoleViewer
	r.routes["GET /api/v1/forecasts"] = RoleViewer
	r.routes["GET /api/v1/baselines"] = RoleViewer
	r.routes["GET /api/v1/blastradius/{id}"] = RoleViewer
	r.routes["GET /api/v1/dependencies"] = RoleViewer
	r.routes["GET /api/v1/decommission"] = RoleViewer
	r.routes["GET /api/v1/migration"] = RoleViewer
	r.routes["GET /api/v1/report"] = RoleViewer
	r.routes["GET /api/v1/coverage"] = RoleViewer
	r.routes["GET /api/v1/briefing"] = RoleViewer
	r.routes["GET /api/v1/overview"] = RoleViewer
	r.routes["GET /api/v1/checks"] = RoleViewer
	r.routes["GET /api/v1/activity"] = RoleViewer
	r.routes["GET /api/v1/drift"] = RoleViewer
	r.routes["GET /api/v1/plans"] = RoleViewer
	r.routes["GET /api/v1/software"] = RoleViewer
	r.routes["GET /api/v1/software/{pkg}"] = RoleViewer
	r.routes["GET /api/v1/platforms"] = RoleViewer
	r.routes["GET /api/v1/actuator/status"] = RoleViewer
	r.routes["GET /metrics"] = RoleViewer

	// Operator tier: Diagnostic runs, scans, planning software mutations
	r.routes["POST /api/v1/orphan/scan"] = RoleOperator
	r.routes["POST /api/v1/checks/{id}/run"] = RoleOperator
	r.routes["POST /api/v1/software/plan"] = RoleOperator

	// Approver tier: Approving execution plans
	r.routes["POST /api/v1/plans/{id}/approve"] = RoleApprover

	// Admin tier: Configuration, token rotation, debug profiling
	r.routes["POST /api/v1/auth/tokens/rotate"] = RoleAdmin
	r.routes["GET /debug/pprof/"] = RoleAdmin
	r.routes["GET /debug/pprof/cmdline"] = RoleAdmin
	r.routes["GET /debug/pprof/profile"] = RoleAdmin
	r.routes["GET /debug/pprof/symbol"] = RoleAdmin
	r.routes["GET /debug/pprof/trace"] = RoleAdmin
}

// RequiredRole returns the role requirement for method and path, or error if undeclared.
func (r *RouteRoleRegistry) RequiredRole(method, path string) (Role, error) {
	exact := fmt.Sprintf("%s %s", method, path)
	if role, exists := r.routes[exact]; exists {
		return role, nil
	}

	// Try pattern matching for dynamic path segments ({id}, {pkg}, {sensor})
	for pattern, role := range r.routes {
		pMethod, pPath, ok := strings.Cut(pattern, " ")
		if !ok || pMethod != method {
			continue
		}
		if matchPathPattern(pPath, path) {
			return role, nil
		}
	}

	return "", fmt.Errorf("route %q lacks required role declaration (deny by default)", exact)
}

func matchPathPattern(pattern, actual string) bool {
	pParts := strings.Split(strings.Trim(pattern, "/"), "/")
	aParts := strings.Split(strings.Trim(actual, "/"), "/")
	if len(pParts) != len(aParts) {
		return false
	}
	for i := range pParts {
		if strings.HasPrefix(pParts[i], "{") && strings.HasSuffix(pParts[i], "}") {
			continue // Dynamic path parameter matches any segment
		}
		if pParts[i] != aParts[i] {
			return false
		}
	}
	return true
}

// AllRoutes returns all registered routes for exhaustive verification tests.
func (r *RouteRoleRegistry) AllRoutes() map[string]Role {
	cp := make(map[string]Role, len(r.routes))
	for k, v := range r.routes {
		cp[k] = v
	}
	return cp
}
