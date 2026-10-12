// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
)

// Registry manages the set of available read-only checks.
type Registry struct {
	mu     sync.RWMutex
	checks map[string]Check
}

// NewRegistry initializes a Registry with all standard checks registered.
func NewRegistry() *Registry {
	r := &Registry{
		checks: make(map[string]Check),
	}

	// DevOps
	r.Register(&AppHealthCheck{})
	r.Register(&AppLogsCheck{})
	r.Register(&CPUMemoryCheck{})

	// Cloud
	r.Register(&CloudInitCheck{})
	r.Register(&CloudAgentCheck{})
	r.Register(&AttachedStorageCheck{})

	// Cloud Platform
	r.Register(&NodeServicesCheck{})
	r.Register(&ContainerStorageCheck{})
	r.Register(&PlatformAgentLogsCheck{})

	// Infrastructure
	r.Register(&DiskInodesCheck{})
	r.Register(&FailedServicesCheck{})
	r.Register(&TimeSyncCheck{})

	// DevSecOps
	r.Register(&UsersSudoCheck{})
	r.Register(&SSHSettingsCheck{})
	r.Register(&AuthLogsCheck{})

	// Platform
	r.Register(&ToolingHealthCheck{})
	r.Register(&ConfigValidationCheck{})
	r.Register(&ServicePermissionsCheck{})

	// Network
	r.Register(&InterfacesRoutesCheck{})
	r.Register(&ListeningPortsCheck{})
	r.Register(&DNSConfigCheck{})
	r.Register(&ConnectivityProbeCheck{})

	return r
}

// Register adds a check to the registry.
func (r *Registry) Register(c Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks[c.ID()] = c
}

// Get retrieves a check by ID.
func (r *Registry) Get(id string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[id]
	return c, ok
}

// All returns all registered checks sorted by ID.
func (r *Registry) All() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]Check, 0, len(r.checks))
	for _, c := range r.checks {
		res = append(res, c)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].ID() < res[j].ID()
	})
	return res
}

// ByRole returns all checks belonging to a role.
func (r *Registry) ByRole(role string) []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var res []Check
	target := strings.ToLower(strings.TrimSpace(role))
	for _, c := range r.checks {
		if strings.ToLower(c.Role()) == target {
			res = append(res, c)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].ID() < res[j].ID()
	})
	return res
}

// Engine coordinates running checks and recording activity logs.
type Engine struct {
	registry *Registry
	actLog   *ActivityLog
	rfs      fs.FS
}

// NewEngine constructs a checks execution engine.
func NewEngine(registry *Registry, actLog *ActivityLog, rfs fs.FS) *Engine {
	if registry == nil {
		registry = NewRegistry()
	}
	if rfs == nil {
		rfs = fs.Default()
	}
	return &Engine{
		registry: registry,
		actLog:   actLog,
		rfs:      rfs,
	}
}

// Registry returns the underlying check registry.
func (e *Engine) Registry() *Registry {
	return e.registry
}

// ActivityLog returns the activity logger.
func (e *Engine) ActivityLog() *ActivityLog {
	return e.actLog
}

// RunCheck executes a check by ID with params and audits to the activity log.
func (e *Engine) RunCheck(ctx context.Context, id string, params map[string]string, tokenHolder string) (contract.CheckResult, error) {
	c, found := e.registry.Get(id)
	if !found {
		return contract.CheckResult{}, fmt.Errorf("check %q not found", id)
	}

	res, err := c.Run(ctx, e.rfs, params)

	if e.actLog != nil {
		_ = e.actLog.Log(ActivityEntry{
			CheckID:     c.ID(),
			Role:        c.Role(),
			TokenHolder: tokenHolder,
			Status:      res.Status,
			Summary:     res.SummaryPlain,
		})
	}

	return res, err
}

// RunRole executes all checks belonging to a specific role.
func (e *Engine) RunRole(ctx context.Context, role string, params map[string]string, tokenHolder string) ([]contract.CheckResult, error) {
	checksList := e.registry.ByRole(role)
	if len(checksList) == 0 {
		return nil, fmt.Errorf("no checks found for role %q", role)
	}

	var results []contract.CheckResult
	for _, c := range checksList {
		res, _ := c.Run(ctx, e.rfs, params)
		results = append(results, res)

		if e.actLog != nil {
			_ = e.actLog.Log(ActivityEntry{
				CheckID:     c.ID(),
				Role:        c.Role(),
				TokenHolder: tokenHolder,
				Status:      res.Status,
				Summary:     res.SummaryPlain,
			})
		}
	}

	return results, nil
}

