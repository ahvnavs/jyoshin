//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrNotLeader = errors.New("instance is not currently the elected leader")
)

// LeaderElector defines a lease-based election interface.
// Designed for HA multi-controller setups with externalized state.
type LeaderElector interface {
	// Campaign initiates leadership contention.
	Campaign(ctx context.Context) error

	// IsLeader returns true if this instance holds the active lease.
	IsLeader() bool

	// StepDown releases the leader lease.
	StepDown(ctx context.Context) error
}

// FileLeaseElector stubs a file-based lock lease elector.
type FileLeaseElector struct {
	mu       sync.RWMutex
	path     string
	isLeader bool
}

func NewFileLeaseElector(path string) *FileLeaseElector {
	return &FileLeaseElector{path: path}
}

func (e *FileLeaseElector) Campaign(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.isLeader = true
	return nil
}

func (e *FileLeaseElector) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isLeader
}

func (e *FileLeaseElector) StepDown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.isLeader = false
	return nil
}

// K8sLeaseElector stubs a Kubernetes coordination.k8s.io/v1 Lease elector.
type K8sLeaseElector struct {
	mu        sync.RWMutex
	leaseName string
	namespace string
	isLeader  bool
}

func NewK8sLeaseElector(namespace, leaseName string) *K8sLeaseElector {
	return &K8sLeaseElector{namespace: namespace, leaseName: leaseName}
}

func (e *K8sLeaseElector) Campaign(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.isLeader = true
	return nil
}

func (e *K8sLeaseElector) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isLeader
}

func (e *K8sLeaseElector) StepDown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.isLeader = false
	return nil
}
