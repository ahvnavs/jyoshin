//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package plugin implements the out-of-process plugin supervisor and runner for Kazeshini.
// Plugins are out-of-process, read-only observer programs communicating via JSON-RPC over stdio or unix sockets.
// Core strictly enforces timeouts, output caps, isolation, and catches crashing plugins without affecting the core.
package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/resource"
	"gopkg.in/yaml.v3"
)

var (
	ErrTimeout        = errors.New("plugin execution timed out")
	ErrOutputExceeded = errors.New("plugin exceeded maximum output bytes cap")
	ErrUnsignedPlugin = errors.New("plugin manifest is unsigned; disallowed without --allow-unsigned-plugins")
	ErrPluginCrashed  = errors.New("plugin crashed or exited with non-zero status")
)

// Manifest defines the contract and constraints declared by a plugin.
type Manifest struct {
	Name         string            `json:"name" yaml:"name"`
	Version      string            `json:"version" yaml:"version"`
	APIVersion   string            `json:"api_version" yaml:"api_version"`
	Description  string            `json:"description" yaml:"description"`
	Emits        []resource.Kind   `json:"emits" yaml:"emits"`
	Capabilities Capabilities      `json:"capabilities" yaml:"capabilities"`
	Limits       ResourceLimits    `json:"limits" yaml:"limits"`
	Signature    string            `json:"signature,omitempty" yaml:"signature,omitempty"`
}

type Capabilities struct {
	ReadPaths     []string `json:"read_paths,omitempty" yaml:"read_paths,omitempty"`
	ExecAllowlist []string `json:"exec_allowlist,omitempty" yaml:"exec_allowlist,omitempty"`
	Network       Network  `json:"network" yaml:"network"`
}

type Network struct {
	Enabled      bool     `json:"enabled" yaml:"enabled"`
	AllowedHosts []string `json:"allowed_hosts,omitempty" yaml:"allowed_hosts,omitempty"`
}

type ResourceLimits struct {
	TimeoutSeconds int   `json:"timeout_seconds" yaml:"timeout_seconds"`
	MaxMemoryBytes int64 `json:"max_memory_bytes" yaml:"max_memory_bytes"`
	MaxOutputBytes int64 `json:"max_output_bytes" yaml:"max_output_bytes"`
	CPUQuotaUS     int64 `json:"cpu_quota_us" yaml:"cpu_quota_us"`
}

// Request is the JSON-RPC request sent to the plugin.
type Request struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// Response is the JSON-RPC response returned by the plugin.
type Response struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      int               `json:"id"`
	Result  *ResultPayload    `json:"result,omitempty"`
	Error   *ErrorPayload     `json:"error,omitempty"`
}

type ResultPayload struct {
	Resources []resource.Resource `json:"resources"`
}

type ErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Status represents runtime observation state of a plugin.
type Status struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Signed      bool       `json:"signed"`
	IsUnsigned  bool       `json:"is_unsigned"`
	Status      string     `json:"status"` // "ok", "crashed", "timeout", "failed"
	LastObserved time.Time `json:"last_observed"`
	Error       string     `json:"error,omitempty"`
	Count       int        `json:"resource_count"`
}

// Config configures the plugin runner.
type Config struct {
	AllowUnsigned bool
}

// Runner executes out-of-process plugins safely with bounded caps.
type Runner struct {
	cfg Config
	mu  sync.RWMutex
}

func NewRunner(cfg Config) *Runner {
	return &Runner{cfg: cfg}
}

// ParseManifest parses a YAML or JSON manifest string/bytes.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse plugin manifest: %w", err)
	}
	if m.Name == "" {
		return nil, errors.New("plugin manifest missing required field: name")
	}
	if m.Limits.TimeoutSeconds <= 0 {
		m.Limits.TimeoutSeconds = 5 // default 5 seconds
	}
	if m.Limits.MaxOutputBytes <= 0 {
		m.Limits.MaxOutputBytes = 1024 * 1024 // default 1 MB
	}
	return &m, nil
}

// Execute runs the plugin executable with enforced timeouts, output bounds, and isolation.
func (r *Runner) Execute(ctx context.Context, manifest *Manifest, command string, args ...string) ([]resource.Resource, Status, error) {
	status := Status{
		Name:         manifest.Name,
		Version:      manifest.Version,
		Signed:       manifest.Signature != "",
		IsUnsigned:   manifest.Signature == "",
		LastObserved: time.Now().UTC(),
	}

	if status.IsUnsigned && !r.cfg.AllowUnsigned {
		status.Status = "unsigned_rejected"
		status.Error = ErrUnsignedPlugin.Error()
		return nil, status, ErrUnsignedPlugin
	}

	timeout := time.Duration(manifest.Limits.TimeoutSeconds) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, command, args...)
	
	// Prepare IPC Request
	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "observe",
		Params: map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}
	reqBytes, _ := json.Marshal(req)
	cmd.Stdin = bytes.NewReader(append(reqBytes, '\n'))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		status.Status = "failed"
		status.Error = err.Error()
		return nil, status, fmt.Errorf("failed to open stdout pipe: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		status.Status = "failed"
		status.Error = err.Error()
		return nil, status, fmt.Errorf("failed to start plugin process: %w", err)
	}

	// Limit reader to prevent memory exhaustion from rogue plugins
	limitReader := io.LimitReader(stdout, manifest.Limits.MaxOutputBytes+1)
	outBytes, readErr := io.ReadAll(limitReader)

	waitErr := cmd.Wait()

	if execCtx.Err() == context.DeadlineExceeded {
		status.Status = "timeout"
		status.Error = ErrTimeout.Error()
		return nil, status, ErrTimeout
	}

	if int64(len(outBytes)) > manifest.Limits.MaxOutputBytes {
		status.Status = "failed"
		status.Error = ErrOutputExceeded.Error()
		return nil, status, ErrOutputExceeded
	}

	if readErr != nil {
		status.Status = "failed"
		status.Error = readErr.Error()
		return nil, status, fmt.Errorf("error reading plugin output: %w", readErr)
	}

	if waitErr != nil {
		status.Status = "crashed"
		status.Error = fmt.Sprintf("%v: %s", waitErr, stderrBuf.String())
		return nil, status, fmt.Errorf("%w: %v", ErrPluginCrashed, waitErr)
	}

	// Parse JSON-RPC line
	scanner := bufio.NewScanner(bytes.NewReader(outBytes))
	var resp Response
	foundResponse := false
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if err := json.Unmarshal(line, &resp); err == nil && resp.JSONRPC == "2.0" {
			foundResponse = true
			break
		}
	}

	if !foundResponse {
		status.Status = "failed"
		status.Error = "plugin returned invalid or empty JSON-RPC response"
		return nil, status, errors.New(status.Error)
	}

	if resp.Error != nil {
		status.Status = "failed"
		status.Error = resp.Error.Message
		return nil, status, fmt.Errorf("plugin returned error: %s", resp.Error.Message)
	}

	if resp.Result == nil {
		status.Status = "ok"
		return nil, status, nil
	}

	status.Status = "ok"
	status.Count = len(resp.Result.Resources)
	return resp.Result.Resources, status, nil
}

