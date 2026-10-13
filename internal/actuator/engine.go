//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package actuator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// ExecutionStatus defines final run outcomes.
type ExecutionStatus string

const (
	StatusSucceeded ExecutionStatus = "SUCCEEDED"
	StatusFailed    ExecutionStatus = "FAILED"
	StatusUncertain ExecutionStatus = "UNCERTAIN"
	StatusAborted   ExecutionStatus = "ABORTED"
)

// ExecutionResult records the comprehensive outcome of executing a plan.
type ExecutionResult struct {
	PlanID       string          `json:"plan_id"`
	Status       ExecutionStatus `json:"status"`
	ExecutedSteps int            `json:"executed_steps"`
	TotalSteps   int             `json:"total_steps"`
	FailedStep   *ExecutionStep  `json:"failed_step,omitempty"`
	Error        string          `json:"error,omitempty"`
	RollbackPlan *RemediationPlan `json:"rollback_plan,omitempty"`
	OutputLogs   []string        `json:"output_logs,omitempty"`
}

// Config sets runtime operational parameters for the actuator engine.
type Config struct {
	SocketPath       string
	AuditLogPath     string
	NonceStorePath   string
	SentinelPath     string // e.g. /etc/kazeshini/actuator.disabled
	ApproverPubKey   ed25519.PublicKey
	PackageManager   string // "apt", "dnf", "pacman", "apk"
	RunningKernel    string
	CurrentHostID    string
	DryRunDefault    bool
}

// DefaultConfig provides conservative defaults.
func DefaultConfig() Config {
	return Config{
		SocketPath:     "/run/kazeshini/actuator.sock",
		AuditLogPath:   "/var/log/kazeshini/actuator-audit.log",
		NonceStorePath: "/var/lib/kazeshini/actuator-nonces.json",
		SentinelPath:   "/etc/kazeshini/actuator.disabled",
		PackageManager: "apt",
		CurrentHostID:  ReadCurrentHostID(),
		DryRunDefault:  true,
	}
}

// Engine coordinates preflights, signature checking, step execution, and audit logging.
type Engine struct {
	cfg        Config
	audit      *AuditLogger
	nonceStore *NonceStore
}

// NewEngine creates a new remediation actuator engine.
func NewEngine(cfg Config, audit *AuditLogger, ns *NonceStore) *Engine {
	return &Engine{
		cfg:        cfg,
		audit:      audit,
		nonceStore: ns,
	}
}

// ExecuteEnvelope handles full preflight verification and step-by-step execution.
func (e *Engine) ExecuteEnvelope(ctx context.Context, env *ExecutionEnvelope, apply bool) (*ExecutionResult, error) {
	now := time.Now().UTC()

	// 1. Check Kill Switch sentinel before doing anything
	if e.isKillSwitchEngaged() {
		return &ExecutionResult{
			PlanID: env.Plan.ID,
			Status: StatusAborted,
			Error:  "Actuator is disabled via kill switch sentinel file",
		}, fmt.Errorf("kill switch engaged: %s exists", e.cfg.SentinelPath)
	}

	// 2. Cryptographic Envelope Verification
	if len(e.cfg.ApproverPubKey) > 0 {
		if err := VerifyEnvelope(env, e.cfg.ApproverPubKey, e.cfg.CurrentHostID, now); err != nil {
			return &ExecutionResult{
				PlanID: env.Plan.ID,
				Status: StatusAborted,
				Error:  fmt.Sprintf("envelope verification failed: %v", err),
			}, err
		}
	}

	// 3. Replay Protection: Check and commit nonce
	if e.nonceStore != nil {
		if err := e.nonceStore.CheckAndRecord(env.Nonce, now); err != nil {
			return &ExecutionResult{
				PlanID: env.Plan.ID,
				Status: StatusAborted,
				Error:  fmt.Sprintf("replay protection check failed: %v", err),
			}, err
		}
	}

	// 4. Preflight Host Health Checks (Locks, Disk, Maintenance)
	if err := e.runHostPreflights(); err != nil {
		return &ExecutionResult{
			PlanID: env.Plan.ID,
			Status: StatusAborted,
			Error:  fmt.Sprintf("host preflight failed: %v", err),
		}, err
	}

	// 5. Execution Loop (One Step at a Time)
	res := &ExecutionResult{
		PlanID:     env.Plan.ID,
		TotalSteps: len(env.Plan.Steps),
		Status:     StatusSucceeded,
	}

	var rollbackSteps []ExecutionStep

	for i, step := range env.Plan.Steps {
		// Verify kill switch at each step boundary
		if e.isKillSwitchEngaged() {
			res.Status = StatusAborted
			res.Error = fmt.Sprintf("kill switch triggered during execution before step %d", i+1)
			_ = e.logAuditRecord(env, i, step, []string{"[KILLED]"}, -1, 0, "ABORTED", "Kill switch engaged")
			break
		}

		cmdSpec, err := BuildCommand(step, e.cfg.PackageManager, e.cfg.RunningKernel)
		if err != nil {
			res.Status = StatusFailed
			res.FailedStep = &step
			res.Error = fmt.Sprintf("step %d allow-list validation failed: %v", i+1, err)
			_ = e.logAuditRecord(env, i, step, []string{"[INVALID]"}, -1, 0, "FAILED", res.Error)
			break
		}

		// Prepare rollback inverse action for completed steps
		if inv := computeInverseStep(step); inv != nil {
			rollbackSteps = append([]ExecutionStep{*inv}, rollbackSteps...)
		}

		if !apply {
			// Dry-run simulation only
			res.ExecutedSteps++
			res.OutputLogs = append(res.OutputLogs, fmt.Sprintf("[DRY-RUN] Would execute: %s %s", cmdSpec.Binary, strings.Join(cmdSpec.Args, " ")))
			_ = e.logAuditRecord(env, i, step, append([]string{cmdSpec.Binary}, cmdSpec.Args...), 0, 0, "SUCCEEDED", "[DRY-RUN SIMULATION]")
			continue
		}

		// Real Step Execution
		startTime := time.Now()
		timeout := time.Duration(step.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = 300 * time.Second // 5 minute default
		}

		stepCtx, stepCancel := context.WithTimeout(ctx, timeout)
		cmd := exec.CommandContext(stepCtx, cmdSpec.Binary, cmdSpec.Args...)
		cmd.Env = []string{
			"LANG=C",
			"LC_ALL=C",
			"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"DEBIAN_FRONTEND=noninteractive",
		}

		var outBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &outBuf

		runErr := cmd.Run()
		stepCancel()
		duration := time.Since(startTime)

		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		tailOutput := outBuf.String()
		if len(tailOutput) > 1024 {
			tailOutput = tailOutput[len(tailOutput)-1024:]
		}

		if stepCtx.Err() == context.DeadlineExceeded {
			// Step timed out: Status is UNCERTAIN (cannot verify host state)
			res.Status = StatusUncertain
			res.FailedStep = &step
			res.Error = fmt.Sprintf("step %d timed out after %v: process state uncertain", i+1, timeout)
			res.OutputLogs = append(res.OutputLogs, fmt.Sprintf("[UNCERTAIN] Step %d timed out", i+1))
			_ = e.logAuditRecord(env, i, step, append([]string{cmdSpec.Binary}, cmdSpec.Args...), -1, duration.Milliseconds(), "UNCERTAIN", tailOutput)
			break
		}

		if runErr != nil {
			// Step failed: STOP IMMEDIATELY
			res.Status = StatusFailed
			res.FailedStep = &step
			res.Error = fmt.Sprintf("step %d execution failed: %v", i+1, runErr)
			res.OutputLogs = append(res.OutputLogs, fmt.Sprintf("[FAILED] %s", tailOutput))
			_ = e.logAuditRecord(env, i, step, append([]string{cmdSpec.Binary}, cmdSpec.Args...), exitCode, duration.Milliseconds(), "FAILED", tailOutput)
			break
		}

		res.ExecutedSteps++
		res.OutputLogs = append(res.OutputLogs, fmt.Sprintf("[OK] Step %d completed: %s", i+1, strings.Join(cmdSpec.Args, " ")))
		_ = e.logAuditRecord(env, i, step, append([]string{cmdSpec.Binary}, cmdSpec.Args...), 0, duration.Milliseconds(), "SUCCEEDED", tailOutput)
	}

	// Generate concrete rollback plan if any failure or uncertain outcome occurred
	if res.Status != StatusSucceeded && len(rollbackSteps) > 0 {
		res.RollbackPlan = &RemediationPlan{
			ID:           fmt.Sprintf("rollback-%s", env.Plan.ID),
			TargetHostID: env.Plan.TargetHostID,
			CreatedAt:    time.Now().UTC(),
			Steps:        rollbackSteps,
			Summary:      fmt.Sprintf("Rollback guidance for failed plan %s (Requires human approval, Principle 17)", env.Plan.ID),
		}
	}

	return res, nil
}

func (e *Engine) isKillSwitchEngaged() bool {
	if e.cfg.SentinelPath == "" {
		return false
	}
	_, err := os.Stat(e.cfg.SentinelPath)
	return err == nil
}

func (e *Engine) runHostPreflights() error {
	// 1. Check package manager lock files
	lockFiles := []string{
		"/var/lib/dpkg/lock",
		"/var/lib/dpkg/lock-frontend",
		"/var/lib/apt/lists/lock",
	}
	for _, lf := range lockFiles {
		if isFileLocked(lf) {
			return fmt.Errorf("package manager lock held on %s", lf)
		}
	}

	// 2. Check disk space on root filesystem (require at least 100 MB free)
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		freeBytes := stat.Bavail * uint64(stat.Bsize)
		if freeBytes < 100*1024*1024 {
			return fmt.Errorf("insufficient disk space on /: %d MB available (minimum 100 MB required)", freeBytes/(1024*1024))
		}
	}

	return nil
}

func isFileLocked(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return false
	}
	defer f.Close()

	// Try non-blocking exclusive flock
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return true // Lock held by another process
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

func (e *Engine) logAuditRecord(env *ExecutionEnvelope, idx int, step ExecutionStep, argv []string, exitCode int, dur int64, status, tail string) error {
	if e.audit == nil {
		return nil
	}
	return e.audit.LogStep(AuditRecord{
		Timestamp:  time.Now().UTC(),
		PlanID:     env.Plan.ID,
		PlanHash:   env.PlanHash,
		Approver:   env.Approver,
		Nonce:      env.Nonce,
		StepIndex:  idx,
		Action:     step.Action,
		Target:     step.Target,
		Argv:       argv,
		ExitCode:   exitCode,
		DurationMs: dur,
		Status:     status,
		OutputTail: tail,
	})
}

func computeInverseStep(s ExecutionStep) *ExecutionStep {
	switch s.Action {
	case "package_install":
		return &ExecutionStep{
			Action: "package_remove",
			Target: s.Target,
		}
	case "package_remove":
		return &ExecutionStep{
			Action: "package_install",
			Target: s.Target,
		}
	case "package_upgrade":
		if s.FromVersion != "" {
			return &ExecutionStep{
				Action:    "package_install",
				Target:    fmt.Sprintf("%s=%s", s.Target, s.FromVersion),
				ToVersion: s.FromVersion,
			}
		}
		return nil
	case "service_start":
		return &ExecutionStep{Action: "service_stop", Target: s.Target}
	case "service_stop":
		return &ExecutionStep{Action: "service_start", Target: s.Target}
	case "service_enable":
		return &ExecutionStep{Action: "service_disable", Target: s.Target}
	case "service_disable":
		return &ExecutionStep{Action: "service_enable", Target: s.Target}
	default:
		return nil
	}
}
