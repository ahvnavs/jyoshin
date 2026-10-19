// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package software: exec allow-list dry-runner for package manager simulations.
//
// Principle 13: Exec ONLY via allow-list. Absolute paths. Fixed args. Cleared env.
// Bounded timeout. 1MB output cap. Package names validated against strict regex.
// No shell expansion. No root required for apt-get -s (simulated only).
package software

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// DryRunConfig controls how simulation commands are executed.
type DryRunConfig struct {
	Timeout      time.Duration // default 10s
	MaxOutputLen int           // default 1MB
}

// DefaultDryRunConfig returns safe defaults.
func DefaultDryRunConfig() DryRunConfig {
	return DryRunConfig{
		Timeout:      10 * time.Second,
		MaxOutputLen: 1024 * 1024,
	}
}

// packageNameRe is the strict regex for valid package names.
// Rejects anything that could be a shell flag or injection.
var packageNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+~:_-]*$`)

// ValidatePackageName rejects names that could inject flags or paths.
// Returns an error describing exactly what was rejected.
func ValidatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name is empty")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("package name %q starts with '-': option injection rejected", name)
	}
	if strings.ContainsAny(name, ";|&`$(){}\\/<>") {
		return fmt.Errorf("package name %q contains shell metacharacters: injection rejected", name)
	}
	if !packageNameRe.MatchString(name) {
		return fmt.Errorf("package name %q does not match allowed pattern (a-zA-Z0-9.+~:_-): rejected", name)
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		return fmt.Errorf("package name %q contains path traversal: rejected", name)
	}
	return nil
}

// DryRunKind specifies the type of simulation.
type DryRunKind string

const (
	DryRunUpgrade DryRunKind = "upgrade"
	DryRunRemove  DryRunKind = "remove"
	DryRunInstall DryRunKind = "install"
)

// DryRunResult holds the output and parsed interpretation of a dry-run simulation.
type DryRunResult struct {
	Manager     string     `json:"manager"` // "apt", "dnf", "pacman", "apk"
	Kind        DryRunKind `json:"kind"`
	PackageName string     `json:"package_name"`
	RawOutput   string     `json:"raw_output"` // verbatim simulated output (Principle 6: fact vs inference)
	Lines       []SimLine  `json:"lines"`      // parsed Inst/Remv/Conf lines
	Error       string     `json:"error,omitempty"`
	TimedOut    bool       `json:"timed_out,omitempty"`
	Truncated   bool       `json:"truncated,omitempty"`
}

// SimLine is one parsed action from the dry-run simulation output.
type SimLine struct {
	Action      string `json:"action"` // "install", "remove", "configure"
	Package     string `json:"package"`
	FromVersion string `json:"from_version,omitempty"` // bracketed current version
	ToVersion   string `json:"to_version,omitempty"`
	Origin      string `json:"origin,omitempty"`
}

// aptAllowedArgs defines the fixed argument sets for apt-get dry-run modes.
// Package name is appended after validation; no shell expansion occurs.
var aptDryRunBaseArgs = map[DryRunKind][]string{
	DryRunUpgrade: {"-s", "-o", "Debug::NoLocking=1", "install", "--only-upgrade"},
	DryRunRemove:  {"-s", "-o", "Debug::NoLocking=1", "purge"},
	DryRunInstall: {"-s", "-o", "Debug::NoLocking=1", "install"},
}

// RunAptDryRun runs apt-get in simulation mode for the given package.
// Uses absolute path /usr/bin/apt-get, cleared environment, bounded timeout.
// Principle 13: Exec allow-list enforced here.
func RunAptDryRun(ctx context.Context, pkgName string, kind DryRunKind, cfg DryRunConfig) DryRunResult {
	res := DryRunResult{
		Manager:     "apt",
		Kind:        kind,
		PackageName: pkgName,
	}

	if err := ValidatePackageName(pkgName); err != nil {
		res.Error = err.Error()
		return res
	}

	baseArgs, ok := aptDryRunBaseArgs[kind]
	if !ok {
		res.Error = fmt.Sprintf("unknown dry-run kind %q", kind)
		return res
	}

	args := append(append([]string{}, baseArgs...), pkgName)

	// Hard timeout
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxOut := cfg.MaxOutputLen
	if maxOut <= 0 {
		maxOut = 1024 * 1024
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "/usr/bin/apt-get", args...) //nolint:gosec // absolute path, allow-listed
	// Cleared environment: Principle 13
	cmd.Env = []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
	}

	out, err := runCapped(cmd, maxOut)

	if execCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.Error = "dry-run timed out"
	} else if err != nil {
		// apt-get -s can return non-zero if there are conflicts; preserve output
		res.Error = err.Error()
	}

	if len(out) >= maxOut {
		out = out[:maxOut]
		res.Truncated = true
	}

	res.RawOutput = string(out)
	res.Lines = parseAptSimOutput(res.RawOutput)
	return res
}

// RunDnfDryRun runs dnf --assumeno upgrade for the given package.
func RunDnfDryRun(ctx context.Context, pkgName string, kind DryRunKind, cfg DryRunConfig) DryRunResult {
	res := DryRunResult{Manager: "dnf", Kind: kind, PackageName: pkgName}

	if err := ValidatePackageName(pkgName); err != nil {
		res.Error = err.Error()
		return res
	}

	var args []string
	switch kind {
	case DryRunUpgrade:
		args = []string{"--assumeno", "upgrade", pkgName}
	case DryRunRemove:
		args = []string{"--assumeno", "remove", pkgName}
	case DryRunInstall:
		args = []string{"--assumeno", "install", pkgName}
	default:
		res.Error = fmt.Sprintf("unknown kind %q", kind)
		return res
	}

	execCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "/usr/bin/dnf", args...) //nolint:gosec
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}

	out, err := runCapped(cmd, cfg.MaxOutputLen)
	if execCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	} else if err != nil {
		res.Error = err.Error()
	}
	res.RawOutput = string(out)
	return res
}

// RunPacmanDryRun uses pacman -Sup to simulate upgrades.
func RunPacmanDryRun(ctx context.Context, pkgName string, kind DryRunKind, cfg DryRunConfig) DryRunResult {
	res := DryRunResult{Manager: "pacman", Kind: kind, PackageName: pkgName}

	if err := ValidatePackageName(pkgName); err != nil {
		res.Error = err.Error()
		return res
	}

	var args []string
	switch kind {
	case DryRunUpgrade:
		args = []string{"-Sup", pkgName}
	default:
		res.Error = fmt.Sprintf("pacman dry-run only supports upgrade, got %q", kind)
		return res
	}

	execCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "/usr/bin/pacman", args...) //nolint:gosec
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}

	out, err := runCapped(cmd, cfg.MaxOutputLen)
	if execCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	} else if err != nil {
		res.Error = err.Error()
	}
	res.RawOutput = string(out)
	return res
}

// RunApkDryRun uses apk --simulate upgrade.
func RunApkDryRun(ctx context.Context, pkgName string, kind DryRunKind, cfg DryRunConfig) DryRunResult {
	res := DryRunResult{Manager: "apk", Kind: kind, PackageName: pkgName}

	if err := ValidatePackageName(pkgName); err != nil {
		res.Error = err.Error()
		return res
	}

	var args []string
	switch kind {
	case DryRunUpgrade:
		args = []string{"--simulate", "upgrade", pkgName}
	case DryRunRemove:
		args = []string{"--simulate", "del", pkgName}
	case DryRunInstall:
		args = []string{"--simulate", "add", pkgName}
	default:
		res.Error = fmt.Sprintf("unknown apk kind %q", kind)
		return res
	}

	execCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "/sbin/apk", args...) //nolint:gosec
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/sbin:/usr/bin:/bin"}

	out, err := runCapped(cmd, cfg.MaxOutputLen)
	if execCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	} else if err != nil {
		res.Error = err.Error()
	}
	res.RawOutput = string(out)
	return res
}

// runCapped executes a command and captures up to maxBytes of combined stdout+stderr.
func runCapped(cmd *exec.Cmd, maxBytes int) ([]byte, error) {
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	out := buf.Bytes()
	if len(out) > maxBytes {
		out = out[:maxBytes]
	}
	return out, err
}

// ParseAptSimOutput parses apt-get -s output lines like:
//
//	Inst sudo [1.9.17p2-1ubuntu3] (1.9.17p2-1ubuntu3.2 Ubuntu:26.04/resolute-security [amd64])
//	Remv old-package [1.0]
//	Conf sudo (1.9.17p2-1ubuntu3.2 ...)
func ParseAptSimOutput(raw string) []SimLine {
	return parseAptSimOutput(raw)
}

func parseAptSimOutput(raw string) []SimLine {
	var lines []SimLine
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		var sl SimLine

		switch {
		case strings.HasPrefix(line, "Inst "):
			sl.Action = "install"
			sl.Package, sl.FromVersion, sl.ToVersion, sl.Origin = parseAptInstLine(line[5:])
		case strings.HasPrefix(line, "Remv "):
			sl.Action = "remove"
			sl.Package, sl.FromVersion, _, _ = parseAptInstLine(line[5:])
		case strings.HasPrefix(line, "Conf "):
			sl.Action = "configure"
			sl.Package, _, sl.ToVersion, sl.Origin = parseAptInstLine(line[5:])
		default:
			continue
		}

		if sl.Package != "" {
			lines = append(lines, sl)
		}
	}
	return lines
}

// parseAptInstLine parses "sudo [1.9.17p2-1ubuntu3] (1.9.17p2-1ubuntu3.2 Ubuntu:26.04/resolute-security [amd64])"
func parseAptInstLine(s string) (pkg, fromVer, toVer, origin string) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return
	}
	pkg = fields[0]
	rest := strings.Join(fields[1:], " ")

	// Extract [from-version]
	if start := strings.Index(rest, "["); start != -1 {
		if end := strings.Index(rest[start:], "]"); end != -1 {
			fromVer = rest[start+1 : start+end]
		}
	}

	// Extract (to-version origin [arch])
	if start := strings.Index(rest, "("); start != -1 {
		inner := rest[start+1:]
		if end := strings.LastIndex(inner, ")"); end != -1 {
			inner = inner[:end]
		}
		innerFields := strings.Fields(inner)
		if len(innerFields) > 0 {
			toVer = innerFields[0]
		}
		if len(innerFields) > 1 {
			origin = strings.Join(innerFields[1:], " ")
		}
	}
	return
}
