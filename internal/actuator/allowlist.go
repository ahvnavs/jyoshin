//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package actuator

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	validPkgRegex  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+~:_-]*$`)
	validUnitRegex = regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)

	// Protected packages that must NEVER be removed under any circumstance
	protectedPackageList = map[string]string{
		"openssh-server": "SSH server daemon; removal locks out remote access",
		"openssh-client": "Core SSH client",
		"sshd":           "SSH daemon binary",
		"systemd":        "Host init system; removal renders system unbootable",
		"systemd-sysv":   "Provides /sbin/init",
		"init":           "Core init stub",
		"libc6":          "Core C library runtime",
		"libc-bin":       "Core C library tools",
		"apt":            "Package management framework",
		"dpkg":           "Low-level package manager",
		"dnf":            "RPM package manager",
		"rpm":            "RPM database binary",
		"pacman":         "Arch package manager",
		"apk":            "Alpine package manager",
	}

	// Protected units that cannot be stopped or disabled
	protectedUnitList = map[string]bool{
		"ssh.service":               true,
		"sshd.service":              true,
		"systemd-journald.service":  true,
		"kazeshini-actuator.service": true,
	}
)

// CommandSpec specifies the exact execution arguments.
type CommandSpec struct {
	Binary string
	Args   []string
}

// BuildCommand validates the step against invariants and maps it to fixed argv.
// No shell interpolation is ever permitted (Principle 13).
func BuildCommand(step ExecutionStep, pkgManager string, runningKernel string) (*CommandSpec, error) {
	switch step.Action {
	case "package_upgrade", "package_install":
		if err := validateTargetName(step.Target, validPkgRegex); err != nil {
			return nil, fmt.Errorf("invalid package name %q: %w", step.Target, err)
		}
		return buildPackageCommand(step.Action, step.Target, pkgManager)

	case "package_remove":
		if err := validateTargetName(step.Target, validPkgRegex); err != nil {
			return nil, fmt.Errorf("invalid package name %q: %w", step.Target, err)
		}
		// Invariant check: Protected package blocklist
		if reason, blocked := protectedPackageList[step.Target]; blocked {
			return nil, fmt.Errorf("OPERATION BLOCKED: %q is a protected core package (%s)", step.Target, reason)
		}
		// Invariant check: Running kernel removal
		if runningKernel != "" && (strings.HasPrefix(step.Target, "linux-image-") || strings.HasPrefix(step.Target, "kernel-")) {
			if strings.Contains(step.Target, runningKernel) {
				return nil, fmt.Errorf("OPERATION BLOCKED: %q matches running kernel (%s)", step.Target, runningKernel)
			}
		}
		return buildPackageCommand(step.Action, step.Target, pkgManager)

	case "service_start", "service_stop", "service_restart", "service_enable", "service_disable":
		if err := validateTargetName(step.Target, validUnitRegex); err != nil {
			return nil, fmt.Errorf("invalid unit name %q: %w", step.Target, err)
		}
		unit := step.Target
		if !strings.Contains(unit, ".") {
			unit += ".service"
		}
		if (step.Action == "service_stop" || step.Action == "service_disable") && protectedUnitList[unit] {
			return nil, fmt.Errorf("OPERATION BLOCKED: stopping or disabling %q is forbidden", unit)
		}
		verb := strings.TrimPrefix(step.Action, "service_")
		return &CommandSpec{
			Binary: "/usr/bin/systemctl",
			Args:   []string{verb, unit},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported action %q: only package and service operations allowed", step.Action)
	}
}

func validateTargetName(name string, pattern *regexp.Regexp) error {
	if name == "" {
		return fmt.Errorf("target name is empty")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("target begins with option flag prefix '-'")
	}
	if strings.ContainsAny(name, ";|&`$(){}\\/<> \t\n") {
		return fmt.Errorf("target contains dangerous characters")
	}
	if !pattern.MatchString(name) {
		return fmt.Errorf("target format does not match allowed regex")
	}
	return nil
}

func buildPackageCommand(action, pkg, mgr string) (*CommandSpec, error) {
	if mgr == "" {
		mgr = "apt"
	}
	switch mgr {
	case "apt":
		switch action {
		case "package_upgrade":
			return &CommandSpec{
				Binary: "/usr/bin/apt-get",
				Args:   []string{"install", "--only-upgrade", "-y", pkg},
			}, nil
		case "package_install":
			return &CommandSpec{
				Binary: "/usr/bin/apt-get",
				Args:   []string{"install", "-y", pkg},
			}, nil
		case "package_remove":
			return &CommandSpec{
				Binary: "/usr/bin/apt-get",
				Args:   []string{"purge", "-y", pkg},
			}, nil
		}
	case "dnf":
		switch action {
		case "package_upgrade":
			return &CommandSpec{
				Binary: "/usr/bin/dnf",
				Args:   []string{"upgrade", "-y", pkg},
			}, nil
		case "package_install":
			return &CommandSpec{
				Binary: "/usr/bin/dnf",
				Args:   []string{"install", "-y", pkg},
			}, nil
		case "package_remove":
			return &CommandSpec{
				Binary: "/usr/bin/dnf",
				Args:   []string{"remove", "-y", pkg},
			}, nil
		}
	case "pacman":
		switch action {
		case "package_upgrade", "package_install":
			return &CommandSpec{
				Binary: "/usr/bin/pacman",
				Args:   []string{"-S", "--noconfirm", pkg},
			}, nil
		case "package_remove":
			return &CommandSpec{
				Binary: "/usr/bin/pacman",
				Args:   []string{"-Rns", "--noconfirm", pkg},
			}, nil
		}
	case "apk":
		switch action {
		case "package_upgrade", "package_install":
			return &CommandSpec{
				Binary: "/sbin/apk",
				Args:   []string{"add", pkg},
			}, nil
		case "package_remove":
			return &CommandSpec{
				Binary: "/sbin/apk",
				Args:   []string{"del", pkg},
			}, nil
		}
	}
	return nil, fmt.Errorf("unsupported package manager %q", mgr)
}

