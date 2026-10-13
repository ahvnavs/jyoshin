// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package software

import (
	"fmt"
	"strings"
)

// SafetyFlag is a specific risk category detected for a proposed package change.
type SafetyFlag struct {
	Code        string `json:"code"`        // machine-readable code e.g. "KERNEL_IN_USE"
	Severity    string `json:"severity"`    // "critical", "high", "medium"
	PlainReason string `json:"plain_reason"` // human-readable explanation (Principle 12)
}

// SafetyAnalysis is the result of analyzing a proposed package change.
type SafetyAnalysis struct {
	Safe    bool         `json:"safe"`
	Blocked bool         `json:"blocked"`  // true if critical flags present
	Flags   []SafetyFlag `json:"flags,omitempty"`
	Summary string       `json:"summary"`
}

// protectedPackages are packages that must never be removed or broken.
// Removing these risks making the system unmanageable or unbootable.
var protectedPackages = map[string]string{
	// Remote access — losing this locks you out over SSH
	"openssh-server": "This is the SSH server. Removing it will cut off all remote access.",
	"openssh-client": "Core SSH client. Removing it will break SSH connections.",
	"sshd":           "SSH daemon binary. Removing it will cut off all remote access.",

	// Init and session management
	"systemd":         "Init system. Removing it will prevent the system from booting.",
	"systemd-sysv":    "Provides /sbin/init. Removing it will prevent the system from booting.",
	"init":            "Init system stub. Required for the boot process.",
	"dbus":            "System message bus. Removing it breaks inter-process communication and the init system.",

	// Core C library — nearly all software links against this
	"libc6":          "Core C library. Almost all programs depend on this. Removing it will break the entire system.",
	"libc-bin":       "Core C library utilities. Tightly coupled to libc6. Removing it will break the system.",
	"libgcc-s1":      "GCC runtime library. Required by many programs compiled with GCC.",

	// Package management — losing this means you can't install anything back
	"apt":            "Package manager. Removing it means you cannot install, update, or remove packages.",
	"apt-utils":      "APT utility programs. Required for package management.",
	"dpkg":           "Low-level package manager. Removing it makes all software management impossible.",
	"dnf":            "DNF package manager. Removing it makes all software management impossible.",
	"rpm":            "RPM package database. Required by DNF and YUM for package management.",
	"pacman":         "Pacman package manager. Removing it makes all software management impossible.",
	"apk":            "APK package manager. Removing it makes all software management impossible.",
}

// AnalyzeSafety evaluates a proposed package change and returns all safety flags.
// It uses deterministic rule-matching only — no AI or heuristics.
func AnalyzeSafety(entry *PackageEntry, kind DryRunKind, dryRun *DryRunResult, runningKernelVersion string) SafetyAnalysis {
	var flags []SafetyFlag

	if entry == nil {
		return SafetyAnalysis{Safe: false, Blocked: true, Summary: "Package not found in installed inventory."}
	}

	// 1. Protected package check
	if reason, isProtected := protectedPackages[entry.Name]; isProtected {
		if kind == DryRunRemove {
			flags = append(flags, SafetyFlag{
				Code:        "PROTECTED_PACKAGE_REMOVAL",
				Severity:    "critical",
				PlainReason: fmt.Sprintf("%q is a protected system component. %s", entry.Name, reason),
			})
		}
	}

	// 2. Kernel-in-use check — removing the currently running kernel image
	if (strings.HasPrefix(entry.Name, "linux-image-") || strings.HasPrefix(entry.Name, "kernel-")) && kind == DryRunRemove {
		if runningKernelVersion != "" && strings.Contains(entry.Name, runningKernelVersion) {
			flags = append(flags, SafetyFlag{
				Code:        "KERNEL_IN_USE",
				Severity:    "critical",
				PlainReason: fmt.Sprintf("Package %q contains the kernel currently running (%s). Removing it would prevent the system from booting.", entry.Name, runningKernelVersion),
			})
		}
	}

	// 3. Held/pinned package — administrator intentionally locked this version
	if entry.IsHeld {
		flags = append(flags, SafetyFlag{
			Code:        "PACKAGE_HELD",
			Severity:    "high",
			PlainReason: fmt.Sprintf("Package %q is marked as held (pinned). An administrator intentionally locked this version. Changing it may break expected system behavior.", entry.Name),
		})
	}
	if entry.IsPinned {
		flags = append(flags, SafetyFlag{
			Code:        "PACKAGE_PINNED",
			Severity:    "high",
			PlainReason: fmt.Sprintf("Package %q has an APT pin preference (%s). Upgrading or removing it overrides this intentional lock.", entry.Name, entry.PinReason),
		})
	}

	// 4. Reverse dependency breakage — other packages need this
	if kind == DryRunRemove && len(entry.ReverseDependents) > 0 {
		deps := entry.ReverseDependents
		sample := deps
		suffix := ""
		if len(deps) > 5 {
			sample = deps[:5]
			suffix = fmt.Sprintf(" and %d more", len(deps)-5)
		}
		flags = append(flags, SafetyFlag{
			Code:        "REVERSE_DEPENDENCY_BREAKAGE",
			Severity:    "high",
			PlainReason: fmt.Sprintf("Package %q is required by %d other installed package(s): %s%s. Removing it will break those packages.", entry.Name, len(deps), strings.Join(sample, ", "), suffix),
		})
	}

	// 5. Major version jump
	if dryRun != nil && entry.Candidate != nil {
		installedMajor := extractMajorVersion(entry.Version)
		candidateMajor := extractMajorVersion(entry.Candidate.Version)
		if installedMajor != "" && candidateMajor != "" && installedMajor != candidateMajor {
			flags = append(flags, SafetyFlag{
				Code:        "MAJOR_VERSION_JUMP",
				Severity:    "medium",
				PlainReason: fmt.Sprintf("Package %q would jump from major version %s to %s. Major version upgrades often contain breaking changes.", entry.Name, installedMajor, candidateMajor),
			})
		}
	}

	// 6. Downgrade detection
	if dryRun != nil && entry.Candidate != nil {
		if isDowngrade(entry.Version, entry.Candidate.Version) {
			flags = append(flags, SafetyFlag{
				Code:        "DOWNGRADE",
				Severity:    "medium",
				PlainReason: fmt.Sprintf("Package %q would be downgraded from %s to %s. Downgrades can cause data incompatibilities and are rarely safe.", entry.Name, entry.Version, entry.Candidate.Version),
			})
		}
	}

	// 7. Active network listener
	if entry.Running.IsRunning && len(entry.Running.ListeningPorts) > 0 {
		ports := strings.Join(entry.Running.ListeningPorts, ", ")
		flags = append(flags, SafetyFlag{
			Code:        "ACTIVE_LISTENER",
			Severity:    "medium",
			PlainReason: fmt.Sprintf("Package %q has active network listeners on ports %s. Removing or replacing it will interrupt those connections.", entry.Name, ports),
		})
	}

	// 8. Running service — upgrade will likely need restart
	if entry.Running.IsRunning && len(entry.Running.ServiceNames) > 0 && kind == DryRunUpgrade {
		svcs := strings.Join(entry.Running.ServiceNames, ", ")
		flags = append(flags, SafetyFlag{
			Code:        "SERVICE_REQUIRES_RESTART",
			Severity:    "low",
			PlainReason: fmt.Sprintf("Package %q has running service(s): %s. After upgrading, these services will need to be restarted to use the new version.", entry.Name, svcs),
		})
	}

	// Determine blocked and safe
	blocked := false
	for _, f := range flags {
		if f.Severity == "critical" {
			blocked = true
			break
		}
	}

	summary := buildSafetySummary(entry.Name, kind, flags, blocked)
	return SafetyAnalysis{
		Safe:    len(flags) == 0,
		Blocked: blocked,
		Flags:   flags,
		Summary: summary,
	}
}

func buildSafetySummary(pkgName string, kind DryRunKind, flags []SafetyFlag, blocked bool) string {
	if len(flags) == 0 {
		return fmt.Sprintf("No safety issues detected. %s of %q appears safe based on local analysis.", kindLabel(kind), pkgName)
	}
	critCount := 0
	highCount := 0
	for _, f := range flags {
		switch f.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		}
	}
	if blocked {
		return fmt.Sprintf("%s of %q is BLOCKED: %d critical safety issue(s) detected.", kindLabel(kind), pkgName, critCount)
	}
	return fmt.Sprintf("%s of %q has %d warning(s) (%d high severity). Review before proceeding.", kindLabel(kind), pkgName, len(flags), highCount)
}

func kindLabel(k DryRunKind) string {
	switch k {
	case DryRunUpgrade:
		return "Upgrade"
	case DryRunRemove:
		return "Removal"
	case DryRunInstall:
		return "Installation"
	default:
		return "Change"
	}
}

// extractMajorVersion returns the first version component (e.g. "2" from "2.39.5-0ubuntu1").
func extractMajorVersion(ver string) string {
	if ver == "" {
		return ""
	}
	// Strip epoch prefix "1:"
	if idx := strings.Index(ver, ":"); idx != -1 {
		ver = ver[idx+1:]
	}
	parts := strings.FieldsFunc(ver, func(r rune) bool {
		return r == '.' || r == '-' || r == '~'
	})
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// isDowngrade returns true if installedVer is higher than candidateVer.
// Uses simple lexicographic comparison — good enough for epoch:major.minor; not
// a full Debian version comparator (that would need deb-version library which
// we don't add; STDLIB-FIRST principle).
func isDowngrade(installedVer, candidateVer string) bool {
	if installedVer == "" || candidateVer == "" {
		return false
	}
	// If they're equal, no downgrade
	if installedVer == candidateVer {
		return false
	}
	// Very basic: if installed > candidate string-wise and installed contains higher epoch/version
	// This is intentionally conservative — we only flag obvious cases
	installedEpoch, installedRest := splitEpoch(installedVer)
	candidateEpoch, candidateRest := splitEpoch(candidateVer)

	if installedEpoch > candidateEpoch {
		return true
	}
	if installedEpoch < candidateEpoch {
		return false
	}
	// Same epoch — compare rest lexicographically (rough approximation)
	return installedRest > candidateRest
}

func splitEpoch(ver string) (int, string) {
	if idx := strings.Index(ver, ":"); idx != -1 {
		var epoch int
		_, _ = fmt.Sscanf(ver[:idx], "%d", &epoch)
		return epoch, ver[idx+1:]
	}
	return 0, ver
}

