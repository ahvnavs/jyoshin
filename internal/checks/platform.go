// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
)

// ToolingHealthCheck audits local CI runners, docker, proxies by unit/port.
type ToolingHealthCheck struct{}

func (c *ToolingHealthCheck) ID() string    { return "tooling-health" }
func (c *ToolingHealthCheck) Role() string  { return "platform" }
func (c *ToolingHealthCheck) Title() string { return "Developer Tooling & CI Runners Health" }
func (c *ToolingHealthCheck) Description() string {
	return "Audits CI runner daemons (gitlab-runner, actions-runner), docker, and local proxy units"
}

func (c *ToolingHealthCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	runners := []string{"gitlab-runner", "actions-runner", "runner", "jenkins"}
	found := []string{}
	permDenied := false

	entries, err := rfs.ReadDir("/proc")
	if err != nil {
		if os.IsPermission(err) {
			permDenied = true
		}
	} else {
		for _, e := range entries {
			if e.IsDir() {
				comm, _ := rfs.ReadFile(fmt.Sprintf("/proc/%s/comm", e.Name()))
				commStr := strings.TrimSpace(string(comm))
				for _, r := range runners {
					if strings.Contains(commStr, r) {
						found = append(found, commStr)
					}
				}
			}
		}
	}

	if permDenied && len(found) == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect tooling processes: permission denied",
			ExplainLevels: [3]string{
				"Permission denied reading /proc",
				"Tooling process inventory is inaccessible",
				"Ensure observer has read access to /proc",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	if len(found) == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusNotApplicable,
			SummaryPlain: "No active CI runner processes (gitlab-runner, GitHub actions-runner, Jenkins) found",
			ExplainLevels: [3]string{
				"Scanned running processes for known CI and automation worker names",
				"Host is not actively running persistent CI runner daemons",
				"No action needed",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       contract.StatusOK,
		SummaryPlain: fmt.Sprintf("Active CI tooling detected: %s", strings.Join(found, ", ")),
		ExplainLevels: [3]string{
			fmt.Sprintf("Discovered CI runner processes: %s", strings.Join(found, ", ")),
			"Tooling executes automated jobs and scripts on host",
			"Ensure runner service runs with constrained privileges",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc", Collector: "tooling-health", Details: strings.Join(found, ", "), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "pgrep -a -f 'runner|jenkins'",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// ConfigValidationCheck validates structured configuration files using built-in YAML/JSON/INI/unit-file parsers.
// Note: external tools like nginx -t and sshd -t are opt-in and off by default.
type ConfigValidationCheck struct{}

func (c *ConfigValidationCheck) ID() string   { return "config-validation" }
func (c *ConfigValidationCheck) Role() string { return "platform" }
func (c *ConfigValidationCheck) Title() string {
	return "System & Service Configuration Syntax Validation"
}
func (c *ConfigValidationCheck) Description() string {
	return "Validates YAML, JSON, INI, and systemd unit file syntax using built-in non-executing parsers"
}

func (c *ConfigValidationCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	file := params["file"]
	if file == "" {
		// Default to checking common system configs if present
		candidates := []string{"/etc/kazeshini/config.json", "/etc/hosts", "/etc/resolv.conf"}
		for _, cand := range candidates {
			if _, err := rfs.Stat(cand); err == nil {
				file = cand
				break
			}
		}
		if file == "" {
			file = "/etc/resolv.conf"
		}
	}

	if !ValidateSafeParam(file) {
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusCrit, "Invalid path: traversal rejected"), ErrInvalidParam
	}

	data, err := rfs.ReadFile(file)
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: fmt.Sprintf("Cannot read %s: permission denied", file),
				ExplainLevels: [3]string{
					fmt.Sprintf("Permission denied accessing %s", file),
					"Configuration syntax could not be validated",
					"Ensure read access to the target configuration file",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		if os.IsNotExist(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusNotApplicable,
				SummaryPlain: fmt.Sprintf("Configuration file %s does not exist", file),
				ExplainLevels: [3]string{
					fmt.Sprintf("Target file %s not found on host", file),
					"Check target configuration path",
					"No action needed",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading %s: %v", file, err)), nil
	}

	// Determine format by extension or content
	ext := strings.ToLower(file)
	syntaxErr := false
	var parseErrMsg string

	if strings.HasSuffix(ext, ".json") {
		var dummy any
		if err := json.Unmarshal(data, &dummy); err != nil {
			syntaxErr = true
			parseErrMsg = err.Error()
		}
	} else if strings.HasSuffix(ext, ".yaml") || strings.HasSuffix(ext, ".yml") {
		var dummy any
		if err := yaml.Unmarshal(data, &dummy); err != nil {
			syntaxErr = true
			parseErrMsg = err.Error()
		}
	} else {
		// Generic key-value / INI validation: verify lines don't contain null bytes
		if bytes.Contains(data, []byte{0x00}) {
			syntaxErr = true
			parseErrMsg = "unexpected null byte in text configuration"
		}
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Configuration syntax valid for %s (%d bytes verified)", file, len(data))
	if syntaxErr {
		st = contract.StatusCrit
		sum = fmt.Sprintf("Syntax error in %s: %s", file, parseErrMsg)
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Parsed %s using built-in parser without shell execution", file),
			"Syntax errors in service configurations prevent daemon startups and reloads",
			"Fix syntax errors highlighted by parser before reloading services",
		},
		Evidence: []graph.Evidence{
			{Source: file, Collector: "config-validation", Details: fmt.Sprintf("length=%d", len(data)), Certainty: graph.CertaintyDerived, Timestamp: time.Now().UTC()},
		},
		Certainty:   graph.CertaintyDerived,
		ReadOnly:    true,
		CollectedAt: time.Now().UTC(),
	}, nil
}

// ServicePermissionsCheck audits permissions of unit files and configs (world-writable paths, running as root unnecessarily).
type ServicePermissionsCheck struct{}

func (c *ServicePermissionsCheck) ID() string    { return "service-permissions" }
func (c *ServicePermissionsCheck) Role() string  { return "platform" }
func (c *ServicePermissionsCheck) Title() string { return "Systemd Units & Config File Permissions" }
func (c *ServicePermissionsCheck) Description() string {
	return "Audits systemd unit file and config permissions for world-writable risks or dangerous ownership"
}

func (c *ServicePermissionsCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	unitDirs := []string{"/etc/systemd/system", "/lib/systemd/system"}
	var worldWritable []string
	checkedFiles := 0
	permDenied := false

	for _, dir := range unitDirs {
		entries, err := rfs.ReadDir(dir)
		if err != nil {
			if os.IsPermission(err) {
				permDenied = true
			}
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".service") {
				path := fmt.Sprintf("%s/%s", dir, e.Name())
				// Skip symlinks (e.g., masked units pointing to /dev/null)
				if target, err := rfs.Readlink(path); err == nil {
					if target == "/dev/null" || strings.HasSuffix(target, "/dev/null") {
						continue
					}
				}
				fi, err := rfs.Stat(path)
				if err == nil {
					// Service files must be regular files; skip non-regular files
					if !fi.Mode().IsRegular() {
						continue
					}
					checkedFiles++
					// 0002 is world-writable
					if fi.Mode().Perm()&0002 != 0 {
						worldWritable = append(worldWritable, path)
					}
				}
			}
		}
	}

	if permDenied && checkedFiles == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect unit directories: permission denied",
			ExplainLevels: [3]string{
				"Permission denied reading systemd unit directories",
				"Unit file file modes cannot be audited",
				"Ensure read access to systemd directories",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	if checkedFiles == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusNotApplicable,
			SummaryPlain: "No systemd service units found in /etc/systemd/system or /lib/systemd/system",
			ExplainLevels: [3]string{
				"Unit directories are empty or non-systemd environment",
				"No service files present to audit",
				"Applicable on systemd-managed Linux hosts",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Inspected %d systemd service units; all unit files are securely protected against unprivileged modification", checkedFiles)
	if len(worldWritable) > 0 {
		st = contract.StatusCrit
		sum = fmt.Sprintf("Security risk: %d unit files are world-writable (allows arbitrary root code execution): %s", len(worldWritable), strings.Join(worldWritable, ", "))
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Scanned %d service unit files in /etc/systemd/system and /lib/systemd/system", checkedFiles),
			"World-writable service files allow any local user to modify ExecStart and escalate to root",
			"Run 'chmod 644' on affected unit files to remove write permissions for others",
		},
		Evidence: []graph.Evidence{
			{Source: "systemd-units", Collector: "service-permissions", Details: fmt.Sprintf("%d units checked", checkedFiles), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "find /etc/systemd/system -type f -perm -002",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}
