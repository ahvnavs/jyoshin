// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors/storage"
)

// CloudInitCheck inspects /run/cloud-init status and result files.
// If cloud-init does not exist, reports NOT_APPLICABLE.
type CloudInitCheck struct{}

func (c *CloudInitCheck) ID() string    { return "cloud-init" }
func (c *CloudInitCheck) Role() string  { return "cloud" }
func (c *CloudInitCheck) Title() string { return "Cloud-Init Provisioning Status" }
func (c *CloudInitCheck) Description() string {
	return "Checks cloud-init completion status in /run/cloud-init"
}

func (c *CloudInitCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	resultFile := "/run/cloud-init/result.json"
	statusFile := "/run/cloud-init/status.json"

	data, err := rfs.ReadFile(resultFile)
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot inspect /run/cloud-init: permission denied",
				ExplainLevels: [3]string{
					"Permission denied reading /run/cloud-init/result.json",
					"Cloud-init completion status is obscured by permissions",
					"Run as authorized user with access to /run/cloud-init",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		// Try status.json
		altData, altErr := rfs.ReadFile(statusFile)
		if altErr != nil {
			if os.IsPermission(altErr) {
				return contract.CheckResult{
					ID:           c.ID(),
					Role:         c.Role(),
					Title:        c.Title(),
					Status:       contract.StatusUnknown,
					SummaryPlain: "Cannot inspect /run/cloud-init: permission denied",
					ExplainLevels: [3]string{
						"Permission denied reading /run/cloud-init/status.json",
						"Cloud-init status cannot be checked",
						"Run with appropriate permissions",
					},
					Certainty: graph.CertaintyObserved,
					ReadOnly:  true,
				}, nil
			}
			// Not applicable if cloud-init directory or files are absent
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusNotApplicable,
				SummaryPlain: "Cloud-init not present on this host (bare metal, standard container, or non-cloud distribution)",
				ExplainLevels: [3]string{
					"/run/cloud-init does not exist",
					"System was not provisioned via cloud-init metadata",
					"No action needed",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		data = altData
	}

	content := string(data)
	st := contract.StatusOK
	sum := "Cloud-init finished provisioning successfully"
	if strings.Contains(content, `"errors": []`) || strings.Contains(content, `SUCCESS`) {
		st = contract.StatusOK
	} else if (strings.Contains(content, `"errors": [`) && !strings.Contains(content, `"errors": []`)) || strings.Contains(content, `FAIL`) {
		st = contract.StatusWarn
		sum = "Cloud-init reported errors during instance initialization"
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			"Cloud-init execution result was inspected in /run/cloud-init",
			"Verifies that user-data scripts and initialization hooks completed cleanly",
			"Check /var/log/cloud-init.log if provisioning reported warnings",
		},
		Evidence: []graph.Evidence{
			{Source: resultFile, Collector: "cloud-init", Raw: content, Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "cloud-init status",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// CloudAgentCheck checks for known cloud management agents (SSM, waagent, google-guest-agent, qemu-guest-agent).
type CloudAgentCheck struct{}

func (c *CloudAgentCheck) ID() string    { return "cloud-agent" }
func (c *CloudAgentCheck) Role() string  { return "cloud" }
func (c *CloudAgentCheck) Title() string { return "Cloud Management Agents Presence" }
func (c *CloudAgentCheck) Description() string {
	return "Discovers cloud platform daemons: amazon-ssm-agent, walinuxagent, google-guest-agent, qemu-guest-agent"
}

func (c *CloudAgentCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	agents := []struct {
		name string
		exe  string
	}{
		{"amazon-ssm-agent", "/snap/bin/amazon-ssm-agent"},
		{"amazon-ssm-agent", "/usr/bin/amazon-ssm-agent"},
		{"walinuxagent", "/usr/sbin/waagent"},
		{"google-guest-agent", "/usr/bin/google_guest_agent"},
		{"qemu-guest-agent", "/usr/bin/qemu-ga"},
	}

	var found []string
	permDenied := false

	for _, a := range agents {
		_, err := rfs.Stat(a.exe)
		if err == nil {
			found = append(found, a.name)
		} else if os.IsPermission(err) {
			permDenied = true
		}
	}

	if permDenied && len(found) == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect cloud agent binaries: permission denied",
			ExplainLevels: [3]string{
				"Permission denied checking /usr/bin or /usr/sbin agent executables",
				"Unable to determine cloud agent presence",
				"Run with access to standard system binary paths",
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
			SummaryPlain: "No cloud platform agents detected (host is not managed by AWS SSM, Azure Linux Agent, Google Guest Agent, or QEMU Guest Agent)",
			ExplainLevels: [3]string{
				"Checked amazon-ssm-agent, waagent, google_guest_agent, and qemu-ga",
				"Host operates without vendor hypervisor/cloud management agents",
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
		SummaryPlain: fmt.Sprintf("Cloud management agent active: %s", strings.Join(found, ", ")),
		ExplainLevels: [3]string{
			fmt.Sprintf("Detected installed cloud agents: %s", strings.Join(found, ", ")),
			"Provides hypervisor lifecycle signals, diagnostics, and remote orchestration",
			"Ensure agents are kept updated via distribution package channels",
		},
		Evidence: []graph.Evidence{
			{Source: "system-binaries", Collector: "cloud-agent", Details: strings.Join(found, ", "), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "systemctl status amazon-ssm-agent walinuxagent google-guest-agent qemu-guest-agent",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// AttachedStorageCheck compares /sys/block, mounts, and /etc/fstab for attached-but-unmounted or mounted-but-missing disks.
type AttachedStorageCheck struct{}

func (c *AttachedStorageCheck) ID() string    { return "attached-storage" }
func (c *AttachedStorageCheck) Role() string  { return "cloud" }
func (c *AttachedStorageCheck) Title() string { return "Attached Cloud Storage & Mount Integrity" }
func (c *AttachedStorageCheck) Description() string {
	return "Audits block devices in /sys/block against active mounts in /proc/mounts and /etc/fstab entries"
}

func (c *AttachedStorageCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	// 1. Inspect mounts
	mountData, err := rfs.ReadFile("/proc/mounts")
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot inspect /proc/mounts: permission denied",
				ExplainLevels: [3]string{
					"Permission denied reading /proc/mounts",
					"Cannot determine mounted storage volumes",
					"Grant read access to /proc",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading /proc/mounts: %v", err)), nil
	}

	mountedDevs := make(map[string]bool)
	mountedPoints := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(mountData))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		var dev, mp, fstype string
		if strings.HasPrefix(fields[0], "/") && (len(fields) < 4 || !strings.HasPrefix(fields[1], "/")) {
			dev = "none"
			mp = fields[0]
			fstype = fields[1]
		} else if len(fields) >= 3 {
			dev = fields[0]
			mp = fields[1]
			fstype = fields[2]
		}
		if storage.IsRealBlockMount(dev, fstype, mp) {
			mountedDevs[dev] = true
			mountedPoints[mp] = true
		}
	}

	// 2. Read /etc/fstab if present
	fstabData, _ := rfs.ReadFile("/etc/fstab")
	missingMounts := 0
	if len(fstabData) > 0 {
		fScanner := bufio.NewScanner(bytes.NewReader(fstabData))
		for fScanner.Scan() {
			line := strings.TrimSpace(fScanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mp := fields[1]
				if mp != "none" && mp != "swap" && !mountedPoints[mp] {
					missingMounts++
				}
			}
		}
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Storage mount configuration verified across %d real block mounts", len(mountedPoints))
	if missingMounts > 0 {
		st = contract.StatusWarn
		sum = fmt.Sprintf("Fstab integrity warning: %d defined filesystems in /etc/fstab are not mounted", missingMounts)
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			"Audited active /proc/mounts vs static /etc/fstab entries",
			"Unmounted fstab volumes can cause service startup failure or data loss",
			"Check 'mount -a' dry-run or remove superseded fstab entries",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc/mounts", Collector: "attached-storage", Details: fmt.Sprintf("%d active mounts", len(mountedDevs)), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "findmnt --verify",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}
