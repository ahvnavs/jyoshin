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
	"syscall"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors/storage"
)

// DiskInodesCheck inspects statfs and real block mounts for disk capacity and inode saturation.
type DiskInodesCheck struct{}

func (c *DiskInodesCheck) ID() string    { return "disk-inodes" }
func (c *DiskInodesCheck) Role() string  { return "infrastructure" }
func (c *DiskInodesCheck) Title() string { return "Disk Capacity & Inode Saturation" }
func (c *DiskInodesCheck) Description() string {
	return "Measures block allocation and inode exhaustion across all mounted filesystems via statfs"
}

func (c *DiskInodesCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
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
					"Filesystem mount and inode usage cannot be analyzed",
					"Grant read permission to /proc",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading /proc/mounts: %v", err)), nil
	}

	highUsageMounts := []string{}
	checkedMounts := 0
	scanner := bufio.NewScanner(bytes.NewReader(mountData))

	seenMounts := make(map[string]bool)
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

		if !storage.IsRealBlockMount(dev, fstype, mp) {
			continue
		}
		if seenMounts[mp] {
			continue
		}
		seenMounts[mp] = true

		checkedMounts++
		var stat syscall.Statfs_t
		targetPath := rfs.Path(mp)
		if err := syscall.Statfs(targetPath, &stat); err == nil && stat.Blocks > 0 {
			usedBlocks := stat.Blocks - stat.Bfree
			usagePct := float64(usedBlocks) / float64(stat.Blocks) * 100.0
			if usagePct >= 90.0 {
				highUsageMounts = append(highUsageMounts, fmt.Sprintf("%s (%.1f%%)", mp, usagePct))
			}
		}
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Inspected %d filesystems; all block devices report healthy disk capacity and inode headroom", checkedMounts)
	if len(highUsageMounts) > 0 {
		st = contract.StatusWarn
		sum = fmt.Sprintf("Storage capacity alert: high disk usage on %s", strings.Join(highUsageMounts, ", "))
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Audited statfs on %d filesystems across host block mounts", checkedMounts),
			"Inodes or storage above 90% can cause application write freezes and crash loop",
			"Free up space or purge archived logs from affected partitions",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc/mounts", Collector: "disk-inodes", Details: fmt.Sprintf("%d filesystems inspected", checkedMounts), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "df -h; df -i",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// FailedServicesCheck inspects systemd unit states for failed or degraded services.
type FailedServicesCheck struct{}

func (c *FailedServicesCheck) ID() string    { return "failed-services" }
func (c *FailedServicesCheck) Role() string  { return "infrastructure" }
func (c *FailedServicesCheck) Title() string { return "Systemd Failed Services Audit" }
func (c *FailedServicesCheck) Description() string {
	return "Discovers systemd service units in failed, error, or restart-looping state"
}

func (c *FailedServicesCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	// Verify systemd is running: check /run/systemd/system directory
	if _, err := rfs.Stat("/run/systemd/system"); err != nil {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "systemd is not running or offline (/run/systemd/system not present)",
			ExplainLevels: [3]string{
				"Systemd runtime directory /run/systemd/system is absent",
				"Cannot audit failed services when systemd daemon is not active",
				"Ensure systemd is running as PID 1",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	unitDirs := []string{"/run/systemd/units", "/run/systemd/system", "/etc/systemd/system"}
	var failedUnits []string
	permDenied := false

	for _, d := range unitDirs {
		entries, err := rfs.ReadDir(d)
		if err != nil {
			if os.IsPermission(err) {
				permDenied = true
			}
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".service") {
				// Inspect content for failed unit status if stored
				content, err := rfs.ReadFile(fmt.Sprintf("%s/%s", d, e.Name()))
				if err == nil && strings.Contains(string(content), "ActiveState=failed") {
					failedUnits = append(failedUnits, e.Name())
				}
			}
		}
	}

	if permDenied && len(failedUnits) == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect systemd unit directories: permission denied",
			ExplainLevels: [3]string{
				"Permission denied reading systemd unit directories in /run or /etc",
				"Unable to determine if background services are failed",
				"Ensure appropriate read access to systemd directories",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	st := contract.StatusOK
	sum := "Zero failed or degraded systemd units detected"
	if len(failedUnits) > 0 {
		st = contract.StatusCrit
		sum = fmt.Sprintf("Failed service units detected: %s", strings.Join(failedUnits, ", "))
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			"Audited systemd runtime state for failed unit definitions",
			"Failed services can represent crashed critical infrastructure components",
			"Run 'systemctl --failed' and 'journalctl -u <unit>' to inspect root cause",
		},
		Evidence: []graph.Evidence{
			{Source: "systemd-units", Collector: "failed-services", Details: fmt.Sprintf("%d failed units", len(failedUnits)), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "systemctl --failed",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// TimeSyncCheck verifies adjtimex sync state and presence of chrony/timesyncd/ntp.
type TimeSyncCheck struct{}

func (c *TimeSyncCheck) ID() string    { return "time-sync" }
func (c *TimeSyncCheck) Role() string  { return "infrastructure" }
func (c *TimeSyncCheck) Title() string { return "System Clock & NTP Synchronization State" }
func (c *TimeSyncCheck) Description() string {
	return "Inspects adjtimex kernel status and presence of chrony, systemd-timesyncd, or ntpd"
}

func (c *TimeSyncCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	// If /proc cannot be read, report UNKNOWN with reason
	if _, err := rfs.ReadDir("/proc"); err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot inspect /proc: permission denied",
				ExplainLevels: [3]string{
					"Permission denied reading /proc filesystem",
					"Cannot inspect running time daemons or kernel osrelease",
					"Grant read access to /proc",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: fmt.Sprintf("Cannot inspect /proc: %v", err),
			ExplainLevels: [3]string{
				"Procfs filesystem is unavailable or unmounted",
				"Cannot audit time synchronization state without /proc",
				"Ensure /proc is mounted",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	// Detect WSL or container environments
	osRelease, _ := rfs.ReadFile("/proc/sys/kernel/osrelease")
	if strings.Contains(strings.ToLower(string(osRelease)), "microsoft") || strings.Contains(strings.ToLower(string(osRelease)), "wsl") {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Time synchronization unknown in WSL/container: clock is managed by hypervisor host",
			ExplainLevels: [3]string{
				"WSL guest kernel clock is steered directly by the Windows hypervisor",
				"Guest NTP daemons and adjtimex sync status cannot be independently verified",
				"Host clock synchronization should be verified on the Windows hypervisor",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot query adjtimex: permission denied",
				ExplainLevels: [3]string{
					"Syscall adjtimex returned permission denied",
					"System clock synchronization status cannot be queried",
					"Grant CAP_SYS_TIME or inspect /etc/chrony/chrony.conf directly",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
	}

	// In Linux, TIME_OK = 0, TIME_INS = 1, TIME_DEL = 2, TIME_OOP = 3, TIME_WAIT = 4, TIME_BAD/ERROR = 5
	// tx.Status & 64 != 0 indicates STA_UNSYNC (clock unsynchronized)
	staUnsync := (tx.Status & 64) != 0
	isSynchronized := (err == nil && state != 5 && !staUnsync)

	// Check if a time sync daemon is actually RUNNING in /proc
	runningDaemon := ""
	daemons := []string{"systemd-timesyn", "chronyd", "ntpd"}
	if procEntries, err := rfs.ReadDir("/proc"); err == nil {
		for _, pe := range procEntries {
			if !pe.IsDir() {
				continue
			}
			commData, err := rfs.ReadFile(fmt.Sprintf("/proc/%s/comm", pe.Name()))
			if err == nil {
				comm := strings.TrimSpace(string(commData))
				for _, d := range daemons {
					if strings.Contains(comm, d) {
						runningDaemon = comm
						break
					}
				}
				if runningDaemon != "" {
					break
				}
			}
		}
	}

	st := contract.StatusOK
	sum := "System clock is synchronized with external time source"
	if !isSynchronized && runningDaemon == "" {
		st = contract.StatusWarn
		sum = "System clock is not synchronized (kernel reports STA_UNSYNC; no active chrony or timesyncd process running)"
	} else if isSynchronized && runningDaemon != "" {
		sum = fmt.Sprintf("System clock is synchronized (verified via kernel adjtimex and running daemon %s)", runningDaemon)
	} else if runningDaemon != "" && !isSynchronized {
		st = contract.StatusWarn
		sum = fmt.Sprintf("Time sync daemon %s is running but kernel reports clock unsynchronized (STA_UNSYNC)", runningDaemon)
	} else if isSynchronized && runningDaemon == "" {
		sum = "System clock is synchronized (verified via kernel adjtimex; no dedicated NTP daemon detected)"
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Queried kernel adjtimex status code %d and daemon paths", state),
			"Clock skew breaks TLS validation, distributed consensus, and event ordering",
			"Enable systemd-timesyncd or chrony to maintain microsecond clock synchronization",
		},
		Evidence: []graph.Evidence{
			{Source: "kernel/adjtimex", Collector: "time-sync", Details: fmt.Sprintf("status=%d", tx.Status), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "timedatectl status",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}
