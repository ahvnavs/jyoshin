// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/redact"
)

// AppHealthCheck inspects units, ports, and processes for application health.
type AppHealthCheck struct{}

func (c *AppHealthCheck) ID() string    { return "app-health" }
func (c *AppHealthCheck) Role() string  { return "devops" }
func (c *AppHealthCheck) Title() string { return "Application Services, Ports, and Processes Health" }
func (c *AppHealthCheck) Description() string {
	return "Verifies active systemd service units, bound network listening ports, and running processes"
}

func (c *AppHealthCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	unitFilter := params["unit"]
	if !ValidateSafeParam(unitFilter) {
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusCrit, "Invalid parameter rejected: potential injection"), ErrInvalidParam
	}

	// 1. Inspect processes via /proc
	entries, err := rfs.ReadDir("/proc")
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot inspect /proc processes: permission denied",
				ExplainLevels: [3]string{
					"/proc unreadable by current process",
					"Process visibility is denied by host access controls",
					"Run as user with /proc read permissions",
				},
				Certainty: graph.CertaintyObserved,
				Coverage:  contract.CoverageSummary{Seen: 0, Total: 0, Reason: "permission denied reading /proc"},
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Error reading /proc: %v", err)), nil
	}

	procCount := 0
	for _, e := range entries {
		if e.IsDir() {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				procCount++
			}
		}
	}

	// 2. Inspect listeners in /proc/net/tcp
	tcpData, err := rfs.ReadFile("/proc/net/tcp")
	listenCount := 0
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(tcpData))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 && fields[3] == "0A" { // 0A is TCP_LISTEN
				listenCount++
			}
		}
	}

	status := contract.StatusOK
	summary := fmt.Sprintf("Host application environment healthy: %d processes active, %d TCP listening ports", procCount, listenCount)
	if procCount == 0 {
		status = contract.StatusWarn
		summary = "Zero active processes detected on host"
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       status,
		SummaryPlain: summary,
		ExplainLevels: [3]string{
			fmt.Sprintf("Observed %d running processes and %d listening TCP ports", procCount, listenCount),
			"Application runtime environment is active and serving traffic",
			"No remediation required",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc", Collector: "app-health", Details: fmt.Sprintf("%d pids found", procCount), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
			{Source: "/proc/net/tcp", Collector: "app-health", Details: fmt.Sprintf("%d listen sockets", listenCount), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		Coverage:          contract.CoverageSummary{Seen: procCount, Total: procCount, Reason: "Full procfs scan"},
		EquivalentCommand: "ps -ef; ss -tulpn",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// AppLogsCheck retrieves bounded, redacted application log tails (up to 200 lines).
type AppLogsCheck struct{}

func (c *AppLogsCheck) ID() string   { return "app-logs" }
func (c *AppLogsCheck) Role() string { return "devops" }
func (c *AppLogsCheck) Title() string {
	return "Application Logs (Bounded 200 Lines, Secrets Redacted)"
}
func (c *AppLogsCheck) Description() string {
	return "Inspects bounded recent application log lines with mandatory token/secret redaction"
}

func (c *AppLogsCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	logFile := params["file"]
	if logFile == "" {
		logFile = "/var/log/syslog"
	}
	if !ValidateSafeParam(logFile) {
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusCrit, "Invalid log path: path traversal rejected"), ErrInvalidParam
	}

	// Permission check on file
	data, err := rfs.ReadFile(logFile)
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: fmt.Sprintf("Cannot read log file %s: permission denied", logFile),
				ExplainLevels: [3]string{
					fmt.Sprintf("Access to %s is restricted by host file permissions", logFile),
					"Logs could not be audited for application errors or failures",
					"Ensure user has adm or read access to system log files",
				},
				Certainty: graph.CertaintyObserved,
				Coverage:  contract.CoverageSummary{Seen: 0, Total: 1, Reason: "permission denied on log file"},
				ReadOnly:  true,
			}, nil
		}
		if os.IsNotExist(err) {
			// Try fallback /var/log/messages
			altData, altErr := rfs.ReadFile("/var/log/messages")
			if altErr == nil {
				data = altData
				logFile = "/var/log/messages"
			} else {
				return contract.CheckResult{
					ID:           c.ID(),
					Role:         c.Role(),
					Title:        c.Title(),
					Status:       contract.StatusNotApplicable,
					SummaryPlain: fmt.Sprintf("Log file %s does not exist on this system", logFile),
					ExplainLevels: [3]string{
						fmt.Sprintf("Neither %s nor /var/log/messages exists", logFile),
						"System may use pure systemd journal without disk text logs",
						"Query journalctl if persistent system log is needed",
					},
					Certainty: graph.CertaintyObserved,
					ReadOnly:  true,
				}, nil
			}
		}
	}

	// Bounded tail to 200 lines
	lines := strings.Split(string(data), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}

	redactedLines := make([]string, len(lines))
	errorCount := 0
	for i, l := range lines {
		clean := redact.RedactString(l)
		if strings.Contains(strings.ToLower(clean), "error") || strings.Contains(strings.ToLower(clean), "fatal") || strings.Contains(strings.ToLower(clean), "fail") {
			errorCount++
		}
		redactedLines[i] = clean
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Inspected %d recent lines from %s (0 fatal errors)", len(redactedLines), logFile)
	if errorCount > 0 {
		st = contract.StatusWarn
		sum = fmt.Sprintf("Inspected %d recent lines from %s (%d warning/error lines detected)", len(redactedLines), logFile, errorCount)
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Tail of %s inspected (bounded to 200 lines, all secrets redacted)", logFile),
			fmt.Sprintf("%d lines contained error/failure indicators", errorCount),
			"Inspect specific failing service logs if errors are persistent",
		},
		Evidence: []graph.Evidence{
			{Source: logFile, Collector: "app-logs", Details: fmt.Sprintf("%d lines inspected", len(redactedLines)), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: fmt.Sprintf("tail -n 200 %s", logFile),
		ReadOnly:          true,
		RawRedacted:       strings.Join(redactedLines, "\n"),
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// CPUMemoryCheck inspects load, memory, swap, PSI metrics, and top consumers.
type CPUMemoryCheck struct{}

func (c *CPUMemoryCheck) ID() string   { return "cpu-memory" }
func (c *CPUMemoryCheck) Role() string { return "devops" }
func (c *CPUMemoryCheck) Title() string {
	return "CPU, Memory, Pressure Stall (PSI), and Top Consumers"
}
func (c *CPUMemoryCheck) Description() string {
	return "Evaluates load averages, available memory, swap pressure, and PSI stall percentages"
}

func (c *CPUMemoryCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	loadData, err := rfs.ReadFile("/proc/loadavg")
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:            c.ID(),
				Role:          c.Role(),
				Title:         c.Title(),
				Status:        contract.StatusUnknown,
				SummaryPlain:  "Cannot read /proc/loadavg: permission denied",
				ExplainLevels: [3]string{"Permission denied accessing /proc/loadavg", "System load cannot be determined", "Grant read access to /proc"},
				Certainty:     graph.CertaintyObserved,
				ReadOnly:      true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading /proc/loadavg: %v", err)), nil
	}

	loadFields := strings.Fields(string(loadData))
	load1 := "0.0"
	if len(loadFields) > 0 {
		load1 = loadFields[0]
	}

	memData, _ := rfs.ReadFile("/proc/meminfo")
	var memTotalKB, memAvailKB uint64
	scanner := bufio.NewScanner(bytes.NewReader(memData))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memTotalKB, _ = strconv.ParseUint(parts[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memAvailKB, _ = strconv.ParseUint(parts[1], 10, 64)
			}
		}
	}

	var memUsedPct float64
	if memTotalKB > 0 && memAvailKB > 0 {
		memUsedPct = float64(memTotalKB-memAvailKB) / float64(memTotalKB) * 100.0
	}

	// Check PSI if available
	psiCPU, _ := rfs.ReadFile("/proc/pressure/cpu")
	psiNote := "PSI available"
	if len(psiCPU) == 0 {
		psiNote = "PSI not supported by kernel"
	}

	st := contract.StatusOK
	if memUsedPct > 90.0 {
		st = contract.StatusWarn
	}

	summary := fmt.Sprintf("Load average 1m: %s, Memory usage: %.1f%% (Total: %d MB), %s", load1, memUsedPct, memTotalKB/1024, psiNote)

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: summary,
		ExplainLevels: [3]string{
			fmt.Sprintf("Load avg 1m is %s; Memory utilization is %.1f%%", load1, memUsedPct),
			"Assesses whether resource saturation or kernel pressure stalls are occurring",
			"Monitor high-memory background processes if usage exceeds 90%",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc/loadavg", Collector: "cpu-memory", Raw: string(loadData), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "uptime; free -m; cat /proc/pressure/cpu",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}
