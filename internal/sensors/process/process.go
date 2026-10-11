// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/sensors"
)

// ProcessInfo models observable attributes of a single process.
type ProcessInfo struct {
	PID          int    `json:"pid"`
	PPID         int    `json:"ppid"`
	Name         string `json:"name"`
	Cmdline      string `json:"cmdline"`
	Exe          string `json:"exe"`
	User         string `json:"user"`
	UID          int    `json:"uid"`
	State        string `json:"state"` // R (running), S (sleeping), D (disk sleep), Z (zombie), etc.
	Threads      int    `json:"threads"`
	StartTime    uint64 `json:"start_time_ticks"`
	Cgroup       string `json:"cgroup,omitempty"`
	OpenFDCount  int    `json:"open_fd_count"`
	UTime        uint64 `json:"utime_ticks"`
	STime        uint64 `json:"stime_ticks"`
	RSSPages     int64  `json:"rss_pages"`
	VSizeBytes   uint64 `json:"vsize_bytes"`
	IOReadBytes  uint64 `json:"io_read_bytes"`
	IOWriteBytes uint64 `json:"io_write_bytes"`
	RestartHint  string `json:"restart_hint,omitempty"`
}

// Sensor collects process attributes by inspecting /proc.
type Sensor struct {
	fs           fs.FS
	maxProcesses int
}

// New creates a new process collector.
func New(fs fs.FS) *Sensor {
	return &Sensor{
		fs:           fs,
		maxProcesses: 2048, // Default bound
	}
}

// SetMaxProcesses configures the process collection limit. A value <= 0 disables capping.
func (s *Sensor) SetMaxProcesses(limit int) {
	s.maxProcesses = limit
}

func (s *Sensor) Name() string {
	return "process"
}

func (s *Sensor) Interval() time.Duration {
	return 30 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	now := start.UTC()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
	}

	entries, err := s.fs.ReadDir("/proc")
	if err != nil {
		if fs.IsPermission(err) {
			obs.Status = sensors.StatusUnknown
			obs.Reason = fmt.Sprintf("permission denied reading /proc: %v", err)
			return obs, nil
		}
		return obs, fmt.Errorf("failed reading /proc directory: %w", err)
	}

	var items []sensors.Item
	totalPids := 0
	count := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a numeric PID directory
		}
		totalPids++

		select {
		case <-ctx.Done():
			obs.Status = sensors.StatusUnknown
			obs.Reason = "collection cancelled or timed out"
			obs.Items = items
			obs.TotalSeen = totalPids
			return obs, nil
		default:
		}

		if s.maxProcesses > 0 && count >= s.maxProcesses {
			// Continue loop to count totalSeen without silent drops
			continue
		}

		proc, ev, ok := s.readProcess(pid, now)
		if !ok {
			// Process vanished mid-read; handle gracefully per requirements
			continue
		}

		items = append(items, sensors.Item{
			ID:        fmt.Sprintf("proc:%d", pid),
			Type:      "process",
			Data:      proc,
			Evidence:  ev,
			Certainty: graph.CertaintyObserved,
		})
		count++
	}

	obs.Items = items
	obs.TotalSeen = totalPids
	if s.maxProcesses > 0 && totalPids > s.maxProcesses {
		obs.Truncated = true
	}
	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) readProcess(pid int, now time.Time) (ProcessInfo, []graph.Evidence, bool) {
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Stat /proc/<pid> to verify process exists and obtain UID
	fi, err := s.fs.Stat(procDir)
	if err != nil {
		return ProcessInfo{}, nil, false
	}

	proc := ProcessInfo{PID: pid}
	var ev []graph.Evidence

	// 1. /proc/<pid>/stat
	statPath := filepath.Join(procDir, "stat")
	statBytes, err := s.fs.ReadFile(statPath)
	if err != nil {
		return ProcessInfo{}, nil, false
	}

	parseProcStat(statBytes, &proc)
	ev = append(ev, graph.Evidence{
		Source:    statPath,
		Collector: s.Name(),
		Timestamp: now,
		Certainty: graph.CertaintyObserved,
	})

	// 2. /proc/<pid>/cmdline
	cmdlinePath := filepath.Join(procDir, "cmdline")
	if cmdData, err := s.fs.ReadFile(cmdlinePath); err == nil {
		proc.Cmdline = string(bytes.ReplaceAll(cmdData, []byte{0}, []byte(" ")))
		proc.Cmdline = strings.TrimSpace(proc.Cmdline)
	}

	// 3. /proc/<pid>/exe (symlink)
	exePath := filepath.Join(procDir, "exe")
	if target, err := s.fs.Readlink(exePath); err == nil {
		proc.Exe = target
	}

	// 4. /proc/<pid>/status for UID / user / threads
	statusPath := filepath.Join(procDir, "status")
	if statusData, err := s.fs.ReadFile(statusPath); err == nil {
		parseProcStatus(statusData, &proc)
	}

	// 5. /proc/<pid>/cgroup
	cgroupPath := filepath.Join(procDir, "cgroup")
	if cgData, err := s.fs.ReadFile(cgroupPath); err == nil {
		proc.Cgroup = strings.TrimSpace(string(cgData))
	}

	// 6. Open FD count (/proc/<pid>/fd)
	fdPath := filepath.Join(procDir, "fd")
	if fdEntries, err := s.fs.ReadDir(fdPath); err == nil {
		proc.OpenFDCount = len(fdEntries)
	}

	// 7. /proc/<pid>/io (may be permission-restricted for unprivileged user)
	ioPath := filepath.Join(procDir, "io")
	if ioData, err := s.fs.ReadFile(ioPath); err == nil {
		parseProcIO(ioData, &proc)
	}

	_ = fi // ensure unused warning suppressed if fi properties not accessed
	return proc, ev, true
}

// parseProcStat extracts fields from /proc/<pid>/stat accounting for comm parentheses
func parseProcStat(data []byte, proc *ProcessInfo) {
	str := string(data)
	firstParen := strings.Index(str, "(")
	lastParen := strings.LastIndex(str, ")")
	if firstParen == -1 || lastParen == -1 || lastParen < firstParen {
		return
	}

	proc.Name = str[firstParen+1 : lastParen]
	rest := strings.TrimSpace(str[lastParen+1:])
	fields := strings.Fields(rest)

	// Fields after comm:
	// 0: state
	// 1: ppid
	// 2: pgrp
	// 3: session
	// 4: tty_nr
	// 5: tpgid
	// 6: flags
	// 7: minflt
	// 8: cminflt
	// 9: majflt
	// 10: cmajflt
	// 11: utime (field 14 in man proc)
	// 12: stime (field 15)
	// 13: cutime
	// 14: cstime
	// 15: priority
	// 16: nice
	// 17: num_threads (field 20)
	// 18: itrealvalue
	// 19: starttime (field 22)
	// 20: vsize (field 23)
	// 21: rss (field 24)

	if len(fields) > 0 {
		proc.State = fields[0]
	}
	if len(fields) > 1 {
		proc.PPID, _ = strconv.Atoi(fields[1])
	}
	if len(fields) > 11 {
		proc.UTime, _ = strconv.ParseUint(fields[11], 10, 64)
	}
	if len(fields) > 12 {
		proc.STime, _ = strconv.ParseUint(fields[12], 10, 64)
	}
	if len(fields) > 17 {
		proc.Threads, _ = strconv.Atoi(fields[17])
	}
	if len(fields) > 19 {
		proc.StartTime, _ = strconv.ParseUint(fields[19], 10, 64)
	}
	if len(fields) > 20 {
		proc.VSizeBytes, _ = strconv.ParseUint(fields[20], 10, 64)
	}
	if len(fields) > 21 {
		proc.RSSPages, _ = strconv.ParseInt(fields[21], 10, 64)
	}
}

func parseProcStatus(data []byte, proc *ProcessInfo) {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				proc.UID, _ = strconv.Atoi(fields[1])
			}
		} else if strings.HasPrefix(line, "Threads:") && proc.Threads == 0 {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				proc.Threads, _ = strconv.Atoi(fields[1])
			}
		}
	}
}

func parseProcIO(data []byte, proc *ProcessInfo) {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "read_bytes:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				proc.IOReadBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "write_bytes:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				proc.IOWriteBytes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
}
