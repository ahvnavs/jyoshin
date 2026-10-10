// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bufio"
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

// UnitInfo models observable properties of a system service/unit.
type UnitInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`         // service, timer, socket, etc.
	ActiveState  string `json:"active_state"` // active, inactive, failed
	LoadState    string `json:"load_state"`   // loaded, not-found
	Description  string `json:"description,omitempty"`
	MainPID      int    `json:"main_pid,omitempty"`
	ExecStart    string `json:"exec_start,omitempty"`
	RestartCount int    `json:"restart_count,omitempty"`
	UnitFile     string `json:"unit_file,omitempty"`
}

// ServiceReport contains overall service subsystem health and units.
type ServiceReport struct {
	InitSystem string     `json:"init_system"` // systemd, sysvinit, openrc, unknown
	Visibility string     `json:"visibility"`  // full, limited, none
	Note       string     `json:"note,omitempty"`
	Units      []UnitInfo `json:"units,omitempty"`
}

// Sensor reads systemd units from /run/systemd and unit file directories.
type Sensor struct {
	fs fs.FS
}

// New creates a new service collector.
func New(fs fs.FS) *Sensor {
	return &Sensor{fs: fs}
}

func (s *Sensor) Name() string {
	return "service"
}

func (s *Sensor) Interval() time.Duration {
	return 60 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	now := start.UTC()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
	}

	report := ServiceReport{
		InitSystem: "unknown",
		Visibility: "limited",
	}

	// 1. Detect init system
	isSystemd := s.detectSystemd()
	if !isSystemd {
		report.InitSystem = s.detectAlternativeInit()
		report.Visibility = "limited"
		report.Note = fmt.Sprintf("non-systemd init system (%s) detected; limited unit inspection available", report.InitSystem)

		obs.Items = []sensors.Item{
			{
				ID:        "service:report",
				Type:      "service_report",
				Data:      report,
				Evidence:  []graph.Evidence{{Source: "/proc/1/comm", Collector: s.Name(), Timestamp: now, Certainty: graph.CertaintyObserved}},
				Certainty: graph.CertaintyDerived,
			},
		}
		obs.Duration = time.Since(start)
		return obs, nil
	}

	report.InitSystem = "systemd"
	report.Visibility = "full"

	// 2. Discover units from /run/systemd/units and system unit search paths
	units := s.discoverUnits(ctx, now)
	report.Units = units

	evidence := []graph.Evidence{
		{
			Source:    "/run/systemd/system",
			Collector: s.Name(),
			Raw:       fmt.Sprintf("discovered %d units", len(units)),
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		},
	}

	items := []sensors.Item{
		{
			ID:        "service:report",
			Type:      "service_report",
			Data:      report,
			Evidence:  evidence,
			Certainty: graph.CertaintyDerived,
		},
	}

	for _, u := range units {
		items = append(items, sensors.Item{
			ID:   fmt.Sprintf("service:%s", u.Name),
			Type: "service_unit",
			Data: u,
			Evidence: []graph.Evidence{
				{
					Source:    u.UnitFile,
					Collector: s.Name(),
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		})
	}

	obs.Items = items
	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) detectSystemd() bool {
	if _, err := s.fs.Stat("/run/systemd/system"); err == nil {
		return true
	}
	if comm, err := s.fs.ReadFile("/proc/1/comm"); err == nil {
		if strings.TrimSpace(string(comm)) == "systemd" {
			return true
		}
	}
	return false
}

func (s *Sensor) detectAlternativeInit() string {
	if comm, err := s.fs.ReadFile("/proc/1/comm"); err == nil {
		name := strings.TrimSpace(string(comm))
		if name != "" {
			return name
		}
	}
	if _, err := s.fs.Stat("/sbin/openrc"); err == nil {
		return "openrc"
	}
	if _, err := s.fs.Stat("/etc/init.d"); err == nil {
		return "sysvinit"
	}
	return "unknown"
}

func (s *Sensor) discoverUnits(ctx context.Context, now time.Time) []UnitInfo {
	var units []UnitInfo
	seen := make(map[string]bool)

	// Search unit directories
	dirs := []string{
		"/run/systemd/system",
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	for _, dir := range dirs {
		select {
		case <-ctx.Done():
			return units
		default:
		}

		entries, err := s.fs.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") && !strings.HasSuffix(name, ".socket") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true

			unitPath := filepath.Join(dir, name)
			info := UnitInfo{
				Name:        name,
				Type:        strings.TrimPrefix(filepath.Ext(name), "."),
				UnitFile:    unitPath,
				ActiveState: "unknown",
				LoadState:   "loaded",
			}

			// Read unit file for Description and ExecStart
			if data, err := s.fs.ReadFile(unitPath); err == nil {
				parseUnitFile(data, &info)
			}

			units = append(units, info)
			if len(units) >= 500 { // Bound work per cycle
				return units
			}
		}
	}

	return units
}

func parseUnitFile(data []byte, u *UnitInfo) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Description=") {
			u.Description = strings.TrimPrefix(line, "Description=")
		} else if strings.HasPrefix(line, "ExecStart=") {
			u.ExecStart = strings.TrimPrefix(line, "ExecStart=")
		} else if strings.HasPrefix(line, "Restart=") {
			// hints
		} else if strings.HasPrefix(line, "MainPID=") {
			if pid, err := strconv.Atoi(strings.TrimPrefix(line, "MainPID=")); err == nil {
				u.MainPID = pid
			}
		}
	}
}
