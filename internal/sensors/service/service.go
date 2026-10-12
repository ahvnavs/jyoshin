// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// UnitInfo models observable properties of a system service/unit.
type UnitInfo struct {
	Name          string `json:"name"`
	Type          string `json:"type"`         // service, timer, socket, etc.
	ActiveState   string `json:"active_state"` // active, inactive, failed
	LoadState     string `json:"load_state"`   // loaded, not-found
	Description   string `json:"description,omitempty"`
	MainPID       int    `json:"main_pid,omitempty"`
	ExecStart     string `json:"exec_start,omitempty"`
	RestartCount  int    `json:"restart_count,omitempty"`
	UnitFile      string `json:"unit_file,omitempty"`
	WorldWritable bool   `json:"world_writable,omitempty"`
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

	// 3. Query real runtime state via allow-listed /usr/bin/systemctl
	s.queryRuntimeUnitStates(ctx, units)

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

			if fi, err := s.fs.Stat(unitPath); err == nil {
				if fi.Mode().Perm()&0002 != 0 {
					info.WorldWritable = true
				}
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

// queryRuntimeUnitStates queries /usr/bin/systemctl show for real runtime state.
// Invariants enforced:
// 1. Allow-listed absolute binary path: /usr/bin/systemctl or /bin/systemctl
// 2. Fixed arguments: show --property=Id,ActiveState,SubState,NRestarts,MainPID,LoadState
// 3. Unit names validated strictly against discovered units (no injection or meta-characters)
// 4. Timeout context (bounded work per cycle)
// 5. 1 MB output cap
// 6. Cleared / sanitized environment: LC_ALL=C, PATH=/usr/bin:/bin
func (s *Sensor) queryRuntimeUnitStates(ctx context.Context, units []UnitInfo) {
	if len(units) == 0 {
		return
	}

	systemctlPath := "/usr/bin/systemctl"
	if fi, err := os.Stat(systemctlPath); err != nil || fi.IsDir() {
		systemctlPath = "/bin/systemctl"
		if fi, err := os.Stat(systemctlPath); err != nil || fi.IsDir() {
			return // systemctl binary not present on host
		}
	}

	// Validate unit names: alphanumeric, dots, dashes, underscores, at-signs (@)
	unitMap := make(map[string]*UnitInfo, len(units))
	var validUnitNames []string
	for i := range units {
		name := units[i].Name
		if isValidUnitName(name) {
			unitMap[name] = &units[i]
			validUnitNames = append(validUnitNames, name)
		}
	}

	if len(validUnitNames) == 0 {
		return
	}

	// Batch units in chunks of 50 to avoid exceeding arg length bounds
	chunkSize := 50
	for i := 0; i < len(validUnitNames); i += chunkSize {
		end := i + chunkSize
		if end > len(validUnitNames) {
			end = len(validUnitNames)
		}
		chunk := validUnitNames[i:end]

		queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		args := append([]string{"show", "--property=Id,ActiveState,SubState,NRestarts,MainPID,LoadState", "--"}, chunk...)
		cmd := exec.CommandContext(queryCtx, systemctlPath, args...)
		cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}

		outReader, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			continue
		}

		if err := cmd.Start(); err != nil {
			cancel()
			continue
		}

		// Enforce 1 MB maximum output cap via io.LimitReader
		lr := io.LimitReader(outReader, 1024*1024)
		out, _ := io.ReadAll(lr)
		_ = cmd.Wait()
		cancel()

		ParseSystemctlShow(out, unitMap)
	}
}

func isValidUnitName(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for _, ch := range name {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '.' && ch != '-' && ch != '_' && ch != '@' {
			return false
		}
	}
	return true
}

// ParseSystemctlShow parses systemctl show key-value blocks separated by blank lines into UnitInfo.
func ParseSystemctlShow(data []byte, units map[string]*UnitInfo) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var currentID string
	props := make(map[string]string)

	flush := func() {
		if currentID != "" {
			if u, ok := units[currentID]; ok {
				if act, ok := props["ActiveState"]; ok && act != "" {
					u.ActiveState = act
				}
				if load, ok := props["LoadState"]; ok && load != "" {
					u.LoadState = load
				}
				if nr, ok := props["NRestarts"]; ok {
					if n, err := strconv.Atoi(nr); err == nil {
						u.RestartCount = n
					}
				}
				if mpid, ok := props["MainPID"]; ok {
					if pid, err := strconv.Atoi(mpid); err == nil && pid > 0 {
						u.MainPID = pid
					}
				}
			}
		}
		currentID = ""
		props = make(map[string]string)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			flush()
			continue
		}
		eqIdx := strings.Index(line, "=")
		if eqIdx == -1 {
			continue
		}
		k := line[:eqIdx]
		v := line[eqIdx+1:]
		if k == "Id" {
			// In case previous block did not end with blank line
			if currentID != "" && currentID != v {
				flush()
			}
			currentID = v
		}
		props[k] = v
	}
	flush()
}
