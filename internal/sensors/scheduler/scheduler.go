// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// ScheduledJob represents a scheduled task (cron or systemd timer).
type ScheduledJob struct {
	Type     string `json:"type"`     // "cron" or "systemd-timer"
	Source   string `json:"source"`   // file path or timer name
	Schedule string `json:"schedule"` // e.g. "0 * * * *" or "hourly" or OnCalendar string
	User     string `json:"user"`     // execution user
	Command  string `json:"command"`  // executed command or target unit
}

// Sensor collects cron jobs and systemd timers.
type Sensor struct {
	rootDir string
}

// NewSensor creates a new scheduler sensor rooted at rootDir.
func NewSensor(rootDir string) *Sensor {
	if rootDir == "" {
		rootDir = "/"
	}
	return &Sensor{rootDir: rootDir}
}

func (s *Sensor) Name() string {
	return "scheduler"
}

func (s *Sensor) Interval() time.Duration {
	return 300 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  start,
		Status:     sensors.StatusSuccess,
	}

	var items []sensors.Item

	// 1. Scan /etc/crontab
	crontabPath := filepath.Join(s.rootDir, "etc", "crontab")
	s.parseCrontab(crontabPath, "root", true, &items, start)

	// 2. Scan /etc/cron.d/
	cronD := filepath.Join(s.rootDir, "etc", "cron.d")
	s.scanCronDir(cronD, true, &items, start)

	// 3. Scan /etc/cron.{hourly,daily,weekly,monthly}
	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		dir := filepath.Join(s.rootDir, "etc", "cron."+period)
		s.scanCronPeriodDir(dir, period, &items, start)
	}

	// 4. Scan /var/spool/cron/crontabs (and /var/spool/cron)
	s.scanUserCrontabs(filepath.Join(s.rootDir, "var", "spool", "cron", "crontabs"), &items, start)
	s.scanUserCrontabs(filepath.Join(s.rootDir, "var", "spool", "cron"), &items, start)

	// 5. Scan systemd timer units in /etc/systemd/system and /lib/systemd/system
	for _, unitDir := range []string{
		filepath.Join(s.rootDir, "etc", "systemd", "system"),
		filepath.Join(s.rootDir, "lib", "systemd", "system"),
		filepath.Join(s.rootDir, "usr", "lib", "systemd", "system"),
	} {
		s.scanSystemdTimers(unitDir, &items, start)
	}

	obs.Items = items
	obs.TotalSeen = len(items)
	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) parseCrontab(path string, defaultUser string, hasUserField bool, items *[]sensors.Item, now time.Time) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() {
		_ = f.Close()
	}()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") {
			continue
		}

		fields := strings.Fields(line)
		var sched, user, cmd string
		if hasUserField && len(fields) >= 7 {
			sched = strings.Join(fields[:5], " ")
			user = fields[5]
			cmd = strings.Join(fields[6:], " ")
		} else if !hasUserField && len(fields) >= 6 {
			sched = strings.Join(fields[:5], " ")
			user = defaultUser
			cmd = strings.Join(fields[5:], " ")
		} else {
			continue
		}

		job := ScheduledJob{
			Type:     "cron",
			Source:   path,
			Schedule: sched,
			User:     user,
			Command:  cmd,
		}

		*items = append(*items, sensors.Item{
			ID:   fmt.Sprintf("cron:%s:%d", filepath.Base(path), lineNum),
			Type: "scheduled_job",
			Data: job,
			Evidence: []graph.Evidence{
				{
					Source:    path,
					Collector: "scheduler",
					Raw:       line,
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
					Details:   fmt.Sprintf("Cron entry at %s:%d", path, lineNum),
				},
			},
			Certainty: graph.CertaintyObserved,
		})
	}
}

func (s *Sensor) scanCronDir(dir string, hasUserField bool, items *[]sensors.Item, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !strings.HasSuffix(e.Name(), "~") {
			s.parseCrontab(filepath.Join(dir, e.Name()), "root", hasUserField, items, now)
		}
	}
}

func (s *Sensor) scanCronPeriodDir(dir, period string, items *[]sensors.Item, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			jobPath := filepath.Join(dir, e.Name())
			job := ScheduledJob{
				Type:     "cron",
				Source:   jobPath,
				Schedule: period,
				User:     "root",
				Command:  jobPath,
			}
			*items = append(*items, sensors.Item{
				ID:   fmt.Sprintf("cron:%s:%s", period, e.Name()),
				Type: "scheduled_job",
				Data: job,
				Evidence: []graph.Evidence{
					{
						Source:    jobPath,
						Collector: "scheduler",
						Timestamp: now,
						Certainty: graph.CertaintyObserved,
						Details:   fmt.Sprintf("Periodic cron script in %s", dir),
					},
				},
				Certainty: graph.CertaintyObserved,
			})
		}
	}
}

func (s *Sensor) scanUserCrontabs(dir string, items *[]sensors.Item, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			user := e.Name()
			s.parseCrontab(filepath.Join(dir, user), user, false, items, now)
		}
	}
}

func (s *Sensor) scanSystemdTimers(dir string, items *[]sensors.Item, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".timer") {
			timerPath := filepath.Join(dir, e.Name())
			schedule, unit := parseTimerFile(timerPath)
			if unit == "" {
				unit = strings.TrimSuffix(e.Name(), ".timer") + ".service"
			}
			job := ScheduledJob{
				Type:     "systemd-timer",
				Source:   timerPath,
				Schedule: schedule,
				User:     "root",
				Command:  unit,
			}
			*items = append(*items, sensors.Item{
				ID:   fmt.Sprintf("timer:%s", e.Name()),
				Type: "scheduled_job",
				Data: job,
				Evidence: []graph.Evidence{
					{
						Source:    timerPath,
						Collector: "scheduler",
						Timestamp: now,
						Certainty: graph.CertaintyObserved,
						Details:   fmt.Sprintf("Systemd timer unit %s", e.Name()),
					},
				},
				Certainty: graph.CertaintyObserved,
			})
		}
	}
}

func parseTimerFile(path string) (schedule string, unit string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer func() {
		_ = f.Close()
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "OnCalendar=") {
			schedule = strings.TrimPrefix(line, "OnCalendar=")
		} else if strings.HasPrefix(line, "OnBootSec=") && schedule == "" {
			schedule = "OnBootSec=" + strings.TrimPrefix(line, "OnBootSec=")
		} else if strings.HasPrefix(line, "Unit=") {
			unit = strings.TrimPrefix(line, "Unit=")
		}
	}
	return schedule, unit
}
