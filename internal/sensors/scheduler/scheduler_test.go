// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSchedulerSensor(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Crontab
	etcDir := filepath.Join(tmpDir, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}
	crontab := `SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user  command
17 * * * * root    cd / && run-parts --report /etc/cron.hourly
`
	if err := os.WriteFile(filepath.Join(etcDir, "crontab"), []byte(crontab), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. cron.daily
	cronDaily := filepath.Join(etcDir, "cron.daily")
	if err := os.MkdirAll(cronDaily, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cronDaily, "logrotate"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// 3. systemd timer
	systemdDir := filepath.Join(etcDir, "systemd", "system")
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		t.Fatal(err)
	}
	timerContent := `[Unit]
Description=Daily Backup Timer

[Timer]
OnCalendar=*-*-* 03:00:00
Unit=backup.service

[Install]
WantedBy=timers.target
`
	if err := os.WriteFile(filepath.Join(systemdDir, "backup.timer"), []byte(timerContent), 0644); err != nil {
		t.Fatal(err)
	}

	sensor := NewSensor(tmpDir)
	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if obs.Status != "ok" {
		t.Fatalf("expected status ok, got %s: %s", obs.Status, obs.Reason)
	}

	if len(obs.Items) != 3 {
		t.Fatalf("expected 3 scheduled items, got %d", len(obs.Items))
	}

	foundCron := false
	foundDaily := false
	foundTimer := false

	for _, it := range obs.Items {
		job := it.Data.(ScheduledJob)
		if job.Type == "cron" && job.Schedule == "17 * * * *" {
			foundCron = true
			if job.User != "root" || job.Command != "cd / && run-parts --report /etc/cron.hourly" {
				t.Errorf("unexpected cron job data: %+v", job)
			}
		}
		if job.Type == "cron" && job.Schedule == "daily" && filepath.Base(job.Command) == "logrotate" {
			foundDaily = true
		}
		if job.Type == "systemd-timer" && job.Schedule == "*-*-* 03:00:00" && job.Command == "backup.service" {
			foundTimer = true
		}
	}

	if !foundCron {
		t.Errorf("crontab job not found")
	}
	if !foundDaily {
		t.Errorf("daily cron job not found")
	}
	if !foundTimer {
		t.Errorf("systemd timer not found")
	}
}
