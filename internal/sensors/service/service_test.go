// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/jyoshin/internal/fs"
)

func TestServiceSensor_SystemdUnits(t *testing.T) {
	root := t.TempDir()

	mustWrite := func(relPath, content string) {
		full := filepath.Join(root, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Mock systemd marker
	mustWrite("/run/systemd/system/README", "systemd active\n")

	// Service unit
	mustWrite("/etc/systemd/system/nginx.service", `[Unit]
Description=A high performance web server and reverse proxy
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/nginx -g 'daemon on;'
`)

	// Timer unit
	mustWrite("/etc/systemd/system/logrotate.timer", `[Unit]
Description=Daily rotation of log files

[Timer]
OnCalendar=daily
`)

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reportItem := obs.Items[0].Data.(ServiceReport)
	if reportItem.InitSystem != "systemd" || reportItem.Visibility != "full" {
		t.Fatalf("expected systemd full visibility, got: %+v", reportItem)
	}

	foundNginx := false
	for _, it := range obs.Items[1:] {
		u := it.Data.(UnitInfo)
		if u.Name == "nginx.service" {
			foundNginx = true
			if u.ExecStart != "/usr/sbin/nginx -g 'daemon on;'" {
				t.Errorf("ExecStart mismatch: got %q", u.ExecStart)
			}
		}
	}

	if !foundNginx {
		t.Errorf("expected to find nginx.service in discovered units")
	}
}

func TestServiceSensor_NonSystemdDegradation(t *testing.T) {
	root := t.TempDir()

	// No systemd markers, mock OpenRC or SysVinit
	full := filepath.Join(root, "proc/1/comm")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("init\n"), 0644); err != nil {
		t.Fatal(err)
	}

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	report := obs.Items[0].Data.(ServiceReport)
	if report.Visibility != "limited" {
		t.Errorf("expected limited visibility for non-systemd, got %s", report.Visibility)
	}
	if report.InitSystem != "init" {
		t.Errorf("expected init system 'init', got %s", report.InitSystem)
	}
}
