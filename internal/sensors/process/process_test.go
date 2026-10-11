// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/fs"
)

func TestProcessSensor_FixturesAndVanishingPID(t *testing.T) {
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

	// PID 1
	mustWrite("/proc/1/stat", "1 (systemd) S 0 1 1 0 -1 4194560 1200 0 0 0 100 200 0 0 20 0 1 0 50 10485760 1024 18446744073709551615")
	mustWrite("/proc/1/cmdline", "/sbin/init\x00")
	mustWrite("/proc/1/status", "Name:\tsystemd\nUid:\t0\t0\t0\t0\nThreads:\t1\n")
	mustWrite("/proc/1/cgroup", "0::/\n")

	// PID 100 - corrupt / vanishing process (directory exists, but stat file missing)
	proc100Dir := filepath.Join(root, "proc/100")
	if err := os.MkdirAll(proc100Dir, 0755); err != nil {
		t.Fatal(err)
	}

	// PID 500 - regular process
	mustWrite("/proc/500/stat", "500 (nginx) S 1 500 500 0 -1 4194560 300 0 0 0 50 60 0 0 20 0 4 0 100 20971520 2048 18446744073709551615")
	mustWrite("/proc/500/cmdline", "nginx: master process\x00/usr/sbin/nginx\x00")
	mustWrite("/proc/500/status", "Name:\tnginx\nUid:\t33\t33\t33\t33\nThreads:\t4\n")

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected collect error: %v", err)
	}

	// We expect PID 1 and PID 500 to be collected; PID 100 must be silently skipped without crashing
	if len(obs.Items) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(obs.Items))
	}

	p1 := obs.Items[0].Data.(ProcessInfo)
	if p1.PID != 1 || p1.Name != "systemd" || p1.Cmdline != "/sbin/init" || p1.UID != 0 {
		t.Errorf("p1 mismatch: %+v", p1)
	}

	p500 := obs.Items[1].Data.(ProcessInfo)
	if p500.PID != 500 || p500.Name != "nginx" || p500.UID != 33 || p500.Threads != 4 {
		t.Errorf("p500 mismatch: %+v", p500)
	}
}

func TestProcessSensor_PermissionDenied(t *testing.T) {
	// Rooted at non-existent or inaccessible proc
	rfs := fs.NewRootedFS("/root/forbidden_test_nonexistent")
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	// Should degrade gracefully to StatusUnknown without panicking
	if err == nil && obs.Status != "unknown" && obs.Status != "error" {
		t.Fatalf("expected error or degraded unknown status, got status=%s, err=%v", obs.Status, err)
	}
}

func TestProcessSensor_Truncation(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(relPath, content string) {
		full := filepath.Join(root, relPath)
		_ = os.MkdirAll(filepath.Dir(full), 0755)
		_ = os.WriteFile(full, []byte(content), 0644)
	}

	// Create 5 process directories
	for pid := 1; pid <= 5; pid++ {
		mustWrite(fmt.Sprintf("/proc/%d/stat", pid), fmt.Sprintf("%d (worker%d) S 0 1 1 0 -1 4194560 100 0 0 0 10 20 0 0 20 0 1 0 50 10485760 1024 18446744073709551615", pid, pid))
		mustWrite(fmt.Sprintf("/proc/%d/status", pid), fmt.Sprintf("Name:\tworker%d\nPid:\t%d\nUid:\t1000\t1000\t1000\t1000\n", pid, pid))
		mustWrite(fmt.Sprintf("/proc/%d/cmdline", pid), fmt.Sprintf("/bin/worker%d\x00", pid))
	}

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)
	sensor.SetMaxProcesses(2)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(obs.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(obs.Items))
	}
	if !obs.Truncated {
		t.Errorf("expected obs.Truncated to be true")
	}
	if obs.TotalSeen != 5 {
		t.Errorf("expected obs.TotalSeen to be 5, got %d", obs.TotalSeen)
	}
}
