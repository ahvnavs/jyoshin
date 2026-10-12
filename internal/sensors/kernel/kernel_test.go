// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package kernel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelSensor(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Setup /proc/version
	procDir := filepath.Join(tmpDir, "proc")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	procVersion := "Linux version 6.8.0-40-generic (buildd@lcy02-amd64-074) #40-Ubuntu SMP PREEMPT_DYNAMIC\n"
	if err := os.WriteFile(filepath.Join(procDir, "version"), []byte(procVersion), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Setup /boot with multiple kernels
	bootDir := filepath.Join(tmpDir, "boot")
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bootDir, "vmlinuz-6.8.0-38-generic"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bootDir, "vmlinuz-6.8.0-40-generic"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bootDir, "vmlinuz-6.8.0-45-generic"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	sensor := NewSensor(tmpDir)
	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if obs.Status != "ok" {
		t.Fatalf("expected status ok, got %s", obs.Status)
	}

	if len(obs.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(obs.Items))
	}

	data := obs.Items[0].Data.(KernelData)
	if data.RunningKernel != "6.8.0-40-generic" {
		t.Errorf("expected running kernel 6.8.0-40-generic, got %s", data.RunningKernel)
	}

	if len(data.InstalledKernels) != 3 {
		t.Errorf("expected 3 installed kernels, got %d", len(data.InstalledKernels))
	}

	// Reclaimable should be 6.8.0-38-generic (not running and not the newest 6.8.0-45-generic)
	if len(data.Reclaimable) != 1 || data.Reclaimable[0] != "6.8.0-38-generic" {
		t.Errorf("expected reclaimable [6.8.0-38-generic], got %v", data.Reclaimable)
	}

	if !data.RebootRequired {
		t.Errorf("expected reboot_required=true because running != latest")
	}
}
