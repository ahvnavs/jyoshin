// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
)

func TestStorageSensor(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc")
	_ = os.MkdirAll(procDir, 0755)

	mountsContent := `/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /var ext4 rw,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
`
	_ = os.WriteFile(filepath.Join(procDir, "mounts"), []byte(mountsContent), 0644)

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if obs.Status != "ok" {
		t.Fatalf("expected status ok, got %s", obs.Status)
	}

	// Should have filtered pseudo filesystems (/proc, /sys) and extracted mounts
	if len(obs.Items) < 2 {
		t.Errorf("expected at least 2 mounts (/ and /var), got %d", len(obs.Items))
	}

	// Test bounded du
	du, err := BoundedDu(context.Background(), rfs, "/proc", 100, 1*time.Second)
	if err != nil {
		t.Fatalf("bounded du failed: %v", err)
	}
	if du.Entries < 1 {
		t.Errorf("expected at least 1 entry in du, got %d", du.Entries)
	}
}

func TestStorageSensor_TmpfsRoRoot(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc")
	_ = os.MkdirAll(procDir, 0755)

	mountsContent := `none / tmpfs ro,nosuid,nodev,relatime 0 0
/dev/nvme0n1p2 /data ext4 rw,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev 0 0
`
	_ = os.WriteFile(filepath.Join(procDir, "mounts"), []byte(mountsContent), 0644)

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var rootMount, dataMount *MountInfo
	for _, it := range obs.Items {
		if m, ok := it.Data.(MountInfo); ok {
			if m.MountPoint == "/" {
				rootMount = &m
			} else if m.MountPoint == "/data" {
				dataMount = &m
			}
		}
	}

	if rootMount == nil {
		t.Fatal("expected root (/) mount to be detected despite tmpfs ro")
	}
	if !rootMount.ReadOnly {
		t.Errorf("expected root mount to be read-only")
	}
	if rootMount.FSType != "tmpfs" {
		t.Errorf("expected fs type tmpfs, got %s", rootMount.FSType)
	}
	if rootMount.IsBlockDevice {
		t.Errorf("expected root tmpfs to not be flagged as block device")
	}

	if dataMount == nil {
		t.Fatal("expected /data mount to be detected")
	}
	if dataMount.ReadOnly {
		t.Errorf("expected /data to be rw")
	}
	if !dataMount.IsBlockDevice {
		t.Errorf("expected /dev/nvme0n1p2 to be flagged as block device")
	}
}
