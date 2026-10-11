// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
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
