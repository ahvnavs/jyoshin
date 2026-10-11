// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootedFS_PathAndRead(t *testing.T) {
	tmp := t.TempDir()
	procDir := filepath.Join(tmp, "proc")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	cpuinfo := filepath.Join(procDir, "cpuinfo")
	if err := os.WriteFile(cpuinfo, []byte("model name: Test CPU\n"), 0644); err != nil {
		t.Fatal(err)
	}

	rfs := NewRootedFS(tmp)

	resolved := rfs.Path("/proc/cpuinfo")
	if resolved != cpuinfo {
		t.Fatalf("expected %s, got %s", cpuinfo, resolved)
	}

	data, err := rfs.ReadFile("/proc/cpuinfo")
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(data) != "model name: Test CPU\n" {
		t.Fatalf("unexpected content: %s", string(data))
	}

	entries, err := rfs.ReadDir("/proc")
	if err != nil {
		t.Fatalf("unexpected ReadDir error: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "cpuinfo" {
		t.Fatalf("unexpected dir entries: %+v", entries)
	}
}
