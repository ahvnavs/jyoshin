// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/jyoshin/internal/fs"
)

func TestResourcesSensor(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc")
	_ = os.MkdirAll(procDir, 0755)

	loadavg := "0.75 0.50 0.25 2/120 1234\n"
	meminfo := `MemTotal:       16384000 kB
MemFree:         4096000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
Cached:          3584000 kB
SwapTotal:       2097152 kB
SwapFree:        1048576 kB
`
	_ = os.WriteFile(filepath.Join(procDir, "loadavg"), []byte(loadavg), 0644)
	_ = os.WriteFile(filepath.Join(procDir, "meminfo"), []byte(meminfo), 0644)

	// Add pressure psi
	pressureDir := filepath.Join(procDir, "pressure")
	_ = os.MkdirAll(pressureDir, 0755)
	_ = os.WriteFile(filepath.Join(pressureDir, "cpu"), []byte("some avg10=1.23 avg60=0.85 avg300=0.42 total=123456\n"), 0644)

	rfs := fs.NewRootedFS(root)
	sensor := New(rfs)

	obs, err := sensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(obs.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(obs.Items))
	}

	sample, ok := obs.Items[0].Data.(ResourceSample)
	if !ok {
		t.Fatalf("unexpected data type: %T", obs.Items[0].Data)
	}

	if sample.Load1 != 0.75 || sample.Load5 != 0.50 || sample.Load15 != 0.25 {
		t.Errorf("loadavg mismatch: %+v", sample)
	}
	if sample.MemTotalBytes != 16384000*1024 {
		t.Errorf("memTotal mismatch: %d", sample.MemTotalBytes)
	}
	if sample.SwapUsedBytes != 1048576*1024 {
		t.Errorf("swapUsed mismatch: %d", sample.SwapUsedBytes)
	}
	if sample.PSI.CPUSomeAvg10 != 1.23 {
		t.Errorf("psi cpu mismatch: %f", sample.PSI.CPUSomeAvg10)
	}
}
