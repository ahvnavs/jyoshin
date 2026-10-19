// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package coverage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/sensors"
	"github.com/OWNER/kazeshini/internal/sensors/network"
	"github.com/OWNER/kazeshini/internal/sensors/process"
	"github.com/OWNER/kazeshini/internal/supervisor"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// TestCoverage_FaultInjection verifies that when /proc/<pid>/fd and exe are unreadable,
// doctor/coverage assessor reports PARTIAL with "N of M", and verdict never returns CALM.
func TestCoverage_FaultInjection(t *testing.T) {
	root := t.TempDir()

	// Build a mock /proc with 3 processes:
	// pid 1: fully readable
	// pid 2: exe missing or unreadable
	// pid 3: status present but fd directory has 000 permissions (unreadable)
	procDir := filepath.Join(root, "proc")
	_ = os.MkdirAll(filepath.Join(procDir, "1", "fd"), 0755)
	_ = os.WriteFile(filepath.Join(procDir, "1", "stat"), []byte("1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 10 10 0 0 20 0 1 0 100 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0"), 0644)
	_ = os.WriteFile(filepath.Join(procDir, "1", "status"), []byte("Name:\tinit\nPid:\t1\nPPid:\t0\nUid:\t0\t0\t0\t0\nThreads:\t1\n"), 0644)
	_ = os.WriteFile(filepath.Join(procDir, "1", "cmdline"), []byte("/sbin/init\x00"), 0644)

	_ = os.MkdirAll(filepath.Join(procDir, "2"), 0755)
	_ = os.WriteFile(filepath.Join(procDir, "2", "stat"), []byte("2 (kthreadd) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0"), 0644)
	_ = os.WriteFile(filepath.Join(procDir, "2", "status"), []byte("Name:\tkthreadd\nPid:\t2\nPPid:\t0\nUid:\t0\t0\t0\t0\nThreads:\t1\n"), 0644)
	// No cmdline, no exe (kernel thread simulation)

	// Pid 3: unreadable fd directory
	_ = os.MkdirAll(filepath.Join(procDir, "3", "fd"), 0000)
	defer os.Chmod(filepath.Join(procDir, "3", "fd"), 0755)
	_ = os.WriteFile(filepath.Join(procDir, "3", "stat"), []byte("3 (secret) S 1 1 1 0 -1 4194560 100 0 0 0 10 10 0 0 20 0 1 0 100 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0"), 0644)
	_ = os.WriteFile(filepath.Join(procDir, "3", "status"), []byte("Name:\tsecret\nPid:\t3\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nThreads:\t1\n"), 0644)

	// Mock /proc/net/tcp with 2 sockets:
	// one mapped to pid 1's socket inode
	// one unmapped because pid 3's fds could not be read
	_ = os.MkdirAll(filepath.Join(procDir, "net"), 0755)
	netTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0
`
	_ = os.WriteFile(filepath.Join(procDir, "net", "tcp"), []byte(netTCP), 0644)

	// Socket 11111 linked in pid 1 fd 3
	_ = os.Symlink("socket:[11111]", filepath.Join(procDir, "1", "fd", "3"))

	rfs := fs.NewRootedFS(root)
	registry := sensors.NewRegistry()
	_ = registry.Register(process.New(rfs))
	_ = registry.Register(network.New(rfs))

	sup := supervisor.New(registry, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, s := range registry.All() {
		_, _ = sup.RunSensorSafe(ctx, s, 2*time.Second)
	}

	invManager := inventory.NewManager(rfs)
	orphanScanner := orphan.NewScanner(rfs, nil)
	assessor := coverage.NewAssessor(sup, invManager, orphanScanner, rfs)

	cov := assessor.Assess(ctx)

	// Assert: coverage honesty reflects missing package manager and partial sockets
	if cov.IsAdequate {
		t.Fatalf("expected coverage to NOT be adequate under fault injection")
	}

	// Verify Network Sockets reports "N of M" (1 mapped out of 2)
	var foundNet bool
	for _, it := range cov.Items {
		if it.Name == "Network Sockets" {
			foundNet = true
			if it.Total != 2 || it.Readable != 1 {
				t.Errorf("expected network sockets 1 of 2 mapped, got readable=%d total=%d", it.Readable, it.Total)
			}
		}
	}
	if !foundNet {
		t.Errorf("Network Sockets coverage item not found in report")
	}

	// Compute verdict with coverage honesty
	vSum := verdict.ComputeVerdictWithCoverage(nil, nil, 0, cov.IsAdequate, cov.SummaryNote)

	// Assert: verdict is NEVER HEALTHY or CALM when visibility is inadequate
	if vSum.StateLabel == "CALM" || vSum.StateLabel == "HEALTHY" || vSum.StateLabel == "Healthy" {
		t.Fatalf("Verdict must NEVER report Healthy when sensor coverage is inadequate!")
	}
	if vSum.StateLabel != "PARTIAL" && vSum.StateLabel != "UNKNOWN" && vSum.StateLabel != "Partial visibility" && vSum.StateLabel != "Unknown" {
		t.Errorf("expected verdict state Partial visibility or Unknown, got %s", vSum.StateLabel)
	}
}
