// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package chaos_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	internalfs "github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/sensors/network"
	"github.com/OWNER/kazeshini/internal/sensors/process"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// faultyFS wraps a RootedFS and randomly injects EIO or EACCES on read operations
type faultyFS struct {
	base     *internalfs.RootedFS
	rnd      *rand.Rand
	mu       sync.Mutex
	errorPct int // probability (0-100) of returning an error
}

func newFaultyFS(root string, errorPct int) *faultyFS {
	return &faultyFS{
		base:     internalfs.NewRootedFS(root),
		rnd:      rand.New(rand.NewSource(42)),
		errorPct: errorPct,
	}
}

func (f *faultyFS) Root() string { return f.base.Root() }
func (f *faultyFS) Path(elem ...string) string { return f.base.Path(elem...) }

func (f *faultyFS) shouldFail() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rnd.Intn(100) < f.errorPct {
		if f.rnd.Intn(2) == 0 {
			return syscall.EIO
		}
		return syscall.EACCES
	}
	return nil
}

func (f *faultyFS) ReadFile(name string) ([]byte, error) {
	if err := f.shouldFail(); err != nil {
		return nil, err
	}
	return f.base.ReadFile(name)
}

func (f *faultyFS) ReadDir(name string) ([]os.DirEntry, error) {
	if err := f.shouldFail(); err != nil {
		return nil, err
	}
	return f.base.ReadDir(name)
}

func (f *faultyFS) Stat(name string) (os.FileInfo, error) {
	if err := f.shouldFail(); err != nil {
		return nil, err
	}
	return f.base.Stat(name)
}

func (f *faultyFS) Readlink(name string) (string, error) {
	if err := f.shouldFail(); err != nil {
		return "", err
	}
	return f.base.Readlink(name)
}

func (f *faultyFS) Open(name string) (*os.File, error) {
	if err := f.shouldFail(); err != nil {
		return nil, err
	}
	return f.base.Open(name)
}

// TestHostileHost_ProcRandomEIOAndEACCES verifies that process and network sensors
// never crash or panic when /proc yields arbitrary EIO or EACCES errors.
func TestHostileHost_ProcRandomEIOAndEACCES(t *testing.T) {
	tmpDir := t.TempDir()

	// Populate basic proc entries
	procDir := filepath.Join(tmpDir, "proc")
	_ = os.MkdirAll(procDir, 0755)

	for pid := 1; pid <= 50; pid++ {
		pDir := filepath.Join(procDir, fmt.Sprintf("%d", pid))
		_ = os.MkdirAll(pDir, 0755)
		_ = os.WriteFile(filepath.Join(pDir, "stat"), []byte(fmt.Sprintf("%d (proc%d) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0", pid, pid)), 0644)
		_ = os.WriteFile(filepath.Join(pDir, "cmdline"), []byte(fmt.Sprintf("proc%d\x00arg\x00", pid)), 0644)
		_ = os.WriteFile(filepath.Join(pDir, "status"), []byte(fmt.Sprintf("Name:\tproc%d\nUid:\t1000\t1000\t1000\t1000\n", pid)), 0644)
	}

	ffs := newFaultyFS(tmpDir, 35) // 35% failure rate

	procSensor := process.New(ffs)
	obs, err := procSensor.Collect(context.Background())
	if err != nil {
		t.Logf("sensor returned error gracefully: %v", err)
	} else {
		t.Logf("sensor collected %d items under 35%% error rate without panic", len(obs.Items))
	}

	netSensor := network.New(ffs)
	netObs, err := netSensor.Collect(context.Background())
	if err != nil {
		t.Logf("netSensor returned error gracefully: %v", err)
	} else {
		t.Logf("netSensor completed with status=%s under random errors", netObs.Status)
	}
}

// TestHostileHost_AdversarialProcessStrings verifies that process names with control
// characters, ANSI color escapes, and HTML/script injection tags do not disrupt or corrupt execution.
func TestHostileHost_AdversarialProcessStrings(t *testing.T) {
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc")
	_ = os.MkdirAll(procDir, 0755)

	adversarialNames := []string{
		"<script>alert(1)</script>",
		"\x1b[31;1mRED_ALERT\x1b[0m",
		"proc\r\nCRLF_INJECTION",
		"$(reboot)",
		"`rm -rf /`",
		"proc with spaces and () inside (weird)",
	}

	for i, advName := range adversarialNames {
		pid := 1000 + i
		pDir := filepath.Join(procDir, fmt.Sprintf("%d", pid))
		_ = os.MkdirAll(pDir, 0755)

		statContent := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0", pid, advName)
		_ = os.WriteFile(filepath.Join(pDir, "stat"), []byte(statContent), 0644)
		_ = os.WriteFile(filepath.Join(pDir, "cmdline"), []byte(advName+"\x00"), 0644)
		_ = os.WriteFile(filepath.Join(pDir, "status"), []byte(fmt.Sprintf("Name:\t%s\nUid:\t1000\t1000\t1000\t1000\n", advName)), 0644)
	}

	rfs := internalfs.NewRootedFS(tmpDir)
	procSensor := process.New(rfs)

	obs, err := procSensor.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error collecting processes: %v", err)
	}

	if len(obs.Items) != len(adversarialNames) {
		t.Fatalf("expected %d items, got %d", len(adversarialNames), len(obs.Items))
	}

	for _, item := range obs.Items {
		pinfo := item.Data.(process.ProcessInfo)
		if pinfo.Name == "" {
			t.Errorf("empty process name for PID %d", pinfo.PID)
		}
		// Confirm verdict calculation with these nodes does not crash
		node := graph.Node{
			ID:        item.ID,
			Type:      graph.NodeProcess,
			Label:     pinfo.Name,
			Certainty: graph.CertaintyObserved,
		}
		v := verdict.ComputeVerdict([]graph.Node{node}, nil, 0)
		if v.StateLabel == "" {
			t.Errorf("verdict calculation returned empty state for %s", pinfo.Name)
		}
	}
}

// TestHostileHost_SymlinkLoopsAndFIFOs verifies that directory scanners (e.g. orphan scanner)
// never hang indefinitely on circular symlinks or FIFO named pipes.
func TestHostileHost_SymlinkLoopsAndFIFOs(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "usr/local/bin")
	_ = os.MkdirAll(binDir, 0755)

	// Create symlink loop: loop1 -> loop2, loop2 -> loop1
	loop1 := filepath.Join(binDir, "loop1")
	loop2 := filepath.Join(binDir, "loop2")
	_ = os.Symlink(loop2, loop1)
	_ = os.Symlink(loop1, loop2)

	// Create a self-pointing symlink
	selfLoop := filepath.Join(binDir, "selfloop")
	_ = os.Symlink(selfLoop, selfLoop)

	// Create a named pipe (FIFO)
	fifoPath := filepath.Join(binDir, "hostile_fifo")
	err := syscall.Mknod(fifoPath, syscall.S_IFIFO|0666, 0)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		t.Logf("mkfifo failed: %v", err)
	}

	rfs := internalfs.NewRootedFS(tmpDir)
	scanner := orphan.NewScanner(rfs, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// RunScan must complete within the 2 second context without hanging on FIFO or symlink loops
	res := scanner.RunScan(ctx, 1*time.Second, 100)
	if ctx.Err() != nil {
		t.Fatal("orphan scan hung on symlink loop or FIFO")
	}
	t.Logf("Orphan scan completed successfully: inspected=%d files, completed=%v", res.FilesInspected, res.Completed)
}
