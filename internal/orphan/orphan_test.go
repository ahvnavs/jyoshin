// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package orphan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/inventory"
	"github.com/OWNER/jyoshin/internal/origin"
)

func TestOrphanScanner_BudgetAndCoverage(t *testing.T) {
	root := t.TempDir()

	usrLocalBin := filepath.Join(root, "usr/local/bin")
	if err := os.MkdirAll(usrLocalBin, 0755); err != nil {
		t.Fatal(err)
	}

	// Create 10 executable binaries
	for i := 0; i < 10; i++ {
		binPath := filepath.Join(usrLocalBin, filepath.Base(filepath.Join("app", string(rune('a'+i)))))
		if err := os.WriteFile(binPath, []byte("echo hi"), 0755); err != nil {
			t.Fatal(err)
		}
	}

	rfs := fs.NewRootedFS(root)
	inv := inventory.NewManager(rfs)
	res := origin.NewResolver(rfs, inv)
	scanner := NewScanner(rfs, res)

	// Test 1: Full scan within budget
	result1 := scanner.RunScan(context.Background(), 2*time.Second, 100)
	if !result1.Completed {
		t.Fatalf("expected completed scan, got false: %s", result1.Reason)
	}
	if result1.CoveragePercent != 100.0 {
		t.Fatalf("expected 100%% coverage, got %f", result1.CoveragePercent)
	}
	if len(result1.Orphans) != 10 {
		t.Fatalf("expected 10 orphans, got %d", len(result1.Orphans))
	}

	// Test 2: Bounded scan by file budget limit
	result2 := scanner.RunScan(context.Background(), 2*time.Second, 5)
	if result2.Completed {
		t.Fatalf("expected uncompleted scan due to file budget limit")
	}
	if result2.FilesInspected != 5 {
		t.Fatalf("expected 5 files inspected, got %d", result2.FilesInspected)
	}
	// 5 inspected out of 10 files in scope = 50% coverage, NOT 100%
	if result2.CoveragePercent != 50.0 {
		t.Fatalf("expected 50%% coverage (5/10), got %f", result2.CoveragePercent)
	}
}
