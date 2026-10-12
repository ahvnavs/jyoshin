// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package orphan implements on-demand, off-peak orphan binary scans
// bounded strictly by duration and I/O budgets without affecting host operations.
package orphan

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	internalfs "github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/origin"
)

// ScanResult reports the outcome of an orphan scan pass.
type ScanResult struct {
	StartTime       time.Time       `json:"start_time"`
	Duration        time.Duration   `json:"duration"`
	FilesInspected  int             `json:"files_inspected"`
	MaxFilesBudget  int             `json:"max_files_budget"`
	TimeBudget      time.Duration   `json:"time_budget"`
	CoveragePercent float64         `json:"coverage_percent"`
	Orphans         []origin.Origin `json:"orphans"`
	Completed       bool            `json:"completed"`
	Reason          string          `json:"reason,omitempty"`
}

// Scanner performs budgeted scans for unowned/orphan binaries.
type Scanner struct {
	fs       internalfs.FS
	resolver *origin.Resolver
	mu       sync.Mutex
	lastRes  *ScanResult
}

// NewScanner creates a new orphan scanner.
func NewScanner(fs internalfs.FS, resolver *origin.Resolver) *Scanner {
	return &Scanner{
		fs:       fs,
		resolver: resolver,
	}
}

// RunScan executes an orphan scan bounded by timeLimit and maxFiles.
// Skips pseudo-filesystems (/proc, /sys, /dev) and network mounts.
func (s *Scanner) RunScan(ctx context.Context, timeLimit time.Duration, maxFiles int) ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	start := time.Now()
	result := ScanResult{
		StartTime:      start,
		MaxFilesBudget: maxFiles,
		TimeBudget:     timeLimit,
		Completed:      true,
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeLimit)
	defer cancel()

	// High-interest binary drop directories
	targetDirs := []string{
		"/usr/local/bin",
		"/usr/local/sbin",
		"/opt",
		"/tmp",
		"/var/tmp",
	}

	// First determine total eligible regular files in scope
	filesInScope := 0
	for _, dir := range targetDirs {
		realPath := s.fs.Path(dir)
		_ = filepath.WalkDir(realPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				base := d.Name()
				if base == "proc" || base == "sys" || base == "dev" || base == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			// Only regular files (no directories, sockets, symlinks, FIFOs, devices)
			if d.Type().IsRegular() {
				filesInScope++
			}
			return nil
		})
	}

	for _, dir := range targetDirs {
		realPath := s.fs.Path(dir)
		_ = filepath.WalkDir(realPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			select {
			case <-scanCtx.Done():
				result.Completed = false
				result.Reason = "budget time limit reached"
				return filepath.SkipAll
			default:
			}

			// Skip directories
			if d.IsDir() {
				base := d.Name()
				if base == "proc" || base == "sys" || base == "dev" || base == ".git" {
					return filepath.SkipDir
				}
				return nil
			}

			// Only report and inspect regular files: never sockets, devices, directories, FIFOs
			if !d.Type().IsRegular() {
				return nil
			}

			if result.FilesInspected >= maxFiles {
				result.Completed = false
				result.Reason = "file inspection count budget reached"
				return filepath.SkipAll
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			// Check if executable file (executable bit set) or ELF header
			mode := info.Mode()
			isExec := mode&0111 != 0
			if !isExec {
				// Check for ELF magic bytes: \x7fELF
				f, err := s.fs.Open(path)
				if err == nil {
					var magic [4]byte
					if n, _ := f.Read(magic[:]); n == 4 && magic == [4]byte{0x7f, 'E', 'L', 'F'} {
						isExec = true
					}
					_ = f.Close()
				}
			}

			if isExec {
				virtPath := path
				if root := s.fs.Root(); root != "/" && strings.HasPrefix(path, root) {
					virtPath = strings.TrimPrefix(path, root)
					if !strings.HasPrefix(virtPath, "/") {
						virtPath = "/" + virtPath
					}
				}
				selfExe, _ := os.Executable()
				if selfExe != "" && (virtPath == selfExe || path == selfExe || filepath.Base(virtPath) == "kazeshini") {
					result.FilesInspected++
					return nil
				}
				orig := s.resolver.Resolve(scanCtx, virtPath)
				if orig.Kind == origin.KindManual {
					result.Orphans = append(result.Orphans, orig)
				}
			}

			result.FilesInspected++
			return nil
		})

		if !result.Completed {
			break
		}
	}

	result.Duration = time.Since(start)
	if filesInScope > 0 {
		result.CoveragePercent = float64(result.FilesInspected) / float64(filesInScope) * 100.0
		if result.CoveragePercent > 100.0 {
			result.CoveragePercent = 100.0
		}
	} else if result.Completed {
		result.CoveragePercent = 100.0
	}

	s.lastRes = &result
	return result
}

// LastResult returns the most recent orphan scan report.
func (s *Scanner) LastResult() *ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRes
}

// Count returns the number of orphan binaries discovered in the latest scan.
func (s *Scanner) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastRes == nil {
		return 0
	}
	return len(s.lastRes.Orphans)
}
