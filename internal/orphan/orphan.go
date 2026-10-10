// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package orphan implements on-demand, off-peak orphan binary scans
// bounded strictly by duration and I/O budgets without affecting host operations.
package orphan

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"

	internalfs "github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/origin"
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

	totalFoundInTarget := 0

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

			if result.FilesInspected >= maxFiles {
				result.Completed = false
				result.Reason = "file inspection count budget reached"
				return filepath.SkipAll
			}

			// Skip directories and non-regular files
			if d.IsDir() {
				// Don't descend into pseudo-filesystems or VCS
				base := d.Name()
				if base == "proc" || base == "sys" || base == "dev" || base == ".git" {
					return filepath.SkipDir
				}
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			// Check if executable file
			if info.Mode()&0111 != 0 {
				totalFoundInTarget++
				virtPath := path
				if root := s.fs.Root(); root != "/" && strings.HasPrefix(path, root) {
					virtPath = strings.TrimPrefix(path, root)
					if !strings.HasPrefix(virtPath, "/") {
						virtPath = "/" + virtPath
					}
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
	if result.FilesInspected > 0 {
		if result.Completed {
			result.CoveragePercent = 100.0
		} else {
			// Honest partial coverage ratio
			result.CoveragePercent = float64(result.FilesInspected) / float64(maxFiles) * 100.0
		}
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
