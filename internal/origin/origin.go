// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package origin resolves "where did this binary/process come from?"
// for any file or process execution path.
package origin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/inventory"
)

// Kind classifies the origin classification of an executable.
type Kind string

const (
	KindPackage   Kind = "package"
	KindEcosystem Kind = "ecosystem"
	KindContainer Kind = "container"
	KindManual    Kind = "manual"
	KindUnknown   Kind = "unknown"
)

// Origin conveys the definitive provenance statement for an executable.
type Origin struct {
	Path       string           `json:"path"`
	Kind       Kind             `json:"kind"`
	Source     string           `json:"source"`
	Version    string           `json:"version,omitempty"`
	Confidence float64          `json:"confidence"` // 1.0 for observed/package, heuristic for manual
	Evidence   []graph.Evidence `json:"evidence"`
	Certainty  graph.Certainty  `json:"certainty"`
}

// Resolver resolves the origin of files and processes.
type Resolver struct {
	fs        fs.FS
	inventory *inventory.Manager
}

// NewResolver initializes a new Origin Resolver.
func NewResolver(fs fs.FS, inv *inventory.Manager) *Resolver {
	return &Resolver{
		fs:        fs,
		inventory: inv,
	}
}

// Resolve investigates path and returns its Origin statement.
func (r *Resolver) Resolve(ctx context.Context, path string) Origin {
	cleanPath := filepath.Clean(path)
	now := time.Now().UTC()

	// 1. Check if owned by system package manager
	if pkg, ev, ok := r.inventory.FindPackageOwner(cleanPath); ok {
		return Origin{
			Path:       cleanPath,
			Kind:       KindPackage,
			Source:     pkg,
			Confidence: 1.0,
			Evidence:   []graph.Evidence{ev},
			Certainty:  graph.CertaintyObserved,
		}
	}

	// 2. Check ecosystem patterns
	if strings.Contains(cleanPath, "/.cargo/bin/") {
		return Origin{
			Path:       cleanPath,
			Kind:       KindEcosystem,
			Source:     "cargo",
			Confidence: 1.0,
			Evidence: []graph.Evidence{
				{
					Source:    cleanPath,
					Collector: "origin",
					Raw:       "located inside ~/.cargo/bin",
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		}
	}

	if strings.Contains(cleanPath, "/node_modules/") {
		return Origin{
			Path:       cleanPath,
			Kind:       KindEcosystem,
			Source:     "npm",
			Confidence: 1.0,
			Evidence: []graph.Evidence{
				{
					Source:    cleanPath,
					Collector: "origin",
					Raw:       "located inside node_modules directory",
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		}
	}

	if strings.Contains(cleanPath, "/.nvm/versions/node/") {
		return Origin{
			Path:       cleanPath,
			Kind:       KindEcosystem,
			Source:     "nvm",
			Confidence: 1.0,
			Evidence: []graph.Evidence{
				{
					Source:    cleanPath,
					Collector: "origin",
					Raw:       "managed by nvm",
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		}
	}

	if strings.Contains(cleanPath, "/snap/") {
		return Origin{
			Path:       cleanPath,
			Kind:       KindEcosystem,
			Source:     "snap",
			Confidence: 1.0,
			Evidence: []graph.Evidence{
				{
					Source:    cleanPath,
					Collector: "origin",
					Raw:       "snap filesystem hierarchy",
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		}
	}

	// 3. Stat the file to evaluate manual drop heuristics
	fi, err := r.fs.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Origin{
				Path:       cleanPath,
				Kind:       KindUnknown,
				Source:     "file_not_found",
				Confidence: 0.0,
				Evidence: []graph.Evidence{
					{
						Source:    cleanPath,
						Collector: "origin",
						Raw:       "file does not exist on disk",
						Timestamp: now,
						Certainty: graph.CertaintyObserved,
					},
				},
				Certainty: graph.CertaintyObserved,
			}
		}
		return Origin{
			Path:       cleanPath,
			Kind:       KindUnknown,
			Source:     fmt.Sprintf("stat_error: %v", err),
			Confidence: 0.0,
			Evidence:   nil,
			Certainty:  graph.CertaintyObserved,
		}
	}

	// Manual drop heuristic classification: /usr/local, /opt, /home, /tmp
	confidence := 0.75
	source := "manual_filesystem_drop"

	switch {
	case strings.HasPrefix(cleanPath, "/tmp/") || strings.HasPrefix(cleanPath, "/var/tmp/"):
		source = "temporary_directory_drop"
		confidence = 0.90
	case strings.HasPrefix(cleanPath, "/usr/local/bin/"):
		source = "manual_usr_local_drop"
		confidence = 0.85
	case strings.HasPrefix(cleanPath, "/opt/"):
		source = "manual_opt_drop"
		confidence = 0.80
	case strings.HasPrefix(cleanPath, "/home/") || strings.HasPrefix(cleanPath, "/root/"):
		source = "user_directory_binary"
		confidence = 0.85
	}

	return Origin{
		Path:       cleanPath,
		Kind:       KindManual,
		Source:     source,
		Confidence: confidence,
		Evidence: []graph.Evidence{
			{
				Source:    cleanPath,
				Collector: "origin",
				Raw:       fmt.Sprintf("untracked by package database, modified: %s, mode: %s", fi.ModTime().Format(time.RFC3339), fi.Mode()),
				Timestamp: now,
				Certainty: graph.CertaintyInferred,
				Details:   "Heuristic classification: binary located in manual drop path without package owner",
			},
		},
		Certainty: graph.CertaintyInferred,
	}
}
