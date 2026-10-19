// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package facts extracts structured, read-only system facts from Kazeshini's
// host observations for consumption by Ansible, Terraform/OpenTofu, Puppet, and Chef.
package facts

import (
	"context"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// FactsPayload is the standard structured dictionary exported by `kazeshini facts --json`.
type FactsPayload struct {
	HostID           string            `json:"host_id"`
	Timestamp        time.Time         `json:"timestamp"`
	VerdictStatus    string            `json:"verdict_status"`
	ChaosIndex       int               `json:"chaos_index"`
	CoveragePercent  float64           `json:"coverage_percent"`
	CoverageAdequate bool              `json:"coverage_adequate"`
	OSRelease        map[string]string `json:"os_release,omitempty"`
	ListeningPorts   []int             `json:"listening_ports"`
	TotalProcesses   int               `json:"total_processes"`
	TotalPackages    int               `json:"total_packages"`
	OrphanFiles      int               `json:"orphan_files"`
	Attributes       map[string]string `json:"attributes"`
}

// Extractor generates FactsPayload from observation nodes and coverage.
type Extractor struct {
	fs fs.FS
}

func NewExtractor(fs fs.FS) *Extractor {
	return &Extractor{fs: fs}
}

func (e *Extractor) Extract(ctx context.Context, nodes []graph.Node, cov coverage.Report, v verdict.Summary, inv *inventory.Inventory) FactsPayload {
	payload := FactsPayload{
		HostID:           "localhost",
		Timestamp:        time.Now().UTC(),
		VerdictStatus:    v.StateLabel,
		ChaosIndex:       v.ChaosIndex,
		CoveragePercent:  cov.OverallCoverage,
		CoverageAdequate: cov.IsAdequate,
		ListeningPorts:   []int{},
		OSRelease:        make(map[string]string),
		Attributes: map[string]string{
			"kazeshini_version": "v0.1.0",
			"read_only":         "true",
		},
	}

	// Read /etc/os-release directly if available
	if data, err := e.fs.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "#") || !strings.Contains(l, "=") {
				continue
			}
			parts := strings.SplitN(l, "=", 2)
			k := strings.TrimSpace(parts[0])
			val := strings.Trim(strings.TrimSpace(parts[1]), `"`)
			payload.OSRelease[k] = val
		}
		if name, ok := payload.OSRelease["PRETTY_NAME"]; ok {
			payload.Attributes["os_name"] = name
		}
	}

	for _, n := range nodes {
		if n.Type == graph.NodeSystem && n.Label != "" {
			payload.HostID = n.Label
		}
		if n.Type == graph.NodePort {
			var p int
			// e.g. "port tcp/80 (all_interfaces)"
			if n.Properties != nil {
				if portVal, ok := n.Properties["port"].(int); ok {
					p = portVal
				}
			}
			if p > 0 {
				payload.ListeningPorts = append(payload.ListeningPorts, p)
			}
		}
		if n.Type == graph.NodeProcess {
			payload.TotalProcesses++
		}
	}

	if inv != nil {
		payload.TotalPackages = len(inv.Packages)
	}

	return payload
}
