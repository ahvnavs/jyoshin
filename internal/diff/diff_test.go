// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package diff_test

import (
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/diff"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/store"
)

func TestDiffEngine_Classifications(t *testing.T) {
	engine := diff.NewEngine()
	now := time.Now().UTC()

	snap1 := store.Snapshot{
		ID:        "snap-1",
		Timestamp: now.Add(-10 * time.Minute),
		Nodes: []graph.Node{
			{
				ID:        "node:port:80",
				Type:      graph.NodePort,
				Label:     "127.0.0.1:80",
				FirstSeen: now.Add(-10 * time.Minute),
				LastSeen:  now.Add(-10 * time.Minute),
				Properties: map[string]any{
					"port":           80,
					"exposure_class": "loopback",
				},
			},
			{
				ID:        "node:pkg:nginx",
				Type:      graph.NodePackage,
				Label:     "nginx",
				FirstSeen: now.Add(-10 * time.Minute),
				LastSeen:  now.Add(-10 * time.Minute),
				Properties: map[string]any{
					"version": "1.22.0",
				},
			},
		},
	}

	snap2 := store.Snapshot{
		ID:        "snap-2",
		Timestamp: now,
		Nodes: []graph.Node{
			// 1. Port changed from loopback to all_interfaces
			{
				ID:        "node:port:80",
				Type:      graph.NodePort,
				Label:     "0.0.0.0:80",
				FirstSeen: now.Add(-10 * time.Minute),
				LastSeen:  now,
				Properties: map[string]any{
					"port":           80,
					"exposure_class": "all_interfaces",
				},
			},
			// 2. Package upgraded from 1.22.0 to 1.24.0
			{
				ID:        "node:pkg:nginx",
				Type:      graph.NodePackage,
				Label:     "nginx",
				FirstSeen: now.Add(-10 * time.Minute),
				LastSeen:  now,
				Properties: map[string]any{
					"version": "1.24.0",
				},
			},
			// 3. New manual binary dropped in /usr/local/bin
			{
				ID:        "node:file:custom-script",
				Type:      graph.NodeFile,
				Label:     "/usr/local/bin/deploy.sh",
				FirstSeen: now,
				LastSeen:  now,
				Properties: map[string]any{
					"path":        "/usr/local/bin/deploy.sh",
					"origin_kind": "manual",
				},
			},
		},
	}

	changeSet := engine.DiffSnapshots(snap1, snap2)

	if changeSet.TotalChanges != 3 {
		t.Fatalf("expected 3 changes, got %d", changeSet.TotalChanges)
	}

	kinds := make(map[diff.ChangeKind]bool)
	for _, ch := range changeSet.Changes {
		kinds[ch.Kind] = true
	}

	if !kinds[diff.ChangeNewlyExposed] {
		t.Errorf("expected ChangeNewlyExposed for port 80")
	}
	if !kinds[diff.ChangeVersionChanged] {
		t.Errorf("expected ChangeVersionChanged for nginx upgrade")
	}
	if !kinds[diff.ChangeNewManualBinary] {
		t.Errorf("expected ChangeNewManualBinary for /usr/local/bin/deploy.sh")
	}
}

func TestDiffEngine_RemovedNode(t *testing.T) {
	engine := diff.NewEngine()
	now := time.Now().UTC()

	snap1 := store.Snapshot{
		ID:        "snap-1",
		Timestamp: now.Add(-5 * time.Minute),
		Nodes: []graph.Node{
			{
				ID:        "node:proc:999",
				Type:      graph.NodeProcess,
				Label:     "rogue-miner",
				FirstSeen: now.Add(-5 * time.Minute),
				LastSeen:  now.Add(-5 * time.Minute),
			},
		},
	}

	snap2 := store.Snapshot{
		ID:        "snap-2",
		Timestamp: now,
		Nodes:     []graph.Node{}, // Process was killed
	}

	changeSet := engine.DiffSnapshots(snap1, snap2)
	if changeSet.TotalChanges != 1 {
		t.Fatalf("expected 1 change, got %d", changeSet.TotalChanges)
	}
	if changeSet.Changes[0].Kind != diff.ChangeRemoved {
		t.Errorf("expected ChangeRemoved, got %s", changeSet.Changes[0].Kind)
	}
}
