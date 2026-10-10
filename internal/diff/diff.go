// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package diff

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/store"
)

// ChangeKind classifies the nature of difference between graph states.
type ChangeKind string

const (
	ChangeAdded           ChangeKind = "added"
	ChangeRemoved         ChangeKind = "removed"
	ChangeVersionChanged  ChangeKind = "version_changed"
	ChangeMoved           ChangeKind = "moved"
	ChangeNewlyExposed    ChangeKind = "newly_exposed"
	ChangeNewListener     ChangeKind = "new_listener"
	ChangeNewManualBinary ChangeKind = "new_manual_binary"
	ChangeOwnershipChange ChangeKind = "ownership_change"
	ChangeStateChanged    ChangeKind = "state_changed"
)

// Change models a single semantic diff item between two graph snapshots.
type Change struct {
	ID            string         `json:"id"`
	Kind          ChangeKind     `json:"kind"`
	NodeType      graph.NodeType `json:"node_type"`
	NodeID        string         `json:"node_id"`
	Label         string         `json:"label"`
	Description   string         `json:"description"`
	ProbableCause string         `json:"probable_cause,omitempty"`
	Before        map[string]any `json:"before,omitempty"`
	After         map[string]any `json:"after,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
}

// ChangeSet aggregates classified changes between two snapshots.
type ChangeSet struct {
	FromSnapshotID string    `json:"from_snapshot_id"`
	ToSnapshotID   string    `json:"to_snapshot_id"`
	FromTimestamp  time.Time `json:"from_timestamp"`
	ToTimestamp    time.Time `json:"to_timestamp"`
	Changes        []Change  `json:"changes"`
	TotalChanges   int       `json:"total_changes"`
	Summary        string    `json:"summary"`
}

// Engine performs deterministic graph diffing and classification.
type Engine struct{}

// NewEngine constructs a diff engine.
func NewEngine() *Engine {
	return &Engine{}
}

// DiffSnapshots compares before and after snapshots and produces a semantic ChangeSet.
func (e *Engine) DiffSnapshots(before, after store.Snapshot) ChangeSet {
	beforeNodes := make(map[string]graph.Node, len(before.Nodes))
	for _, n := range before.Nodes {
		beforeNodes[n.ID] = n
	}

	afterNodes := make(map[string]graph.Node, len(after.Nodes))
	for _, n := range after.Nodes {
		afterNodes[n.ID] = n
	}

	var changes []Change

	// 1. Detect Added and Modified Nodes
	for id, afterNode := range afterNodes {
		beforeNode, existed := beforeNodes[id]
		if !existed {
			// Newly added node
			ch := e.classifyAddedNode(afterNode, after.Timestamp)
			changes = append(changes, ch)
			continue
		}

		// Node existed: inspect modifications
		modChanges := e.classifyModifiedNode(beforeNode, afterNode, after.Timestamp)
		changes = append(changes, modChanges...)
	}

	// 2. Detect Removed Nodes
	for id, beforeNode := range beforeNodes {
		if _, exists := afterNodes[id]; !exists {
			ch := Change{
				ID:            fmt.Sprintf("del:%s", id),
				Kind:          ChangeRemoved,
				NodeType:      beforeNode.Type,
				NodeID:        id,
				Label:         beforeNode.Label,
				Description:   fmt.Sprintf("%s %q was removed", beforeNode.Type, beforeNode.Label),
				ProbableCause: "Uninstalled or terminated process/service",
				Before:        beforeNode.Properties,
				Timestamp:     after.Timestamp,
			}
			changes = append(changes, ch)
		}
	}

	// Stable sort by ChangeKind and NodeID
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].NodeID < changes[j].NodeID
	})

	summary := fmt.Sprintf("%d changes detected between snapshots", len(changes))
	if len(changes) == 0 {
		summary = "No changes detected. System state identical."
	}

	return ChangeSet{
		FromSnapshotID: before.ID,
		ToSnapshotID:   after.ID,
		FromTimestamp:  before.Timestamp,
		ToTimestamp:    after.Timestamp,
		Changes:        changes,
		TotalChanges:   len(changes),
		Summary:        summary,
	}
}

func (e *Engine) classifyAddedNode(node graph.Node, ts time.Time) Change {
	kind := ChangeAdded
	desc := fmt.Sprintf("New %s node %q detected", node.Type, node.Label)
	cause := "System activity"

	switch node.Type {
	case graph.NodePort:
		kind = ChangeNewListener
		exp, _ := node.Properties["exposure_class"].(string)
		desc = fmt.Sprintf("New listening socket opened on %s (exposure: %s)", node.Label, exp)
		if exp == "all_interfaces" {
			kind = ChangeNewlyExposed
			desc = fmt.Sprintf("New listening socket EXPOSED on all interfaces: %s", node.Label)
			cause = "Service started with 0.0.0.0 or [::] listener"
		} else {
			cause = "Service or process began listening"
		}

	case graph.NodeFile:
		originKind, _ := node.Properties["origin_kind"].(string)
		path, _ := node.Properties["path"].(string)
		if originKind == "manual" || strings.HasPrefix(path, "/usr/local/") || strings.HasPrefix(path, "/opt/") {
			kind = ChangeNewManualBinary
			desc = fmt.Sprintf("New unmanaged/manual executable dropped at %s", node.Label)
			cause = "Manual curl/tarball installation or ad-hoc admin drop"
		} else {
			desc = fmt.Sprintf("New file %s installed", node.Label)
			cause = "Package installation or build tool output"
		}

	case graph.NodePackage:
		desc = fmt.Sprintf("New package or software origin detected: %s", node.Label)
		cause = "Package manager transaction (apt/dpkg/rpm/pacman/apk)"

	case graph.NodeProcess:
		desc = fmt.Sprintf("New process spawned: %s", node.Label)
		cause = "Process launch or systemd service unit start"

	case graph.NodeService:
		desc = fmt.Sprintf("New systemd service unit discovered: %s", node.Label)
		cause = "Service unit enablement or installation"
	}

	return Change{
		ID:            fmt.Sprintf("add:%s", node.ID),
		Kind:          kind,
		NodeType:      node.Type,
		NodeID:        node.ID,
		Label:         node.Label,
		Description:   desc,
		ProbableCause: cause,
		After:         node.Properties,
		Timestamp:     ts,
	}
}

func (e *Engine) classifyModifiedNode(before, after graph.Node, ts time.Time) []Change {
	var changes []Change

	// Version change
	bVer, bHasVer := before.Properties["version"].(string)
	aVer, aHasVer := after.Properties["version"].(string)
	if bHasVer && aHasVer && bVer != aVer {
		changes = append(changes, Change{
			ID:            fmt.Sprintf("ver:%s", after.ID),
			Kind:          ChangeVersionChanged,
			NodeType:      after.Type,
			NodeID:        after.ID,
			Label:         after.Label,
			Description:   fmt.Sprintf("%s %q version changed from %s to %s", after.Type, after.Label, bVer, aVer),
			ProbableCause: "Package upgrade or binary update",
			Before:        map[string]any{"version": bVer},
			After:         map[string]any{"version": aVer},
			Timestamp:     ts,
		})
	}

	// Port exposure changes
	if after.Type == graph.NodePort {
		bExp, _ := before.Properties["exposure_class"].(string)
		aExp, _ := after.Properties["exposure_class"].(string)
		if bExp != aExp && aExp == "all_interfaces" {
			changes = append(changes, Change{
				ID:            fmt.Sprintf("exp:%s", after.ID),
				Kind:          ChangeNewlyExposed,
				NodeType:      after.Type,
				NodeID:        after.ID,
				Label:         after.Label,
				Description:   fmt.Sprintf("Port %s changed exposure from %s to all_interfaces", after.Label, bExp),
				ProbableCause: "Service configuration change or firewall modification",
				Before:        map[string]any{"exposure_class": bExp},
				After:         map[string]any{"exposure_class": aExp},
				Timestamp:     ts,
			})
		}
	}

	// Process or File ownership change
	bUser, bHasUser := before.Properties["user"].(string)
	aUser, aHasUser := after.Properties["user"].(string)
	if bHasUser && aHasUser && bUser != aUser {
		changes = append(changes, Change{
			ID:            fmt.Sprintf("owner:%s", after.ID),
			Kind:          ChangeOwnershipChange,
			NodeType:      after.Type,
			NodeID:        after.ID,
			Label:         after.Label,
			Description:   fmt.Sprintf("%s %q ownership changed from %s to %s", after.Type, after.Label, bUser, aUser),
			ProbableCause: "chown or privilege change",
			Before:        map[string]any{"user": bUser},
			After:         map[string]any{"user": aUser},
			Timestamp:     ts,
		})
	}

	// Service state change
	if after.Type == graph.NodeService {
		bState, _ := before.Properties["active_state"].(string)
		aState, _ := after.Properties["active_state"].(string)
		if bState != "" && aState != "" && bState != aState {
			cause := "Service daemon state transition"
			if aState == "failed" {
				cause = "Crash, misconfiguration, or unhandled exit"
			}
			changes = append(changes, Change{
				ID:            fmt.Sprintf("state:%s", after.ID),
				Kind:          ChangeStateChanged,
				NodeType:      after.Type,
				NodeID:        after.ID,
				Label:         after.Label,
				Description:   fmt.Sprintf("Service %s active state transitioned from %s to %s", after.Label, bState, aState),
				ProbableCause: cause,
				Before:        map[string]any{"active_state": bState},
				After:         map[string]any{"active_state": aState},
				Timestamp:     ts,
			})
		}
	}

	return changes
}
