// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package graph defines the provenance graph domain model: nodes, edges,
// evidence items, and certainty classifications.
package graph

import (
	"errors"
	"fmt"
	"time"
)

// Certainty represents the confidence level and provenance class of a claim or observation.
// Principle 6: FACT vs INFERENCE. Never present an inference as fact.
type Certainty string

const (
	// CertaintyObserved represents facts read directly from kernel /proc, /sys, os packages, etc.
	CertaintyObserved Certainty = "OBSERVED"
	// CertaintyDerived represents deterministically computed values from observed facts.
	CertaintyDerived Certainty = "DERIVED"
	// CertaintyInferred represents heuristic deductions with an associated confidence score in [0.0, 1.0].
	CertaintyInferred Certainty = "INFERRED"
)

// IsValid validates whether the Certainty value is one of the supported enum variants.
func (c Certainty) IsValid() bool {
	switch c {
	case CertaintyObserved, CertaintyDerived, CertaintyInferred:
		return true
	default:
		return false
	}
}

// Evidence captures a discrete proof item backing a node, edge, or finding.
type Evidence struct {
	Source    string    `json:"source"`            // e.g. "/proc/1/cmdline", "dpkg-query", "/sys/class/net"
	Collector string    `json:"collector"`         // Sensor name responsible for this observation
	Raw       string    `json:"raw,omitempty"`     // Exact excerpt or normalized value observed
	Timestamp time.Time `json:"timestamp"`         // Timestamp when evidence was gathered
	Certainty Certainty `json:"certainty"`         // OBSERVED, DERIVED, or INFERRED
	Details   string    `json:"details,omitempty"` // Human-readable explanation of how this was gathered
}

// Validate checks that required fields in Evidence are populated and conformant.
func (e Evidence) Validate() error {
	if e.Source == "" {
		return errors.New("evidence source is required")
	}
	if e.Collector == "" {
		return errors.New("evidence collector is required")
	}
	if !e.Certainty.IsValid() {
		return fmt.Errorf("invalid evidence certainty: %q", e.Certainty)
	}
	if e.Timestamp.IsZero() {
		return errors.New("evidence timestamp must not be zero")
	}
	return nil
}

// NodeType identifies the category of entity in the server provenance graph.
type NodeType string

const (
	NodeFile       NodeType = "file"
	NodePackage    NodeType = "package"
	NodeProcess    NodeType = "process"
	NodeService    NodeType = "service"
	NodePort       NodeType = "port"
	NodeConnection NodeType = "connection"
	NodeUser       NodeType = "user"
	NodeContainer  NodeType = "container"
	NodeResource   NodeType = "resource"
	NodeSystem     NodeType = "system"
)

// Node represents an entity in the server truth provenance graph.
type Node struct {
	ID         string         `json:"id"`                   // Unique canonical identifier (e.g. "proc:1234", "pkg:dpkg:nginx")
	Type       NodeType       `json:"type"`                 // Node kind
	Label      string         `json:"label"`                // Human-readable display label
	Properties map[string]any `json:"properties,omitempty"` // Structured attributes
	Evidence   []Evidence     `json:"evidence"`             // Supporting evidence items
	Certainty  Certainty      `json:"certainty"`            // Overall certainty for this node
	FirstSeen  time.Time      `json:"first_seen"`           // When node was first detected
	LastSeen   time.Time      `json:"last_seen"`            // When node was last detected
}

// Validate ensures node fields conform to required constraints.
func (n Node) Validate() error {
	if n.ID == "" {
		return errors.New("node id is required")
	}
	if n.Type == "" {
		return errors.New("node type is required")
	}
	if n.Label == "" {
		return errors.New("node label is required")
	}
	if !n.Certainty.IsValid() {
		return fmt.Errorf("invalid node certainty: %q", n.Certainty)
	}
	if n.FirstSeen.IsZero() {
		return errors.New("node first_seen timestamp must not be zero")
	}
	if n.LastSeen.IsZero() {
		return errors.New("node last_seen timestamp must not be zero")
	}
	for i, ev := range n.Evidence {
		if err := ev.Validate(); err != nil {
			return fmt.Errorf("invalid evidence at index %d: %w", i, err)
		}
	}
	return nil
}

// Edge represents a directed relation between two provenance nodes.
type Edge struct {
	ID         string         `json:"id"`                   // Unique canonical identifier (e.g. "proc:1234->port:80")
	SourceID   string         `json:"source_id"`            // ID of the source node
	TargetID   string         `json:"target_id"`            // ID of the target node
	Relation   string         `json:"relation"`             // e.g. "listens_on", "spawned_by", "installed_via"
	Properties map[string]any `json:"properties,omitempty"` // Relation properties
	Evidence   []Evidence     `json:"evidence"`             // Proof backing this relationship
	Certainty  Certainty      `json:"certainty"`            // OBSERVED, DERIVED, or INFERRED
	Confidence float64        `json:"confidence"`           // 1.0 for OBSERVED/DERIVED; [0.0, 1.0] for INFERRED
}

// Validate ensures edge fields conform to required constraints.
func (e Edge) Validate() error {
	if e.ID == "" {
		return errors.New("edge id is required")
	}
	if e.SourceID == "" {
		return errors.New("edge source_id is required")
	}
	if e.TargetID == "" {
		return errors.New("edge target_id is required")
	}
	if e.Relation == "" {
		return errors.New("edge relation is required")
	}
	if !e.Certainty.IsValid() {
		return fmt.Errorf("invalid edge certainty: %q", e.Certainty)
	}
	if e.Confidence < 0.0 || e.Confidence > 1.0 {
		return fmt.Errorf("edge confidence %f out of range [0.0, 1.0]", e.Confidence)
	}
	for i, ev := range e.Evidence {
		if err := ev.Validate(); err != nil {
			return fmt.Errorf("invalid evidence at index %d: %w", i, err)
		}
	}
	return nil
}
