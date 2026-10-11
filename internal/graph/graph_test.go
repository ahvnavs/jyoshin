// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCertainty_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		c     Certainty
		valid bool
	}{
		{"observed", CertaintyObserved, true},
		{"derived", CertaintyDerived, true},
		{"inferred", CertaintyInferred, true},
		{"unknown", Certainty("UNKNOWN"), false},
		{"empty", Certainty(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.IsValid(); got != tt.valid {
				t.Fatalf("expected valid=%v, got %v", tt.valid, got)
			}
		})
	}
}

func TestNode_ValidationAndJSONRoundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	validNode := Node{
		ID:    "proc:1024",
		Type:  NodeProcess,
		Label: "systemd-resolved",
		Properties: map[string]any{
			"pid":  float64(1024),
			"user": "systemd-resolve",
		},
		Evidence: []Evidence{
			{
				Source:    "/proc/1024/status",
				Collector: "process_collector",
				Raw:       "Name: systemd-resolved",
				Timestamp: now,
				Certainty: CertaintyObserved,
			},
		},
		Certainty: CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}

	if err := validNode.Validate(); err != nil {
		t.Fatalf("validNode failed validation: %v", err)
	}

	data, err := json.Marshal(validNode)
	if err != nil {
		t.Fatalf("failed to marshal node: %v", err)
	}

	var roundtrip Node
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("failed to unmarshal node: %v", err)
	}

	if err := roundtrip.Validate(); err != nil {
		t.Fatalf("roundtrip node failed validation: %v", err)
	}

	if roundtrip.ID != validNode.ID || roundtrip.Type != validNode.Type || roundtrip.Label != validNode.Label {
		t.Fatalf("roundtrip fields mismatch: %+v vs %+v", roundtrip, validNode)
	}
}

func TestNode_ValidationErrors(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		node Node
	}{
		{"missing id", Node{Type: NodeProcess, Label: "p", Certainty: CertaintyObserved, FirstSeen: now, LastSeen: now}},
		{"missing type", Node{ID: "p1", Label: "p", Certainty: CertaintyObserved, FirstSeen: now, LastSeen: now}},
		{"missing label", Node{ID: "p1", Type: NodeProcess, Certainty: CertaintyObserved, FirstSeen: now, LastSeen: now}},
		{"invalid certainty", Node{ID: "p1", Type: NodeProcess, Label: "p", Certainty: "FOO", FirstSeen: now, LastSeen: now}},
		{"zero first seen", Node{ID: "p1", Type: NodeProcess, Label: "p", Certainty: CertaintyObserved, LastSeen: now}},
		{"zero last seen", Node{ID: "p1", Type: NodeProcess, Label: "p", Certainty: CertaintyObserved, FirstSeen: now}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.node.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", tt.name)
			}
		})
	}
}

func TestEdge_ValidationAndJSONRoundtrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	edge := Edge{
		ID:         "proc:1024->port:53",
		SourceID:   "proc:1024",
		TargetID:   "port:53",
		Relation:   "listens_on",
		Certainty:  CertaintyDerived,
		Confidence: 1.0,
		Evidence: []Evidence{
			{
				Source:    "/proc/net/udp",
				Collector: "network_collector",
				Timestamp: now,
				Certainty: CertaintyObserved,
			},
		},
	}

	if err := edge.Validate(); err != nil {
		t.Fatalf("edge validation failed: %v", err)
	}

	data, err := json.Marshal(edge)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	var roundtrip Edge
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if err := roundtrip.Validate(); err != nil {
		t.Fatalf("roundtrip edge validation failed: %v", err)
	}

	if roundtrip.ID != edge.ID || roundtrip.Relation != edge.Relation {
		t.Fatalf("mismatch: %+v vs %+v", roundtrip, edge)
	}
}
