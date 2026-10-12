// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package resource

import (
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
)

func TestResource_Mapping(t *testing.T) {
	node := graph.Node{
		ID:    "service:nginx",
		Type:  graph.NodeService,
		Label: "nginx.service",
		Properties: map[string]any{
			"active_state": "active",
		},
		Evidence: []graph.Evidence{
			{
				Source:    "/bin/systemctl",
				Collector: "service",
				Timestamp: time.Now().UTC(),
				Certainty: graph.CertaintyObserved,
			},
		},
		Certainty: graph.CertaintyObserved,
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	res := FromGraphNode(node)
	if res.Kind != KindService {
		t.Fatalf("expected KindService, got %s", res.Kind)
	}
	if res.Name != "nginx.service" {
		t.Fatalf("expected name nginx.service, got %s", res.Name)
	}
	if res.Metadata.Labels["graph_id"] != "service:nginx" {
		t.Fatalf("expected graph_id label, got %v", res.Metadata.Labels)
	}

	back := res.ToGraphNode()
	if back.ID != "service:nginx" {
		t.Fatalf("expected id service:nginx, got %s", back.ID)
	}
	if back.Type != graph.NodeService {
		t.Fatalf("expected type NodeService, got %s", back.Type)
	}
	if len(back.Evidence) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(back.Evidence))
	}
}

