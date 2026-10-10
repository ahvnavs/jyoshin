// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package decisions_test

import (
	"testing"
	"time"

	"github.com/OWNER/jyoshin/internal/decisions"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/graphbuilder"
)

func TestDecisions_DecommissionAndMigration(t *testing.T) {
	pGraph := graphbuilder.NewProvenanceGraph()
	now := time.Now().UTC()

	// Add an exposed port, a timer, and a secret file path
	port := graph.Node{
		ID:        "port:8080",
		Type:      graph.NodePort,
		Label:     "0.0.0.0:8080",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
		Properties: map[string]any{
			"port":           8080,
			"exposure_class": "all_interfaces",
		},
	}
	timer := graph.Node{
		ID:        "svc:backup.timer",
		Type:      graph.NodeService,
		Label:     "backup.timer",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
	}
	secretFile := graph.Node{
		ID:        "file:ssl-key",
		Type:      graph.NodeFile,
		Label:     "/etc/ssl/private/server.key",
		Certainty: graph.CertaintyObserved,
		FirstSeen: now,
		LastSeen:  now,
		Properties: map[string]any{
			"path": "/etc/ssl/private/server.key",
		},
	}

	_ = pGraph.UpsertNode(port)
	_ = pGraph.UpsertNode(timer)
	_ = pGraph.UpsertNode(secretFile)

	eng := decisions.NewEngine(pGraph)

	// 1. Decommission evaluation: Should NOT be safe to turn off
	decom := eng.EvaluateDecommission()
	if decom.SafeToTurnOff {
		t.Errorf("expected SafeToTurnOff == false due to public port and timer")
	}
	if len(decom.Blockers) < 2 {
		t.Errorf("expected at least 2 blockers, got %d", len(decom.Blockers))
	}

	// 2. Migration planning: Should identify secret path without leaking content
	plan := eng.PlanMigration()
	if len(plan.Ports) != 1 || plan.Ports[0] != "0.0.0.0:8080" {
		t.Errorf("expected port 0.0.0.0:8080 in migration plan")
	}
	if len(plan.SecretsPaths) != 1 || plan.SecretsPaths[0] != "/etc/ssl/private/server.key" {
		t.Errorf("expected secret path /etc/ssl/private/server.key in migration plan")
	}

	// 3. Dependencies topology
	depMap := eng.GetDependencies()
	if len(depMap.InboundEndpoints) != 1 {
		t.Errorf("expected 1 inbound endpoint, got %d", len(depMap.InboundEndpoints))
	}
	if depMap.InboundEndpoints[0].Role != decisions.RoleAPI {
		t.Errorf("expected RoleAPI for port 8080, got %s", depMap.InboundEndpoints[0].Role)
	}
}
