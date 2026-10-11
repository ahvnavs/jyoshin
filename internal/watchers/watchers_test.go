// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package watchers_test

import (
	"context"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/watchers"
)

func TestWatchers_DeduplicationAndRateLimiting(t *testing.T) {
	cooldown := 500 * time.Millisecond
	mgr := watchers.NewManager(cooldown)
	ctx := context.Background()

	changeSet := diff.ChangeSet{
		Changes: []diff.Change{
			{
				ID:       "ch-1",
				Kind:     diff.ChangeNewlyExposed,
				NodeType: graph.NodePort,
				NodeID:   "port:0.0.0.0:3306",
				Label:    "0.0.0.0:3306",
			},
		},
	}

	// First evaluation fires alert
	alerts1 := mgr.ProcessChangeSet(ctx, changeSet)
	if len(alerts1) != 1 {
		t.Fatalf("expected 1 alert on initial breach, got %d", len(alerts1))
	}
	if alerts1[0].Severity != rules.SeverityCritical {
		t.Errorf("expected SeverityCritical for exposed port, got %s", alerts1[0].Severity)
	}

	// Immediate second evaluation should be deduplicated / rate limited
	alerts2 := mgr.ProcessChangeSet(ctx, changeSet)
	if len(alerts2) != 0 {
		t.Fatalf("expected 0 alerts due to cooldown deduplication, got %d", len(alerts2))
	}

	// After cooldown, same event can fire again
	time.Sleep(cooldown + 50*time.Millisecond)
	alerts3 := mgr.ProcessChangeSet(ctx, changeSet)
	if len(alerts3) != 1 {
		t.Fatalf("expected alert to re-fire after cooldown expiry, got %d", len(alerts3))
	}
}

func TestWatchers_ForecastExhaustionAlert(t *testing.T) {
	mgr := watchers.NewManager(1 * time.Minute)

	// Normal forecast: no alert
	resNormal := forecast.Result{
		Resource: forecast.ResourceDisk,
		Target:   "/",
		State:    forecast.StateOK,
	}
	alertNormal := mgr.ProcessForecast(resNormal)
	if alertNormal != nil {
		t.Errorf("expected no alert for StateOK")
	}

	// Imminent exhaustion: fires alert
	resCrit := forecast.Result{
		Resource:         forecast.ResourceDisk,
		Target:           "/var/log",
		State:            forecast.StateExhaustionRisk,
		TimeToExhaustion: 4 * time.Hour,
		Message:          "Disk /var/log exhaustion predicted in 4h",
	}
	alertCrit := mgr.ProcessForecast(resCrit)
	if alertCrit == nil {
		t.Fatalf("expected alert for StateExhaustionRisk")
	}
	if alertCrit.Severity != rules.SeverityCritical {
		t.Errorf("expected critical alert for exhaustion risk, got %s", alertCrit.Severity)
	}
}
