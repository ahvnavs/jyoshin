// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package drift_test

import (
	"context"
	"testing"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/desired"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/resource"
)

func TestDriftEngine_Evaluation(t *testing.T) {
	ctx := context.Background()
	engine := drift.NewEngine()

	desiredState := desired.DesiredState{
		RequiredPackages: []desired.PackageExpectation{
			{Name: "openssh-server", Version: "1:9"},
			{Name: "git", Version: "2.39"},
		},
		ForbiddenPackages: []string{"telnetd"},
		RequiredServices: []desired.ServiceExpectation{
			{Name: "sshd", State: "active"},
		},
		AllowedPorts: []desired.PortExpectation{
			{Port: 22, Protocol: "tcp"},
		},
	}

	adequateCov := coverage.Report{
		IsAdequate: true,
		Items: []coverage.ItemCoverage{
			{Name: "packages", Category: "packages", Status: "full", Readable: 10, Total: 10},
			{Name: "services", Category: "services", Status: "full", Readable: 10, Total: 10},
			{Name: "sockets", Category: "network", Status: "full", Readable: 10, Total: 10},
		},
	}

	t.Run("matching observed host: zero drift", func(t *testing.T) {
		observed := []resource.Resource{
			{
				Kind: resource.KindPackage,
				Name: "openssh-server",
				Spec: map[string]any{"version": "1:9.2p1-2+deb12u3"},
			},
			{
				Kind: resource.KindPackage,
				Name: "git",
				Spec: map[string]any{"version": "2.39.5-0+deb12u1"},
			},
			{
				Kind: resource.KindService,
				Name: "sshd",
				Spec: map[string]any{"active_state": "active"},
			},
			{
				Kind: resource.KindPort,
				Name: "22/tcp",
				Spec: map[string]any{"port": 22, "protocol": "tcp"},
			},
		}

		items, summary := engine.Evaluate(ctx, desiredState, observed, adequateCov)
		if len(items) != 0 || summary.TotalDrift != 0 {
			t.Errorf("expected 0 drift items, got %d items: %+v", len(items), items)
		}
	})

	t.Run("missing, extra, mismatch, wrong-state, unexpected-port detected", func(t *testing.T) {
		observed := []resource.Resource{
			// git is missing
			// openssh-server has version mismatch
			{
				Kind: resource.KindPackage,
				Name: "openssh-server",
				Spec: map[string]any{"version": "1:8.4p1"},
			},
			// forbidden telnetd is present
			{
				Kind: resource.KindPackage,
				Name: "telnetd",
			},
			// sshd is stopped
			{
				Kind: resource.KindService,
				Name: "sshd",
				Spec: map[string]any{"active_state": "inactive"},
			},
			// Port 22 is open, but unexpected port 6667 is also open
			{
				Kind: resource.KindPort,
				Name: "22/tcp",
				Spec: map[string]any{"port": 22, "protocol": "tcp"},
			},
			{
				Kind: resource.KindPort,
				Name: "6667/tcp",
				Spec: map[string]any{"port": 6667, "protocol": "tcp"},
			},
		}

		items, summary := engine.Evaluate(ctx, desiredState, observed, adequateCov)
		if summary.Missing < 1 {
			t.Errorf("expected missing git package, got %d missing", summary.Missing)
		}
		if summary.Mismatch < 1 {
			t.Errorf("expected mismatch openssh-server version, got %d mismatch", summary.Mismatch)
		}
		if summary.Extra < 1 {
			t.Errorf("expected extra telnetd package, got %d extra", summary.Extra)
		}
		if summary.WrongState < 1 {
			t.Errorf("expected wrong-state sshd service, got %d wrong state", summary.WrongState)
		}
		if summary.Ports < 1 {
			t.Errorf("expected unexpected port 6667, got %d unexpected ports", summary.Ports)
		}
		if len(items) != 5 {
			t.Errorf("expected exactly 5 drift items, got %d", len(items))
		}
	})

	t.Run("Principle 11: partial or offline coverage returns unknown", func(t *testing.T) {
		partialCov := coverage.Report{
			IsAdequate: false,
			Items: []coverage.ItemCoverage{
				{Name: "packages", Category: "packages", Status: "unavailable", Readable: 0, Total: 10},
				{Name: "services", Category: "services", Status: "unavailable", Readable: 0, Total: 10},
				{Name: "sockets", Category: "network", Status: "unavailable", Readable: 0, Total: 10},
			},
		}

		items, summary := engine.Evaluate(ctx, desiredState, nil, partialCov)
		if summary.Unknown == 0 {
			t.Errorf("expected unknown drift items when coverage is offline, got summary: %+v", summary)
		}
		for _, item := range items {
			if item.Kind != drift.KindUnknown {
				t.Errorf("expected KindUnknown when coverage is offline, got %q on %s", item.Kind, item.ID)
			}
		}
	})
}
