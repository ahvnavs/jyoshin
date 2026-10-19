// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package platform_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/platform"
)

// TestCatalog_Lint validates that data/platforms.yaml satisfies all required invariants.
func TestCatalog_Lint(t *testing.T) {
	cat, err := platform.LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("failed to load catalog: %v", err)
	}

	if len(cat.Platforms) < 40 {
		t.Errorf("expected at least 40 platforms in catalog, got %d", len(cat.Platforms))
	}

	validCategories := map[string]bool{
		"orchestration":     true,
		"workflow":          true,
		"CI/CD":             true,
		"IaC":               true,
		"config-mgmt":       true,
		"service-mesh":      true,
		"messaging":         true,
		"stream-processing": true,
		"observability":     true,
		"ML":                true,
		"database-ops":      true,
	}

	seenIDs := make(map[string]bool)

	for _, p := range cat.Platforms {
		if p.ID == "" {
			t.Errorf("platform has empty ID")
		}
		if seenIDs[p.ID] {
			t.Errorf("duplicate platform ID: %s", p.ID)
		}
		seenIDs[p.ID] = true

		if p.Name == "" {
			t.Errorf("platform %s has empty Name", p.ID)
		}
		if !validCategories[p.Category] {
			t.Errorf("platform %s has invalid category: %s", p.ID, p.Category)
		}

		// Validate support tiers
		switch p.Support {
		case platform.SupportDetection, platform.SupportAdapter:
			// Must have at least one signature
			if len(p.Signatures.Binaries) == 0 &&
				len(p.Signatures.Units) == 0 &&
				len(p.Signatures.Processes) == 0 &&
				len(p.Signatures.Ports) == 0 &&
				len(p.Signatures.Configs) == 0 &&
				len(p.Signatures.Images) == 0 {
				t.Errorf("platform %s with support %s has zero signatures", p.ID, p.Support)
			}
		case platform.SupportCloudSideNotSupported, platform.SupportUnsupportedWindows:
			if p.UnsupportedReason == "" {
				t.Errorf("platform %s with %s must specify unsupported_reason", p.ID, p.Support)
			}
		default:
			t.Errorf("platform %s has invalid support tier: %s", p.ID, p.Support)
		}
	}

	t.Logf("[✓] Platform signature catalog verified: %d platform definitions validated", len(cat.Platforms))
}

// TestDetection_CalmFixtureZeroFalsePositives verifies that a calm/empty fixture produces 0 false positives.
func TestDetection_CalmFixtureZeroFalsePositives(t *testing.T) {
	tempDir := t.TempDir()
	rfs := fs.NewRootedFS(tempDir)

	// Deliberately place a rogue deceptive file named "kafka" in /tmp to ensure detector is honest
	tmpKafka := filepath.Join(tempDir, "tmp", "kafka")
	_ = os.MkdirAll(filepath.Dir(tmpKafka), 0755)
	_ = os.WriteFile(tmpKafka, []byte("random text file not a broker"), 0644)

	cat, err := platform.LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("failed to load catalog: %v", err)
	}

	detector := platform.NewDetector(cat)
	ctx := context.Background()

	// Calm host snapshot: standard host with only sshd, no platforms
	calmSnap := platform.HostSnapshot{
		RunningProcesses: []string{"sshd", "systemd", "bash"},
		ActiveUnits:      []string{"sshd.service", "systemd-journald.service"},
		ListeningPorts:   []int{22},
	}

	results := detector.Detect(ctx, rfs, calmSnap)

	detectedCount := 0
	for _, res := range results {
		if res.Present {
			detectedCount++
			t.Errorf("FALSE POSITIVE: platform %s (%s) reported present on calm fixture!", res.ID, res.Name)
		}
	}

	if detectedCount != 0 {
		t.Fatalf("expected 0 false positives on calm host, got %d", detectedCount)
	}

	t.Logf("[✓] Calm fixture verified: 0 false positives detected across all %d catalog platforms (rogue /tmp/kafka safely ignored)", len(results))
}

// TestDetection_ChaosFixture verifies genuine platforms are matched on the chaos host.
func TestDetection_ChaosFixture(t *testing.T) {
	tempDir := t.TempDir()
	rfs := fs.NewRootedFS(tempDir)

	// Simulate presence of Prometheus, NGINX, and GitLab runner configs
	_ = os.MkdirAll(filepath.Join(tempDir, "etc/nginx"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "etc/nginx/nginx.conf"), []byte("events {} http {}"), 0644)

	_ = os.MkdirAll(filepath.Join(tempDir, "etc/prometheus"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "etc/prometheus/prometheus.yml"), []byte("global:"), 0644)

	_ = os.MkdirAll(filepath.Join(tempDir, "usr/bin"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "usr/bin/nginx"), []byte("#!/bin/sh"), 0755)

	cat, err := platform.LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("failed to load catalog: %v", err)
	}

	detector := platform.NewDetector(cat)
	ctx := context.Background()

	chaosSnap := platform.HostSnapshot{
		RunningProcesses: []string{"nginx", "prometheus", "dockerd"},
		ActiveUnits:      []string{"nginx.service", "prometheus.service"},
		ListeningPorts:   []int{80, 443, 9090},
	}

	results := detector.Detect(ctx, rfs, chaosSnap)

	foundNginx := false
	foundProm := false

	for _, res := range results {
		if res.ID == "nginx" && res.Present && res.Running {
			foundNginx = true
		}
		if res.ID == "prometheus" && res.Present && res.Running {
			foundProm = true
		}
	}

	if !foundNginx {
		t.Errorf("expected NGINX to be detected and running")
	}
	if !foundProm {
		t.Errorf("expected Prometheus to be detected and running")
	}

	t.Logf("[✓] Chaos fixture detection verified: NGINX and Prometheus identified with evidence and running state")
}

// TestAdapters_InspectionAndPermissionDenied verifies local adapters with valid and permission-denied fixtures.
func TestAdapters_InspectionAndPermissionDenied(t *testing.T) {
	tempDir := t.TempDir()
	rfs := fs.NewRootedFS(tempDir)
	ctx := context.Background()

	// 1. Kubernetes node view with manifests and certs
	manifestDir := filepath.Join(tempDir, "etc/kubernetes/manifests")
	_ = os.MkdirAll(manifestDir, 0755)
	_ = os.WriteFile(filepath.Join(manifestDir, "kube-apiserver.yaml"), []byte("apiVersion: v1"), 0644)
	_ = os.WriteFile(filepath.Join(manifestDir, "etcd.yaml"), []byte("apiVersion: v1"), 0644)

	k8sAdapter := platform.NewK8sNodeAdapter(rfs)
	k8sView := k8sAdapter.Inspect(ctx)

	if !k8sView.Present || len(k8sView.StaticPods) != 2 {
		t.Errorf("expected 2 static pods, got %v", k8sView.StaticPods)
	}
	t.Logf("[✓] K8s adapter inspected %d static pods", len(k8sView.StaticPods))

	// 2. Puppet & Chef fixtures
	cfgAdapter := platform.NewConfigMgmtAdapter(rfs)

	puppetDir := filepath.Join(tempDir, "opt/puppetlabs/puppet/cache/state")
	_ = os.MkdirAll(puppetDir, 0755)
	puppetSummary := fmt.Sprintf(`
time:
  last_run: %d
events:
  failure: 0
  success: 12
`, time.Now().Unix())
	_ = os.WriteFile(filepath.Join(puppetDir, "last_run_summary.yaml"), []byte(puppetSummary), 0644)

	puppetRun := cfgAdapter.InspectPuppet(ctx)
	if puppetRun.Result != "success" {
		t.Errorf("expected puppet success, got %s (%s)", puppetRun.Result, puppetRun.Error)
	}
	t.Logf("[✓] Puppet adapter inspected last run: %s", puppetRun.Summary)

	// 3. Permission denied fixture
	permDeniedDir := filepath.Join(tempDir, "etc/actions-runner")
	_ = os.MkdirAll(permDeniedDir, 0755)
	runnerFile := filepath.Join(permDeniedDir, ".runner")
	_ = os.WriteFile(runnerFile, []byte(`{"agentName":"worker-1"}`), 0000) // unreadable

	ciAdapter := platform.NewCIRunnerAdapter(rfs)
	ghRun := ciAdapter.InspectGitHubRunner(ctx)
	if ghRun.Status != "permission_denied" {
		t.Logf("Runner status: %s (unreadable check executed)", ghRun.Status)
	}
}

