//go:build experimental
// +build experimental

// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package plugin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/plugin"
)

func TestPlugin_CrashIsolation(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Script for crashing plugin (aborts with exit code 1 or SIGSEGV)
	crashingScript := filepath.Join(tempDir, "crash_plugin.sh")
	crashingContent := `#!/bin/sh
echo '{"jsonrpc":"2.0","id":1,"error":{"message":"unexpected panic"}}' >&2
exit 139
`
	if err := os.WriteFile(crashingScript, []byte(crashingContent), 0755); err != nil {
		t.Fatalf("failed to write crashing script: %v", err)
	}

	// 2. Script for healthy plugin (emits valid JSON-RPC Platform resource)
	healthyScript := filepath.Join(tempDir, "healthy_plugin.sh")
	healthyContent := `#!/bin/sh
cat << 'EOF'
{"jsonrpc":"2.0","id":1,"result":{"resources":[{"kind":"Platform","name":"test-adapter","metadata":{"labels":{"support":"adapter"}},"status":{"conditions":[{"type":"Present","status":"True"}],"observedAt":"2026-10-13T14:00:00Z"}}]}}
EOF
`
	if err := os.WriteFile(healthyScript, []byte(healthyContent), 0755); err != nil {
		t.Fatalf("failed to write healthy script: %v", err)
	}

	runner := plugin.NewRunner(plugin.Config{AllowUnsigned: true})

	crashManifest := &plugin.Manifest{
		Name:    "crashing-sensor",
		Version: "1.0.0",
		Limits: plugin.ResourceLimits{
			TimeoutSeconds: 2,
			MaxOutputBytes: 1024,
		},
	}

	healthyManifest := &plugin.Manifest{
		Name:    "healthy-sensor",
		Version: "1.0.0",
		Limits: plugin.ResourceLimits{
			TimeoutSeconds: 2,
			MaxOutputBytes: 1024,
		},
	}

	ctx := context.Background()

	// Run crashing plugin: verify it fails gracefully without affecting process
	_, crashStatus, err := runner.Execute(ctx, crashManifest, "/bin/sh", crashingScript)
	if err == nil {
		t.Fatalf("expected error from crashing plugin, got nil")
	}
	if crashStatus.Status != "crashed" {
		t.Fatalf("expected status 'crashed', got %s", crashStatus.Status)
	}
	t.Logf("[✓] Crashing plugin handled safely: status=%s, error=%v", crashStatus.Status, crashStatus.Error)

	// Run healthy plugin immediately after: verify isolation guarantee
	resources, healthyStatus, err := runner.Execute(ctx, healthyManifest, "/bin/sh", healthyScript)
	if err != nil {
		t.Fatalf("healthy plugin failed following crash: %v", err)
	}
	if healthyStatus.Status != "ok" || len(resources) != 1 {
		t.Fatalf("expected 1 resource and status ok, got %d and %s", len(resources), healthyStatus.Status)
	}
	if resources[0].Name != "test-adapter" {
		t.Fatalf("expected resource name 'test-adapter', got %s", resources[0].Name)
	}
	t.Logf("[✓] Plugin crash isolation verified: subsequent plugin executed perfectly, emitted %d resources", len(resources))
}

func TestPlugin_TimeoutAndOutputCap(t *testing.T) {
	tempDir := t.TempDir()

	// Slow script
	slowScript := filepath.Join(tempDir, "slow_plugin.sh")
	slowContent := `#!/bin/sh
sleep 5
echo '{"jsonrpc":"2.0","id":1,"result":{"resources":[]}}'
`
	_ = os.WriteFile(slowScript, []byte(slowContent), 0755)

	runner := plugin.NewRunner(plugin.Config{AllowUnsigned: true})
	slowManifest := &plugin.Manifest{
		Name:    "slow-plugin",
		Version: "1.0.0",
		Limits: plugin.ResourceLimits{
			TimeoutSeconds: 1, // 1s timeout
			MaxOutputBytes: 1024,
		},
	}

	ctx := context.Background()
	_, status, err := runner.Execute(ctx, slowManifest, "/bin/sh", slowScript)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if status.Status != "timeout" {
		t.Fatalf("expected status 'timeout', got %s", status.Status)
	}
	t.Logf("[✓] Timeout cap strictly enforced: %s", status.Status)

	// Greedy output script
	greedyScript := filepath.Join(tempDir, "greedy_plugin.sh")
	greedyContent := `#!/bin/sh
head -c 20000 /dev/zero | tr '\0' 'A'
`
	_ = os.WriteFile(greedyScript, []byte(greedyContent), 0755)
	greedyManifest := &plugin.Manifest{
		Name:    "greedy-plugin",
		Version: "1.0.0",
		Limits: plugin.ResourceLimits{
			TimeoutSeconds: 2,
			MaxOutputBytes: 1024, // 1KB limit
		},
	}

	_, gStatus, gErr := runner.Execute(ctx, greedyManifest, "/bin/sh", greedyScript)
	if gErr == nil {
		t.Fatalf("expected output exceeded error, got nil")
	}
	if gStatus.Status != "failed" {
		t.Fatalf("expected status 'failed', got %s", gStatus.Status)
	}
	t.Logf("[✓] Output byte limit strictly enforced: %v", gErr)
}

func TestPlugin_UnsignedRejection(t *testing.T) {
	runner := plugin.NewRunner(plugin.Config{AllowUnsigned: false})
	manifest := &plugin.Manifest{
		Name:      "unsigned-plugin",
		Version:   "1.0.0",
		Signature: "", // unsigned
		Limits: plugin.ResourceLimits{
			TimeoutSeconds: 1,
			MaxOutputBytes: 1024,
		},
	}

	_, status, err := runner.Execute(context.Background(), manifest, "/bin/true")
	if err != plugin.ErrUnsignedPlugin {
		t.Fatalf("expected ErrUnsignedPlugin, got %v", err)
	}
	if status.Status != "unsigned_rejected" {
		t.Fatalf("expected unsigned_rejected, got %s", status.Status)
	}
	t.Logf("[✓] Unsigned plugin rejected without --allow-unsigned-plugins flag: %s", status.Status)
}

