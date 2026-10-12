// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package desired_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/desired"
)

func TestDesiredState_ValidationAndSelectors(t *testing.T) {
	tmpDir := t.TempDir()
	manifestFile := filepath.Join(tmpDir, "kazeshini.desired.yaml")

	validYAML := `
apiVersion: kazeshini.io/v1
kind: DesiredState
metadata:
  name: test-spec
  description: "Test manifest for validation"
rules:
  - selector:
      matchLabels:
        role: web
    state:
      requiredPackages:
        - name: nginx
          version: "1.24"
      forbiddenPackages:
        - telnetd
      requiredServices:
        - name: nginx
      allowedPorts:
        - port: 80
        - port: 443
      filesMetadata:
        - path: /etc/nginx/nginx.conf
          mode: "0644"
          owner: root
  - selector:
      matchLabels:
        role: db
    state:
      requiredPackages:
        - name: postgresql
      allowedPorts:
        - port: 5432
`
	if err := os.WriteFile(manifestFile, []byte(validYAML), 0644); err != nil {
		t.Fatalf("failed to write test manifest: %v", err)
	}

	// 1. Test Load and Validate
	m, err := desired.LoadFile(manifestFile)
	if err != nil {
		t.Fatalf("LoadFile failed on valid YAML: %v", err)
	}

	if m.Metadata.Name != "test-spec" {
		t.Errorf("expected metadata.name 'test-spec', got %q", m.Metadata.Name)
	}

	// 2. Test Selector Matching: role=web
	webState := m.ForHost(map[string]string{"role": "web"})
	if len(webState.RequiredPackages) != 1 || webState.RequiredPackages[0].Name != "nginx" {
		t.Errorf("expected 1 required package 'nginx' for role:web, got %+v", webState.RequiredPackages)
	}
	if len(webState.ForbiddenPackages) != 1 || webState.ForbiddenPackages[0] != "telnetd" {
		t.Errorf("expected forbidden package 'telnetd', got %+v", webState.ForbiddenPackages)
	}
	if len(webState.AllowedPorts) != 2 {
		t.Errorf("expected 2 allowed ports for web, got %d", len(webState.AllowedPorts))
	}

	// 3. Test Selector Matching: role=db
	dbState := m.ForHost(map[string]string{"role": "db"})
	if len(dbState.RequiredPackages) != 1 || dbState.RequiredPackages[0].Name != "postgresql" {
		t.Errorf("expected 1 required package 'postgresql' for role:db, got %+v", dbState.RequiredPackages)
	}

	// 4. Test Invalid Manifests
	invalidCases := []struct {
		name string
		yaml string
	}{
		{
			name: "missing apiVersion",
			yaml: "kind: DesiredState\nmetadata:\n  name: x\n",
		},
		{
			name: "invalid kind",
			yaml: "apiVersion: kazeshini.io/v1\nkind: OtherKind\nmetadata:\n  name: x\n",
		},
		{
			name: "invalid port number",
			yaml: "apiVersion: kazeshini.io/v1\nkind: DesiredState\nmetadata:\n  name: x\nrules:\n  - state:\n      allowedPorts:\n        - port: 70000\n",
		},
		{
			name: "relative file path",
			yaml: "apiVersion: kazeshini.io/v1\nkind: DesiredState\nmetadata:\n  name: x\nrules:\n  - state:\n      filesMetadata:\n        - path: relative/path.txt\n",
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			badFile := filepath.Join(tmpDir, tc.name+".yaml")
			_ = os.WriteFile(badFile, []byte(tc.yaml), 0644)
			_, err := desired.LoadFile(badFile)
			if err == nil {
				t.Errorf("expected validation failure for case %q, but succeeded", tc.name)
			}
		})
	}
}

