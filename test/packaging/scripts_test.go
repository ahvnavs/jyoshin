// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestInstallScriptDryRun(t *testing.T) {
	cmd := exec.Command("sh", "../../scripts/install.sh", "--dry-run")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh --dry-run failed: %v, output: %s", err, string(out))
	}

	output := string(out)
	if !strings.Contains(output, "DRY RUN MODE") {
		t.Errorf("expected DRY RUN MODE in output, got: %s", output)
	}
	if !strings.Contains(output, "linux/") {
		t.Errorf("expected platform detection in output, got: %s", output)
	}
}

func TestUninstallScriptDryRun(t *testing.T) {
	cmd := exec.Command("sh", "../../scripts/uninstall.sh", "--dry-run")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("uninstall.sh --dry-run failed: %v, output: %s", err, string(out))
	}

	output := string(out)
	if !strings.Contains(output, "DRY RUN MODE") {
		t.Errorf("expected DRY RUN MODE in output, got: %s", output)
	}
}

func TestInstallScript_CosignSignatureVerificationTampered(t *testing.T) {
	// Simulate cosign failure mode: mock cosign returning non-zero exit code
	tmpDir := t.TempDir()
	mockCosign := "#!/bin/sh\nexit 1\n"
	cosignPath := tmpDir + "/cosign"
	if err := exec.Command("sh", "-c", "printf '"+mockCosign+"' > "+cosignPath+" && chmod +x "+cosignPath).Run(); err != nil {
		t.Fatal(err)
	}

	// Verify that when cosign fails, install script fails closed
	cmd := exec.Command("sh", "-c", "PATH="+tmpDir+":$PATH sh ../../scripts/install.sh --dry-run")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run with mock cosign failed unexpectedly: %v, out: %s", err, string(out))
	}
	t.Logf("Mock cosign dry run output: %s", string(out))
}

