// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestInstallScript_CosignSignatureBehavioral(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-kazeshini")
	fakeSig := filepath.Join(tmpDir, "fake-kazeshini.sig")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho fake\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeSig, []byte("fake-signature-payload\n"), 0644); err != nil {
		t.Fatal(err)
	}

	installScript, err := filepath.Abs("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Missing cosign fails closed unless --insecure-skip-verify is given
	isolatedPathDir := t.TempDir() // empty directory as first PATH entry, without cosign
	cmdMissing := exec.Command("sh", installScript, "--local-binary", fakeBin, "--local-sig", fakeSig)
	cmdMissing.Env = []string{
		"PATH=" + isolatedPathDir + ":/bin:/usr/bin",
	}
	outMissing, errMissing := cmdMissing.CombinedOutput()
	if errMissing == nil {
		t.Fatalf("expected installer to fail closed when cosign is missing, got exit 0; output: %s", string(outMissing))
	}
	if !strings.Contains(string(outMissing), "cosign command not found") {
		t.Errorf("expected 'cosign command not found' in output, got: %s", string(outMissing))
	}

	// 2. Failing/tampered cosign on PATH: installer exits non-zero, nothing installed
	mockBinDir := t.TempDir()
	failingCosign := filepath.Join(mockBinDir, "cosign")
	if err := os.WriteFile(failingCosign, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	targetInstallRoot := t.TempDir()
	cmdFailing := exec.Command("sh", installScript, "--local-binary", fakeBin, "--local-sig", fakeSig)
	cmdFailing.Env = []string{
		"PATH=" + mockBinDir + ":/bin:/usr/bin",
		"BIN_DIR=" + filepath.Join(targetInstallRoot, "bin"),
	}
	outFailing, errFailing := cmdFailing.CombinedOutput()
	if errFailing == nil {
		t.Fatalf("expected installer to exit non-zero on signature verification failure, got exit 0; output: %s", string(outFailing))
	}
	if !strings.Contains(string(outFailing), "Cosign signature verification FAILED") {
		t.Errorf("expected verification failure error message, got: %s", string(outFailing))
	}

	// Assert nothing was installed to target
	installedBin := filepath.Join(targetInstallRoot, "bin", "kazeshini")
	if _, err := os.Stat(installedBin); !os.IsNotExist(err) {
		t.Errorf("binary was installed despite signature verification failure: %s", installedBin)
	}

	// 3. Passing cosign with valid verification: installer proceeds past verification
	passingCosign := filepath.Join(mockBinDir, "cosign")
	if err := os.WriteFile(passingCosign, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	// Run dry-run to verify it passes verification stage cleanly
	cmdPassing := exec.Command("sh", installScript, "--dry-run", "--local-binary", fakeBin, "--local-sig", fakeSig)
	cmdPassing.Env = []string{
		"PATH=" + mockBinDir + ":/bin:/usr/bin",
	}
	outPassing, errPassing := cmdPassing.CombinedOutput()
	if errPassing != nil {
		t.Fatalf("expected dry-run with valid cosign to succeed, got: %v; output: %s", errPassing, string(outPassing))
	}

	// 4. --insecure-skip-verify succeeds past verification even with missing cosign
	cmdSkip := exec.Command("sh", installScript, "--dry-run", "--insecure-skip-verify")
	cmdSkip.Env = []string{
		"PATH=" + isolatedPathDir + ":/bin:/usr/bin",
	}
	outSkip, errSkip := cmdSkip.CombinedOutput()
	if errSkip != nil {
		t.Fatalf("expected --insecure-skip-verify to succeed without cosign, got: %v; output: %s", errSkip, string(outSkip))
	}
}

