// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package software_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/software"
)

func TestValidatePackageName(t *testing.T) {
	valid := []string{
		"sudo",
		"libc6",
		"linux-image-6.8.0-40-generic",
		"python3.12",
		"libssl3",
		"openssh-server",
		"gcc-13-base",
		"pkg+test",
		"foo_bar",
		"a:b",
		"123pkg",
	}
	for _, name := range valid {
		if err := software.ValidatePackageName(name); err != nil {
			t.Errorf("expected valid package %q, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		"-s",
		"--option",
		"sudo;rm -rf /",
		"pkg|cat",
		"pkg&echo",
		"pkg$VAR",
		"pkg`whoami`",
		"../etc/passwd",
		"pkg/name",
		"pkg\\test",
		"pkg name",
		">outfile",
		"<infile",
	}
	for _, name := range invalid {
		if err := software.ValidatePackageName(name); err == nil {
			t.Errorf("expected invalid package %q to fail validation, but it passed", name)
		}
	}
}

func TestInventoryReader_Fixtures(t *testing.T) {
	tmpDir := t.TempDir()

	// Setup fake /var/lib/dpkg/status
	dpkgDir := filepath.Join(tmpDir, "var/lib/dpkg")
	if err := os.MkdirAll(dpkgDir, 0755); err != nil {
		t.Fatal(err)
	}

	statusContent := `Package: sudo
Status: install ok installed
Version: 1.9.17p2-1ubuntu3
Architecture: amd64
Section: admin
Depends: libc6 (>= 2.38), libpam0g
Description: Provide limited super user privileges to specific users

Package: libc6
Status: install ok installed
Version: 2.39-0ubuntu8.2
Architecture: amd64
Section: libs
Description: GNU C Library: Shared libraries

Package: held-pkg
Status: hold ok installed
Version: 1.0.0
Architecture: amd64
Section: utils
Description: Intentionally held package
`
	if err := os.WriteFile(filepath.Join(dpkgDir, "status"), []byte(statusContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Setup /var/lib/apt/lists
	listsDir := filepath.Join(tmpDir, "var/lib/apt/lists")
	if err := os.MkdirAll(listsDir, 0755); err != nil {
		t.Fatal(err)
	}

	securityPackages := `Package: sudo
Version: 1.9.17p2-1ubuntu3.2
Origin: Ubuntu
Architecture: amd64
Section: admin

Package: libc6
Version: 2.39-0ubuntu8.2
Origin: Ubuntu
Architecture: amd64
`
	secFile := filepath.Join(listsDir, "archive.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages")
	if err := os.WriteFile(secFile, []byte(securityPackages), 0644); err != nil {
		t.Fatal(err)
	}

	// Create preferences for pinned package
	prefDir := filepath.Join(tmpDir, "etc/apt/preferences.d")
	if err := os.MkdirAll(prefDir, 0755); err != nil {
		t.Fatal(err)
	}
	prefContent := `Package: sudo
Pin: release a=resolute-security
Pin-Priority: 900
`
	if err := os.WriteFile(filepath.Join(prefDir, "sudo-pin"), []byte(prefContent), 0644); err != nil {
		t.Fatal(err)
	}

	rfs := fs.NewRootedFS(tmpDir)
	reader := software.NewInventoryReader(rfs)

	nodes := []graph.Node{
		{
			ID:    "proc:1",
			Type:  graph.NodeProcess,
			Label: "sudo",
			Properties: map[string]any{
				"cmd": "/usr/bin/sudo",
			},
		},
		{
			ID:    "svc:1",
			Type:  graph.NodeService,
			Label: "sudo.service",
		},
	}

	inv := reader.Collect(nodes)
	if inv.TotalInstalled != 3 {
		t.Fatalf("expected 3 installed packages, got %d", inv.TotalInstalled)
	}

	// Sudo checks
	sudo := reader.LookupPackage("sudo", nodes)
	if sudo == nil {
		t.Fatal("package sudo not found in inventory")
	}
	if !sudo.IsUpgradable {
		t.Errorf("expected sudo to be upgradable")
	}
	if sudo.Candidate == nil || sudo.Candidate.Version != "1.9.17p2-1ubuntu3.2" {
		t.Errorf("expected candidate version 1.9.17p2-1ubuntu3.2, got %+v", sudo.Candidate)
	}
	if sudo.Candidate.UpgradeKind != software.UpgradeKindSecurity {
		t.Errorf("expected upgrade kind to be security, got %s", sudo.Candidate.UpgradeKind)
	}
	if !sudo.IsPinned {
		t.Errorf("expected sudo to be pinned via preferences")
	}
	if !sudo.Running.IsRunning {
		t.Errorf("expected sudo to be marked as running from nodes")
	}

	// Held pkg checks
	held := reader.LookupPackage("held-pkg", nodes)
	if held == nil {
		t.Fatal("package held-pkg not found in inventory")
	}
	if !held.IsHeld {
		t.Errorf("expected held-pkg to be held")
	}

	// Libc6 checks (reverse dependency of sudo)
	libc := reader.LookupPackage("libc6", nodes)
	if libc == nil {
		t.Fatal("package libc6 not found")
	}
	hasSudoRevDep := false
	for _, rd := range libc.ReverseDependents {
		if rd == "sudo" {
			hasSudoRevDep = true
			break
		}
	}
	if !hasSudoRevDep {
		t.Errorf("expected sudo to be reverse dependent of libc6, got %v", libc.ReverseDependents)
	}
}

func TestInventoryReader_StaleMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	dpkgDir := filepath.Join(tmpDir, "var/lib/dpkg")
	_ = os.MkdirAll(dpkgDir, 0755)
	_ = os.WriteFile(filepath.Join(dpkgDir, "status"), []byte("Package: bash\nStatus: install ok installed\nVersion: 5.0\n\n"), 0644)

	listsDir := filepath.Join(tmpDir, "var/lib/apt/lists")
	_ = os.MkdirAll(listsDir, 0755)

	pkgFile := filepath.Join(listsDir, "archive_Packages")
	_ = os.WriteFile(pkgFile, []byte("Package: bash\nVersion: 5.1\n\n"), 0644)

	// Set mtime to 10 days ago (stale)
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	_ = os.Chtimes(pkgFile, oldTime, oldTime)

	rfs := fs.NewRootedFS(tmpDir)
	reader := software.NewInventoryReader(rfs)

	inv := reader.Collect(nil)
	if !inv.Metadata.IsStale {
		t.Errorf("expected metadata to be marked stale (>7 days)")
	}
	if !inv.Metadata.RefreshNeeded {
		t.Errorf("expected refresh needed to be true")
	}
	if inv.Metadata.RefreshCmd != "sudo apt-get update" {
		t.Errorf("unexpected refresh command: %s", inv.Metadata.RefreshCmd)
	}
}

func TestAnalyzeSafety_ProtectedAndKernel(t *testing.T) {
	// 1. Removing protected package
	libc := &software.PackageEntry{
		Name:    "libc6",
		Version: "2.39",
	}
	safetyLibc := software.AnalyzeSafety(libc, software.DryRunRemove, nil, "")
	if !safetyLibc.Blocked {
		t.Errorf("expected removal of libc6 to be blocked")
	}
	foundProtected := false
	for _, f := range safetyLibc.Flags {
		if f.Code == "PROTECTED_PACKAGE_REMOVAL" {
			foundProtected = true
			break
		}
	}
	if !foundProtected {
		t.Errorf("expected PROTECTED_PACKAGE_REMOVAL flag for libc6")
	}

	// 2. Removing current running kernel
	kernel := &software.PackageEntry{
		Name:    "linux-image-6.8.0-40-generic",
		Version: "6.8.0-40.40",
	}
	safetyKernel := software.AnalyzeSafety(kernel, software.DryRunRemove, nil, "6.8.0-40-generic")
	if !safetyKernel.Blocked {
		t.Errorf("expected removal of running kernel to be blocked")
	}
	foundKernel := false
	for _, f := range safetyKernel.Flags {
		if f.Code == "KERNEL_IN_USE" {
			foundKernel = true
			break
		}
	}
	if !foundKernel {
		t.Errorf("expected KERNEL_IN_USE flag")
	}

	// 3. Upgrading a normal package with no issues
	curl := &software.PackageEntry{
		Name:         "curl",
		Version:      "8.5.0-2ubuntu10",
		IsUpgradable: true,
		Candidate: &software.CandidateInfo{
			Version:     "8.5.0-2ubuntu10.1",
			UpgradeKind: software.UpgradeKindSecurity,
		},
	}
	safetyCurl := software.AnalyzeSafety(curl, software.DryRunUpgrade, nil, "")
	if safetyCurl.Blocked || !safetyCurl.Safe {
		t.Errorf("expected curl upgrade to be safe, got %+v", safetyCurl)
	}
}

func TestPlanner_CreatePlan(t *testing.T) {
	tmpDir := t.TempDir()
	dpkgDir := filepath.Join(tmpDir, "var/lib/dpkg")
	_ = os.MkdirAll(dpkgDir, 0755)
	_ = os.WriteFile(filepath.Join(dpkgDir, "status"), []byte("Package: sudo\nStatus: install ok installed\nVersion: 1.9.17\n\n"), 0644)

	listsDir := filepath.Join(tmpDir, "var/lib/apt/lists")
	_ = os.MkdirAll(listsDir, 0755)
	_ = os.WriteFile(filepath.Join(listsDir, "test_Packages"), []byte("Package: sudo\nVersion: 1.9.18\n\n"), 0644)

	rfs := fs.NewRootedFS(tmpDir)
	reader := software.NewInventoryReader(rfs)
	planner := software.NewPlanner(reader, nil)

	ctx := context.Background()
	plan, err := planner.CreatePlan(ctx, "sudo", software.DryRunUpgrade, nil, "")
	if err != nil {
		t.Fatalf("unexpected error creating plan: %v", err)
	}
	if plan.PackageName != "sudo" {
		t.Errorf("expected package sudo, got %s", plan.PackageName)
	}
	if !strings.Contains(plan.EquivalentCommand, "apt-get install --only-upgrade") {
		t.Errorf("unexpected equivalent command: %s", plan.EquivalentCommand)
	}
}
