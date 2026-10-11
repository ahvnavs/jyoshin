// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/fs"
)

func TestInventory_DpkgParsing(t *testing.T) {
	root := t.TempDir()

	dpkgStatus := `Package: bash
Status: install ok installed
Priority: required
Architecture: amd64
Version: 5.2.21-2ubuntu4

Package: curl
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 8.5.0-2ubuntu10

Package: removed-pkg
Status: deinstall ok config-files
Priority: optional
Architecture: amd64
Version: 1.0.0
`
	fullPath := filepath.Join(root, "var/lib/dpkg/status")
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(dpkgStatus), 0644); err != nil {
		t.Fatal(err)
	}

	rfs := fs.NewRootedFS(root)
	mgr := NewManager(rfs)

	pkgs, err := mgr.readDpkgStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 installed packages (excluding removed-pkg), got %d", len(pkgs))
	}
	if pkgs[0].Name != "bash" || pkgs[0].Version != "5.2.21-2ubuntu4" {
		t.Errorf("pkg[0] mismatch: %+v", pkgs[0])
	}
	if pkgs[1].Name != "curl" || pkgs[1].Version != "8.5.0-2ubuntu10" {
		t.Errorf("pkg[1] mismatch: %+v", pkgs[1])
	}
}

func TestInventory_PacmanParsing(t *testing.T) {
	root := t.TempDir()

	pacmanDesc := `%NAME%
nginx

%VERSION%
1.26.1-1

%ARCH%
x86_64
`
	descPath := filepath.Join(root, "var/lib/pacman/local/nginx-1.26.1-1/desc")
	if err := os.MkdirAll(filepath.Dir(descPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descPath, []byte(pacmanDesc), 0644); err != nil {
		t.Fatal(err)
	}

	rfs := fs.NewRootedFS(root)
	mgr := NewManager(rfs)

	pkgs, err := mgr.readPacmanLocal()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "nginx" || pkgs[0].Version != "1.26.1-1" || pkgs[0].Manager != "pacman" {
		t.Errorf("pacman pkg mismatch: %+v", pkgs[0])
	}
}

func TestInventory_ApkParsing(t *testing.T) {
	root := t.TempDir()

	apkInstalled := `C:Q1abc
P:busybox
V:1.36.1-r15
A:x86_64

C:Q1def
P:ssl_client
V:1.36.1-r15
A:x86_64
`
	installedPath := filepath.Join(root, "lib/apk/db/installed")
	if err := os.MkdirAll(filepath.Dir(installedPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installedPath, []byte(apkInstalled), 0644); err != nil {
		t.Fatal(err)
	}

	rfs := fs.NewRootedFS(root)
	mgr := NewManager(rfs)

	pkgs, err := mgr.readApkInstalled()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "busybox" || pkgs[0].Manager != "apk" {
		t.Errorf("apk pkg[0] mismatch: %+v", pkgs[0])
	}
}

func TestInventory_OwnershipIndex(t *testing.T) {
	root := t.TempDir()

	listContent := `/usr/bin/python3
/usr/bin/pydoc3
`
	listPath := filepath.Join(root, "var/lib/dpkg/info/python3-minimal:amd64.list")
	if err := os.MkdirAll(filepath.Dir(listPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, []byte(listContent), 0644); err != nil {
		t.Fatal(err)
	}

	rfs := fs.NewRootedFS(root)
	mgr := NewManager(rfs)

	owner, ev, ok := mgr.FindPackageOwner("/usr/bin/python3")
	if !ok {
		t.Fatal("expected to find package owner for /usr/bin/python3")
	}
	if owner != "python3-minimal" {
		t.Fatalf("expected owner python3-minimal, got %s", owner)
	}
	if ev.Certainty != "OBSERVED" {
		t.Fatalf("expected certainty OBSERVED, got %s", ev.Certainty)
	}

	// Test caching
	ownerCached, _, ok := mgr.FindPackageOwner("/usr/bin/python3")
	if !ok || ownerCached != "python3-minimal" {
		t.Fatalf("cache lookup failed")
	}
}

func TestInventory_CollectInventory(t *testing.T) {
	root := t.TempDir()
	rfs := fs.NewRootedFS(root)
	mgr := NewManager(rfs)

	inv, err := mgr.CollectInventory(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv.Summary.SystemPackages != 0 {
		t.Fatalf("expected 0 packages in empty root, got %d", inv.Summary.SystemPackages)
	}
}
