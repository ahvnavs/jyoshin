// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package fuzz_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/OWNER/kazeshini/internal/checks"
	"github.com/OWNER/kazeshini/internal/desired"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/platform"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/software"
)

// FuzzRuleYAML verifies the YAML rule parser never panics on arbitrary malformed inputs.
func FuzzRuleYAML(f *testing.F) {
	seeds := []string{
		"id: RUL-001\ntitle: Test\nseverity: high\ncategory: hygiene\n",
		"id: [malformed\n",
		"some: {random: 123, invalid: [true, false]}\n",
		"",
		strings.Repeat("a: b\n", 100),
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var r rules.RuleDefinition
		_ = yaml.Unmarshal(data, &r)
		_ = r.Validate()
	})
}

// FuzzPackageDpkgStatus verifies dpkg status parser resilience against corrupted strings.
func FuzzPackageDpkgStatus(f *testing.F) {
	seeds := []string{
		"Package: bash\nStatus: install ok installed\nVersion: 5.1-6\n\n",
		"Package:\nStatus: corrupted\n",
		"\x00\xff\xfePackage: test\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		rfs := fs.NewRootedFS(tmpDir)

		dpkgDir := rfs.Path("/var/lib/dpkg")
		_ = os.MkdirAll(dpkgDir, 0755)
		_ = os.WriteFile(filepath.Join(dpkgDir, "status"), data, 0644)

		mgr := inventory.NewManager(rfs)
		_, _ = mgr.CollectInventory(t.Context())
	})
}

// FuzzDesiredYAML verifies desired state YAML parsing and linting never panics.
func FuzzDesiredYAML(f *testing.F) {
	seeds := []string{
		"apiVersion: v1\nmetadata:\n  name: prod\nspec:\n  packages:\n    required:\n      - name: nginx\n",
		"invalid: [unclosed\n",
		"spec: null\n",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var manifest desired.Manifest
		_ = yaml.Unmarshal(data, &manifest)
	})
}

// FuzzPlatformSignatures verifies platform signature catalog parser resilience.
func FuzzPlatformSignatures(f *testing.F) {
	seeds := []string{
		"platforms:\n  - id: test\n    name: Test\n    category: orchestration\n    support: detection\n    signatures:\n      binaries: [\"test\"]\n",
		"platforms: corrupted\n",
		"null\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var cat platform.Catalog
		_ = yaml.Unmarshal(data, &cat)
	})
}

// FuzzDryRunOutput verifies package manager simulation/dry-run parsers never panic.
func FuzzDryRunOutput(f *testing.F) {
	seeds := []string{
		"Inst nginx [1.18.0] (1.20.0 Ubuntu:22.04/jammy-updates [amd64])\nConf nginx (1.20.0 Ubuntu:22.04/jammy-updates [amd64])\n",
		"Remv apache2 [2.4.52]\n",
		"random non-matching output lines\x00with nulls\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = software.ParseAptSimOutput(string(data))
	})
}

// FuzzOIDCClaims verifies resilience of OIDC JSON claim decoding.
func FuzzOIDCClaims(f *testing.F) {
	seeds := []string{
		`{"sub":"usr-123","email":"admin@corp.internal","groups":["devops","admin"]}`,
		`{"sub":123,"groups":"invalid_type"}`,
		`{}`,
		`[1,2,3]`,
		`{"malformed":`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var claims map[string]any
		_ = json.Unmarshal(data, &claims)
	})
}

// FuzzSSHDConfig verifies OpenSSH configuration parsing never panics on arbitrary or corrupted inputs.
func FuzzSSHDConfig(f *testing.F) {
	seeds := []string{
		"PermitRootLogin yes\nPasswordAuthentication no\nPermitEmptyPasswords no\n",
		"PermitRootLogin prohibit-password\n",
		"# comment\n\x00\xff invalid utf-8\n",
		"Include /etc/ssh/sshd_config.d/*.conf\n",
		strings.Repeat("PermitRootLogin no\n", 50),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		rfs := fs.NewRootedFS(tmpDir)
		sshDir := rfs.Path("/etc/ssh")
		_ = os.MkdirAll(sshDir, 0755)
		_ = os.WriteFile(filepath.Join(sshDir, "sshd_config"), data, 0644)

		chk := &checks.SSHSettingsCheck{}
		_, _ = chk.Run(context.Background(), rfs, nil)
	})
}

// FuzzPasswdAndSudoers verifies passwd and sudoers parsing resilience.
func FuzzPasswdAndSudoers(f *testing.F) {
	seeds := []string{
		"root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User,,,:/home/user:/bin/bash\n",
		"%sudo ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) NOPASSWD: ALL\n",
		"\x00\x00corrupt:::000\n",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		rfs := fs.NewRootedFS(tmpDir)
		etcDir := rfs.Path("/etc")
		_ = os.MkdirAll(etcDir, 0755)
		_ = os.WriteFile(filepath.Join(etcDir, "passwd"), data, 0644)
		_ = os.WriteFile(filepath.Join(etcDir, "sudoers"), data, 0644)

		chk := &checks.UsersSudoCheck{}
		_, _ = chk.Run(context.Background(), rfs, nil)
	})
}

// FuzzResolvConf verifies /etc/resolv.conf parsing resilience.
func FuzzResolvConf(f *testing.F) {
	seeds := []string{
		"nameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch corp.internal\noptions edns0\n",
		"nameserver [::1]:53\n",
		"\x00nameserver invalid\n",
		strings.Repeat("nameserver 127.0.0.1\n", 100),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		rfs := fs.NewRootedFS(tmpDir)
		etcDir := rfs.Path("/etc")
		_ = os.MkdirAll(etcDir, 0755)
		_ = os.WriteFile(filepath.Join(etcDir, "resolv.conf"), data, 0644)

		chk := &checks.DNSConfigCheck{}
		_, _ = chk.Run(context.Background(), rfs, nil)
	})
}

