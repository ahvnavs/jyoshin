// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package fuzz_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/inventory"
	"github.com/OWNER/jyoshin/internal/rules"
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
