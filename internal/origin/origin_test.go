// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package origin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/inventory"
)

func TestOriginResolver(t *testing.T) {
	root := t.TempDir()

	mustWrite := func(relPath, content string) {
		full := filepath.Join(root, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Package-owned binary
	mustWrite("/var/lib/dpkg/info/coreutils.list", "/bin/ls\n/bin/cat\n")
	mustWrite("/bin/ls", "ELF dummy")

	// 2. Ecosystem binary (cargo)
	mustWrite("/root/.cargo/bin/ripgrep", "ELF dummy")

	// 3. Manual drop (/usr/local/bin)
	mustWrite("/usr/local/bin/custom-server", "ELF dummy")

	// 4. Temp drop (/tmp)
	mustWrite("/tmp/miner-exploit", "ELF dummy")

	rfs := fs.NewRootedFS(root)
	inv := inventory.NewManager(rfs)
	resolver := NewResolver(rfs, inv)

	ctx := context.Background()

	// Test 1: Package owned
	o1 := resolver.Resolve(ctx, "/bin/ls")
	if o1.Kind != KindPackage || o1.Source != "coreutils" || o1.Certainty != graph.CertaintyObserved {
		t.Errorf("o1 mismatch: %+v", o1)
	}

	// Test 2: Ecosystem
	o2 := resolver.Resolve(ctx, "/root/.cargo/bin/ripgrep")
	if o2.Kind != KindEcosystem || o2.Source != "cargo" {
		t.Errorf("o2 mismatch: %+v", o2)
	}

	// Test 3: Manual drop
	o3 := resolver.Resolve(ctx, "/usr/local/bin/custom-server")
	if o3.Kind != KindManual || o3.Certainty != graph.CertaintyInferred || o3.Confidence <= 0 {
		t.Errorf("o3 mismatch: %+v", o3)
	}

	// Test 4: Temp drop
	o4 := resolver.Resolve(ctx, "/tmp/miner-exploit")
	if o4.Kind != KindManual || o4.Source != "temporary_directory_drop" {
		t.Errorf("o4 mismatch: %+v", o4)
	}

	// Test 5: Non-existent file
	o5 := resolver.Resolve(ctx, "/opt/missing")
	if o5.Kind != KindUnknown || o5.Source != "file_not_found" {
		t.Errorf("o5 mismatch: %+v", o5)
	}

	// Test 6: Merged-/usr resolution (/usr/bin/bash owned in dpkg list, queried as /bin/bash)
	mustWrite("/var/lib/dpkg/info/bash.list", "/usr/bin/bash\n/etc/bash.bashrc\n")
	mustWrite("/usr/bin/bash", "ELF dummy")
	mustWrite("/bin/bash", "ELF dummy")

	o6 := resolver.Resolve(ctx, "/bin/bash")
	if o6.Kind != KindPackage || o6.Source != "bash" {
		t.Errorf("expected /bin/bash to resolve to package bash, got: %+v", o6)
	}

	// Test 7: Symlink resolution (/bin/sh -> /usr/bin/bash)
	_ = os.Symlink(filepath.Join(root, "usr/bin/bash"), filepath.Join(root, "bin/sh"))
	o7 := resolver.Resolve(ctx, "/bin/sh")
	if o7.Kind != KindPackage || o7.Source != "bash" {
		t.Errorf("expected symlink /bin/sh to resolve to package bash, got: %+v", o7)
	}
}
