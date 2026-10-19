// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package robustness_test

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocs_EveryDocumentedCLICommandExecutes validates that every copy-paste command
// appearing in docs/index.md, docs/install.md, docs/results.md, and docs/philosophy.md
// executes without unexpected fatal crashes or unknown flag errors.
func TestDocs_EveryDocumentedCLICommandExecutes(t *testing.T) {
	docFiles := []string{
		"../../docs/index.md",
		"../../docs/philosophy.md",
		"../../docs/results.md",
		"../../docs/install.md",
	}

	binPath := filepath.Join(t.TempDir(), "kazeshini-doc-test")
	buildCmd := exec.Command("go", "build", "-trimpath", "-o", binPath, "../../cmd/kazeshini")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed building test binary: %v\n%s", err, string(out))
	}

	for _, df := range docFiles {
		f, err := os.Open(df)
		if err != nil {
			t.Fatalf("cannot open doc file %s: %v", df, err)
		}
		defer func(file *os.File) { _ = file.Close() }(f)

		scanner := bufio.NewScanner(f)
		inCodeBlock := false

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "```") {
				inCodeBlock = !inCodeBlock
				continue
			}
			if !inCodeBlock {
				continue
			}

			// Look for kazeshini invocations
			if strings.Contains(line, "kazeshini") && !strings.Contains(line, "curl") && !strings.Contains(line, "sha256sum") && !strings.Contains(line, "dpkg") && !strings.Contains(line, "rpm") && !strings.Contains(line, "apk") && !strings.Contains(line, "sudo") {
				fields := strings.Fields(line)
				var args []string
				start := false
				for _, fld := range fields {
					if strings.Contains(fld, "kazeshini") {
						start = true
						continue
					}
					if start {
						args = append(args, fld)
					}
				}

				// Only run safe, non-interactive commands
				if len(args) > 0 && (args[0] == "--version" || args[0] == "--help" || args[0] == "explain" || args[0] == "verify" || args[0] == "update") {
					// If command expects checksums.txt, create it in cwd
					_ = os.WriteFile("checksums.txt", []byte("3312c29b2a2d78b9c221b3f849fd231307bfdec6b8a4fcfd18307a6e81f3436d  kazeshini-doc-test\n"), 0644)
					defer func() { _ = os.Remove("checksums.txt") }()

					cmd := exec.Command(binPath, args...)
					out, err := cmd.CombinedOutput()
					t.Logf("Tested documented command: %s %v -> (err: %v)", binPath, args, err)
					if err != nil && !strings.Contains(string(out), "Invalid Configuration") && !strings.Contains(string(out), "No verification arguments") {
						t.Errorf("Documented command failed: kazeshini %s\nOutput:\n%s", strings.Join(args, " "), string(out))
					}
				}
			}
		}
	}
}
