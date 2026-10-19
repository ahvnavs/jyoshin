// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Allowed outbound egress points documented in docs/NETWORK_EGRESS.md:
// 1. Connectivity probe (explicit user-clicked target in web UI or checks)
// 2. Opt-in manual update check (kazeshini update --check --url <url>)
// 3. Configured OpenTelemetry exporter (if otel.enabled=true in config)
// 4. Container engine socket query (/var/run/docker.sock via unix socket HTTP transport)
// Zero unsolicited telemetry, phone-homes, or analytics are permitted.

func TestSecurity_ZeroUnsolicitedNetworkEgress(t *testing.T) {
	root := "../.."
	fset := token.NewFileSet()

	forbiddenCalls := map[string]bool{
		"http.Get":  true,
		"http.Post": true,
		"http.Head": true,
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip actuator or experimental if in separate directory
		if strings.Contains(path, "vendor") || strings.Contains(path, ".git") {
			return nil
		}

		node, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}

		// Inspect all files importing net/http
		importsNetHTTP := false
		for _, imp := range node.Imports {
			if imp.Path.Value == `"net/http"` {
				importsNetHTTP = true
				break
			}
		}

		if !importsNetHTTP {
			return nil
		}

		// Full parse to inspect calls
		fullNode, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		ast.Inspect(fullNode, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			callName := ident.Name + "." + sel.Sel.Name
			if forbiddenCalls[callName] {
				t.Errorf("FORBIDDEN DEFAULT HTTP CALL DETECTED: %s in %s (must use controlled, bounded context with zero telemetry)", callName, path)
			}
			return true
		})

		return nil
	})

	if err != nil {
		t.Fatalf("failed scanning source tree: %v", err)
	}
}

