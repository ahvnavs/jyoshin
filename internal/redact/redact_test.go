// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"testing"

	"github.com/OWNER/kazeshini/internal/redact"
)

func TestRedact_SecretKeysAndPaths(t *testing.T) {
	sensitiveKeys := []string{
		"DB_PASSWORD",
		"api_key",
		"AUTH_TOKEN",
		"BEARER_TOKEN",
		"jwt_secret",
		"AWS_SECRET_ACCESS_KEY",
		"client_secret",
	}

	for _, k := range sensitiveKeys {
		if !redact.IsSecretKey(k) {
			t.Errorf("expected IsSecretKey == true for %s", k)
		}
	}

	safeKeys := []string{"PORT", "HOST", "NODE_ENV", "USER", "PATH", "APP_NAME"}
	for _, k := range safeKeys {
		if redact.IsSecretKey(k) {
			t.Errorf("expected IsSecretKey == false for %s", k)
		}
	}

	sensitivePaths := []string{
		"/etc/ssl/private/server.key",
		"/home/user/.ssh/id_rsa",
		"/root/.ssh/id_ed25519",
		"/etc/shadow",
		"/home/app/.aws/credentials",
	}
	for _, p := range sensitivePaths {
		if !redact.IsSecretPath(p) {
			t.Errorf("expected IsSecretPath == true for %s", p)
		}
	}
}

func TestRedact_TokensAndEnvMaps(t *testing.T) {
	env := map[string]string{
		"DATABASE_URL": "postgres://user:supersecret123@localhost:5432/db",
		"DB_PASSWORD":  "mypassword",
		"AWS_KEY":      "AKIAIOSFODNN7EXAMPLE",
		"PUBLIC_PORT":  "8080",
	}

	redacted := redact.RedactEnvMap(env)

	if redacted["DB_PASSWORD"] != redact.RedactedPlaceholder {
		t.Errorf("expected DB_PASSWORD to be redacted, got %s", redacted["DB_PASSWORD"])
	}
	if redacted["AWS_KEY"] != redact.RedactedPlaceholder {
		t.Errorf("expected AWS key pattern to be scrubbed, got %s", redacted["AWS_KEY"])
	}
	if redacted["PUBLIC_PORT"] != "8080" {
		t.Errorf("expected PUBLIC_PORT to remain unchanged, got %s", redacted["PUBLIC_PORT"])
	}
}

func TestRedact_Properties(t *testing.T) {
	props := map[string]any{
		"token":   "4bed8b001721fda34e2294c259bcc33ab8e939fea9aaa0cfb909be37b846b2e8",
		"service": "postgres",
		"nested": map[string]string{
			"api_secret": "xyz123",
			"host":       "127.0.0.1",
		},
	}

	res := redact.RedactProperties(props)
	if res["token"] != redact.RedactedPlaceholder {
		t.Errorf("expected token to be [REDACTED], got %v", res["token"])
	}
	nested, ok := res["nested"].(map[string]string)
	if !ok || nested["api_secret"] != redact.RedactedPlaceholder {
		t.Errorf("expected nested api_secret to be [REDACTED]")
	}
	if nested["host"] != "127.0.0.1" {
		t.Errorf("expected host to be preserved, got %s", nested["host"])
	}
}
