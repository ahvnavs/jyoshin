// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package redact ensures no secret values (passwords, tokens, keys, env var values)
// ever leak to reports, API outputs, or logs.
package redact

import (
	"regexp"
)

var (
	// Suspicious environment variable or parameter keys
	secretKeyRegex = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_?key|auth|bearer|private_?key|credential|cert|salt|secret_access_key)`)

	// Sensitive file path patterns
	secretPathRegex = regexp.MustCompile(`(?i)(\.pem|\.key|id_rsa|id_ed25519|\.p12|\.pfx|shadow|credentials|\.netrc|\.aws/credentials)$`)

	// High entropy / token patterns (e.g. AWS keys, JWTs, standard bearer hex tokens)
	jwtRegex    = regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`)
	awsKeyRegex = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	hex32Regex  = regexp.MustCompile(`\b[0-9a-fA-F]{32,64}\b`)
)

const RedactedPlaceholder = "[REDACTED]"

// IsSecretKey checks if a configuration key or environment variable name implies sensitive contents.
func IsSecretKey(key string) bool {
	return secretKeyRegex.MatchString(key)
}

// IsSecretPath checks if a file path targets private cryptographic or auth data.
func IsSecretPath(path string) bool {
	return secretPathRegex.MatchString(path)
}

// RedactString scrubs identifiable tokens, keys, and credentials from an arbitrary string.
func RedactString(input string) string {
	if input == "" {
		return ""
	}

	out := jwtRegex.ReplaceAllString(input, RedactedPlaceholder)
	out = awsKeyRegex.ReplaceAllString(out, RedactedPlaceholder)
	out = hex32Regex.ReplaceAllString(out, RedactedPlaceholder)
	return out
}

// RedactEnvMap scrubs maps of environment variables or properties:
// Secret keys have their values completely replaced by [REDACTED].
// Non-secret keys have their text inspected for token patterns.
func RedactEnvMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		if IsSecretKey(k) {
			result[k] = RedactedPlaceholder
		} else {
			result[k] = RedactString(v)
		}
	}
	return result
}

// RedactProperties scrubs generic property maps while preserving structural metadata.
func RedactProperties(props map[string]any) map[string]any {
	if props == nil {
		return nil
	}
	result := make(map[string]any, len(props))
	for k, v := range props {
		if IsSecretKey(k) {
			result[k] = RedactedPlaceholder
			continue
		}

		switch val := v.(type) {
		case string:
			result[k] = RedactString(val)
		case map[string]string:
			result[k] = RedactEnvMap(val)
		case map[string]any:
			result[k] = RedactProperties(val)
		case []string:
			redactedSlice := make([]string, len(val))
			for i, s := range val {
				redactedSlice[i] = RedactString(s)
			}
			result[k] = redactedSlice
		default:
			result[k] = v
		}
	}
	return result
}
