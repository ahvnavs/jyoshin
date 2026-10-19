// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package kzerror standardizes user-facing errors into structured, human-readable help.
// Adheres strictly to Principle 12 ("Human-First") and Phase 39 Error-As-Help specs:
// Every error must provide a stable KZ-1xxx code, What happened, Why, and What to do next.
package kzerror

import (
	"fmt"
)

// KZError represents a structured, actionable user-facing error.
type KZError struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	What        string `json:"what"`
	Why         string `json:"why"`
	WhatNext    string `json:"what_next"`
	InternalErr error  `json:"-"`
}

func (e *KZError) Error() string {
	return fmt.Sprintf("[%s] %s: %s\nWhy: %s\nNext step: %s",
		e.Code, e.Title, e.What, e.Why, e.WhatNext)
}

func (e *KZError) Unwrap() error {
	return e.InternalErr
}

// FormatTerminal renders a friendly box or formatted text for the terminal.
func (e *KZError) FormatTerminal() string {
	return fmt.Sprintf("\n\033[1;31m[ERROR %s]\033[0m \033[1m%s\033[0m\n  What happened: %s\n  Why:           %s\n  \033[1;32mNext step:\033[0m      %s\n",
		e.Code, e.Title, e.What, e.Why, e.WhatNext)
}

// Standard errors
var (
	ErrPlatformIncompatible = &KZError{
		Code:     "KZ-1001",
		Title:    "Platform Incompatible",
		What:     "Operating system is not Linux.",
		Why:      "Kazeshini inspects Linux procfs and sysfs directly to establish ground truth.",
		WhatNext: "Run Kazeshini on a Linux server running kernel 3.10 or newer.",
	}

	ErrProcfsUnavailable = &KZError{
		Code:     "KZ-1002",
		Title:    "Procfs Unavailable",
		What:     "The /proc filesystem was not found on this machine.",
		Why:      "The procfs mount is absent, or running in an unmounted minimal container.",
		WhatNext: "Mount procfs ('mount -t proc proc /proc') or start the container with '/proc' mounted.",
	}

	ErrPermissionDenied = &KZError{
		Code:     "KZ-1003",
		Title:    "Permission Denied",
		What:     "Cannot read protected system database or socket table.",
		Why:      "Current unprivileged user account lacks read permissions for this resource.",
		WhatNext: "Run 'sudo kazeshini' for full root visibility, or continue with degraded partial visibility.",
	}

	ErrPortBindingFailed = &KZError{
		Code:     "KZ-1004",
		Title:    "Port Binding Failed",
		What:     "Cannot bind local HTTP server to the requested port.",
		Why:      "The port is already held by another application on 127.0.0.1.",
		WhatNext: "Run 'kazeshini serve --port <free-port>' or use default port auto-allocation 'kazeshini open'.",
	}

	ErrManifestInvalid = &KZError{
		Code:     "KZ-1005",
		Title:    "Manifest Invalid",
		What:     "Desired state manifest could not be parsed.",
		Why:      "Syntax error or schema violation in YAML specification file.",
		WhatNext: "Run 'kazeshini desired lint <file>' to view the exact validation errors.",
	}

	ErrInvalidParam = &KZError{
		Code:     "KZ-1006",
		Title:    "Invalid Parameter",
		What:     "Command parameter rejected by security safety guard.",
		Why:      "Parameter contains forbidden characters (;, |, &, .., or shell metacharacters).",
		WhatNext: "Use plain alphanumeric names without shell syntax or path traversal.",
	}

	ErrProbeBlocked = &KZError{
		Code:     "KZ-1007",
		Title:    "Network Probe Blocked",
		What:     "Outbound probe dial was blocked by security policy.",
		Why:      "Destination IP is a forbidden target (cloud metadata 169.254.169.254, loopback, or link-local).",
		WhatNext: "Probes are only permitted to explicit, user-specified public or corporate gateway targets.",
	}

	ErrAuthFailed = &KZError{
		Code:     "KZ-1008",
		Title:    "Authentication Failure",
		What:     "Missing or invalid API access token.",
		Why:      "Bearer token provided in header does not match active session or token store.",
		WhatNext: "Run 'kazeshini token' to display the valid local authentication token.",
	}

	ErrRateLimited = &KZError{
		Code:     "KZ-1009",
		Title:    "Rate Limited",
		What:     "Too many failed requests from client IP.",
		Why:      "Brute-force protection temporarily locked the connecting IP address.",
		WhatNext: "Wait for the lockout period (60 seconds) to expire before retrying.",
	}

	ErrRequestTooLarge = &KZError{
		Code:     "KZ-1010",
		Title:    "Request Entity Too Large",
		What:     "Request body exceeds memory safety limits.",
		Why:      "Request payload sent to endpoint exceeded the 2 MB security threshold.",
		WhatNext: "Ensure uploaded configuration or log payloads are smaller than 2 MB.",
	}
)

// Error codes
const (
	CodePlatformIncompatible = "KZ-1001"
	CodeProcfsUnavailable    = "KZ-1002"
	CodePermissionDenied     = "KZ-1003"
	CodePortBindingFailed    = "KZ-1004"
	CodeManifestInvalid      = "KZ-1005"
	CodeInvalidParam         = "KZ-1006"
	CodeProbeBlocked         = "KZ-1007"
	CodeAuthFailed           = "KZ-1008"
	CodeRateLimited          = "KZ-1009"
	CodeRequestTooLarge      = "KZ-1010"
	CodeInvalidConfig        = "KZ-1011"
	CodeSensorTimeout        = "KZ-1012"
)

// New constructs a structured user-facing KZError.
func New(code, what, why, whatNext string) *KZError {
	title := "System Error"
	switch code {
	case CodePlatformIncompatible:
		title = "Platform Incompatible"
	case CodeProcfsUnavailable:
		title = "Procfs Unavailable"
	case CodePermissionDenied:
		title = "Permission Denied"
	case CodePortBindingFailed:
		title = "Port Binding Failed"
	case CodeManifestInvalid:
		title = "Manifest Invalid"
	case CodeInvalidParam:
		title = "Invalid Parameter"
	case CodeProbeBlocked:
		title = "Network Probe Blocked"
	case CodeAuthFailed:
		title = "Authentication Failure"
	case CodeRateLimited:
		title = "Rate Limited"
	case CodeRequestTooLarge:
		title = "Request Too Large"
	case CodeInvalidConfig:
		title = "Invalid Configuration or Target"
	case CodeSensorTimeout:
		title = "Sensor Operation Timeout"
	}
	return &KZError{
		Code:     code,
		Title:    title,
		What:     what,
		Why:      why,
		WhatNext: whatNext,
	}
}

// Wrap returns a structured KZError wrapping an underlying error.
func Wrap(base *KZError, internal error) *KZError {
	if base == nil {
		return &KZError{
			Code:        "KZ-1999",
			Title:       "Unexpected System Error",
			What:        "An unexpected error occurred during execution.",
			Why:         "Underlying system operation failed.",
			WhatNext:    "Run 'kazeshini doctor' to verify host visibility.",
			InternalErr: internal,
		}
	}
	clone := *base
	clone.InternalErr = internal
	return &clone
}
