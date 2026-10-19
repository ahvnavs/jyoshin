// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package kzerror_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/OWNER/kazeshini/internal/kzerror"
)

// TestKZError_FormatAndContract verifies that every defined error implements the 3-part help contract.
func TestKZError_FormatAndContract(t *testing.T) {
	allErrors := []*kzerror.KZError{
		kzerror.ErrPlatformIncompatible,
		kzerror.ErrProcfsUnavailable,
		kzerror.ErrPermissionDenied,
		kzerror.ErrPortBindingFailed,
		kzerror.ErrManifestInvalid,
		kzerror.ErrInvalidParam,
		kzerror.ErrProbeBlocked,
		kzerror.ErrAuthFailed,
		kzerror.ErrRateLimited,
		kzerror.ErrRequestTooLarge,
	}

	for _, err := range allErrors {
		t.Run(err.Code, func(t *testing.T) {
			if !strings.HasPrefix(err.Code, "KZ-1") {
				t.Errorf("expected KZ-1xxx prefix, got %s", err.Code)
			}
			if err.What == "" {
				t.Errorf("error %s missing 'What'", err.Code)
			}
			if err.Why == "" {
				t.Errorf("error %s missing 'Why'", err.Code)
			}
			if err.WhatNext == "" {
				t.Errorf("error %s missing 'WhatNext'", err.Code)
			}

			formatted := err.FormatTerminal()
			if !strings.Contains(formatted, err.Code) || !strings.Contains(formatted, "Next step") {
				t.Errorf("terminal formatting missing required elements: %s", formatted)
			}
		})
	}

	// Test wrapping
	underlying := errors.New("underlying io failure")
	wrapped := kzerror.Wrap(kzerror.ErrPermissionDenied, underlying)
	if !errors.Is(wrapped, underlying) {
		t.Errorf("expected wrapped error to unwrap to underlying error")
	}
}

