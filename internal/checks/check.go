// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package checks implements deterministic, read-only diagnostic checks
// returning standardized contract.CheckResult structures.
package checks

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
)

// Check is the interface implemented by all read-only inspection checks.
type Check interface {
	ID() string
	Role() string // legacy role alias
	Title() string
	Description() string
	Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error)
}

// ActivityEntry records execution history for checks.
type ActivityEntry struct {
	CheckID     string          `json:"check_id"`
	Role        string          `json:"role"`
	Domain      string          `json:"domain,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
	TokenHolder string          `json:"token_holder"` // "local-cli", "bearer-token", or client identity
	Status      contract.Status `json:"status"`
	Summary     string          `json:"summary"`
}

// Common error sentinels
var (
	ErrPermissionDenied = errors.New("permission denied")
	ErrNotApplicable    = errors.New("feature not applicable")
	ErrInvalidParam     = errors.New("invalid parameter")
)

// ValidateSafeParam rejects path traversal or shell injection sequences in check parameters.
func ValidateSafeParam(val string) bool {
	if val == "" {
		return true
	}
	// Reject path traversal
	if strings.Contains(val, "..") {
		return false
	}
	// Reject control characters and injection meta-characters
	for _, ch := range val {
		if ch < 32 || ch == 127 || ch == ';' || ch == '&' || ch == '|' || ch == '`' || ch == '$' || ch == '>' || ch == '<' || ch == '\n' || ch == '\r' {
			return false
		}
	}
	return true
}
