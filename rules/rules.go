// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules embedded rules fs wrapper
package rules

import "embed"

//go:embed *.yaml
var EmbeddedRules embed.FS

