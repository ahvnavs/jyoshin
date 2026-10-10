// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package data provides embedded static data assets such as EOL tables.
package data

import "embed"

//go:embed eol.yaml prices.yaml
var EOLData embed.FS
