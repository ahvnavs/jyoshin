// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package web provides embedded static assets for the Kazeshini local web UI.
package web

import "embed"

//go:embed index.html css/* js/*
var Assets embed.FS
