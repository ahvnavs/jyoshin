// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package logging provides structured slog logger initialization adhering to
// Jyōshin's deterministic, blame-free, and machine-first principles.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Config configures structured logging output.
type Config struct {
	Level  string
	Format string // "json" or "text"
}

// Setup initializes the global slog default logger according to configuration.
func Setup(cfg Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	var out io.Writer = os.Stderr

	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(out, opts)
	} else {
		handler = slog.NewTextHandler(out, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}
