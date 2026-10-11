// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfig_Default(t *testing.T) {
	cfg := Default()
	if cfg.Host != "127.0.0.1" {
		t.Fatalf("expected host 127.0.0.1, got %s", cfg.Host)
	}
	if cfg.Port != 7777 {
		t.Fatalf("expected port 7777, got %d", cfg.Port)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config validation failed: %v", err)
	}
}

func TestConfig_LoopbackRefusal(t *testing.T) {
	tests := []struct {
		host        string
		allowRemote bool
		wantErr     bool
	}{
		{"127.0.0.1", false, false},
		{"localhost", false, false},
		{"::1", false, false},
		{"0.0.0.0", false, true},
		{"0.0.0.0", true, false},
		{"192.168.1.50", false, true},
		{"192.168.1.50", true, false},
	}

	for _, tt := range tests {
		cfg := Default()
		cfg.Host = tt.host
		cfg.AllowRemote = tt.allowRemote

		err := cfg.Validate()
		if tt.wantErr && err == nil {
			t.Fatalf("expected validation error for host %s with allowRemote=%v, got nil", tt.host, tt.allowRemote)
		}
		if !tt.wantErr && err != nil {
			t.Fatalf("unexpected validation error for host %s with allowRemote=%v: %v", tt.host, tt.allowRemote, err)
		}
	}
}

func TestConfig_LoadFileAndEnv(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(`{"port": 8888, "log_level": "debug"}`), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	t.Setenv("KAZESHINI_PORT", "9999")
	t.Setenv("KAZESHINI_SCAN_INTERVAL", "30s")

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Port != 9999 { // env overrides file
		t.Fatalf("expected port 9999, got %d", cfg.Port)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected log level debug from file, got %s", cfg.LogLevel)
	}
	if cfg.ScanInterval != 30*time.Second {
		t.Fatalf("expected scan interval 30s, got %v", cfg.ScanInterval)
	}
}
