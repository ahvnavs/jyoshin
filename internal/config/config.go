// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package config defines the configuration structure, defaults, validation,
// and loading from environment variables and config files.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// OTelConfig defines optional OpenTelemetry metrics export configuration.
type OTelConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Endpoint string `json:"endpoint" yaml:"endpoint"`
	Protocol string `json:"protocol" yaml:"protocol"` // "grpc" or "http"
	Insecure bool   `json:"insecure" yaml:"insecure"`
}

// Config represents all runtime settings for Jyōshin.
type Config struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	AllowRemote  bool          `json:"allow_remote"`
	DataDir      string        `json:"data_dir"`
	RulesDir     string        `json:"rules_dir"`
	LogLevel     string        `json:"log_level"`
	LogFormat    string        `json:"log_format"`
	ScanInterval time.Duration `json:"scan_interval"`
	AuthRequired bool          `json:"auth_required"`
	OTel         OTelConfig    `json:"otel"`
}

// Default returns the default configuration.
// Principle 5: NO NETWORK EGRESS by default. Default host is strictly 127.0.0.1.
func Default() Config {
	return Config{
		Host:         "127.0.0.1",
		Port:         7777,
		AllowRemote:  false,
		DataDir:      "/var/lib/jyoshin",
		RulesDir:     "rules",
		LogLevel:     "info",
		LogFormat:    "text",
		ScanInterval: 60 * time.Second,
		AuthRequired: true,
	}
}

// Address returns the combined host:port string.
func (c Config) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Validate checks configuration invariants.
// Refuses non-loopback bindings unless AllowRemote is explicitly true.
func (c Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", c.Port)
	}

	ip := net.ParseIP(c.Host)
	if ip == nil && c.Host != "localhost" {
		return fmt.Errorf("invalid host %q: must be a valid IP address or 'localhost'", c.Host)
	}

	isLoopback := false
	if c.Host == "localhost" {
		isLoopback = true
	} else if ip != nil && ip.IsLoopback() {
		isLoopback = true
	}

	if !isLoopback && !c.AllowRemote {
		return fmt.Errorf("refusing to bind to non-loopback address %q without --allow-remote", c.Host)
	}

	if c.ScanInterval <= 0 {
		return errors.New("scan_interval must be greater than zero")
	}

	return nil
}

// Load merges defaults with an optional JSON config file and environment variables.
func Load(configPath string) (Config, error) {
	cfg := Default()

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return cfg, fmt.Errorf("failed to read config file %q: %w", configPath, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("failed to parse config file %q: %w", configPath, err)
		}
	}

	// Environment variable overrides
	if host := os.Getenv("JYOSHIN_HOST"); host != "" {
		cfg.Host = host
	}
	if portStr := os.Getenv("JYOSHIN_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			cfg.Port = p
		}
	}
	if allowRemoteStr := os.Getenv("JYOSHIN_ALLOW_REMOTE"); allowRemoteStr != "" {
		cfg.AllowRemote = strings.ToLower(allowRemoteStr) == "true" || allowRemoteStr == "1"
	}
	if dataDir := os.Getenv("JYOSHIN_DATA_DIR"); dataDir != "" {
		cfg.DataDir = dataDir
	}
	if rulesDir := os.Getenv("JYOSHIN_RULES_DIR"); rulesDir != "" {
		cfg.RulesDir = rulesDir
	}
	if logLevel := os.Getenv("JYOSHIN_LOG_LEVEL"); logLevel != "" {
		cfg.LogLevel = logLevel
	}
	if logFormat := os.Getenv("JYOSHIN_LOG_FORMAT"); logFormat != "" {
		cfg.LogFormat = logFormat
	}
	if intervalStr := os.Getenv("JYOSHIN_SCAN_INTERVAL"); intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			cfg.ScanInterval = d
		}
	}
	if authReqStr := os.Getenv("JYOSHIN_AUTH_REQUIRED"); authReqStr != "" {
		cfg.AuthRequired = strings.ToLower(authReqStr) == "true" || authReqStr == "1"
	}

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}
