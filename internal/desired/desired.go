// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package desired defines the schema, loading, validation, and selector matching
// for declarative desired state manifests (kazeshini.desired.yaml).
package desired

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest represents the top-level kazeshini.desired.yaml document.
type Manifest struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Kind       string         `yaml:"kind" json:"kind"`
	Metadata   ManifestMeta   `yaml:"metadata" json:"metadata"`
	Rules      []TargetRule   `yaml:"rules" json:"rules"`
}

type ManifestMeta struct {
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// TargetRule targets a set of hosts by label selector and specifies desired state constraints.
type TargetRule struct {
	Selector Selector     `yaml:"selector" json:"selector"`
	State    DesiredState `yaml:"state" json:"state"`
}

// Selector matches host labels. Empty selector matches all hosts.
type Selector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty" json:"matchLabels,omitempty"`
}

func (s Selector) Matches(hostLabels map[string]string) bool {
	if len(s.MatchLabels) == 0 {
		return true // Match all
	}
	if hostLabels == nil {
		return false
	}
	for k, v := range s.MatchLabels {
		if hostVal, ok := hostLabels[k]; !ok || hostVal != v {
			return false
		}
	}
	return true
}

// PackageExpectation declares package presence and version constraints.
type PackageExpectation struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"` // Semver or exact prefix
}

// ServiceExpectation declares systemd unit state.
type ServiceExpectation struct {
	Name    string `yaml:"name" json:"name"`
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	State   string `yaml:"state,omitempty" json:"state,omitempty"` // "active", "stopped"
}

// PortExpectation specifies allowed or forbidden network listening ports.
type PortExpectation struct {
	Port     int    `yaml:"port" json:"port"`
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"` // "tcp", "udp"
}

// PlatformExpectation specifies container or runtime versions.
type PlatformExpectation struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
}

// FileMetadataExpectation asserts permissions/owner without reading contents (Principle 2).
type FileMetadataExpectation struct {
	Path  string `yaml:"path" json:"path"`
	Owner string `yaml:"owner,omitempty" json:"owner,omitempty"`
	Group string `yaml:"group,omitempty" json:"group,omitempty"`
	Mode  string `yaml:"mode,omitempty" json:"mode,omitempty"` // e.g. "0644"
}

// DesiredState holds the declarative requirements for matched hosts.
type DesiredState struct {
	RequiredPackages   []PackageExpectation      `yaml:"requiredPackages,omitempty" json:"requiredPackages,omitempty"`
	ForbiddenPackages  []string                  `yaml:"forbiddenPackages,omitempty" json:"forbiddenPackages,omitempty"`
	RequiredServices   []ServiceExpectation      `yaml:"requiredServices,omitempty" json:"requiredServices,omitempty"`
	AllowedPorts       []PortExpectation         `yaml:"allowedPorts,omitempty" json:"allowedPorts,omitempty"`
	RequiredPlatforms  []PlatformExpectation     `yaml:"requiredPlatforms,omitempty" json:"requiredPlatforms,omitempty"`
	FilesMetadata      []FileMetadataExpectation `yaml:"filesMetadata,omitempty" json:"filesMetadata,omitempty"`
}

// LoadFile reads and validates a kazeshini.desired.yaml file or directory.
func LoadFile(path string) (*Manifest, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open desired state: %w", err)
	}

	targetPath := path
	if fi.IsDir() {
		candidate := filepath.Join(path, "kazeshini.desired.yaml")
		if _, err := os.Stat(candidate); err == nil {
			targetPath = candidate
		} else {
			candidateYml := filepath.Join(path, "kazeshini.desired.yml")
			if _, err := os.Stat(candidateYml); err == nil {
				targetPath = candidateYml
			} else {
				return nil, fmt.Errorf("no kazeshini.desired.yaml found in directory %q", path)
			}
		}
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read desired state %s: %w", targetPath, err)
	}

	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("yaml parse error in %s: %w", targetPath, err)
	}

	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("schema validation error: %w", err)
	}

	return &manifest, nil
}

// Validate checks manifest JSON/YAML schema conformance.
func (m *Manifest) Validate() error {
	if m.APIVersion == "" {
		return errors.New("apiVersion is required (expected 'kazeshini.io/v1')")
	}
	if m.Kind != "DesiredState" {
		return fmt.Errorf("invalid kind %q: expected 'DesiredState'", m.Kind)
	}
	if m.Metadata.Name == "" {
		return errors.New("metadata.name is required")
	}

	for i, r := range m.Rules {
		for _, pkg := range r.State.RequiredPackages {
			if strings.TrimSpace(pkg.Name) == "" {
				return fmt.Errorf("rule[%d]: requiredPackage name cannot be empty", i)
			}
		}
		for _, svc := range r.State.RequiredServices {
			if strings.TrimSpace(svc.Name) == "" {
				return fmt.Errorf("rule[%d]: requiredService name cannot be empty", i)
			}
		}
		for _, p := range r.State.AllowedPorts {
			if p.Port <= 0 || p.Port > 65535 {
				return fmt.Errorf("rule[%d]: port %d out of valid range (1-65535)", i, p.Port)
			}
		}
		for _, f := range r.State.FilesMetadata {
			if f.Path == "" || !strings.HasPrefix(f.Path, "/") {
				return fmt.Errorf("rule[%d]: file metadata path %q must be an absolute path", i, f.Path)
			}
		}
	}

	return nil
}

// ForHost merges all TargetRules matching the given host labels into a unified DesiredState.
func (m *Manifest) ForHost(hostLabels map[string]string) DesiredState {
	var merged DesiredState

	for _, rule := range m.Rules {
		if rule.Selector.Matches(hostLabels) {
			merged.RequiredPackages = append(merged.RequiredPackages, rule.State.RequiredPackages...)
			merged.ForbiddenPackages = append(merged.ForbiddenPackages, rule.State.ForbiddenPackages...)
			merged.RequiredServices = append(merged.RequiredServices, rule.State.RequiredServices...)
			merged.AllowedPorts = append(merged.AllowedPorts, rule.State.AllowedPorts...)
			merged.RequiredPlatforms = append(merged.RequiredPlatforms, rule.State.RequiredPlatforms...)
			merged.FilesMetadata = append(merged.FilesMetadata, rule.State.FilesMetadata...)
		}
	}

	return merged
}

// LoadHostLabels reads labels from a YAML or JSON labels file if provided,
// or returns default host labels.
func LoadHostLabels(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{"role": "server"}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	labels := make(map[string]string)
	if err := yaml.Unmarshal(data, &labels); err != nil {
		return nil, err
	}
	return labels, nil
}

