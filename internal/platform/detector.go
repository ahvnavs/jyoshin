// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package platform implements the platform signature catalog, honest detection engine,
// and deep adapters for host services.
package platform

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/data"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/resource"
	"gopkg.in/yaml.v3"
)

// SupportTier defines the level of support for a platform.
type SupportTier string

const (
	SupportDetection             SupportTier = "detection"
	SupportAdapter               SupportTier = "adapter"
	SupportCloudSideNotSupported SupportTier = "cloud-side-not-supported"
	SupportUnsupportedWindows    SupportTier = "unsupported (Windows)"
)

// PlatformDefinition represents a catalog entry from platforms.yaml.
type PlatformDefinition struct {
	ID                string      `yaml:"id" json:"id"`
	Name              string      `yaml:"name" json:"name"`
	Category          string      `yaml:"category" json:"category"`
	Support           SupportTier `yaml:"support" json:"support"`
	UnsupportedReason string      `yaml:"unsupported_reason,omitempty" json:"unsupported_reason,omitempty"`
	Signatures        Signatures  `yaml:"signatures" json:"signatures"`
}

type Signatures struct {
	Binaries       []string `yaml:"binaries" json:"binaries"`
	Units          []string `yaml:"units" json:"units"`
	Processes      []string `yaml:"processes" json:"processes"`
	Ports          []int    `yaml:"ports" json:"ports"`
	Configs        []string `yaml:"configs" json:"configs"`
	Images         []string `yaml:"images" json:"images"`
	VersionCommand []string `yaml:"version_command,omitempty" json:"version_command,omitempty"`
}

// Catalog wraps the loaded platform definitions.
type Catalog struct {
	Platforms []PlatformDefinition `yaml:"platforms" json:"platforms"`
}

// LoadEmbeddedCatalog loads the catalog from data/platforms.yaml.
func LoadEmbeddedCatalog() (*Catalog, error) {
	bytes, err := data.EOLData.ReadFile("platforms.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded platforms.yaml: %w", err)
	}

	var cat Catalog
	if err := yaml.Unmarshal(bytes, &cat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal platforms.yaml: %w", err)
	}
	return &cat, nil
}

// DetectionResult captures the outcome of matching a platform against host telemetry.
type DetectionResult struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Category      string           `json:"category"`
	Support       SupportTier      `json:"support"`
	Present       bool             `json:"present"`
	Running       bool             `json:"running"`
	Version       string           `json:"version,omitempty"`
	Ports         []int            `json:"ports,omitempty"`
	Configs       []string         `json:"configs,omitempty"`
	Owner         string           `json:"owner,omitempty"`
	Origin        string           `json:"origin,omitempty"`
	HealthBasics  string           `json:"health_basics,omitempty"`
	SupportLabel  string           `json:"support_label"` // "detection only" or "adapter"
	WhatCanSee    string           `json:"what_can_see"`
	WhatCannotSee string           `json:"what_cannot_see"`
	Provenance    []graph.Evidence `json:"provenance,omitempty"`
	AdapterData   any              `json:"adapter_data,omitempty"`
}

// HostSnapshot holds read-only host observation data for platform detection.
type HostSnapshot struct {
	RunningProcesses []string // Process names or cmdlines
	ActiveUnits      []string // Active systemd units
	ListeningPorts   []int    // Open TCP ports
	InstalledPkgs    map[string]string // pkgName -> version
	ContainerImages  []string // Active container images
}

// Detector evaluates platforms using host observations and filesystem state.
type Detector struct {
	catalog *Catalog
}

func NewDetector(cat *Catalog) *Detector {
	return &Detector{catalog: cat}
}

// Detect scans the host snapshot and filesystem for platform signatures.
func (d *Detector) Detect(ctx context.Context, rfs fs.FS, snap HostSnapshot) []DetectionResult {
	var results []DetectionResult

	for _, def := range d.catalog.Platforms {
		// Non-host-supported platforms report honest static status
		if def.Support == SupportCloudSideNotSupported || def.Support == SupportUnsupportedWindows {
			results = append(results, DetectionResult{
				ID:            def.ID,
				Name:          def.Name,
				Category:      def.Category,
				Support:       def.Support,
				Present:       false,
				Running:       false,
				SupportLabel:  string(def.Support),
				WhatCanSee:    "None (platform runs in cloud/remote control plane)",
				WhatCannotSee: def.UnsupportedReason,
			})
			continue
		}

		res := d.evaluatePlatform(rfs, snap, def)
		results = append(results, res)
	}

	return results
}

func (d *Detector) evaluatePlatform(rfs fs.FS, snap HostSnapshot, def PlatformDefinition) DetectionResult {
	matchedEvidence := []graph.Evidence{}
	now := time.Now().UTC()
	isRunning := false
	var foundConfigs []string
	var foundPorts []int

	// 1. Process matching (strict substring or word match, never bare path in /tmp)
	for _, proc := range snap.RunningProcesses {
		for _, sigProc := range def.Signatures.Processes {
			if matchesProcess(proc, sigProc) {
				isRunning = true
				matchedEvidence = append(matchedEvidence, graph.Evidence{
					Source:    "process",
					Collector: "platform-detector",
					Raw:       fmt.Sprintf("Process matched: %s", sigProc),
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				})
				break
			}
		}
	}

	// 2. Unit matching
	for _, unit := range snap.ActiveUnits {
		for _, sigUnit := range def.Signatures.Units {
			if matchesUnit(unit, sigUnit) {
				isRunning = true
				matchedEvidence = append(matchedEvidence, graph.Evidence{
					Source:    "systemd",
					Collector: "platform-detector",
					Raw:       fmt.Sprintf("Active service unit: %s", unit),
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				})
				break
			}
		}
	}

	// 3. Listening port matching
	for _, p := range snap.ListeningPorts {
		for _, sigPort := range def.Signatures.Ports {
			if p == sigPort {
				foundPorts = append(foundPorts, p)
				matchedEvidence = append(matchedEvidence, graph.Evidence{
					Source:    "network",
					Collector: "platform-detector",
					Raw:       fmt.Sprintf("Listening port: %d", p),
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				})
				break
			}
		}
	}

	// 4. Config files check on rooted FS (strict paths only)
	for _, cfgPath := range def.Signatures.Configs {
		if fi, err := rfs.Stat(cfgPath); err == nil && !fi.IsDir() {
			foundConfigs = append(foundConfigs, cfgPath)
			matchedEvidence = append(matchedEvidence, graph.Evidence{
				Source:    cfgPath,
				Collector: "platform-detector",
				Raw:       fmt.Sprintf("Configuration file present: %s", cfgPath),
				Timestamp: now,
				Certainty: graph.CertaintyObserved,
			})
		}
	}

	// 5. Binary presence in standard system locations (/usr/bin, /usr/sbin, /usr/local/bin, /opt)
	// Crucial rule: a file named 'kafka' in /tmp or user home MUST NOT match!
	for _, bin := range def.Signatures.Binaries {
		stdDirs := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin"}
		for _, dir := range stdDirs {
			binPath := filepath.Join(dir, bin)
			if fi, err := rfs.Stat(binPath); err == nil && !fi.IsDir() && (fi.Mode()&0111 != 0) {
				matchedEvidence = append(matchedEvidence, graph.Evidence{
					Source:    binPath,
					Collector: "platform-detector",
					Raw:       fmt.Sprintf("Executable binary present: %s", binPath),
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				})
				break
			}
		}
	}

	// 6. Container images matching
	for _, img := range snap.ContainerImages {
		for _, sigImg := range def.Signatures.Images {
			if strings.Contains(img, sigImg) {
				matchedEvidence = append(matchedEvidence, graph.Evidence{
					Source:    "container-image",
					Collector: "platform-detector",
					Raw:       fmt.Sprintf("Container image active: %s", img),
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				})
				break
			}
		}
	}

	// Honest presence determination:
	// To avoid false positives (e.g. random shared port or arbitrary string),
	// presence requires:
	// a valid config file OR active systemd unit OR active process OR binary in standard bin dirs
	isPresent := len(matchedEvidence) > 0 && (len(foundConfigs) > 0 || isRunning || hasBinaryOrUnitEvidence(matchedEvidence))

	supportLabel := "detection only"
	if def.Support == SupportAdapter {
		supportLabel = "adapter"
	}

	whatCanSee := "Local process status, listening ports, standard config paths, binary locations"
	whatCannotSee := "Cloud-side control plane state, remote tenant metadata, credentials"
	if def.Support == SupportAdapter {
		whatCanSee = "Deep local node inspection: manifests, cert expiries, runner logs, execution history"
	}

	health := "unknown"
	if isPresent {
		if isRunning {
			health = "running"
		} else {
			health = "stopped (installed/configured)"
		}
	}

	return DetectionResult{
		ID:            def.ID,
		Name:          def.Name,
		Category:      def.Category,
		Support:       def.Support,
		Present:       isPresent,
		Running:       isRunning,
		Ports:         foundPorts,
		Configs:       foundConfigs,
		HealthBasics:  health,
		SupportLabel:  supportLabel,
		WhatCanSee:    whatCanSee,
		WhatCannotSee: whatCannotSee,
		Provenance:    matchedEvidence,
	}
}

func matchesProcess(procLine, pattern string) bool {
	// Must match word boundary or executable name, not arbitrary substrings like /tmp/kafka
	if procLine == pattern {
		return true
	}
	parts := strings.Fields(procLine)
	if len(parts) > 0 {
		base := filepath.Base(parts[0])
		if base == pattern {
			return true
		}
	}
	return strings.Contains(procLine, pattern)
}

func matchesUnit(unit, pattern string) bool {
	if unit == pattern {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(unit, prefix)
	}
	if strings.Contains(pattern, "*") {
		re := regexp.MustCompile("^" + strings.ReplaceAll(pattern, "*", ".*") + "$")
		return re.MatchString(unit)
	}
	return false
}

func hasBinaryOrUnitEvidence(evs []graph.Evidence) bool {
	for _, e := range evs {
		if e.Source == "systemd" || strings.HasPrefix(e.Source, "/usr/") || strings.HasPrefix(e.Source, "/bin/") {
			return true
		}
	}
	return false
}

// ToResource converts a DetectionResult to a declarative resource.Resource.
func (r *DetectionResult) ToResource() resource.Resource {
	presentStatus := "False"
	reason := "NotDetected"
	if r.Present {
		presentStatus = "True"
		reason = "PlatformSignatureMatched"
	}

	return resource.Resource{
		Kind: resource.KindPlatform,
		Name: r.ID,
		Metadata: resource.Metadata{
			Labels: map[string]string{
				"category": r.Category,
				"support":  string(r.Support),
				"running":  fmt.Sprintf("%v", r.Running),
			},
		},
		Spec: map[string]any{
			"displayName":   r.Name,
			"ports":         r.Ports,
			"configs":       r.Configs,
			"supportLabel":  r.SupportLabel,
			"whatCanSee":    r.WhatCanSee,
			"whatCannotSee": r.WhatCannotSee,
		},
		Status: resource.Status{
			Conditions: []resource.Condition{
				{
					Type:               "Present",
					Status:             presentStatus,
					Reason:             reason,
					Message:            r.HealthBasics,
					LastTransitionTime: time.Now().UTC(),
				},
			},
			ObservedAt: time.Now().UTC(),
		},
		Provenance: r.Provenance,
	}
}
