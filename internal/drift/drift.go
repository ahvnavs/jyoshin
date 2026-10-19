// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package drift compares desired state manifests against observed resource graphs
// to identify concrete discrepancies.
package drift

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/desired"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/resource"
)

// Kind classifies the specific form of drift detected.
type Kind string

const (
	KindMissing         Kind = "missing"
	KindExtra           Kind = "extra"
	KindVersionMismatch Kind = "version-mismatch"
	KindWrongState      Kind = "wrong-state"
	KindUnexpectedPort  Kind = "unexpected-port"
	KindUnknown         Kind = "unknown"
)

// Item represents a single concrete discrepancy between desired and actual state.
type Item struct {
	ID             string           `json:"id"`
	ResourceKind   resource.Kind    `json:"resource_kind"`
	Name           string           `json:"name"`
	Kind           Kind             `json:"kind"`
	Summary        string           `json:"summary"`
	Expected       string           `json:"expected"`
	Actual         string           `json:"actual"`
	Certainty      graph.Certainty  `json:"certainty"`
	Evidence       []graph.Evidence `json:"evidence,omitempty"`
	CoverageStatus string           `json:"coverage_status"` // "adequate", "partial", "unknown"
	Timestamp      time.Time        `json:"timestamp"`
}

// Summary provides an aggregate count of drift across kinds.
type Summary struct {
	TotalDrift int `json:"total_drift"`
	Missing    int `json:"missing"`
	Extra      int `json:"extra"`
	Mismatch   int `json:"mismatch"`
	WrongState int `json:"wrong_state"`
	Ports      int `json:"ports"`
	Unknown    int `json:"unknown"`
}

// Engine performs deterministic drift detection.
type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

// Evaluate compares desired state with observed resources and coverage.
// Principle 11: If coverage is unavailable or partial for a domain, reports "unknown"
// rather than falsely asserting missing or extra.
func (e *Engine) Evaluate(
	ctx context.Context,
	desired desired.DesiredState,
	resources []resource.Resource,
	cov coverage.Report,
) ([]Item, Summary) {
	now := time.Now().UTC()
	var items []Item

	// Index observed resources by Kind and Name
	observedPkg := make(map[string]resource.Resource)
	observedSvc := make(map[string]resource.Resource)
	observedPorts := make(map[string]resource.Resource)
	observedPlatforms := make(map[string]resource.Resource)

	for _, r := range resources {
		switch r.Kind {
		case resource.KindPackage:
			observedPkg[r.Name] = r
		case resource.KindService:
			observedSvc[r.Name] = r
			// Strip .service suffix if present for lookup
			if strings.HasSuffix(r.Name, ".service") {
				observedSvc[strings.TrimSuffix(r.Name, ".service")] = r
			}
		case resource.KindPort:
			observedPorts[r.Name] = r
		case resource.KindPlatform:
			observedPlatforms[r.Name] = r
		}
	}

	// 1. Package Evaluation
	pkgCoverageAdequate := isSubsystemAdequate(cov, "packages", "package")
	for _, req := range desired.RequiredPackages {
		if !pkgCoverageAdequate {
			items = append(items, Item{
				ID:             fmt.Sprintf("drift:pkg:unknown:%s", req.Name),
				ResourceKind:   resource.KindPackage,
				Name:           req.Name,
				Kind:           KindUnknown,
				Summary:        fmt.Sprintf("Package %q presence cannot be confirmed: package database unreadable or sensor coverage partial", req.Name),
				Expected:       fmt.Sprintf("installed (version: %s)", req.Version),
				Actual:         "visibility unavailable",
				Certainty:      graph.CertaintyObserved,
				CoverageStatus: "partial",
				Timestamp:      now,
			})
			continue
		}

		obs, found := observedPkg[req.Name]
		if !found {
			items = append(items, Item{
				ID:             fmt.Sprintf("drift:pkg:missing:%s", req.Name),
				ResourceKind:   resource.KindPackage,
				Name:           req.Name,
				Kind:           KindMissing,
				Summary:        fmt.Sprintf("Required package %q is missing from the system", req.Name),
				Expected:       fmt.Sprintf("installed (version: %s)", req.Version),
				Actual:         "not installed",
				Certainty:      graph.CertaintyObserved,
				CoverageStatus: "adequate",
				Timestamp:      now,
			})
			continue
		}

		// Check version mismatch if constraint declared
		if req.Version != "" && obs.Spec != nil {
			if obsVer, ok := obs.Spec["version"].(string); ok && obsVer != "" {
				if !strings.HasPrefix(obsVer, req.Version) {
					items = append(items, Item{
						ID:             fmt.Sprintf("drift:pkg:mismatch:%s", req.Name),
						ResourceKind:   resource.KindPackage,
						Name:           req.Name,
						Kind:           KindVersionMismatch,
						Summary:        fmt.Sprintf("Package %q version %s does not meet desired version constraint %s", req.Name, obsVer, req.Version),
						Expected:       req.Version,
						Actual:         obsVer,
						Certainty:      graph.CertaintyObserved,
						Evidence:       obs.Provenance,
						CoverageStatus: "adequate",
						Timestamp:      now,
					})
				}
			}
		}
	}

	// Forbidden packages check
	for _, fpkg := range desired.ForbiddenPackages {
		if !pkgCoverageAdequate {
			continue
		}
		if obs, found := observedPkg[fpkg]; found {
			items = append(items, Item{
				ID:             fmt.Sprintf("drift:pkg:extra:%s", fpkg),
				ResourceKind:   resource.KindPackage,
				Name:           fpkg,
				Kind:           KindExtra,
				Summary:        fmt.Sprintf("Forbidden package %q is currently installed on host", fpkg),
				Expected:       "absent",
				Actual:         "installed",
				Certainty:      graph.CertaintyObserved,
				Evidence:       obs.Provenance,
				CoverageStatus: "adequate",
				Timestamp:      now,
			})
		}
	}

	// 2. Service Evaluation
	svcCoverageAdequate := isSubsystemAdequate(cov, "services", "service", "init")
	for _, req := range desired.RequiredServices {
		if !svcCoverageAdequate {
			items = append(items, Item{
				ID:             fmt.Sprintf("drift:svc:unknown:%s", req.Name),
				ResourceKind:   resource.KindService,
				Name:           req.Name,
				Kind:           KindUnknown,
				Summary:        fmt.Sprintf("Service %q status cannot be verified: systemd offline or init inspection denied", req.Name),
				Expected:       "active",
				Actual:         "init sensor offline",
				Certainty:      graph.CertaintyObserved,
				CoverageStatus: "partial",
				Timestamp:      now,
			})
			continue
		}

		obs, found := observedSvc[req.Name]
		if !found {
			items = append(items, Item{
				ID:             fmt.Sprintf("drift:svc:missing:%s", req.Name),
				ResourceKind:   resource.KindService,
				Name:           req.Name,
				Kind:           KindMissing,
				Summary:        fmt.Sprintf("Required service %q is not installed or registered", req.Name),
				Expected:       "active and enabled",
				Actual:         "not found",
				Certainty:      graph.CertaintyObserved,
				CoverageStatus: "adequate",
				Timestamp:      now,
			})
			continue
		}

		// Check service active state
		activeState := "unknown"
		if obs.Spec != nil {
			if as, ok := obs.Spec["active_state"].(string); ok {
				activeState = as
			}
		}
		desiredState := req.State
		if desiredState == "" {
			desiredState = "active"
		}
		if activeState != desiredState {
			items = append(items, Item{
				ID:             fmt.Sprintf("drift:svc:wrong-state:%s", req.Name),
				ResourceKind:   resource.KindService,
				Name:           req.Name,
				Kind:           KindWrongState,
				Summary:        fmt.Sprintf("Service %q is currently in state %q; expected %q", req.Name, activeState, desiredState),
				Expected:       desiredState,
				Actual:         activeState,
				Certainty:      graph.CertaintyObserved,
				Evidence:       obs.Provenance,
				CoverageStatus: "adequate",
				Timestamp:      now,
			})
		}
	}

	// 3. Port Evaluation (Unexpected Ports)
	if len(desired.AllowedPorts) > 0 {
		portCoverageAdequate := isSubsystemAdequate(cov, "sockets", "network")
		if !portCoverageAdequate {
			items = append(items, Item{
				ID:             "drift:port:unknown",
				ResourceKind:   resource.KindPort,
				Name:           "network-ports",
				Kind:           KindUnknown,
				Summary:        "Network listening ports cannot be fully verified: socket table or /proc visibility partial",
				Expected:       "allowed port list",
				Actual:         "coverage partial",
				Certainty:      graph.CertaintyObserved,
				CoverageStatus: "partial",
				Timestamp:      now,
			})
		} else {
			allowedMap := make(map[int]bool)
			for _, ap := range desired.AllowedPorts {
				allowedMap[ap.Port] = true
			}

			for _, p := range observedPorts {
				portNum := 0
				if p.Spec != nil {
					if pn, ok := p.Spec["port"].(float64); ok {
						portNum = int(pn)
					} else if pn, ok := p.Spec["port"].(int); ok {
						portNum = pn
					}
				}
				if portNum > 0 && !allowedMap[portNum] {
					items = append(items, Item{
						ID:             fmt.Sprintf("drift:port:unexpected:%d", portNum),
						ResourceKind:   resource.KindPort,
						Name:           fmt.Sprintf("port:%d", portNum),
						Kind:           KindUnexpectedPort,
						Summary:        fmt.Sprintf("Unexpected listening port %d detected on host", portNum),
						Expected:       "closed or explicitly allowed",
						Actual:         fmt.Sprintf("open (listener: %s)", p.Name),
						Certainty:      graph.CertaintyObserved,
						Evidence:       p.Provenance,
						CoverageStatus: "adequate",
						Timestamp:      now,
					})
				}
			}
		}
	}

	// Compute summary counts
	var sum Summary
	sum.TotalDrift = len(items)
	for _, it := range items {
		switch it.Kind {
		case KindMissing:
			sum.Missing++
		case KindExtra:
			sum.Extra++
		case KindVersionMismatch:
			sum.Mismatch++
		case KindWrongState:
			sum.WrongState++
		case KindUnexpectedPort:
			sum.Ports++
		case KindUnknown:
			sum.Unknown++
		}
	}

	return items, sum
}

func isSubsystemAdequate(cov coverage.Report, matchTokens ...string) bool {
	if len(cov.Items) == 0 {
		return true // Default optimistic if no item breakdown
	}
	for _, it := range cov.Items {
		nameLower := strings.ToLower(it.Name)
		catLower := strings.ToLower(it.Category)
		for _, tok := range matchTokens {
			if strings.Contains(nameLower, tok) || strings.Contains(catLower, tok) {
				if it.Status == "unavailable" || it.Status == "unknown" {
					return false
				}
				if it.Total > 0 && it.Readable == 0 {
					return false
				}
			}
		}
	}
	return true
}
