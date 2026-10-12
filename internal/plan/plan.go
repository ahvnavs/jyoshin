// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package plan converts detected drift items into a deterministic, topologically ordered DAG of Steps.
// Plans are plain, explainable data without execution capabilities (Principle 2).
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/OWNER/kazeshini/internal/blastradius"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/resource"
)

// Action represents the required remediation verb.
type Action string

const (
	ActionInstall PackageAction = "install"
	ActionRemove  PackageAction = "remove"
	ActionUpgrade PackageAction = "upgrade"
	ActionStart   ServiceAction = "start"
	ActionEnable  ServiceAction = "enable"
	ActionClose   PortAction    = "close"
)

type PackageAction string
type ServiceAction string
type PortAction string

// Step represents a single remediation operation in the plan DAG.
type Step struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	ResourceKind      resource.Kind `json:"resource_kind"`
	ResourceName      string   `json:"resource_name"`
	Action            string   `json:"action"`
	Dependencies      []string `json:"dependencies,omitempty"` // IDs of prerequisite steps
	Preconditions     []string `json:"preconditions"`
	Postconditions    []string `json:"postconditions"`
	Risk              string   `json:"risk"` // "low", "medium", "high"
	Reversible        bool     `json:"reversible"`
	RequiresReboot    bool     `json:"requires_reboot"`
	BlastRadiusScore  int      `json:"blast_radius_score"` // 0-100
	BlastRadiusText   string   `json:"blast_radius_text"`
	EquivalentCommands []string `json:"equivalent_commands"` // SHOWN ONLY, never executed (Principle 2)
}

// Plan represents an entire DAG of topologically ordered remediation steps.
type Plan struct {
	ID             string    `json:"id"`
	Hash           string    `json:"hash"` // Stable deterministic SHA256 of steps
	CreatedAt      time.Time `json:"created_at"`
	Steps          []Step    `json:"steps"`
	TotalSteps     int       `json:"total_steps"`
	MaxRisk        string    `json:"max_risk"`
	RequiresReboot bool      `json:"requires_reboot"`
	IsReversible   bool      `json:"is_reversible"`
	MaxBlastScore  int       `json:"max_blast_score"`
	Summary        string    `json:"summary"`
}

// Planner generates deterministic plans from drift items.
type Planner struct {
	blastAnalyzer *blastradius.Analyzer
}

func NewPlanner(analyzer *blastradius.Analyzer) *Planner {
	return &Planner{blastAnalyzer: analyzer}
}

// CreatePlan transforms drift items into a topologically ordered Plan.
func (p *Planner) CreatePlan(driftItems []drift.Item) (*Plan, error) {
	var rawSteps []Step

	for _, d := range driftItems {
		step := p.driftToStep(d)
		if step != nil {
			rawSteps = append(rawSteps, *step)
		}
	}

	// 1. Establish dependencies (e.g., packages before services, removals before additions)
	rawSteps = p.wireDependencies(rawSteps)

	// 2. Topologically order the DAG
	sortedSteps, err := TopologicalSort(rawSteps)
	if err != nil {
		return nil, fmt.Errorf("plan DAG dependency error: %w", err)
	}

	// 3. Compute stable deterministic hash across step contents
	h := sha256.New()
	maxRisk := "low"
	requiresReboot := false
	allReversible := true
	maxBlast := 0

	for _, s := range sortedSteps {
		h.Write([]byte(fmt.Sprintf("%s:%s:%s:%s|", s.ID, s.ResourceKind, s.ResourceName, s.Action)))
		if s.Risk == "high" {
			maxRisk = "high"
		} else if s.Risk == "medium" && maxRisk != "high" {
			maxRisk = "medium"
		}
		if s.RequiresReboot {
			requiresReboot = true
		}
		if !s.Reversible {
			allReversible = false
		}
		if s.BlastRadiusScore > maxBlast {
			maxBlast = s.BlastRadiusScore
		}
	}

	planHash := hex.EncodeToString(h.Sum(nil))
	planID := fmt.Sprintf("plan-%s", planHash[:12])

	return &Plan{
		ID:             planID,
		Hash:           planHash,
		CreatedAt:      time.Now().UTC(),
		Steps:          sortedSteps,
		TotalSteps:     len(sortedSteps),
		MaxRisk:        maxRisk,
		RequiresReboot: requiresReboot,
		IsReversible:   allReversible,
		MaxBlastScore:  maxBlast,
		Summary:        fmt.Sprintf("Plan with %d deterministic steps to resolve host drift (Max Risk: %s, Max Blast: %d)", len(sortedSteps), maxRisk, maxBlast),
	}, nil
}

func (p *Planner) driftToStep(d drift.Item) *Step {
	switch d.ResourceKind {
	case resource.KindPackage:
		switch d.Kind {
		case drift.KindMissing:
			return &Step{
				ID:           fmt.Sprintf("pkg-install-%s", d.Name),
				Title:        fmt.Sprintf("Install package %s", d.Name),
				Description:  fmt.Sprintf("Install package %s to satisfy desired state constraint %s", d.Name, d.Expected),
				ResourceKind: resource.KindPackage,
				ResourceName: d.Name,
				Action:       "install",
				Preconditions: []string{
					"Package manager cache is up-to-date",
					fmt.Sprintf("Package %q exists in configured apt/rpm repositories", d.Name),
				},
				Postconditions: []string{
					fmt.Sprintf("Package %q is registered as installed in dpkg/rpm database", d.Name),
				},
				Risk:             "low",
				Reversible:       true,
				RequiresReboot:   false,
				BlastRadiusScore: 10,
				BlastRadiusText:  "Installing new package has low impact on existing services",
				EquivalentCommands: []string{
					fmt.Sprintf("sudo apt-get install -y %s", d.Name),
				},
			}
		case drift.KindExtra:
			return &Step{
				ID:           fmt.Sprintf("pkg-remove-%s", d.Name),
				Title:        fmt.Sprintf("Remove forbidden package %s", d.Name),
				Description:  fmt.Sprintf("Purge forbidden package %s to satisfy desired state security profile", d.Name),
				ResourceKind: resource.KindPackage,
				ResourceName: d.Name,
				Action:       "remove",
				Preconditions: []string{
					fmt.Sprintf("Package %q is currently installed", d.Name),
					fmt.Sprintf("No mission-critical services strictly depend on %s", d.Name),
				},
				Postconditions: []string{
					fmt.Sprintf("Package %q is removed from system inventory", d.Name),
				},
				Risk:             "medium",
				Reversible:       true,
				RequiresReboot:   false,
				BlastRadiusScore: 25,
				BlastRadiusText:  "Removing package could impact unmapped binary callers",
				EquivalentCommands: []string{
					fmt.Sprintf("sudo apt-get purge -y %s", d.Name),
				},
			}
		case drift.KindVersionMismatch:
			return &Step{
				ID:           fmt.Sprintf("pkg-upgrade-%s", d.Name),
				Title:        fmt.Sprintf("Upgrade package %s to %s", d.Name, d.Expected),
				Description:  fmt.Sprintf("Upgrade package %s from observed %s to expected %s", d.Name, d.Actual, d.Expected),
				ResourceKind: resource.KindPackage,
				ResourceName: d.Name,
				Action:       "upgrade",
				Preconditions: []string{
					fmt.Sprintf("Target version %s is available in repository", d.Expected),
				},
				Postconditions: []string{
					fmt.Sprintf("Package %s reports version >= %s", d.Name, d.Expected),
				},
				Risk:             "low",
				Reversible:       true,
				RequiresReboot:   false,
				BlastRadiusScore: 15,
				BlastRadiusText:  "Software minor upgrade",
				EquivalentCommands: []string{
					fmt.Sprintf("sudo apt-get install --only-upgrade -y %s", d.Name),
				},
			}
		}

	case resource.KindService:
		switch d.Kind {
		case drift.KindMissing:
			return &Step{
				ID:           fmt.Sprintf("svc-setup-%s", d.Name),
				Title:        fmt.Sprintf("Install and enable service unit %s", d.Name),
				Description:  fmt.Sprintf("Deploy unit file and enable %s.service", d.Name),
				ResourceKind: resource.KindService,
				ResourceName: d.Name,
				Action:       "enable",
				Preconditions: []string{
					fmt.Sprintf("Unit file for %s is placed in /etc/systemd/system", d.Name),
				},
				Postconditions: []string{
					fmt.Sprintf("systemctl is-enabled %s returns enabled", d.Name),
				},
				Risk:             "low",
				Reversible:       true,
				RequiresReboot:   false,
				BlastRadiusScore: 10,
				BlastRadiusText:  "New service enablement",
				EquivalentCommands: []string{
					fmt.Sprintf("sudo systemctl enable --now %s", d.Name),
				},
			}
		case drift.KindWrongState:
			return &Step{
				ID:           fmt.Sprintf("svc-start-%s", d.Name),
				Title:        fmt.Sprintf("Start service %s", d.Name),
				Description:  fmt.Sprintf("Bring service %s from observed state %q to desired state %q", d.Name, d.Actual, d.Expected),
				ResourceKind: resource.KindService,
				ResourceName: d.Name,
				Action:       "start",
				Preconditions: []string{
					fmt.Sprintf("Unit %s is not masked", d.Name),
				},
				Postconditions: []string{
					fmt.Sprintf("systemctl is-active %s returns active", d.Name),
				},
				Risk:             "low",
				Reversible:       true,
				RequiresReboot:   false,
				BlastRadiusScore: 15,
				BlastRadiusText:  "Activating stopped service",
				EquivalentCommands: []string{
					fmt.Sprintf("sudo systemctl start %s", d.Name),
				},
			}
		}

	case resource.KindPort:
		if d.Kind == drift.KindUnexpectedPort {
			return &Step{
				ID:           fmt.Sprintf("port-close-%s", d.Name),
				Title:        fmt.Sprintf("Investigate listener on %s", d.Name),
				Description:  fmt.Sprintf("Identify listener process on %s and reconfigure to close unexpected listener", d.Name),
				ResourceKind: resource.KindPort,
				ResourceName: d.Name,
				Action:       "close",
				Preconditions: []string{
					fmt.Sprintf("Port %s is currently bound and listening", d.Name),
				},
				Postconditions: []string{
					fmt.Sprintf("Port %s is no longer open in /proc/net/tcp", d.Name),
				},
				Risk:             "medium",
				Reversible:       true,
				RequiresReboot:   false,
				BlastRadiusScore: 20,
				BlastRadiusText:  "Closing unauthorized open port",
				EquivalentCommands: []string{
					fmt.Sprintf("# Inspect listening PID: ss -tulpn | grep %s", d.Name),
				},
			}
		}
	}

	return nil
}

// wireDependencies sets dependencies so that package installs run before service activations,
// and package removals happen after service stops.
func (p *Planner) wireDependencies(steps []Step) []Step {
	pkgInstalls := make(map[string]string)
	for _, s := range steps {
		if s.ResourceKind == resource.KindPackage && s.Action == "install" {
			pkgInstalls[s.ResourceName] = s.ID
		}
	}

	for i := range steps {
		// If step is a service activation, depend on any matching package install
		if steps[i].ResourceKind == resource.KindService {
			if depID, ok := pkgInstalls[steps[i].ResourceName]; ok {
				steps[i].Dependencies = append(steps[i].Dependencies, depID)
			}
		}
	}

	return steps
}

// TopologicalSort sorts DAG steps so that all dependencies come before their dependents.
// Rejects and returns error on cycles.
func TopologicalSort(steps []Step) ([]Step, error) {
	nodeMap := make(map[string]Step, len(steps))
	inDegree := make(map[string]int, len(steps))
	adj := make(map[string][]string, len(steps))

	for _, s := range steps {
		nodeMap[s.ID] = s
		inDegree[s.ID] = len(s.Dependencies)
		for _, dep := range s.Dependencies {
			adj[dep] = append(adj[dep], s.ID)
		}
	}

	// Deterministic queue order: sort IDs initially
	var zeroDegree []string
	for _, s := range steps {
		if inDegree[s.ID] == 0 {
			zeroDegree = append(zeroDegree, s.ID)
		}
	}
	sort.Strings(zeroDegree)

	var ordered []Step
	for len(zeroDegree) > 0 {
		currID := zeroDegree[0]
		zeroDegree = zeroDegree[1:]
		ordered = append(ordered, nodeMap[currID])

		dependents := adj[currID]
		sort.Strings(dependents)
		for _, depID := range dependents {
			inDegree[depID]--
			if inDegree[depID] == 0 {
				zeroDegree = append(zeroDegree, depID)
				sort.Strings(zeroDegree)
			}
		}
	}

	if len(ordered) != len(steps) {
		return nil, fmt.Errorf("dependency cycle detected in plan DAG (%d of %d steps ordered)", len(ordered), len(steps))
	}

	return ordered, nil
}

