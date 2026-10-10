// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package decisions computes dependency network topology, decommissioning readiness,
// and migration requirements for a Linux host.
package decisions

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/graphbuilder"
	"github.com/OWNER/jyoshin/internal/redact"
)

// EndpointRole categorizes an inferred network participant.
type EndpointRole string

const (
	RoleDatabase EndpointRole = "database"
	RoleCache    EndpointRole = "cache"
	RoleAPI      EndpointRole = "api_gateway"
	RoleQueue    EndpointRole = "message_queue"
	RoleGeneric  EndpointRole = "generic_service"
)

// DependencyEndpoint models an inbound or outbound network peer.
type DependencyEndpoint struct {
	Address   string          `json:"address"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol"`
	Direction string          `json:"direction"` // "inbound" or "outbound"
	Role      EndpointRole    `json:"role"`      // INFERRED
	Certainty graph.Certainty `json:"certainty"` // Typically DERIVED or INFERRED
	Details   string          `json:"details"`
}

// DependencyMap models full topological dependencies.
type DependencyMap struct {
	InboundEndpoints  []DependencyEndpoint `json:"inbound"`
	OutboundEndpoints []DependencyEndpoint `json:"outbound"`
	ASCIIMap          string               `json:"ascii_map"`
}

// DecommissionReport answers: "Is it safe to turn this server off?"
type DecommissionReport struct {
	SafeToTurnOff bool     `json:"safe_to_turn_off"`
	Verdict       string   `json:"verdict"`
	Blockers      []string `json:"blockers"`
	ActiveSockets int      `json:"active_sockets"`
	ActiveJobs    int      `json:"active_jobs"`
	UniqueVolumes []string `json:"unique_volumes"`
}

// MigrationPlan answers: "What must move?"
type MigrationPlan struct {
	Services     []string `json:"services"`
	DataPaths    []string `json:"data_paths"`
	ConfigPaths  []string `json:"config_paths"`
	Ports        []string `json:"ports"`
	CronJobs     []string `json:"cron_jobs"`
	SecretsPaths []string `json:"secrets_paths"` // Redacted paths only, never secret values
}

// Engine evaluates dependency topology and decommission/migration readiness.
type Engine struct {
	pGraph *graphbuilder.ProvenanceGraph
}

// NewEngine creates a new decisions engine.
func NewEngine(pGraph *graphbuilder.ProvenanceGraph) *Engine {
	return &Engine{pGraph: pGraph}
}

// InferRole heuristically deduces the functional role of a port/process (labeled INFERRED).
func InferRole(port int, name string) EndpointRole {
	nameLower := strings.ToLower(name)
	switch {
	case port == 5432 || port == 3306 || port == 27017 || strings.Contains(nameLower, "postgres") || strings.Contains(nameLower, "mysql") || strings.Contains(nameLower, "mongo"):
		return RoleDatabase
	case port == 6379 || port == 11211 || strings.Contains(nameLower, "redis") || strings.Contains(nameLower, "memcached"):
		return RoleCache
	case port == 5672 || port == 9092 || strings.Contains(nameLower, "kafka") || strings.Contains(nameLower, "rabbitmq"):
		return RoleQueue
	case port == 80 || port == 443 || port == 8080 || port == 8443 || strings.Contains(nameLower, "nginx") || strings.Contains(nameLower, "envoy"):
		return RoleAPI
	default:
		return RoleGeneric
	}
}

// GetDependencies builds inbound and outbound maps with ASCII rendering.
func (e *Engine) GetDependencies() DependencyMap {
	var inbound, outbound []DependencyEndpoint

	if e.pGraph == nil {
		return DependencyMap{ASCIIMap: "[No graph data available]"}
	}

	nodes, _ := e.pGraph.Snapshot()
	for _, n := range nodes {
		switch n.Type {
		case graph.NodePort:
			portNum, _ := n.Properties["port"].(int)
			proto, _ := n.Properties["protocol"].(string)
			exp, _ := n.Properties["exposure_class"].(string)
			role := InferRole(portNum, n.Label)

			inbound = append(inbound, DependencyEndpoint{
				Address:   n.Label,
				Port:      portNum,
				Protocol:  proto,
				Direction: "inbound",
				Role:      role,
				Certainty: graph.CertaintyInferred,
				Details:   fmt.Sprintf("Listening socket (exposure: %s)", exp),
			})

		case graph.NodeConnection:
			remAddr, _ := n.Properties["remote_address"].(string)
			remPort, _ := n.Properties["remote_port"].(int)
			proto, _ := n.Properties["protocol"].(string)
			role := InferRole(remPort, remAddr)

			outbound = append(outbound, DependencyEndpoint{
				Address:   remAddr,
				Port:      remPort,
				Protocol:  proto,
				Direction: "outbound",
				Role:      role,
				Certainty: graph.CertaintyObserved,
				Details:   "Active established TCP connection",
			})
		}
	}

	// Sort endpoints
	sort.Slice(inbound, func(i, j int) bool { return inbound[i].Port < inbound[j].Port })
	sort.Slice(outbound, func(i, j int) bool { return outbound[i].Address < outbound[j].Address })

	// Generate clean ASCII map
	var sb strings.Builder
	sb.WriteString("+------------------ DEPENDENCY TOPOLOGY MAP ------------------+\n")
	sb.WriteString("| INBOUND CLIENTS                 HOST                 OUTBOUND |\n")
	sb.WriteString("+--------------------------------------------------------------+\n")
	if len(inbound) == 0 && len(outbound) == 0 {
		sb.WriteString("|  (no inbound traffic)    -->   [LOCAL HOST]   -->  (isolated) |\n")
	} else {
		for _, in := range inbound {
			sb.WriteString(fmt.Sprintf("| [IN] %-20s -> [%-12s]               |\n", in.Address, in.Role))
		}
		sb.WriteString("|                                                              |\n")
		for _, out := range outbound {
			sb.WriteString(fmt.Sprintf("|                            [HOST] -> [OUT] %-17s |\n", fmt.Sprintf("%s:%d", out.Address, out.Port)))
		}
	}
	sb.WriteString("+--------------------------------------------------------------+\n")

	return DependencyMap{
		InboundEndpoints:  inbound,
		OutboundEndpoints: outbound,
		ASCIIMap:          sb.String(),
	}
}

// EvaluateDecommission assesses whether the host can be safely decommissioned.
func (e *Engine) EvaluateDecommission() DecommissionReport {
	if e.pGraph == nil {
		return DecommissionReport{
			SafeToTurnOff: false,
			Verdict:       "UNKNOWN: Provenance graph unavailable.",
			Blockers:      []string{"System observation data missing"},
		}
	}

	nodes, _ := e.pGraph.Snapshot()
	var blockers []string
	socketCount := 0
	jobCount := 0
	uniqueVolumes := make(map[string]bool)

	for _, n := range nodes {
		switch n.Type {
		case graph.NodePort:
			socketCount++
			if exp, _ := n.Properties["exposure_class"].(string); exp == "all_interfaces" {
				blockers = append(blockers, fmt.Sprintf("Active public listener: %s", n.Label))
			}
		case graph.NodeConnection:
			blockers = append(blockers, fmt.Sprintf("Active connected client: %s", n.Label))
		case graph.NodeService:
			if strings.HasSuffix(n.Label, ".timer") || strings.Contains(n.Label, "cron") {
				jobCount++
				blockers = append(blockers, fmt.Sprintf("Scheduled background timer: %s", n.Label))
			}
		case graph.NodeFile:
			if path, ok := n.Properties["path"].(string); ok {
				if strings.HasPrefix(path, "/var/lib/") || strings.HasPrefix(path, "/data") {
					uniqueVolumes[path] = true
				}
			}
		}
	}

	volList := make([]string, 0, len(uniqueVolumes))
	for v := range uniqueVolumes {
		volList = append(volList, v)
	}
	sort.Strings(volList)

	safe := len(blockers) == 0
	verdict := "SAFE: Host has zero active listeners, zero clients, and zero scheduled timers. Safe to turn off."
	if !safe {
		verdict = fmt.Sprintf("BLOCKED: Cannot turn off host. %d active traffic or workload blockers identified.", len(blockers))
	}

	return DecommissionReport{
		SafeToTurnOff: safe,
		Verdict:       verdict,
		Blockers:      blockers,
		ActiveSockets: socketCount,
		ActiveJobs:    jobCount,
		UniqueVolumes: volList,
	}
}

// PlanMigration computes all assets, configs, ports, and secret paths that must be migrated.
func (e *Engine) PlanMigration() MigrationPlan {
	plan := MigrationPlan{}
	if e.pGraph == nil {
		return plan
	}

	nodes, _ := e.pGraph.Snapshot()
	services := make(map[string]bool)
	dataPaths := make(map[string]bool)
	configPaths := make(map[string]bool)
	ports := make(map[string]bool)
	secrets := make(map[string]bool)

	for _, n := range nodes {
		switch n.Type {
		case graph.NodeService:
			services[n.Label] = true
		case graph.NodePort:
			ports[n.Label] = true
		case graph.NodeFile:
			path, _ := n.Properties["path"].(string)
			if path == "" {
				path = n.Label
			}

			// Check if secret path without reading secret value
			if redact.IsSecretPath(path) {
				secrets[path] = true
				continue
			}

			if strings.HasPrefix(path, "/etc/") {
				configPaths[path] = true
			} else if strings.HasPrefix(path, "/var/lib/") || strings.HasPrefix(path, "/data") {
				dataPaths[path] = true
			}
		}
	}

	for s := range services {
		plan.Services = append(plan.Services, s)
	}
	for d := range dataPaths {
		plan.DataPaths = append(plan.DataPaths, d)
	}
	for c := range configPaths {
		plan.ConfigPaths = append(plan.ConfigPaths, c)
	}
	for p := range ports {
		plan.Ports = append(plan.Ports, p)
	}
	for sec := range secrets {
		plan.SecretsPaths = append(plan.SecretsPaths, sec)
	}

	sort.Strings(plan.Services)
	sort.Strings(plan.DataPaths)
	sort.Strings(plan.ConfigPaths)
	sort.Strings(plan.Ports)
	sort.Strings(plan.SecretsPaths)

	return plan
}
