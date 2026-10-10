// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

// Package graphbuilder constructs and incrementally maintains the Provenance Graph
// from sensor observations and provides provenance walking (why, dependents).
package graphbuilder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/sensors"
	"github.com/OWNER/jyoshin/internal/sensors/host"
	"github.com/OWNER/jyoshin/internal/sensors/network"
	"github.com/OWNER/jyoshin/internal/sensors/process"
	"github.com/OWNER/jyoshin/internal/sensors/service"
)

// GenerateNodeID computes a stable deterministic identifier for a node based on its type and natural keys.
func GenerateNodeID(nodeType graph.NodeType, naturalKey string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", nodeType, strings.TrimSpace(naturalKey))))
	return fmt.Sprintf("%s:%s", nodeType, hex.EncodeToString(h[:8]))
}

// GenerateEdgeID computes a stable deterministic identifier for a directed edge.
func GenerateEdgeID(sourceID, targetID, relation string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s->%s:%s", sourceID, targetID, relation)))
	return fmt.Sprintf("edge:%s", hex.EncodeToString(h[:8]))
}

// ProvenanceGraph models the in-memory directed provenance graph with memory bounds and query capabilities.
type ProvenanceGraph struct {
	mu       sync.RWMutex
	nodes    map[string]graph.Node
	edges    map[string]graph.Edge
	adjOut   map[string][]string // sourceID -> []edgeID
	adjIn    map[string][]string // targetID -> []edgeID
	maxNodes int
	maxEdges int
}

// NewProvenanceGraph creates a new memory-bounded ProvenanceGraph.
func NewProvenanceGraph() *ProvenanceGraph {
	return &ProvenanceGraph{
		nodes:    make(map[string]graph.Node),
		edges:    make(map[string]graph.Edge),
		adjOut:   make(map[string][]string),
		adjIn:    make(map[string][]string),
		maxNodes: 100000,
		maxEdges: 250000,
	}
}

// UpsertNode incrementally inserts or updates a node in the graph.
func (g *ProvenanceGraph) UpsertNode(n graph.Node) error {
	if err := n.Validate(); err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.nodes) >= g.maxNodes {
		if _, exists := g.nodes[n.ID]; !exists {
			return fmt.Errorf("provenance graph node capacity (%d) reached", g.maxNodes)
		}
	}

	if existing, exists := g.nodes[n.ID]; exists {
		n.FirstSeen = existing.FirstSeen
	}
	g.nodes[n.ID] = n
	return nil
}

// UpsertEdge incrementally inserts or updates an edge in the graph.
func (g *ProvenanceGraph) UpsertEdge(e graph.Edge) error {
	if err := e.Validate(); err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.edges) >= g.maxEdges {
		if _, exists := g.edges[e.ID]; !exists {
			return fmt.Errorf("provenance graph edge capacity (%d) reached", g.maxEdges)
		}
	}

	if _, exists := g.edges[e.ID]; !exists {
		g.adjOut[e.SourceID] = append(g.adjOut[e.SourceID], e.ID)
		g.adjIn[e.TargetID] = append(g.adjIn[e.TargetID], e.ID)
	}

	g.edges[e.ID] = e
	return nil
}

// GetNode retrieves a node by ID.
func (g *ProvenanceGraph) GetNode(id string) (graph.Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// Summary returns high-level node and edge counts.
func (g *ProvenanceGraph) Summary() (int, int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes), len(g.edges)
}

// Snapshot returns a copy of all current nodes and edges.
func (g *ProvenanceGraph) Snapshot() ([]graph.Node, []graph.Edge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]graph.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	edges := make([]graph.Edge, 0, len(g.edges))
	for _, e := range g.edges {
		edges = append(edges, e)
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })

	return nodes, edges
}

// ProvenanceChain represents the walked explanation for why a node exists.
type ProvenanceChain struct {
	TargetNode graph.Node   `json:"target_node"`
	Chain      []graph.Node `json:"chain"`
	Edges      []graph.Edge `json:"edges"`
}

// Why walks backward along incoming edges to explain why a node exists.
func (g *ProvenanceGraph) Why(targetID string) (*ProvenanceChain, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	target, exists := g.nodes[targetID]
	if !exists {
		return nil, fmt.Errorf("node %q not found", targetID)
	}

	chain := []graph.Node{target}
	var chainEdges []graph.Edge
	visited := map[string]bool{targetID: true}
	currID := targetID

	for {
		inEdges := g.adjIn[currID]
		if len(inEdges) == 0 {
			break
		}

		// Take the first incoming edge
		edge := g.edges[inEdges[0]]
		prevID := edge.SourceID
		if visited[prevID] {
			break // Cycle prevention
		}
		visited[prevID] = true

		if prevNode, ok := g.nodes[prevID]; ok {
			chain = append(chain, prevNode)
			chainEdges = append(chainEdges, edge)
			currID = prevID
		} else {
			break
		}
	}

	return &ProvenanceChain{
		TargetNode: target,
		Chain:      chain,
		Edges:      chainEdges,
	}, nil
}

// Dependents walks forward along outgoing edges to find what depends on targetID.
func (g *ProvenanceGraph) Dependents(targetID string) ([]graph.Node, []graph.Edge, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, exists := g.nodes[targetID]; !exists {
		return nil, nil, fmt.Errorf("node %q not found", targetID)
	}

	var depNodes []graph.Node
	var depEdges []graph.Edge
	visited := map[string]bool{targetID: true}
	queue := []string{targetID}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, edgeID := range g.adjOut[curr] {
			edge := g.edges[edgeID]
			depEdges = append(depEdges, edge)
			if !visited[edge.TargetID] {
				visited[edge.TargetID] = true
				if node, ok := g.nodes[edge.TargetID]; ok {
					depNodes = append(depNodes, node)
					queue = append(queue, edge.TargetID)
				}
			}
		}
	}

	return depNodes, depEdges, nil
}

// IngestObservation incrementally integrates observations from sensors into the graph.
func (g *ProvenanceGraph) IngestObservation(obs sensors.Observation) {
	now := obs.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	switch obs.SensorName {
	case "host":
		g.ingestHost(obs, now)
	case "process":
		g.ingestProcess(obs, now)
	case "service":
		g.ingestService(obs, now)
	case "network":
		g.ingestNetwork(obs, now)
	}
}

func (g *ProvenanceGraph) ingestHost(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		info, ok := it.Data.(host.HostInfo)
		if !ok {
			continue
		}

		nodeID := GenerateNodeID(graph.NodeSystem, info.Hostname)
		_ = g.UpsertNode(graph.Node{
			ID:    nodeID,
			Type:  graph.NodeSystem,
			Label: fmt.Sprintf("host:%s", info.Hostname),
			Properties: map[string]any{
				"distro":         info.Distro,
				"kernel":         info.Kernel,
				"cpu_count":      info.CPUCount,
				"memory_bytes":   info.MemoryBytes,
				"virtualization": info.Virtualization,
				"cloud_provider": info.CloudProvider,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyDerived,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}

func (g *ProvenanceGraph) ingestProcess(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		p, ok := it.Data.(process.ProcessInfo)
		if !ok {
			continue
		}

		procNodeID := GenerateNodeID(graph.NodeProcess, fmt.Sprintf("%d:%s", p.PID, p.Name))
		_ = g.UpsertNode(graph.Node{
			ID:    procNodeID,
			Type:  graph.NodeProcess,
			Label: fmt.Sprintf("%s (pid %d)", p.Name, p.PID),
			Properties: map[string]any{
				"pid":      p.PID,
				"ppid":     p.PPID,
				"cmdline":  p.Cmdline,
				"exe":      p.Exe,
				"uid":      p.UID,
				"threads":  p.Threads,
				"vsize":    p.VSizeBytes,
				"open_fds": p.OpenFDCount,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})

		// File node for exe if available
		if p.Exe != "" {
			fileNodeID := GenerateNodeID(graph.NodeFile, p.Exe)
			_ = g.UpsertNode(graph.Node{
				ID:        fileNodeID,
				Type:      graph.NodeFile,
				Label:     p.Exe,
				Certainty: graph.CertaintyObserved,
				FirstSeen: now,
				LastSeen:  now,
			})

			edgeID := GenerateEdgeID(fileNodeID, procNodeID, "executes")
			_ = g.UpsertEdge(graph.Edge{
				ID:         edgeID,
				SourceID:   fileNodeID,
				TargetID:   procNodeID,
				Relation:   "executes",
				Certainty:  graph.CertaintyObserved,
				Confidence: 1.0,
			})
		}

		// User node
		userNodeID := GenerateNodeID(graph.NodeUser, fmt.Sprintf("uid:%d", p.UID))
		_ = g.UpsertNode(graph.Node{
			ID:        userNodeID,
			Type:      graph.NodeUser,
			Label:     fmt.Sprintf("user:uid=%d", p.UID),
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})

		edgeID := GenerateEdgeID(userNodeID, procNodeID, "owns")
		_ = g.UpsertEdge(graph.Edge{
			ID:         edgeID,
			SourceID:   userNodeID,
			TargetID:   procNodeID,
			Relation:   "owns",
			Certainty:  graph.CertaintyObserved,
			Confidence: 1.0,
		})
	}
}

func (g *ProvenanceGraph) ingestService(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		u, ok := it.Data.(service.UnitInfo)
		if !ok {
			continue
		}

		svcNodeID := GenerateNodeID(graph.NodeService, u.Name)
		_ = g.UpsertNode(graph.Node{
			ID:    svcNodeID,
			Type:  graph.NodeService,
			Label: u.Name,
			Properties: map[string]any{
				"active_state": u.ActiveState,
				"unit_file":    u.UnitFile,
				"exec_start":   u.ExecStart,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}

func (g *ProvenanceGraph) ingestNetwork(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		if it.Type != "listening_port" {
			continue
		}
		l, ok := it.Data.(network.SocketInfo)
		if !ok {
			continue
		}

		portNatural := fmt.Sprintf("%s:%d", l.Protocol, l.LocalPort)
		portNodeID := GenerateNodeID(graph.NodePort, portNatural)

		_ = g.UpsertNode(graph.Node{
			ID:    portNodeID,
			Type:  graph.NodePort,
			Label: fmt.Sprintf("port %s/%d (%s)", l.Protocol, l.LocalPort, l.ExposureClass),
			Properties: map[string]any{
				"protocol":       l.Protocol,
				"local_ip":       l.LocalIP,
				"local_port":     l.LocalPort,
				"exposure_class": l.ExposureClass,
				"inode":          l.Inode,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})

		// Link process to port if PID is known
		if l.PID > 0 {
			procNodeID := GenerateNodeID(graph.NodeProcess, fmt.Sprintf("%d:%s", l.PID, l.ProcessName))
			_ = g.UpsertNode(graph.Node{
				ID:        procNodeID,
				Type:      graph.NodeProcess,
				Label:     fmt.Sprintf("%s (pid %d)", l.ProcessName, l.PID),
				Certainty: graph.CertaintyObserved,
				FirstSeen: now,
				LastSeen:  now,
			})

			edgeID := GenerateEdgeID(procNodeID, portNodeID, "listens_on")
			_ = g.UpsertEdge(graph.Edge{
				ID:         edgeID,
				SourceID:   procNodeID,
				TargetID:   portNodeID,
				Relation:   "listens_on",
				Certainty:  graph.CertaintyObserved,
				Confidence: 1.0,
			})
		}
	}
}
