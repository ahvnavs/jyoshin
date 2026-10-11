// Copyright 2026 Kazeshini Authors
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

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/origin"
	"github.com/OWNER/kazeshini/internal/sensors"
	"github.com/OWNER/kazeshini/internal/sensors/container"
	"github.com/OWNER/kazeshini/internal/sensors/host"
	"github.com/OWNER/kazeshini/internal/sensors/kernel"
	"github.com/OWNER/kazeshini/internal/sensors/network"
	"github.com/OWNER/kazeshini/internal/sensors/process"
	"github.com/OWNER/kazeshini/internal/sensors/resources"
	"github.com/OWNER/kazeshini/internal/sensors/scheduler"
	"github.com/OWNER/kazeshini/internal/sensors/service"
	"github.com/OWNER/kazeshini/internal/sensors/storage"
	"github.com/OWNER/kazeshini/internal/sensors/user"
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
	mu             sync.RWMutex
	nodes          map[string]graph.Node
	edges          map[string]graph.Edge
	adjOut         map[string][]string // sourceID -> []edgeID
	adjIn          map[string][]string // targetID -> []edgeID
	originResolver *origin.Resolver
	maxNodes       int
	maxEdges       int
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

// SetOriginResolver connects an origin resolver for automated file -> origin provenance links.
func (g *ProvenanceGraph) SetOriginResolver(r *origin.Resolver) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.originResolver = r
}

// SeedFromSnapshot initializes the graph with historical nodes from persistent storage,
// preserving first_seen timestamps across daemon restarts.
func (g *ProvenanceGraph) SeedFromSnapshot(nodes []graph.Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, n := range nodes {
		if !n.FirstSeen.IsZero() {
			if existing, exists := g.nodes[n.ID]; exists {
				if n.FirstSeen.Before(existing.FirstSeen) {
					existing.FirstSeen = n.FirstSeen
					g.nodes[n.ID] = existing
				}
			} else {
				g.nodes[n.ID] = n
			}
		}
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

// GetNode retrieves a node by its ID.
func (g *ProvenanceGraph) GetNode(id string) (graph.Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// NodeCount returns the current number of nodes in the graph.
func (g *ProvenanceGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns the current number of edges in the graph.
func (g *ProvenanceGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// Summary returns the node count and edge count of the graph.
func (g *ProvenanceGraph) Summary() (int, int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes), len(g.edges)
}

// Snapshot returns deterministic, sorted copies of all nodes and edges.
func (g *ProvenanceGraph) Snapshot() ([]graph.Node, []graph.Edge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]graph.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	edges := make([]graph.Edge, 0, len(g.edges))
	for _, e := range g.edges {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})

	return nodes, edges
}

// ProvenanceChain represents the backward trace answering "Why does X exist?".
type ProvenanceChain struct {
	TargetNode graph.Node   `json:"target_node"`
	Chain      []graph.Node `json:"chain"` // target -> parent -> grandparent ... -> origin
	Edges      []graph.Edge `json:"edges"`
}

// Why walks backward along incoming edges to determine the root origin of targetID.
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

		// Prefer structural provenance relations:
		// installed_by (file <- origin) > executes (proc <- file) > listens_on (port <- proc) > runs / spawned_by / manages
		relationPriority := func(rel string) int {
			switch rel {
			case "installed_by":
				return 100
			case "executes":
				return 90
			case "listens_on":
				return 80
			case "spawned_by":
				return 70
			case "runs":
				return 60
			case "manages":
				return 50
			case "member_of":
				return 40
			default:
				return 10
			}
		}

		selectedEdgeID := inEdges[0]
		bestPrio := relationPriority(g.edges[selectedEdgeID].Relation)

		for _, eID := range inEdges[1:] {
			e := g.edges[eID]
			prio := relationPriority(e.Relation)
			if prio > bestPrio {
				selectedEdgeID = eID
				bestPrio = prio
			}
		}

		edge := g.edges[selectedEdgeID]
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
	case "storage":
		g.ingestStorage(obs, now)
	case "resources":
		g.ingestResources(obs, now)
	case "container":
		g.ingestContainer(obs, now)
	case "user":
		g.ingestUser(obs, now)
	case "scheduler":
		g.ingestScheduler(obs, now)
	case "kernel":
		g.ingestKernel(obs, now)
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
				"distro_version": info.DistroVersion,
				"distro_family":  info.DistroFamily,
				"kernel":         info.Kernel,
				"cpu_count":      info.CPUCount,
				"memory_bytes":   info.MemoryBytes,
				"virtualization": info.Virtualization,
				"cloud_provider": info.CloudProvider,
				"instance_type":  info.InstanceType,
				"uptime_seconds": info.UptimeSeconds,
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
				"name":     p.Name,
				"pid":      p.PID,
				"ppid":     p.PPID,
				"cmdline":  p.Cmdline,
				"exe":      p.Exe,
				"uid":      p.UID,
				"threads":  p.Threads,
				"vsize":    p.VSizeBytes,
				"open_fds": p.OpenFDCount,
				"cgroup":   p.Cgroup,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})

		// Wire cgroup node if present
		if p.Cgroup != "" {
			cgNodeID := GenerateNodeID(graph.NodeCgroup, p.Cgroup)
			_ = g.UpsertNode(graph.Node{
				ID:        cgNodeID,
				Type:      graph.NodeCgroup,
				Label:     fmt.Sprintf("cgroup:%s", p.Cgroup),
				Certainty: graph.CertaintyObserved,
				FirstSeen: now,
				LastSeen:  now,
				Evidence:  it.Evidence,
			})

			edgeID := GenerateEdgeID(cgNodeID, procNodeID, "member_of")
			_ = g.UpsertEdge(graph.Edge{
				ID:         edgeID,
				SourceID:   cgNodeID,
				TargetID:   procNodeID,
				Relation:   "member_of",
				Certainty:  graph.CertaintyObserved,
				Confidence: 1.0,
			})

			// Extract service unit from cgroup (e.g. /system.slice/nginx.service -> nginx.service)
			if idx := strings.Index(p.Cgroup, ".service"); idx != -1 {
				unitStart := strings.LastIndex(p.Cgroup[:idx], "/")
				if unitStart != -1 {
					unitName := p.Cgroup[unitStart+1 : idx+8]
					svcNodeID := GenerateNodeID(graph.NodeService, unitName)
					_ = g.UpsertNode(graph.Node{
						ID:        svcNodeID,
						Type:      graph.NodeService,
						Label:     unitName,
						Certainty: graph.CertaintyDerived,
						FirstSeen: now,
						LastSeen:  now,
						Evidence:  it.Evidence,
					})

					procToSvcEdgeID := GenerateEdgeID(procNodeID, svcNodeID, "runs")
					_ = g.UpsertEdge(graph.Edge{
						ID:         procToSvcEdgeID,
						SourceID:   procNodeID,
						TargetID:   svcNodeID,
						Relation:   "runs",
						Certainty:  graph.CertaintyDerived,
						Confidence: 1.0,
					})
				}
			}
		}

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

			// Origin resolution: wire file -> origin
			g.resolveAndWireOrigin(p.Exe, fileNodeID, now)
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

func (g *ProvenanceGraph) resolveAndWireOrigin(filePath string, fileNodeID string, now time.Time) {
	g.mu.RLock()
	resolver := g.originResolver
	g.mu.RUnlock()

	if resolver == nil {
		return
	}

	orig := resolver.Resolve(nil, filePath)
	originLabel := fmt.Sprintf("%s:%s", orig.Kind, orig.Source)
	if orig.Kind == origin.KindManual {
		originLabel = "manual"
	}
	originNodeID := GenerateNodeID(graph.NodeOrigin, originLabel)

	_ = g.UpsertNode(graph.Node{
		ID:        originNodeID,
		Type:      graph.NodeOrigin,
		Label:     originLabel,
		Certainty: orig.Certainty,
		Properties: map[string]any{
			"kind":       orig.Kind,
			"source":     orig.Source,
			"version":    orig.Version,
			"confidence": orig.Confidence,
		},
		Evidence:  orig.Evidence,
		FirstSeen: now,
		LastSeen:  now,
	})

	edgeID := GenerateEdgeID(originNodeID, fileNodeID, "installed_by")
	_ = g.UpsertEdge(graph.Edge{
		ID:         edgeID,
		SourceID:   originNodeID,
		TargetID:   fileNodeID,
		Relation:   "installed_by",
		Certainty:  orig.Certainty,
		Confidence: orig.Confidence,
	})
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
				"active_state":   u.ActiveState,
				"unit_file":      u.UnitFile,
				"exec_start":     u.ExecStart,
				"restart_count":  u.RestartCount,
				"world_writable": u.WorldWritable,
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
		if it.Type == "network_report" {
			if rep, ok := it.Data.(network.NetworkReport); ok {
				for _, cg := range rep.ConnectionGroups {
					connID := GenerateNodeID(graph.NodeConnection, fmt.Sprintf("%s:%d", cg.RemoteIP, cg.PID))
					_ = g.UpsertNode(graph.Node{
						ID:    connID,
						Type:  graph.NodeConnection,
						Label: fmt.Sprintf("conn:%s (count %d)", cg.RemoteIP, cg.Count),
						Properties: map[string]any{
							"remote_ip":    cg.RemoteIP,
							"pid":          cg.PID,
							"process_name": cg.ProcessName,
							"count":        cg.Count,
						},
						Evidence:  it.Evidence,
						Certainty: graph.CertaintyObserved,
						FirstSeen: now,
						LastSeen:  now,
					})

					if cg.PID > 0 {
						procNodeID := GenerateNodeID(graph.NodeProcess, fmt.Sprintf("%d:%s", cg.PID, cg.ProcessName))
						_ = g.UpsertNode(graph.Node{
							ID:        procNodeID,
							Type:      graph.NodeProcess,
							Label:     fmt.Sprintf("%s (pid %d)", cg.ProcessName, cg.PID),
							Certainty: graph.CertaintyObserved,
							FirstSeen: now,
							LastSeen:  now,
						})

						edgeID := GenerateEdgeID(procNodeID, connID, "communicates_with")
						_ = g.UpsertEdge(graph.Edge{
							ID:         edgeID,
							SourceID:   procNodeID,
							TargetID:   connID,
							Relation:   "communicates_with",
							Certainty:  graph.CertaintyObserved,
							Confidence: 1.0,
						})
					}
				}
			}
			continue
		}

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

func (g *ProvenanceGraph) ingestStorage(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		m, ok := it.Data.(storage.MountInfo)
		if !ok {
			continue
		}

		resNodeID := GenerateNodeID(graph.NodeResource, fmt.Sprintf("mount:%s", m.MountPoint))
		_ = g.UpsertNode(graph.Node{
			ID:    resNodeID,
			Type:  graph.NodeResource,
			Label: fmt.Sprintf("mount %s (%s)", m.MountPoint, m.FSType),
			Properties: map[string]any{
				"mount_point": m.MountPoint,
				"device":      m.Device,
				"fs_type":     m.FSType,
				"total_bytes": m.TotalBytes,
				"used_bytes":  m.UsedBytes,
				"usage_ratio": m.UsageRatio,
				"read_only":   m.ReadOnly,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}

func (g *ProvenanceGraph) ingestResources(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		s, ok := it.Data.(resources.ResourceSample)
		if !ok {
			continue
		}

		resNodeID := GenerateNodeID(graph.NodeResource, "system:load")
		_ = g.UpsertNode(graph.Node{
			ID:    resNodeID,
			Type:  graph.NodeResource,
			Label: fmt.Sprintf("loadavg: %.2f %.2f %.2f", s.Load1, s.Load5, s.Load15),
			Properties: map[string]any{
				"load1":            s.Load1,
				"load5":            s.Load5,
				"load15":           s.Load15,
				"running_tasks":    s.RunningTasks,
				"mem_usage_ratio":  s.MemUsageRatio,
				"swap_usage_ratio": s.SwapUsageRatio,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}

func (g *ProvenanceGraph) ingestContainer(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		c, ok := it.Data.(container.ContainerInfo)
		if !ok {
			continue
		}

		cNodeID := GenerateNodeID(graph.NodeContainer, c.ID)
		name := c.ID
		if len(c.Names) > 0 {
			name = c.Names[0]
		}

		_ = g.UpsertNode(graph.Node{
			ID:    cNodeID,
			Type:  graph.NodeContainer,
			Label: fmt.Sprintf("container:%s (%s)", name, c.Image),
			Properties: map[string]any{
				"id":      c.ID,
				"image":   c.Image,
				"state":   c.State,
				"runtime": c.Runtime,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}

func (g *ProvenanceGraph) ingestUser(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		u, ok := it.Data.(user.UserData)
		if !ok {
			continue
		}

		uNodeID := GenerateNodeID(graph.NodeUser, fmt.Sprintf("uid:%d", u.UID))
		oldestKeyAge := 0
		for _, k := range u.AuthorizedKeys {
			if k.AgeDays > oldestKeyAge {
				oldestKeyAge = k.AgeDays
			}
		}

		_ = g.UpsertNode(graph.Node{
			ID:    uNodeID,
			Type:  graph.NodeUser,
			Label: fmt.Sprintf("user:%s (uid %d)", u.Username, u.UID),
			Properties: map[string]any{
				"username":            u.Username,
				"uid":                 u.UID,
				"gid":                 u.GID,
				"home_dir":            u.HomeDir,
				"shell":               u.Shell,
				"has_sudo":            u.HasSudo,
				"keys_count":          len(u.AuthorizedKeys),
				"oldest_key_age_days": oldestKeyAge,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}

func (g *ProvenanceGraph) ingestScheduler(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		j, ok := it.Data.(scheduler.ScheduledJob)
		if !ok {
			continue
		}

		jobNodeID := GenerateNodeID(graph.NodeService, fmt.Sprintf("sched:%s:%s", j.Type, j.Command))
		_ = g.UpsertNode(graph.Node{
			ID:    jobNodeID,
			Type:  graph.NodeService,
			Label: fmt.Sprintf("scheduled:%s (%s)", j.Type, j.Schedule),
			Properties: map[string]any{
				"schedule_type": j.Type,
				"schedule":      j.Schedule,
				"command":       j.Command,
				"user":          j.User,
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}

func (g *ProvenanceGraph) ingestKernel(obs sensors.Observation, now time.Time) {
	for _, it := range obs.Items {
		k, ok := it.Data.(kernel.KernelData)
		if !ok {
			continue
		}

		kernelNodeID := GenerateNodeID(graph.NodeSystem, "system:kernel")
		_ = g.UpsertNode(graph.Node{
			ID:    kernelNodeID,
			Type:  graph.NodeSystem,
			Label: fmt.Sprintf("kernel:%s", k.RunningKernel),
			Properties: map[string]any{
				"running_kernel":    k.RunningKernel,
				"reboot_required":   k.RebootRequired,
				"reclaimable_count": len(k.Reclaimable),
				"installed_count":   len(k.InstalledKernels),
			},
			Evidence:  it.Evidence,
			Certainty: graph.CertaintyObserved,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
}
