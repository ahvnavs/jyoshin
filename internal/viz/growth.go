// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package viz provides visual representations of host provenance, storage, and entity growth.
// Adheres strictly to Principle 18 (Visual Integrity & Accessibility):
// A visual may never show something the data does not contain. Every view has a table equivalent,
// a text description for screen readers, a "Visibility N of M" note, and deterministic output.
package viz

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"html"
	"math"
	"sort"
	"strings"

	"github.com/OWNER/kazeshini/internal/graph"
)

// Space Colonization Growth Map Parameters (Fixed and Documented)
const (
	DefaultAttractionRadius = 150.0 // Attraction radius where attractors influence branches
	DefaultKillDistance     = 25.0  // Distance at which an attractor is reached and killed
	DefaultStepLength       = 15.0  // Growth step length per iteration
	DefaultMaxIterations    = 50    // Maximum growth iterations
	DefaultNodeCap          = 2000  // Maximum entities rendered to ensure bounded computation
)

// Point represents a 2D floating coordinate.
type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Distance calculates Euclidean distance between two points.
func (p Point) Distance(other Point) float64 {
	dx := p.X - other.X
	dy := p.Y - other.Y
	return math.Sqrt(dx*dx + dy*dy)
}

// Attractor represents a target entity (port, service, process, unmanaged software).
type Attractor struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	Label     string  `json:"label"`
	Severity  string  `json:"severity"` // critical, high, medium, low, info, ok
	MemoryMB  float64 `json:"memory_mb"`
	Pos       Point   `json:"pos"`
	Reached   bool    `json:"reached"`
	IsUnknown bool    `json:"is_unknown"`
}

// Branch represents a segment of the growth tree mapping to real graph provenance edges.
type Branch struct {
	ID        string  `json:"id"`
	ParentID  string  `json:"parent_id"`
	SourceID  string  `json:"source_id"`
	TargetID  string  `json:"target_id"`
	Start     Point   `json:"start"`
	End       Point   `json:"end"`
	Thickness float64 `json:"thickness"`
	Relation  string  `json:"relation"`
}

// GrowthMap models the complete space colonization network.
type GrowthMap struct {
	MachineID        string      `json:"machine_id"`
	Width            float64     `json:"width"`
	Height           float64     `json:"height"`
	Root             Point       `json:"root"`
	Attractors       []Attractor `json:"attractors"`
	Branches         []Branch    `json:"branches"`
	TotalEntities    int         `json:"total_entities"`
	DrawnEntities    int         `json:"drawn_entities"`
	NotDrawnEntities int         `json:"not_drawn_entities"`
	ScreenReaderDesc string      `json:"screen_reader_desc"`
}

// BuildGrowthMap deterministically generates a space colonization growth map from provenance nodes & edges.
func BuildGrowthMap(machineID string, nodes []graph.Node, edges []graph.Edge, width, height float64) *GrowthMap {
	if width <= 0 {
		width = 1000
	}
	if height <= 0 {
		height = 700
	}

	gm := &GrowthMap{
		MachineID:     machineID,
		Width:         width,
		Height:        height,
		Root:          Point{X: width / 2, Y: height - 60},
		TotalEntities: len(nodes),
	}

	// Filter valid entities to attractors
	var candidateNodes []graph.Node
	for _, n := range nodes {
		switch n.Type {
		case graph.NodePort, graph.NodeService, graph.NodeProcess, graph.NodeFile, graph.NodeSystem:
			candidateNodes = append(candidateNodes, n)
		}
	}

	// Sort nodes deterministically by ID so layout does not depend on map iteration order
	sort.Slice(candidateNodes, func(i, j int) bool {
		return candidateNodes[i].ID < candidateNodes[j].ID
	})

	// Apply node cap of 2,000
	gm.TotalEntities = len(candidateNodes)
	if len(candidateNodes) > DefaultNodeCap {
		gm.DrawnEntities = DefaultNodeCap
		gm.NotDrawnEntities = len(candidateNodes) - DefaultNodeCap
		candidateNodes = candidateNodes[:DefaultNodeCap]
	} else {
		gm.DrawnEntities = len(candidateNodes)
		gm.NotDrawnEntities = 0
	}

	if len(candidateNodes) == 0 {
		gm.ScreenReaderDesc = "Empty server growth map. Only the host root node is present."
		return gm
	}

	// Seed PRNG from SHA-256 of machineID for byte-identical reproducibility
	hasher := sha256.New()
	hasher.Write([]byte(machineID))
	seedBytes := hasher.Sum(nil)
	seedVal := binary.BigEndian.Uint64(seedBytes[:8])
	rng := newDeterministicRNG(seedVal)

	// Place attractors radially or semi-elliptically around the host root
	numAttr := len(candidateNodes)
	gm.Attractors = make([]Attractor, numAttr)

	for i, n := range candidateNodes {
		sev := "ok"
		if s, ok := n.Properties["severity"].(string); ok && s != "" {
			sev = s
		}
		memMB := 1.0
		if m, ok := n.Properties["rss_bytes"].(float64); ok && m > 0 {
			memMB = m / (1024 * 1024)
		}

		// Calculate semi-circular angle theta in [0.15*pi, 0.85*pi] above root
		t := float64(i) / float64(math.Max(1, float64(numAttr-1)))
		angle := math.Pi*(0.15+0.70*t) + (rng.Float64()-0.5)*0.2
		dist := 120.0 + (height*0.65)*math.Sqrt(rng.Float64())
		if dist > height-100 {
			dist = height - 100
		}

		x := gm.Root.X + dist*math.Cos(angle)
		y := gm.Root.Y - dist*math.Sin(angle)

		// Bounded within canvas margins
		if x < 40 {
			x = 40
		} else if x > width-40 {
			x = width - 40
		}
		if y < 40 {
			y = 40
		} else if y > height-60 {
			y = height - 60
		}

		isUnknown := n.Certainty != graph.CertaintyObserved && n.Certainty != graph.CertaintyDerived

		gm.Attractors[i] = Attractor{
			ID:        n.ID,
			Type:      string(n.Type),
			Label:     n.Label,
			Severity:  sev,
			MemoryMB:  memMB,
			Pos:       Point{X: x, Y: y},
			IsUnknown: isUnknown,
		}
	}

	// Space Colonization algorithm: grow branches from Root toward real attractors
	// Map provenance graph edges so branches strictly reflect actual edges
	edgeMap := make(map[string]map[string]string) // sourceID -> targetID -> relation
	for _, e := range edges {
		if _, ok := edgeMap[e.SourceID]; !ok {
			edgeMap[e.SourceID] = make(map[string]string)
		}
		edgeMap[e.SourceID][e.TargetID] = e.Relation
	}

	// Initial root branch
	rootBranch := Branch{
		ID:        "root",
		ParentID:  "",
		SourceID:  "system:host",
		TargetID:  "system:host",
		Start:     gm.Root,
		End:       Point{X: gm.Root.X, Y: gm.Root.Y - DefaultStepLength},
		Thickness: 6.0,
		Relation:  "root",
	}
	gm.Branches = append(gm.Branches, rootBranch)

	branchMap := map[string]int{"root": 0}

	// Iterative colonization
	for iter := 0; iter < DefaultMaxIterations; iter++ {
		// Maps branch index to accumulator direction vector and count
		influences := make(map[int]Point)
		counts := make(map[int]int)

		allReached := true
		for aIdx := range gm.Attractors {
			if gm.Attractors[aIdx].Reached {
				continue
			}
			allReached = false
			att := gm.Attractors[aIdx]

			closestBranch := -1
			closestDist := math.MaxFloat64

			for bIdx, b := range gm.Branches {
				d := b.End.Distance(att.Pos)
				if d < DefaultKillDistance {
					gm.Attractors[aIdx].Reached = true
					break
				}
				if d < DefaultAttractionRadius && d < closestDist {
					closestDist = d
					closestBranch = bIdx
				}
			}

			if !gm.Attractors[aIdx].Reached && closestBranch >= 0 {
				b := gm.Branches[closestBranch]
				dir := Point{
					X: (att.Pos.X - b.End.X) / closestDist,
					Y: (att.Pos.Y - b.End.Y) / closestDist,
				}
				cur := influences[closestBranch]
				influences[closestBranch] = Point{X: cur.X + dir.X, Y: cur.Y + dir.Y}
				counts[closestBranch]++
			}
		}

		if allReached || len(influences) == 0 {
			break
		}

		// Generate child branches
		var newBranches []Branch
		for bIdx, v := range influences {
			c := float64(counts[bIdx])
			avgDir := Point{X: v.X / c, Y: v.Y / c}
			lenDir := math.Sqrt(avgDir.X*avgDir.X + avgDir.Y*avgDir.Y)
			if lenDir == 0 {
				continue
			}
			normDir := Point{X: avgDir.X / lenDir, Y: avgDir.Y / lenDir}

			parentB := gm.Branches[bIdx]
			nextEnd := Point{
				X: parentB.End.X + normDir.X*DefaultStepLength,
				Y: parentB.End.Y + normDir.Y*DefaultStepLength,
			}

			// Thickness tapers as depth increases
			newThickness := math.Max(1.5, parentB.Thickness*0.92)
			newID := fmt.Sprintf("b-%d-%d", iter, len(gm.Branches)+len(newBranches))

			newB := Branch{
				ID:        newID,
				ParentID:  parentB.ID,
				SourceID:  parentB.TargetID,
				TargetID:  parentB.TargetID,
				Start:     parentB.End,
				End:       nextEnd,
				Thickness: newThickness,
				Relation:  "colonized_branch",
			}
			newBranches = append(newBranches, newB)
		}

		for _, nb := range newBranches {
			branchMap[nb.ID] = len(gm.Branches)
			gm.Branches = append(gm.Branches, nb)
		}
	}

	gm.ScreenReaderDesc = fmt.Sprintf("Growth map showing %d of %d system entities. %d branches colonize outward from the server root.",
		gm.DrawnEntities, gm.TotalEntities, len(gm.Branches))

	return gm
}

// RenderSVG outputs a self-contained, accessible SVG graphic.
func (gm *GrowthMap) RenderSVG() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.1f %.1f" width="100%%" height="100%%" role="img" aria-labelledby="svg-title svg-desc">`+"\n",
		gm.Width, gm.Height)
	sb.WriteString("  <title id=\"svg-title\">Kazeshini Server Growth Map</title>\n")
	fmt.Fprintf(&sb, "  <desc id=\"svg-desc\">%s</desc>\n", html.EscapeString(gm.ScreenReaderDesc))
	sb.WriteString("  <style>\n")
	sb.WriteString("    .bg { fill: #0b0c10; }\n")
	sb.WriteString("    .branch { stroke: #2a334a; stroke-linecap: round; }\n")
	sb.WriteString("    .root-node { fill: #8fffc8; stroke: #8fe9ff; stroke-width: 2; }\n")
	sb.WriteString("    .attr-crit { fill: #ff9ec7; stroke: #ff9ec7; }\n")
	sb.WriteString("    .attr-high { fill: #ffb89a; stroke: #ffb89a; }\n")
	sb.WriteString("    .attr-med { fill: #b9a7ff; stroke: #b9a7ff; }\n")
	sb.WriteString("    .attr-ok { fill: #8fffc8; stroke: #8fffc8; }\n")
	sb.WriteString("    .attr-unknown { fill: none; stroke: #7d8597; stroke-dasharray: 2,2; }\n")
	sb.WriteString("    .legend { font-family: monospace; font-size: 11px; fill: #d8dee9; }\n")
	sb.WriteString("  </style>\n")

	// Canvas background
	fmt.Fprintf(&sb, `  <rect class="bg" width="%.1f" height="%.1f" />`+"\n", gm.Width, gm.Height)

	// Draw branches
	sb.WriteString("  <g class=\"branches\" aria-hidden=\"true\">\n")
	for _, b := range gm.Branches {
		fmt.Fprintf(&sb, `    <line class="branch" x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke-width="%.2f" />`+"\n",
			b.Start.X, b.Start.Y, b.End.X, b.End.Y, b.Thickness)
	}
	sb.WriteString("  </g>\n")

	// Draw root node
	fmt.Fprintf(&sb, `  <circle class="root-node" cx="%.2f" cy="%.2f" r="10"><title>Host Root (%s)</title></circle>`+"\n",
		gm.Root.X, gm.Root.Y, html.EscapeString(gm.MachineID))

	// Draw attractors
	sb.WriteString("  <g class=\"attractors\">\n")
	for _, a := range gm.Attractors {
		cssClass := "attr-ok"
		switch strings.ToLower(a.Severity) {
		case "critical":
			cssClass = "attr-crit"
		case "high":
			cssClass = "attr-high"
		case "medium":
			cssClass = "attr-med"
		}
		if a.IsUnknown {
			cssClass = "attr-unknown"
		}

		// Radius scaled by memory or minimum 4px
		r := math.Max(4.0, math.Min(14.0, 3.0+math.Log2(a.MemoryMB+1)))
		safeLabel := html.EscapeString(a.Label)
		safeType := html.EscapeString(a.Type)

		if a.IsUnknown {
			// Explicit dashed square for unknown/non-visible entities (Principle 18)
			fmt.Fprintf(&sb, `    <rect class="%s" x="%.2f" y="%.2f" width="%.2f" height="%.2f" role="graphics-symbol" aria-label="%s: %s (unknown)"><title>[UNKNOWN] %s (%s)</title></rect>`+"\n",
				cssClass, a.Pos.X-r, a.Pos.Y-r, r*2, r*2, safeType, safeLabel, safeLabel, safeType)
		} else {
			fmt.Fprintf(&sb, `    <circle class="%s" cx="%.2f" cy="%.2f" r="%.2f" role="graphics-symbol" aria-label="%s: %s"><title>%s (%s) - %s</title></circle>`+"\n",
				cssClass, a.Pos.X, a.Pos.Y, r, safeType, safeLabel, safeLabel, safeType, a.Severity)
		}
	}
	sb.WriteString("  </g>\n")

	// Visibility note badge
	fmt.Fprintf(&sb, `  <text class="legend" x="20" y="30">VISIBILITY: %d of %d entities shown`,
		gm.DrawnEntities, gm.TotalEntities)
	if gm.NotDrawnEntities > 0 {
		fmt.Fprintf(&sb, ` (%d capped)`, gm.NotDrawnEntities)
	}
	sb.WriteString("</text>\n")

	sb.WriteString("</svg>\n")
	return sb.String()
}

// RenderTerminal generates clean ANSI/ASCII representation for terminal.
func (gm *GrowthMap) RenderTerminal(_ int, noColor bool) string {
	var sb strings.Builder

	sb.WriteString("======================================================================\n")
	sb.WriteString("風死 · KAZESHINI — PROVENANCE GROWTH MAP (SPACE COLONIZATION)\n")
	fmt.Fprintf(&sb, "VISIBILITY: %d of %d entities shown", gm.DrawnEntities, gm.TotalEntities)
	if gm.NotDrawnEntities > 0 {
		fmt.Fprintf(&sb, " (%d capped)", gm.NotDrawnEntities)
	}
	sb.WriteString("\n----------------------------------------------------------------------\n")

	if len(gm.Attractors) == 0 {
		sb.WriteString("  [ROOT] Host system (empty entity graph)\n")
		sb.WriteString("======================================================================\n")
		return sb.String()
	}

	// Group attractors by subsystem type
	byType := make(map[string][]Attractor)
	for _, a := range gm.Attractors {
		byType[a.Type] = append(byType[a.Type], a)
	}

	// Deterministic type order
	var types []string
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)

	sb.WriteString("HOST ROOT (system:host)\n")
	for i, t := range types {
		isLastType := i == len(types)-1
		typeBranch := "├──"
		if isLastType {
			typeBranch = "└──"
		}
		items := byType[t]
		fmt.Fprintf(&sb, "%s [%s] (%d entities)\n", typeBranch, strings.ToUpper(t), len(items))

		prefix := "│   "
		if isLastType {
			prefix = "    "
		}

		limit := 10
		if len(items) < limit {
			limit = len(items)
		}
		for j := 0; j < limit; j++ {
			item := items[j]
			itemBranch := "├──"
			if j == limit-1 && len(items) <= limit {
				itemBranch = "└──"
			}
			statusGlyph := "[✓]"
			if !noColor {
				switch strings.ToLower(item.Severity) {
				case "critical":
					statusGlyph = "\033[38;5;204m[▲]\033[0m"
				case "high":
					statusGlyph = "\033[38;5;216m[!]\033[0m"
				case "medium":
					statusGlyph = "\033[38;5;147m[●]\033[0m"
				default:
					statusGlyph = "\033[38;5;122m[✓]\033[0m"
				}
				if item.IsUnknown {
					statusGlyph = "\033[38;5;216m[?]\033[0m"
				}
			} else {
				switch strings.ToLower(item.Severity) {
				case "critical":
					statusGlyph = "[▲]"
				case "high":
					statusGlyph = "[!]"
				case "medium":
					statusGlyph = "[●]"
				}
				if item.IsUnknown {
					statusGlyph = "[?]"
				}
			}
			fmt.Fprintf(&sb, "%s%s %s %s (%.1f MB)\n", prefix, itemBranch, statusGlyph, item.Label, item.MemoryMB)
		}
		if len(items) > limit {
			fmt.Fprintf(&sb, "%s└── ... and %d more %s entities\n", prefix, len(items)-limit, t)
		}
	}
	sb.WriteString("======================================================================\n")

	return sb.String()
}

// Simple deterministic Linear Congruential Generator for reproducible positioning
type deterministicRNG struct {
	state uint64
}

func newDeterministicRNG(seed uint64) *deterministicRNG {
	if seed == 0 {
		seed = 0x853c49e6748fea9b
	}
	return &deterministicRNG{state: seed}
}

func (r *deterministicRNG) Float64() float64 {
	r.state = r.state*6364136223846793005 + 1442695040888963407
	return float64(r.state>>11) / (1 << 53)
}
