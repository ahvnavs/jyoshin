// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package resource defines the unified declarative resource model for Kazeshini.
package resource

import (
	"errors"
	"fmt"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
)

// Kind identifies the declarative kind of a resource.
type Kind string

const (
	KindHost     Kind = "Host"
	KindPackage  Kind = "Package"
	KindService  Kind = "Service"
	KindPort     Kind = "Port"
	KindProcess  Kind = "Process"
	KindPlatform Kind = "Platform"
	KindCheck    Kind = "Check"
	KindPlan     Kind = "Plan"
	KindPolicy   Kind = "Policy"
	KindEvent    Kind = "Event"
)

// Condition represents an observed condition on a resource.
type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"` // "True", "False", "Unknown"
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// Metadata captures identity, ownership, and classification.
type Metadata struct {
	Labels    map[string]string `json:"labels,omitempty"`
	Owner     string            `json:"owner,omitempty"`
	CreatedBy string            `json:"createdBy,omitempty"`
}

// Status captures runtime observations and conditions.
type Status struct {
	Conditions []Condition `json:"conditions,omitempty"`
	ObservedAt time.Time   `json:"observedAt"`
}

// Resource is the core declarative resource container.
type Resource struct {
	Kind       Kind             `json:"kind"`
	Name       string           `json:"name"`
	Metadata   Metadata         `json:"metadata"`
	Spec       map[string]any   `json:"spec,omitempty"`
	Status     Status           `json:"status"`
	Provenance []graph.Evidence `json:"provenance,omitempty"`
}

// Validate checks resource structural integrity.
func (r Resource) Validate() error {
	if r.Kind == "" {
		return errors.New("resource kind is required")
	}
	if r.Name == "" {
		return errors.New("resource name is required")
	}
	return nil
}

// FromGraphNode maps an internal graph.Node onto a unified Resource without breaking APIs.
func FromGraphNode(n graph.Node) Resource {
	var k Kind
	switch n.Type {
	case graph.NodeSystem:
		k = KindHost
	case graph.NodePackage, graph.NodeOrigin:
		k = KindPackage
	case graph.NodeService:
		k = KindService
	case graph.NodePort:
		k = KindPort
	case graph.NodeProcess:
		k = KindProcess
	case graph.NodeContainer, graph.NodeCgroup:
		k = KindPlatform
	default:
		k = KindHost
	}

	labels := make(map[string]string)
	labels["graph_id"] = n.ID
	labels["graph_type"] = string(n.Type)
	labels["certainty"] = string(n.Certainty)

	return Resource{
		Kind: k,
		Name: n.Label,
		Metadata: Metadata{
			Labels:    labels,
			CreatedBy: "sensor",
		},
		Spec: n.Properties,
		Status: Status{
			ObservedAt: n.LastSeen,
			Conditions: []Condition{
				{
					Type:               "Observed",
					Status:             "True",
					Reason:             fmt.Sprintf("Certainty%s", n.Certainty),
					LastTransitionTime: n.LastSeen,
				},
			},
		},
		Provenance: n.Evidence,
	}
}

// ToGraphNode converts a Resource back to a graph.Node representation.
func (r Resource) ToGraphNode() graph.Node {
	var nt graph.NodeType
	switch r.Kind {
	case KindHost:
		nt = graph.NodeSystem
	case KindPackage:
		nt = graph.NodePackage
	case KindService:
		nt = graph.NodeService
	case KindPort:
		nt = graph.NodePort
	case KindProcess:
		nt = graph.NodeProcess
	case KindPlatform:
		nt = graph.NodeContainer
	default:
		nt = graph.NodeResource
	}

	id := r.Name
	cert := graph.CertaintyObserved
	if r.Metadata.Labels != nil {
		if gid, ok := r.Metadata.Labels["graph_id"]; ok && gid != "" {
			id = gid
		}
		if c, ok := r.Metadata.Labels["certainty"]; ok && graph.Certainty(c).IsValid() {
			cert = graph.Certainty(c)
		}
	}

	obsAt := r.Status.ObservedAt
	if obsAt.IsZero() {
		obsAt = time.Now().UTC()
	}

	return graph.Node{
		ID:         id,
		Type:       nt,
		Label:      r.Name,
		Properties: r.Spec,
		Evidence:   r.Provenance,
		Certainty:  cert,
		FirstSeen:  obsAt,
		LastSeen:   obsAt,
	}
}
