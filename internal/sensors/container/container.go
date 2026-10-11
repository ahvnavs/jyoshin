// Copyright 2026 Jyōshin Authors
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/OWNER/jyoshin/internal/fs"
	"github.com/OWNER/jyoshin/internal/graph"
	"github.com/OWNER/jyoshin/internal/sensors"
)

// ContainerInfo captures inspected metadata of a container.
type ContainerInfo struct {
	ID      string            `json:"id"`
	Names   []string          `json:"names"`
	Image   string            `json:"image"`
	ImageID string            `json:"image_id"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Runtime string            `json:"runtime"` // docker, podman, containerd
	Created int64             `json:"created"`
	Ports   []PortMapping     `json:"ports"`
	Mounts  []MountInfo       `json:"mounts"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type PortMapping struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort uint16 `json:"private_port"`
	PublicPort  uint16 `json:"public_port,omitempty"`
	Type        string `json:"type"` // tcp, udp
}

type MountInfo struct {
	Type        string `json:"type"` // bind, volume
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

// Sensor inspects container engines read-only via standard Unix sockets or metadata.
type Sensor struct {
	fs fs.FS
}

func New(fs fs.FS) *Sensor {
	return &Sensor{fs: fs}
}

func (s *Sensor) Name() string {
	return "container"
}

func (s *Sensor) Interval() time.Duration {
	return 30 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	now := start.UTC()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
	}

	var items []sensors.Item

	// Probe standard read-only socket paths
	socketTargets := []struct {
		runtime string
		path    string
	}{
		{"docker", "/var/run/docker.sock"},
		{"podman", "/run/podman/podman.sock"},
		{"containerd", "/run/containerd/containerd.sock"},
	}

	for _, target := range socketTargets {
		realSocket := s.fs.Path(target.path)
		if fi, err := s.fs.Stat(target.path); err == nil && (fi.Mode()&osModeSocket != 0 || fi.Mode().Type() == osModeSocket) {
			containers, err := s.fetchContainersHTTP(ctx, realSocket, target.runtime)
			if err == nil {
				for _, c := range containers {
					items = append(items, sensors.Item{
						ID:   fmt.Sprintf("container:%s:%s", target.runtime, c.ID),
						Type: "container",
						Data: c,
						Evidence: []graph.Evidence{
							{
								Source:    target.path,
								Collector: "container",
								Raw:       fmt.Sprintf("%s container %s (%s)", target.runtime, c.ID[:min(12, len(c.ID))], c.Image),
								Timestamp: now,
								Certainty: graph.CertaintyObserved,
							},
						},
						Certainty: graph.CertaintyObserved,
					})
				}
			}
		}
	}

	obs.Items = items
	obs.Duration = time.Since(start)
	return obs, nil
}

const osModeSocket = 1 << (32 - 1 - 7) // os.ModeSocket

func (s *Sensor) fetchContainersHTTP(ctx context.Context, socketPath, runtime string) ([]ContainerInfo, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/containers/json?all=1", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var rawList []struct {
		ID      string   `json:"Id"`
		Names   []string `json:"Names"`
		Image   string   `json:"Image"`
		ImageID string   `json:"ImageID"`
		State   string   `json:"State"`
		Status  string   `json:"Status"`
		Created int64    `json:"Created"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort uint16 `json:"PrivatePort"`
			PublicPort  uint16 `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			Mode        string `json:"Mode"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		Labels map[string]string `json:"Labels"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawList); err != nil {
		return nil, err
	}

	var result []ContainerInfo
	for _, raw := range rawList {
		c := ContainerInfo{
			ID:      raw.ID,
			Names:   raw.Names,
			Image:   raw.Image,
			ImageID: raw.ImageID,
			State:   raw.State,
			Status:  raw.Status,
			Runtime: runtime,
			Created: raw.Created,
			Labels:  raw.Labels,
		}
		for _, p := range raw.Ports {
			c.Ports = append(c.Ports, PortMapping{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			})
		}
		for _, m := range raw.Mounts {
			c.Mounts = append(c.Mounts, MountInfo{
				Type:        m.Type,
				Source:      m.Source,
				Destination: m.Destination,
				Mode:        m.Mode,
				RW:          m.RW,
			})
		}
		result = append(result, c)
	}

	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
