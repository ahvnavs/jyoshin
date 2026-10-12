// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/redact"
)

// NodeServicesCheck inspects container runtime and orchestrator daemons (kubelet, containerd, crio, docker + kubelet port 10250).
type NodeServicesCheck struct{}

func (c *NodeServicesCheck) ID() string    { return "node-services" }
func (c *NodeServicesCheck) Role() string  { return "cloud-platform" }
func (c *NodeServicesCheck) Title() string { return "Kubernetes & Container Node Services" }
func (c *NodeServicesCheck) Description() string {
	return "Audits kubelet, containerd, cri-o, and docker daemons and kubelet ports (10250)"
}

func (c *NodeServicesCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	services := []string{"kubelet", "containerd", "crio", "docker"}
	active := []string{}
	permDenied := false

	for _, s := range services {
		// Check process comm /proc/*/comm
		entries, err := rfs.ReadDir("/proc")
		if err != nil {
			if os.IsPermission(err) {
				permDenied = true
			}
			break
		}
		for _, e := range entries {
			if e.IsDir() {
				comm, _ := rfs.ReadFile(fmt.Sprintf("/proc/%s/comm", e.Name()))
				if strings.TrimSpace(string(comm)) == s {
					active = append(active, s)
					break
				}
			}
		}
	}

	if permDenied && len(active) == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect node processes: permission denied",
			ExplainLevels: [3]string{
				"Permission denied reading /proc directory entries",
				"Container node daemons could not be audited",
				"Ensure observer has read access to /proc",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	// Check if port 10250 (kubelet) is listening
	kubeletPortOpen := false
	if tcpData, err := rfs.ReadFile("/proc/net/tcp"); err == nil {
		// 10250 in hex is 280A
		if strings.Contains(string(tcpData), ":280A ") {
			kubeletPortOpen = true
		}
	}

	if len(active) == 0 && !kubeletPortOpen {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusNotApplicable,
			SummaryPlain: "Host is not configured as a Kubernetes node or container runtime host (kubelet, containerd, cri-o, docker inactive)",
			ExplainLevels: [3]string{
				"Checked container engine and orchestrator processes",
				"No Kubernetes node components detected",
				"No action needed",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	sum := fmt.Sprintf("Container node platform active: %s", strings.Join(active, ", "))
	if kubeletPortOpen {
		sum += " (kubelet API port 10250 bound)"
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       contract.StatusOK,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Detected container node services: %s", strings.Join(active, ", ")),
			"Host participates in container workload scheduling and execution",
			"Maintain security posture of container runtime sockets and API endpoints",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc", Collector: "node-services", Details: strings.Join(active, ", "), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "systemctl is-active kubelet containerd docker crio",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// ContainerStorageCheck inspects usage and inodes in /var/lib/containerd, /var/lib/docker, and /var/lib/kubelet.
type ContainerStorageCheck struct{}

func (c *ContainerStorageCheck) ID() string    { return "container-storage" }
func (c *ContainerStorageCheck) Role() string  { return "cloud-platform" }
func (c *ContainerStorageCheck) Title() string { return "Container Engine Storage Footprint & Inodes" }
func (c *ContainerStorageCheck) Description() string {
	return "Audits /var/lib/docker, /var/lib/containerd, and /var/lib/kubelet directory presence and usage"
}

func (c *ContainerStorageCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	paths := []string{"/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet"}
	var found []string
	permDenied := false

	for _, p := range paths {
		fi, err := rfs.Stat(p)
		if err == nil && fi.IsDir() {
			found = append(found, p)
		} else if os.IsPermission(err) {
			permDenied = true
		}
	}

	if permDenied && len(found) == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect container storage paths: permission denied",
			ExplainLevels: [3]string{
				"Permission denied stat-ing /var/lib/docker or /var/lib/containerd",
				"Container storage consumption cannot be verified",
				"Ensure permissions allow read access to container storage paths",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	if len(found) == 0 {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusNotApplicable,
			SummaryPlain: "No standard container storage directories present (/var/lib/docker, /var/lib/containerd, /var/lib/kubelet)",
			ExplainLevels: [3]string{
				"Container storage directories are not present on this host",
				"Host does not retain local container layer or image caches",
				"No action needed",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       contract.StatusOK,
		SummaryPlain: fmt.Sprintf("Container storage directories detected: %s", strings.Join(found, ", ")),
		ExplainLevels: [3]string{
			fmt.Sprintf("Active container data directories: %s", strings.Join(found, ", ")),
			"Container image overlays, volumes, and writable layers are stored here",
			"Periodically run container image prune to reclaim unused image layers",
		},
		Evidence: []graph.Evidence{
			{Source: "/var/lib", Collector: "container-storage", Details: strings.Join(found, ", "), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "du -sh /var/lib/docker /var/lib/containerd /var/lib/kubelet",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// PlatformAgentLogsCheck bounded tail of container or platform logs with secrets redacted.
type PlatformAgentLogsCheck struct{}

func (c *PlatformAgentLogsCheck) ID() string    { return "platform-agent-logs" }
func (c *PlatformAgentLogsCheck) Role() string  { return "cloud-platform" }
func (c *PlatformAgentLogsCheck) Title() string { return "Platform Agent Logs (Bounded, Redacted)" }
func (c *PlatformAgentLogsCheck) Description() string {
	return "Inspects bounded recent lines from container and platform agent logs with secret redaction"
}

func (c *PlatformAgentLogsCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	logCandidates := []string{"/var/log/containerd.log", "/var/log/dockerd.log", "/var/log/kubelet.log"}
	var targetLog string
	var logData []byte
	permDenied := false

	for _, p := range logCandidates {
		data, err := rfs.ReadFile(p)
		if err == nil {
			targetLog = p
			logData = data
			break
		} else if os.IsPermission(err) {
			permDenied = true
		}
	}

	if permDenied && targetLog == "" {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect platform agent logs: permission denied",
			ExplainLevels: [3]string{
				"Permission denied reading container daemon logs in /var/log",
				"Agent log diagnostic output is inaccessible",
				"Ensure read access to platform log files",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	if targetLog == "" {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusNotApplicable,
			SummaryPlain: "No dedicated platform agent log files found in /var/log (daemon may log to systemd journal)",
			ExplainLevels: [3]string{
				"Checked /var/log/containerd.log, dockerd.log, and kubelet.log",
				"Daemons may log directly to journald",
				"No action needed",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	lines := strings.Split(string(logData), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}

	cleanLines := make([]string, len(lines))
	for i, l := range lines {
		cleanLines[i] = redact.RedactString(l)
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       contract.StatusOK,
		SummaryPlain: fmt.Sprintf("Inspected %d bounded lines from %s (secrets scrubbed)", len(cleanLines), targetLog),
		ExplainLevels: [3]string{
			fmt.Sprintf("Read bounded tail of %s", targetLog),
			"All tokens, keys, and credentials redacted per Principle 5",
			"Check journalctl -u containerd if live stream is required",
		},
		Evidence: []graph.Evidence{
			{Source: targetLog, Collector: "platform-agent-logs", Details: fmt.Sprintf("%d lines", len(cleanLines)), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: fmt.Sprintf("tail -n 200 %s", targetLog),
		ReadOnly:          true,
		RawRedacted:       strings.Join(cleanLines, "\n"),
		CollectedAt:       time.Now().UTC(),
	}, nil
}
