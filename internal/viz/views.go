// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"fmt"
	"sort"
	"strings"
)

// StorageNode models a filesystem mount or storage entity for treemap and terminal rendering.
type StorageNode struct {
	Name       string         `json:"name"`
	MountPoint string         `json:"mount_point"`
	Device     string         `json:"device"`
	FSType     string         `json:"fs_type"`
	TotalBytes uint64         `json:"total_bytes"`
	UsedBytes  uint64         `json:"used_bytes"`
	FreeBytes  uint64         `json:"free_bytes"`
	UsageRatio float64        `json:"usage_ratio"`
	Children   []*StorageNode `json:"children,omitempty"`
}

// RenderStorageTerminal outputs a deterministic ASCII treemap table for the terminal.
func RenderStorageTerminal(mounts []StorageNode, cols int) string {
	if cols <= 0 {
		cols = 80
	}
	var sb strings.Builder

	sb.WriteString("======================================================================\n")
	sb.WriteString("風死 · KAZESHINI — STORAGE TREEMAP & ALLOCATION\n")
	sb.WriteString("----------------------------------------------------------------------\n")
	fmt.Fprintf(&sb, "%-20s | %-12s | %-10s | %-8s | %s\n", "MOUNTPOINT", "USED / TOTAL", "PERCENT", "TYPE", "DEVICE")
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	sort.Slice(mounts, func(i, j int) bool {
		return mounts[i].UsedBytes > mounts[j].UsedBytes
	})

	for _, m := range mounts {
		usedGB := float64(m.UsedBytes) / (1024 * 1024 * 1024)
		totalGB := float64(m.TotalBytes) / (1024 * 1024 * 1024)
		pct := m.UsageRatio * 100.0

		// ASCII Bar representation
		barWidth := 15
		fillWidth := int((m.UsageRatio) * float64(barWidth))
		if fillWidth > barWidth {
			fillWidth = barWidth
		}
		bar := "[" + strings.Repeat("#", fillWidth) + strings.Repeat("-", barWidth-fillWidth) + "]"

		fmt.Fprintf(&sb, "%-20s | %5.1fG/%-5.1fG | %5.1f%% %-17s | %-8s | %s\n",
			m.MountPoint, usedGB, totalGB, pct, bar, m.FSType, m.Device)
	}
	sb.WriteString("======================================================================\n")

	return sb.String()
}

// NetworkSocketRow models a process x remote endpoint socket mapping.
type NetworkSocketRow struct {
	ProcessName string `json:"process_name"`
	PID         int    `json:"pid"`
	LocalPort   int    `json:"local_port"`
	Protocol    string `json:"protocol"`
	RemoteIP    string `json:"remote_ip"`
	RemotePort  int    `json:"remote_port"`
	State       string `json:"state"`
}

// RenderNetworkMatrixTerminal formats the network matrix for terminal view.
func RenderNetworkMatrixTerminal(rows []NetworkSocketRow, cols int) string {
	if cols <= 0 {
		cols = 80
	}
	var sb strings.Builder

	sb.WriteString("======================================================================\n")
	sb.WriteString("風死 · KAZESHINI — NETWORK MATRIX (PROCESS x REMOTE ENDPOINT)\n")
	sb.WriteString("----------------------------------------------------------------------\n")
	fmt.Fprintf(&sb, "%-16s | %-6s | %-5s | %-18s | %-20s | %s\n",
		"PROCESS", "PID", "PROTO", "LOCAL ENDPOINT", "REMOTE ENDPOINT", "STATE")
	sb.WriteString(strings.Repeat("-", 78) + "\n")

	if len(rows) == 0 {
		sb.WriteString("  No active socket descriptors observed.\n")
	} else {
		for _, r := range rows {
			loc := fmt.Sprintf(":%d", r.LocalPort)
			rem := fmt.Sprintf("%s:%d", r.RemoteIP, r.RemotePort)
			if r.RemoteIP == "" || r.RemotePort == 0 {
				rem = "*:*"
			}
			fmt.Fprintf(&sb, "%-16s | %-6d | %-5s | %-18s | %-20s | %s\n",
				r.ProcessName, r.PID, strings.ToUpper(r.Protocol), loc, rem, r.State)
		}
	}
	sb.WriteString("======================================================================\n")
	return sb.String()
}

