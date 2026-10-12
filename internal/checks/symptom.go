// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"fmt"
	"strings"
)

// Symptom defines a human-facing problem scenario mapped to read-only checks.
type Symptom struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CheckIDs    []string `json:"check_ids"`
	Reasons     []string `json:"reasons"` // One-line reason per check in order
}

// SymptomExplanation pairs an observed result with potential causes.
type SymptomExplanation struct {
	CheckID       string `json:"check_id"`
	Title         string `json:"title"`
	Status        string `json:"status"`
	ObservedFact  string `json:"observed_fact"`  // What was directly seen
	PossibleCause string `json:"possible_cause"` // Inferred diagnostic explanation
}

// AvailableSymptoms returns the deterministic list of symptoms.
func AvailableSymptoms() []Symptom {
	return []Symptom{
		{
			ID:          "slow",
			Name:        "Something is slow",
			Description: "High CPU/memory utilization, kernel pressure stall, or thrashing disk IO",
			CheckIDs: []string{
				"cpu-memory",
				"disk-inodes",
				"app-health",
				"time-sync",
			},
			Reasons: []string{
				"Check CPU/memory load averages, PSI pressure, and top memory consumers",
				"Inspect disk capacity and inode saturation causing blocking IO",
				"Identify crashed or CPU-bound application units and socket bottlenecks",
				"Verify system clock synchronization to rule out leap-second or drift stalls",
			},
		},
		{
			ID:          "service-down",
			Name:        "Service down",
			Description: "Application daemon failed, stopped listening, or exited unexpectedly",
			CheckIDs: []string{
				"failed-services",
				"app-health",
				"app-logs",
				"service-permissions",
			},
			Reasons: []string{
				"Identify systemd units currently in a failed or degraded state",
				"Check whether required application processes and ports are running",
				"Inspect recent application logs for fatal errors and panic traces",
				"Check unit file and configuration permissions preventing startup",
			},
		},
		{
			ID:          "cant-connect",
			Name:        "Can't connect",
			Description: "Network listener unreachable, DNS failure, or interface routing issue",
			CheckIDs: []string{
				"listening-ports",
				"dns-config",
				"interfaces-routes",
				"app-health",
			},
			Reasons: []string{
				"Check if target network ports are actually open and bound to appropriate interfaces",
				"Inspect /etc/resolv.conf nameservers and DNS search configuration",
				"Verify network interfaces are UP and default IPv4/IPv6 routes exist",
				"Confirm the backend application process backing the port is active",
			},
		},
		{
			ID:          "disk-full",
			Name:        "Disk full",
			Description: "Filesystem space or inode exhaustion, or runaway container storage",
			CheckIDs: []string{
				"disk-inodes",
				"container-storage",
				"attached-storage",
				"app-logs",
			},
			Reasons: []string{
				"Inspect storage capacity and inode utilization across all mounted filesystems",
				"Check container engine storage (/var/lib/docker, containerd, kubelet)",
				"Check for unmounted block devices or fstab mount mismatches",
				"Check if application logs in /var/log or journal are consuming space",
			},
		},
		{
			ID:          "looks-hacked",
			Name:        "Looks hacked",
			Description: "Unexpected listening ports, unauthorized sudo access, suspicious SSH logins",
			CheckIDs: []string{
				"users-sudo",
				"ssh-settings",
				"auth-logs",
				"listening-ports",
				"service-permissions",
			},
			Reasons: []string{
				"Inspect user accounts, sudo/wheel membership, and NOPASSWD sudoers rules",
				"Audit sshd_config for root login, password auth, and empty passwords",
				"Inspect recent failed authentication attempts and brute-force sources",
				"Check for unexpected network sockets listening on external interfaces",
				"Audit service and configuration file permissions for world-writable paths",
			},
		},
	}
}

// FindSymptom looks up a symptom by id or name substring.
func FindSymptom(query string) (*Symptom, error) {
	q := strings.TrimSpace(strings.ToLower(query))
	syms := AvailableSymptoms()
	for i := range syms {
		if syms[i].ID == q || strings.Contains(strings.ToLower(syms[i].Name), q) {
			return &syms[i], nil
		}
	}
	return nil, fmt.Errorf("unknown symptom %q (available: slow, service-down, cant-connect, disk-full, looks-hacked)", query)
}

