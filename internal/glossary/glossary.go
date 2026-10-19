// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package glossary provides access to canonical definitions for all system terms
// (port, service, package, kernel, inode, unmanaged software, etc.) per docs/GLOSSARY.md.
package glossary

import (
	"strings"
)

// TermDefinition represents a multi-level explanation of a concept.
type TermDefinition struct {
	Term      string `json:"term"`
	Summary   string `json:"summary"`   // Plain-English sentence suitable for non-technical users
	Details   string `json:"details"`   // Operational details and context
	Technical string `json:"technical"` // Concrete technical specifications / procfs / syscall mechanics
}

var catalog = map[string]TermDefinition{
	"port": {
		Term:      "port",
		Summary:   "A port is like a door for network traffic. Programs use it to talk to other computers.",
		Details:   "When a program wants to communicate over the network, it opens a port (e.g. 80 for websites, 22 for remote login). Listening ports reachable on all interfaces are accessible to outside callers.",
		Technical: "Represented in /proc/net/tcp and /proc/net/udp as hexadecimal socket descriptors bound to local IP addresses and ports.",
	},
	"service": {
		Term:      "service",
		Summary:   "A service is a background program. It starts up and runs tasks for the server.",
		Details:   "Services manage web servers, databases, and system tasks. If a service crashes or enters a degraded state, users or other applications may be unable to connect.",
		Technical: "Supervised by the init daemon (systemd, OpenRC). Tracked via systemd D-Bus and unit state files in /run/systemd/system.",
	},
	"package": {
		Term:      "package",
		Summary:   "A package is a bundle of software files. The system installs and tracks it safely.",
		Details:   "Using packages ensures programs receive security updates, can be uninstalled safely, and do not leave behind orphan files.",
		Technical: "Indexed in native package manager databases (/var/lib/dpkg/status for apt, /var/lib/rpm for dnf/rpm, /var/lib/pacman for pacman, /lib/apk/db for apk).",
	},
	"kernel": {
		Term:      "kernel",
		Summary:   "The kernel is the main engine of the server. It manages the hardware, memory, and disks.",
		Details:   "All applications ask the kernel to access disks, network connections, or memory. Kazeshini reads kernel status files directly without changing them.",
		Technical: "The running Linux kernel, observable via /proc/version, uname(2), and sysfs.",
	},
	"inode": {
		Term:      "inode",
		Summary:   "An inode is an index number for a file. The disk uses it to track each item.",
		Details:   "Even if a disk has free gigabytes left, running out of inodes prevents creating any new files (such as log entries or user uploads).",
		Technical: "Data structure storing metadata about regular files and directories. Measured via statvfs(3) and statfs(2) syscalls (f_files and f_ffree).",
	},
	"unmanaged software": {
		Term:      "unmanaged software",
		Summary:   "This is software put on the machine by hand. The system package tool does not track it.",
		Details:   "Because the operating system does not know about it, it will not receive automated security patches and may be forgotten over time.",
		Technical: "Executables located in directories such as /usr/local/bin, /opt, or /tmp with no matching record in native package manager registries.",
	},
	"risk score": {
		Term:      "risk score",
		Summary:   "A score from 0 to 100. Lower numbers mean the server is safe, while high numbers show problems.",
		Details:   "Points are added when critical security flaws, failed services, or unprotected network ports are detected.",
		Technical: "Calculated deterministically from weighted finding severities, open exposure counts, failed units, and unmanaged executables.",
	},
	"drift": {
		Term:      "drift",
		Summary:   "Drift means settings have changed. The server does not match what you expected.",
		Details:   "For example, if a package was accidentally installed or removed outside of configuration management, Kazeshini points out the difference.",
		Technical: "Set-difference comparison between declarative desired state manifest and observed resource graph.",
	},
	"visibility": {
		Term:      "visibility",
		Summary:   "Visibility is how much of the server was seen. It tells you what could be checked.",
		Details:   "If running without administrator (root) rights, some security files cannot be read. Kazeshini is always honest about what it could not inspect.",
		Technical: "Ratio of readable system resources and successful sensor observations against total target entities.",
	},
}

// Lookup returns the 3-level definition of a system term, or false if not found.
func Lookup(term string) (TermDefinition, bool) {
	clean := strings.ToLower(strings.TrimSpace(term))
	def, ok := catalog[clean]
	if ok {
		return def, true
	}
	// Only try substring match if term is not a dashed/underscored identifier
	if !strings.ContainsAny(clean, "-_") {
		for k, v := range catalog {
			if strings.Contains(clean, k) || strings.Contains(k, clean) {
				return v, true
			}
		}
	}
	return TermDefinition{}, false
}

// AllTerms returns all canonical terms in the glossary.
func AllTerms() []TermDefinition {
	var list []TermDefinition
	for _, v := range catalog {
		list = append(list, v)
	}
	return list
}
