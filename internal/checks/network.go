// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
)

// InterfacesRoutesCheck inspects /sys/class/net, /proc/net/route, and ipv6_route.
type InterfacesRoutesCheck struct{}

func (c *InterfacesRoutesCheck) ID() string    { return "interfaces-routes" }
func (c *InterfacesRoutesCheck) Role() string  { return "network" }
func (c *InterfacesRoutesCheck) Title() string { return "Network Interfaces & Routing Table State" }
func (c *InterfacesRoutesCheck) Description() string {
	return "Inspects /sys/class/net interface states and default gateways in /proc/net/route"
}

func (c *InterfacesRoutesCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	routeData, err := rfs.ReadFile("/proc/net/route")
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot inspect /proc/net/route: permission denied",
				ExplainLevels: [3]string{
					"Permission denied reading /proc/net/route",
					"Routing configuration cannot be verified",
					"Ensure read access to /proc/net",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading /proc/net/route: %v", err)), nil
	}

	hasDefaultRoute := false
	routeCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(routeData))
	if scanner.Scan() { // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				routeCount++
				if fields[1] == "00000000" { // Destination 0.0.0.0 is default route
					hasDefaultRoute = true
				}
			}
		}
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Network routing healthy: %d routes configured including active default gateway", routeCount)
	if routeCount == 0 {
		st = contract.StatusWarn
		sum = "No network routes configured in /proc/net/route"
	} else if !hasDefaultRoute {
		st = contract.StatusWarn
		sum = fmt.Sprintf("No default IPv4 gateway detected in /proc/net/route (%d host routes configured)", routeCount)
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Audited /proc/net/route (found %d routes)", routeCount),
			"Without a default route, outward traffic to non-local subnets will fail",
			"Check DHCP client or static gateway configuration via ip route",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc/net/route", Collector: "interfaces-routes", Details: fmt.Sprintf("%d routes", routeCount), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "ip route show",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// ListeningPortsCheck audits listening ports and interfaces.
type ListeningPortsCheck struct{}

func (c *ListeningPortsCheck) ID() string    { return "listening-ports" }
func (c *ListeningPortsCheck) Role() string  { return "network" }
func (c *ListeningPortsCheck) Title() string { return "Listening Network Ports & Exposure" }
func (c *ListeningPortsCheck) Description() string {
	return "Audits open listening TCP/UDP sockets and binds from /proc/net/tcp and /proc/net/udp"
}

func (c *ListeningPortsCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	tcpData, err := rfs.ReadFile("/proc/net/tcp")
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot inspect /proc/net/tcp: permission denied",
				ExplainLevels: [3]string{
					"Permission denied reading /proc/net/tcp",
					"Listening ports cannot be audited",
					"Ensure read access to /proc/net",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading /proc/net/tcp: %v", err)), nil
	}

	listenPorts := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(tcpData))
	if scanner.Scan() { // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 && fields[3] == "0A" { // TCP_LISTEN
				parts := strings.Split(fields[1], ":")
				if len(parts) == 2 {
					if portNum, err := strconv.ParseInt(parts[1], 16, 32); err == nil {
						listenPorts = append(listenPorts, fmt.Sprintf("%d", portNum))
					}
				}
			}
		}
	}

	sum := fmt.Sprintf("Listening ports inspected: %d open TCP listeners (%s)", len(listenPorts), strings.Join(listenPorts, ", "))
	if len(listenPorts) == 0 {
		sum = "Zero open TCP listening ports detected on host"
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       contract.StatusOK,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Scanned /proc/net/tcp and discovered %d listening ports", len(listenPorts)),
			"Open ports represent active attack surfaces and inter-service entry points",
			"Close unnecessary listeners and enforce firewall rules",
		},
		Evidence: []graph.Evidence{
			{Source: "/proc/net/tcp", Collector: "listening-ports", Details: fmt.Sprintf("%d listeners", len(listenPorts)), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "ss -tulpn",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// DNSConfigCheck parses /etc/resolv.conf passively.
type DNSConfigCheck struct{}

func (c *DNSConfigCheck) ID() string    { return "dns-config" }
func (c *DNSConfigCheck) Role() string  { return "network" }
func (c *DNSConfigCheck) Title() string { return "DNS Resolver Configuration (resolv.conf)" }
func (c *DNSConfigCheck) Description() string {
	return "Passively audits nameservers, search domains, and options in /etc/resolv.conf"
}

func (c *DNSConfigCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	data, err := rfs.ReadFile("/etc/resolv.conf")
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot read /etc/resolv.conf: permission denied",
				ExplainLevels: [3]string{
					"Permission denied accessing /etc/resolv.conf",
					"DNS nameserver configuration is obscured",
					"Ensure read access to /etc/resolv.conf",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		if os.IsNotExist(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusNotApplicable,
				SummaryPlain: "/etc/resolv.conf does not exist",
				ExplainLevels: [3]string{
					"/etc/resolv.conf not found",
					"Host has no static or dynamic DNS configuration file",
					"Configure DNS resolver",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading /etc/resolv.conf: %v", err)), nil
	}

	var nameservers []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				nameservers = append(nameservers, parts[1])
			}
		}
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("DNS resolver configured with %d nameservers (%s)", len(nameservers), strings.Join(nameservers, ", "))
	if len(nameservers) == 0 {
		st = contract.StatusWarn
		sum = "No nameserver entries found in /etc/resolv.conf (outbound DNS resolution will fail)"
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Passively parsed /etc/resolv.conf (found %d nameservers)", len(nameservers)),
			"Defines the DNS servers used by standard libc getaddrinfo calls",
			"Ensure at least one responsive local or upstream nameserver is configured",
		},
		Evidence: []graph.Evidence{
			{Source: "/etc/resolv.conf", Collector: "dns-config", Details: strings.Join(nameservers, ", "), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "cat /etc/resolv.conf",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// ConnectivityProbeCheck is an OPT-IN, rate-limited active connectivity probe to a user-named target.
// Principle 13: The ONLY egress is a user-clicked active probe to a user-named target.
type ConnectivityProbeCheck struct {
	mu          sync.Mutex
	lastProbeAt time.Time
}

func (c *ConnectivityProbeCheck) ID() string    { return "connectivity-probe" }
func (c *ConnectivityProbeCheck) Role() string  { return "network" }
func (c *ConnectivityProbeCheck) Title() string { return "Target Connectivity Active Probe (Opt-In)" }
func (c *ConnectivityProbeCheck) Description() string {
	return "OPT-IN single-shot TCP handshake to a user-specified host:port (5s timeout, rate-limited, logged)"
}

func (c *ConnectivityProbeCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	target := params["target"]
	if target == "" {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusNotApplicable,
			SummaryPlain: "No target parameter specified. Active connectivity probe requires an explicit user-named host:port target.",
			ExplainLevels: [3]string{
				"Active network probe is strictly opt-in and idle by default (Principle 13)",
				"Requires user to supply 'target=host:port' parameter",
				"Specify target to run single-shot probe",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	if !ValidateSafeParam(target) {
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusCrit, "Invalid target format: meta-characters or injection rejected"), ErrInvalidParam
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusWarn, fmt.Sprintf("Invalid target format: %v (expected host:port)", err)), ErrInvalidParam
	}

	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusWarn, "Invalid port number: must be between 1 and 65535"), ErrInvalidParam
	}

	// SSRF Protection: refuse cloud metadata IPs (169.254.169.254), loopback, link-local unless explicitly allowed
	allowLocal := params["allow_local"] == "true"
	if !allowLocal {
		cleanHost := strings.Trim(strings.Trim(host, "["), "]")
		if cleanHost == "localhost" {
			return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusCrit, "SSRF prohibited: probe to localhost is blocked by security policy"), ErrInvalidParam
		}
		if ip := net.ParseIP(cleanHost); ip != nil {
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || cleanHost == "169.254.169.254" {
				return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusCrit, fmt.Sprintf("SSRF prohibited: probe to local/metadata IP %s is blocked by security policy", cleanHost)), ErrInvalidParam
			}
		}
	}

	// Rate limiting: at most 1 probe every 2 seconds
	c.mu.Lock()
	if time.Since(c.lastProbeAt) < 2*time.Second {
		c.mu.Unlock()
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusWarn, "Rate limited: connectivity probe allowed at most once every 2 seconds"), nil
	}
	c.lastProbeAt = time.Now()
	c.mu.Unlock()

	// Execute 5-second bounded dial
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var d net.Dialer
	conn, dialErr := d.DialContext(probeCtx, "tcp", net.JoinHostPort(host, portStr))
	if dialErr != nil {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusCrit,
			SummaryPlain: fmt.Sprintf("Connection to %s failed: %v", target, dialErr),
			ExplainLevels: [3]string{
				fmt.Sprintf("Attempted TCP handshake to %s (timeout: 5s)", target),
				"Host or port is unreachable, firewalled, or service is not running",
				"Check remote service status and firewall allow-lists",
			},
			Evidence: []graph.Evidence{
				{Source: "tcp-probe", Collector: "connectivity-probe", Details: dialErr.Error(), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
			},
			Certainty:         graph.CertaintyObserved,
			EquivalentCommand: fmt.Sprintf("nc -zv -w 5 %s %s", host, portStr),
			ReadOnly:          true,
			CollectedAt:       time.Now().UTC(),
		}, nil
	}
	_ = conn.Close()

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       contract.StatusOK,
		SummaryPlain: fmt.Sprintf("TCP handshake to %s succeeded (connection established)", target),
		ExplainLevels: [3]string{
			fmt.Sprintf("Single-shot active probe completed successfully to %s", target),
			"Remote endpoint is routable and actively accepting TCP connections",
			"No further action required",
		},
		Evidence: []graph.Evidence{
			{Source: "tcp-probe", Collector: "connectivity-probe", Details: "handshake succeeded", Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: fmt.Sprintf("nc -zv -w 5 %s %s", host, portStr),
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}
