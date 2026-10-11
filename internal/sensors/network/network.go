// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// ExposureClass classifies listening socket exposure.
type ExposureClass string

const (
	ExposureLoopback      ExposureClass = "loopback"
	ExposurePrivate       ExposureClass = "private"
	ExposureAllInterfaces ExposureClass = "all_interfaces"
	ExposureUnknown       ExposureClass = "unknown"
)

// SocketInfo captures details of a listening or connected network socket.
type SocketInfo struct {
	Protocol      string        `json:"protocol"` // tcp, tcp6, udp, udp6, unix
	LocalIP       string        `json:"local_ip"`
	LocalPort     int           `json:"local_port"`
	RemoteIP      string        `json:"remote_ip,omitempty"`
	RemotePort    int           `json:"remote_port,omitempty"`
	State         string        `json:"state"` // LISTEN, ESTABLISHED, etc.
	Inode         uint64        `json:"inode"`
	PID           int           `json:"pid,omitempty"`
	ProcessName   string        `json:"process_name,omitempty"`
	ExposureClass ExposureClass `json:"exposure_class"`
}

// ConnectionGroup aggregates established connections by remote IP and process.
type ConnectionGroup struct {
	RemoteIP    string `json:"remote_ip"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Count       int    `json:"count"`
}

// NetworkReport encapsulates network listeners and established connection groups.
type NetworkReport struct {
	Listeners        []SocketInfo      `json:"listeners"`
	EstablishedCount int               `json:"established_count"`
	ConnectionGroups []ConnectionGroup `json:"connection_groups"`
}

// Sensor parses network socket tables from /proc/net.
type Sensor struct {
	fs fs.FS
}

// New creates a new network sensor.
func New(fs fs.FS) *Sensor {
	return &Sensor{fs: fs}
}

func (s *Sensor) Name() string {
	return "network"
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

	// 1. Build map of socket inode -> PID / process name
	inodeMap, permDenied := s.buildInodePIDMap(ctx)

	// 2. Parse listening and established sockets
	sockets, err := s.collectSockets(ctx, inodeMap)
	if err != nil {
		obs.Status = sensors.StatusUnknown
		obs.Reason = fmt.Sprintf("failed reading socket tables: %v", err)
		return obs, nil
	}

	if permDenied > 0 {
		obs.Status = sensors.StatusUnknown
		obs.Reason = fmt.Sprintf("unknown, permission: unreadable /proc/<pid>/fd for %d processes; port->process mapping has reduced visibility", permDenied)
	}

	var listeners []SocketInfo
	var established []SocketInfo
	groupsMap := make(map[string]*ConnectionGroup)

	for _, sock := range sockets {
		if sock.State == "LISTEN" {
			listeners = append(listeners, sock)
		} else if sock.State == "ESTABLISHED" {
			established = append(established, sock)
			key := fmt.Sprintf("%s:%d", sock.RemoteIP, sock.PID)
			if g, exists := groupsMap[key]; exists {
				g.Count++
			} else {
				groupsMap[key] = &ConnectionGroup{
					RemoteIP:    sock.RemoteIP,
					PID:         sock.PID,
					ProcessName: sock.ProcessName,
					Count:       1,
				}
			}
		}
	}

	var groups []ConnectionGroup
	for _, g := range groupsMap {
		groups = append(groups, *g)
	}

	report := NetworkReport{
		Listeners:        listeners,
		EstablishedCount: len(established),
		ConnectionGroups: groups,
	}

	evidence := []graph.Evidence{
		{
			Source:    "/proc/net/{tcp,tcp6,udp,udp6}",
			Collector: s.Name(),
			Raw:       fmt.Sprintf("%d listeners, %d established", len(listeners), len(established)),
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		},
	}

	items := []sensors.Item{
		{
			ID:        "network:report",
			Type:      "network_report",
			Data:      report,
			Evidence:  evidence,
			Certainty: graph.CertaintyDerived,
		},
	}

	for _, l := range listeners {
		items = append(items, sensors.Item{
			ID:   fmt.Sprintf("port:%s:%d", l.Protocol, l.LocalPort),
			Type: "listening_port",
			Data: l,
			Evidence: []graph.Evidence{
				{
					Source:    fmt.Sprintf("/proc/net/%s", l.Protocol),
					Collector: s.Name(),
					Raw:       fmt.Sprintf("inode %d bound to %s:%d", l.Inode, l.LocalIP, l.LocalPort),
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		})
	}

	obs.Items = items
	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) collectSockets(ctx context.Context, inodeMap map[uint64]procMeta) ([]SocketInfo, error) {
	var results []SocketInfo

	tables := []struct {
		proto string
		path  string
	}{
		{"tcp", "/proc/net/tcp"},
		{"tcp6", "/proc/net/tcp6"},
		{"udp", "/proc/net/udp"},
		{"udp6", "/proc/net/udp6"},
	}

	for _, t := range tables {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		data, err := s.fs.ReadFile(t.path)
		if err != nil {
			continue // Gracefully skip unreadable or absent tables
		}

		socks := parseProcNet(data, t.proto, inodeMap)
		results = append(results, socks...)
	}

	return results, nil
}

type procMeta struct {
	pid  int
	name string
}

func (s *Sensor) buildInodePIDMap(ctx context.Context) (map[uint64]procMeta, int) {
	m := make(map[uint64]procMeta)
	permissionDeniedCount := 0

	entries, err := s.fs.ReadDir("/proc")
	if err != nil {
		return m, 0
	}

	count := 0
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return m, permissionDeniedCount
		default:
		}

		if count > 2048 {
			break
		}

		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read proc name
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		commBytes, _ := s.fs.ReadFile(commPath)
		pname := strings.TrimSpace(string(commBytes))

		// Read fd entries
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fdEntries, err := s.fs.ReadDir(fdDir)
		if err != nil {
			if errors.Is(err, os.ErrPermission) || os.IsPermission(err) {
				permissionDeniedCount++
			}
			continue
		}

		for _, fe := range fdEntries {
			link, err := s.fs.Readlink(fmt.Sprintf("%s/%s", fdDir, fe.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
					m[inode] = procMeta{pid: pid, name: pname}
				}
			}
		}
		count++
	}

	return m, permissionDeniedCount
}

func parseProcNet(data []byte, proto string, inodeMap map[uint64]procMeta) []SocketInfo {
	var list []SocketInfo
	scanner := bufio.NewScanner(bytes.NewReader(data))

	// Skip header line
	if scanner.Scan() {
		// header
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddrHex := fields[1]
		remoteAddrHex := fields[2]
		stateHex := fields[3]
		inodeStr := fields[9]

		localIP, localPort := parseHexAddr(localAddrHex)
		remoteIP, remotePort := parseHexAddr(remoteAddrHex)
		state := decodeTCPState(stateHex, proto)

		inode, _ := strconv.ParseUint(inodeStr, 10, 64)

		info := SocketInfo{
			Protocol:      proto,
			LocalIP:       localIP,
			LocalPort:     localPort,
			RemoteIP:      remoteIP,
			RemotePort:    remotePort,
			State:         state,
			Inode:         inode,
			ExposureClass: classifyExposure(localIP),
		}

		if meta, ok := inodeMap[inode]; ok {
			info.PID = meta.pid
			info.ProcessName = meta.name
		}

		list = append(list, info)
	}

	return list
}

func parseHexAddr(s string) (ipStr string, port int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "unknown", 0
	}

	port64, _ := strconv.ParseInt(parts[1], 16, 32)
	port = int(port64)

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "unknown", port
	}

	if len(ipBytes) == 4 {
		// IPv4 in little-endian in /proc/net/tcp
		ipStr = fmt.Sprintf("%d.%d.%d.%d", ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
		return
	}

	if len(ipBytes) == 16 {
		// IPv6 in 32-bit words little-endian
		var v6 [16]byte
		for i := 0; i < 16; i += 4 {
			v6[i] = ipBytes[i+3]
			v6[i+1] = ipBytes[i+2]
			v6[i+2] = ipBytes[i+1]
			v6[i+3] = ipBytes[i]
		}
		ip := net.IP(v6[:])
		ipStr = ip.String()
		return
	}

	return "unknown", port
}

func decodeTCPState(hexState, proto string) string {
	if strings.HasPrefix(proto, "udp") {
		// UDP is connectionless; socket entry typically represents bound listener
		return "LISTEN"
	}
	switch hexState {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	default:
		return "UNKNOWN"
	}
}

func classifyExposure(ipStr string) ExposureClass {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ExposureUnknown
	}

	if ip.IsUnspecified() {
		return ExposureAllInterfaces
	}
	if ip.IsLoopback() {
		return ExposureLoopback
	}
	if ip.IsPrivate() {
		return ExposurePrivate
	}

	return ExposureAllInterfaces
}
