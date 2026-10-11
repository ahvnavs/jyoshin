// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// HostInfo contains full host identity data.
type HostInfo struct {
	Hostname       string  `json:"hostname"`
	Distro         string  `json:"distro"`
	DistroVersion  string  `json:"distro_version"`
	DistroFamily   string  `json:"distro_family"`
	Kernel         string  `json:"kernel"`
	Arch           string  `json:"arch"`
	UptimeSeconds  float64 `json:"uptime_seconds"`
	CPUCount       int     `json:"cpu_count"`
	CPUModel       string  `json:"cpu_model"`
	MemoryBytes    uint64  `json:"memory_bytes"`
	SwapBytes      uint64  `json:"swap_bytes"`
	Virtualization string  `json:"virtualization"` // e.g. "kvm", "wsl", "docker", "none"
	CloudProvider  string  `json:"cloud_provider"` // "aws", "gcp", "azure", "none", "unknown"
	InstanceType   string  `json:"instance_type"`
}

// Sensor collects host identity data strictly read-only from /proc and /sys.
type Sensor struct {
	fs fs.FS
}

// New creates a new host sensor.
func New(fs fs.FS) *Sensor {
	return &Sensor{fs: fs}
}

func (s *Sensor) Name() string {
	return "host"
}

func (s *Sensor) Interval() time.Duration {
	return 300 * time.Second // Host identity changes rarely
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	now := start.UTC()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
	}

	info := HostInfo{
		DistroFamily:   "other",
		Virtualization: "none",
		CloudProvider:  "none",
		InstanceType:   "unknown",
	}
	var evidence []graph.Evidence

	// 1. Hostname
	if data, err := s.fs.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		info.Hostname = strings.TrimSpace(string(data))
		evidence = append(evidence, graph.Evidence{
			Source:    "/proc/sys/kernel/hostname",
			Collector: s.Name(),
			Raw:       info.Hostname,
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
	} else if data, err := s.fs.ReadFile("/etc/hostname"); err == nil {
		info.Hostname = strings.TrimSpace(string(data))
		evidence = append(evidence, graph.Evidence{
			Source:    "/etc/hostname",
			Collector: s.Name(),
			Raw:       info.Hostname,
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
	}

	// 2. Kernel
	if data, err := s.fs.ReadFile("/proc/version"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			info.Kernel = fields[2]
			evidence = append(evidence, graph.Evidence{
				Source:    "/proc/version",
				Collector: s.Name(),
				Raw:       info.Kernel,
				Timestamp: now,
				Certainty: graph.CertaintyObserved,
			})
		}
	}

	// 3. Distro (os-release)
	if data, err := s.readOSRelease(); err == nil {
		distro, version, id, idLike := parseOSRelease(data)
		info.Distro = distro
		info.DistroVersion = version
		info.DistroFamily = classifyDistroFamily(id, idLike)
		evidence = append(evidence, graph.Evidence{
			Source:    "/etc/os-release",
			Collector: s.Name(),
			Raw:       fmt.Sprintf("ID=%s, ID_LIKE=%s", id, idLike),
			Timestamp: now,
			Certainty: graph.CertaintyDerived,
			Details:   fmt.Sprintf("Classified distro family as %s", info.DistroFamily),
		})
	}

	// 4. Uptime
	if data, err := s.fs.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if up, err := strconv.ParseFloat(fields[0], 64); err == nil {
				info.UptimeSeconds = up
			}
		}
	}

	// 5. CPU info & Arch
	if data, err := s.fs.ReadFile("/proc/cpuinfo"); err == nil {
		count, model, arch := parseCPUInfo(data)
		info.CPUCount = count
		info.CPUModel = model
		if arch != "" {
			info.Arch = arch
		}
		evidence = append(evidence, graph.Evidence{
			Source:    "/proc/cpuinfo",
			Collector: s.Name(),
			Raw:       fmt.Sprintf("cpus=%d, model=%s", count, model),
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
	}

	// 6. Memory & Swap
	if data, err := s.fs.ReadFile("/proc/meminfo"); err == nil {
		memTotal, swapTotal := parseMemInfo(data)
		info.MemoryBytes = memTotal
		info.SwapBytes = swapTotal
		evidence = append(evidence, graph.Evidence{
			Source:    "/proc/meminfo",
			Collector: s.Name(),
			Raw:       fmt.Sprintf("MemTotal=%d bytes, SwapTotal=%d bytes", memTotal, swapTotal),
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
	}

	// 7. Virtualization & Container detection
	virt, virtEv := s.detectVirtualization(now)
	info.Virtualization = virt
	evidence = append(evidence, virtEv...)

	// 8. Cloud provider & instance type via DMI (/sys/class/dmi/id)
	cloud, instance, dmiEv := s.detectCloudDMI(now)
	info.CloudProvider = cloud
	info.InstanceType = instance
	evidence = append(evidence, dmiEv...)

	obs.Items = []sensors.Item{
		{
			ID:        "host:identity",
			Type:      "host_identity",
			Data:      info,
			Evidence:  evidence,
			Certainty: graph.CertaintyDerived,
		},
	}
	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) readOSRelease() ([]byte, error) {
	if data, err := s.fs.ReadFile("/etc/os-release"); err == nil {
		return data, nil
	}
	return s.fs.ReadFile("/usr/lib/os-release")
}

func parseOSRelease(data []byte) (distro, version, id, idLike string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := strings.Trim(parts[1], `"'`)
		switch key {
		case "PRETTY_NAME":
			distro = val
		case "NAME":
			if distro == "" {
				distro = val
			}
		case "VERSION_ID":
			version = val
		case "ID":
			id = val
		case "ID_LIKE":
			idLike = val
		}
	}
	return
}

func classifyDistroFamily(id, idLike string) string {
	combined := strings.ToLower(id + " " + idLike)
	switch {
	case strings.Contains(combined, "debian") || strings.Contains(combined, "ubuntu"):
		return "debian"
	case strings.Contains(combined, "rhel") || strings.Contains(combined, "centos") || strings.Contains(combined, "fedora") || strings.Contains(combined, "rocky") || strings.Contains(combined, "alma"):
		return "rhel"
	case strings.Contains(combined, "arch") || strings.Contains(combined, "manjaro"):
		return "arch"
	case strings.Contains(combined, "alpine"):
		return "alpine"
	case strings.Contains(combined, "suse") || strings.Contains(combined, "opensuse"):
		return "suse"
	default:
		return "other"
	}
}

func parseCPUInfo(data []byte) (count int, model, arch string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "processor") {
			count++
		} else if strings.HasPrefix(line, "model name") && model == "" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				model = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "CPU implementer") || strings.HasPrefix(line, "Architecture") {
			arch = "arm"
		}
	}
	if count == 0 {
		count = 1
	}
	return
}

func parseMemInfo(data []byte) (memTotal, swapTotal uint64) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = parseMemField(line)
		} else if strings.HasPrefix(line, "SwapTotal:") {
			swapTotal = parseMemField(line)
		}
	}
	return
}

func parseMemField(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			return kb * 1024
		}
	}
	return 0
}

func (s *Sensor) detectVirtualization(now time.Time) (string, []graph.Evidence) {
	var ev []graph.Evidence

	// Check container markers
	if _, err := s.fs.Stat("/.dockerenv"); err == nil {
		ev = append(ev, graph.Evidence{
			Source:    "/.dockerenv",
			Collector: s.Name(),
			Raw:       "file exists",
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
		return "docker", ev
	}
	if _, err := s.fs.Stat("/run/.containerenv"); err == nil {
		ev = append(ev, graph.Evidence{
			Source:    "/run/.containerenv",
			Collector: s.Name(),
			Raw:       "file exists",
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
		return "podman", ev
	}

	// Check WSL
	if ver, err := s.fs.ReadFile("/proc/version"); err == nil && strings.Contains(strings.ToLower(string(ver)), "microsoft") {
		ev = append(ev, graph.Evidence{
			Source:    "/proc/version",
			Collector: s.Name(),
			Raw:       "contains 'microsoft'",
			Timestamp: now,
			Certainty: graph.CertaintyDerived,
		})
		return "wsl", ev
	}

	// Check hypervisor flag in cpuinfo
	if cpuinfo, err := s.fs.ReadFile("/proc/cpuinfo"); err == nil && strings.Contains(string(cpuinfo), "hypervisor") {
		ev = append(ev, graph.Evidence{
			Source:    "/proc/cpuinfo",
			Collector: s.Name(),
			Raw:       "flags contain 'hypervisor'",
			Timestamp: now,
			Certainty: graph.CertaintyDerived,
		})
		return "vm", ev
	}

	return "none", ev
}

func (s *Sensor) detectCloudDMI(now time.Time) (provider, instanceType string, ev []graph.Evidence) {
	provider = "none"
	instanceType = "unknown"

	dmiSysVendor := "/sys/class/dmi/id/sys_vendor"
	dmiProductName := "/sys/class/dmi/id/product_name"
	dmiProductVersion := "/sys/class/dmi/id/product_version"

	vendorBytes, vErr := s.fs.ReadFile(dmiSysVendor)
	productBytes, pErr := s.fs.ReadFile(dmiProductName)
	versionBytes, _ := s.fs.ReadFile(dmiProductVersion)

	vendor := strings.ToLower(strings.TrimSpace(string(vendorBytes)))
	product := strings.ToLower(strings.TrimSpace(string(productBytes)))
	version := strings.ToLower(strings.TrimSpace(string(versionBytes)))

	if vErr == nil {
		ev = append(ev, graph.Evidence{
			Source:    dmiSysVendor,
			Collector: s.Name(),
			Raw:       vendor,
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
	}
	if pErr == nil {
		ev = append(ev, graph.Evidence{
			Source:    dmiProductName,
			Collector: s.Name(),
			Raw:       product,
			Timestamp: now,
			Certainty: graph.CertaintyObserved,
		})
	}

	switch {
	case strings.Contains(vendor, "amazon") || strings.Contains(version, "amazon"):
		provider = "aws"
		if pErr == nil && product != "" {
			instanceType = product
		}
	case strings.Contains(vendor, "google") || strings.Contains(product, "google"):
		provider = "gcp"
		if pErr == nil && product != "" {
			instanceType = product
		}
	case strings.Contains(vendor, "microsoft") && strings.Contains(product, "virtual machine"):
		provider = "azure"
		instanceType = "azure-vm"
	case strings.Contains(vendor, "digitalocean"):
		provider = "digitalocean"
	case strings.Contains(vendor, "hetzner"):
		provider = "hetzner"
	}

	return
}
