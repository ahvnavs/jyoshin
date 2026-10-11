// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package kernel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// KernelData represents kernel version status and reclaimable kernels.
type KernelData struct {
	RunningKernel    string   `json:"running_kernel"`
	InstalledKernels []string `json:"installed_kernels"`
	Reclaimable      []string `json:"reclaimable_kernels"`
	RebootRequired   bool     `json:"reboot_required"`
}

// Sensor collects kernel version and installed/reclaimable kernels.
type Sensor struct {
	rootDir string
}

// NewSensor creates a new kernel sensor rooted at rootDir.
func NewSensor(rootDir string) *Sensor {
	if rootDir == "" {
		rootDir = "/"
	}
	return &Sensor{rootDir: rootDir}
}

func (s *Sensor) Name() string {
	return "kernel"
}

func (s *Sensor) Interval() time.Duration {
	return 300 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  start,
		Status:     sensors.StatusSuccess,
	}

	running := s.getRunningKernel()
	installed := s.getInstalledKernels()

	var reclaimable []string
	rebootRequired := false

	// If the newest installed kernel is different from running, reboot may be required.
	// Any installed kernel that is older/not the running kernel and not the latest is reclaimable.
	latestInstalled := ""
	if len(installed) > 0 {
		latestInstalled = installed[len(installed)-1]
		if latestInstalled != "" && running != "" && !strings.Contains(running, latestInstalled) && latestInstalled != running {
			rebootRequired = true
		}
	}

	for _, k := range installed {
		if k != running && (latestInstalled == "" || k != latestInstalled) {
			reclaimable = append(reclaimable, k)
		}
	}

	data := KernelData{
		RunningKernel:    running,
		InstalledKernels: installed,
		Reclaimable:      reclaimable,
		RebootRequired:   rebootRequired,
	}

	obs.Items = []sensors.Item{
		{
			ID:   "kernel:status",
			Type: "kernel",
			Data: data,
			Evidence: []graph.Evidence{
				{
					Source:    filepath.Join(s.rootDir, "proc", "version"),
					Collector: "kernel",
					Timestamp: start,
					Certainty: graph.CertaintyObserved,
					Details:   fmt.Sprintf("Running: %s, Installed: %v", running, installed),
				},
			},
			Certainty: graph.CertaintyObserved,
		},
	}
	obs.TotalSeen = 1
	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) getRunningKernel() string {
	procVer := filepath.Join(s.rootDir, "proc", "version")
	data, err := os.ReadFile(procVer)
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			return fields[2]
		}
	}

	// Fallback to /proc/sys/kernel/osrelease
	osRelease := filepath.Join(s.rootDir, "proc", "sys", "kernel", "osrelease")
	data, err = os.ReadFile(osRelease)
	if err == nil {
		return strings.TrimSpace(string(data))
	}

	return ""
}

func (s *Sensor) getInstalledKernels() []string {
	var kernels []string
	bootDir := filepath.Join(s.rootDir, "boot")
	entries, err := os.ReadDir(bootDir)
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "vmlinuz-") {
				ver := strings.TrimPrefix(name, "vmlinuz-")
				kernels = append(kernels, ver)
			}
		}
	}

	// Also check /lib/modules if /boot was empty or missing
	if len(kernels) == 0 {
		modDir := filepath.Join(s.rootDir, "lib", "modules")
		entries, err := os.ReadDir(modDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					kernels = append(kernels, e.Name())
				}
			}
		}
	}

	return kernels
}
