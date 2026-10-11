// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"bufio"
	"bytes"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// ResourceSample contains instantaneous system-wide performance and pressure metrics.
type ResourceSample struct {
	Timestamp      time.Time  `json:"timestamp"`
	Load1          float64    `json:"load_1"`
	Load5          float64    `json:"load_5"`
	Load15         float64    `json:"load_15"`
	RunningTasks   int        `json:"running_tasks"`
	TotalTasks     int        `json:"total_tasks"`
	MemTotalBytes  uint64     `json:"mem_total_bytes"`
	MemAvailBytes  uint64     `json:"mem_avail_bytes"`
	MemUsedBytes   uint64     `json:"mem_used_bytes"`
	MemUsageRatio  float64    `json:"mem_usage_ratio"`
	SwapTotalBytes uint64     `json:"swap_total_bytes"`
	SwapFreeBytes  uint64     `json:"swap_free_bytes"`
	SwapUsedBytes  uint64     `json:"swap_used_bytes"`
	SwapUsageRatio float64    `json:"swap_usage_ratio"`
	PSI            PSIMetrics `json:"psi"`
}

// PSIMetrics captures Pressure Stall Information (CPU, memory, IO).
type PSIMetrics struct {
	CPUSomeAvg10 float64 `json:"cpu_some_avg10"`
	MemSomeAvg10 float64 `json:"mem_some_avg10"`
	MemFullAvg10 float64 `json:"mem_full_avg10"`
	IOSomeAvg10  float64 `json:"io_some_avg10"`
	IOFullAvg10  float64 `json:"io_full_avg10"`
}

// Sensor collects CPU, memory, load, swap, and PSI metrics.
type Sensor struct {
	fs fs.FS
}

// New creates a new resources sensor.
func New(fs fs.FS) *Sensor {
	return &Sensor{fs: fs}
}

func (s *Sensor) Name() string {
	return "resources"
}

func (s *Sensor) Interval() time.Duration {
	return 10 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	now := start.UTC()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
	}

	sample := ResourceSample{Timestamp: now}

	// 1. /proc/loadavg
	if loadData, err := s.fs.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(loadData))
		if len(fields) >= 4 {
			sample.Load1, _ = strconv.ParseFloat(fields[0], 64)
			sample.Load5, _ = strconv.ParseFloat(fields[1], 64)
			sample.Load15, _ = strconv.ParseFloat(fields[2], 64)
			parts := strings.Split(fields[3], "/")
			if len(parts) == 2 {
				sample.RunningTasks, _ = strconv.Atoi(parts[0])
				sample.TotalTasks, _ = strconv.Atoi(parts[1])
			}
		}
	}

	// 2. /proc/meminfo
	if memData, err := s.fs.ReadFile("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(memData))
		var memTotal, memAvail, memFree, buffers, cached, swapTotal, swapFree uint64
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			valStr := strings.TrimSpace(parts[1])
			valFields := strings.Fields(valStr)
			if len(valFields) == 0 {
				continue
			}
			kb, _ := strconv.ParseUint(valFields[0], 10, 64)
			bytesVal := kb * 1024

			switch key {
			case "MemTotal":
				memTotal = bytesVal
			case "MemAvailable":
				memAvail = bytesVal
			case "MemFree":
				memFree = bytesVal
			case "Buffers":
				buffers = bytesVal
			case "Cached":
				cached = bytesVal
			case "SwapTotal":
				swapTotal = bytesVal
			case "SwapFree":
				swapFree = bytesVal
			}
		}

		sample.MemTotalBytes = memTotal
		if memAvail > 0 {
			sample.MemAvailBytes = memAvail
		} else {
			sample.MemAvailBytes = memFree + buffers + cached
		}
		if sample.MemTotalBytes >= sample.MemAvailBytes {
			sample.MemUsedBytes = sample.MemTotalBytes - sample.MemAvailBytes
			if sample.MemTotalBytes > 0 {
				sample.MemUsageRatio = float64(sample.MemUsedBytes) / float64(sample.MemTotalBytes)
			}
		}

		sample.SwapTotalBytes = swapTotal
		sample.SwapFreeBytes = swapFree
		if swapTotal >= swapFree {
			sample.SwapUsedBytes = swapTotal - swapFree
			if swapTotal > 0 {
				sample.SwapUsageRatio = float64(sample.SwapUsedBytes) / float64(swapTotal)
			}
		}
	}

	// 3. /proc/pressure (PSI) - optional on older kernels
	sample.PSI.CPUSomeAvg10 = s.readPSIAvg("/proc/pressure/cpu", "some")
	sample.PSI.MemSomeAvg10 = s.readPSIAvg("/proc/pressure/memory", "some")
	sample.PSI.MemFullAvg10 = s.readPSIAvg("/proc/pressure/memory", "full")
	sample.PSI.IOSomeAvg10 = s.readPSIAvg("/proc/pressure/io", "some")
	sample.PSI.IOFullAvg10 = s.readPSIAvg("/proc/pressure/io", "full")

	obs.Items = []sensors.Item{
		{
			ID:   "resource:system",
			Type: "resource_sample",
			Data: sample,
			Evidence: []graph.Evidence{
				{
					Source:    "/proc/loadavg",
					Collector: "resources",
					Timestamp: now,
					Certainty: graph.CertaintyObserved,
				},
			},
			Certainty: graph.CertaintyObserved,
		},
	}

	obs.Duration = time.Since(start)
	return obs, nil
}

func (s *Sensor) readPSIAvg(path, linePrefix string) float64 {
	data, err := s.fs.ReadFile(path)
	if err != nil {
		return 0.0
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, linePrefix+" ") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "avg10=") {
					val, _ := strconv.ParseFloat(strings.TrimPrefix(f, "avg10="), 64)
					return val
				}
			}
		}
	}
	return 0.0
}
