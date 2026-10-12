// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/sensors"
)

// MountInfo captures storage metrics for a mounted filesystem.
type MountInfo struct {
	Device        string  `json:"device"`
	MountPoint    string  `json:"mount_point"`
	FSType        string  `json:"fs_type"`
	Options       string  `json:"options"`
	TotalBytes    uint64  `json:"total_bytes"`
	UsedBytes     uint64  `json:"used_bytes"`
	FreeBytes     uint64  `json:"free_bytes"`
	UsageRatio    float64 `json:"usage_ratio"`
	TotalInodes   uint64  `json:"total_inodes"`
	UsedInodes    uint64  `json:"used_inodes"`
	FreeInodes    uint64  `json:"free_inodes"`
	InodeRatio    float64 `json:"inode_ratio"`
	ReadOnly      bool    `json:"read_only"`
	IsBlockDevice bool    `json:"is_block_device"`
}

// Sensor collects mount points and disk statistics.
type Sensor struct {
	fs fs.FS
}

// New creates a new storage sensor.
func New(fs fs.FS) *Sensor {
	return &Sensor{fs: fs}
}

func (s *Sensor) Name() string {
	return "storage"
}

func (s *Sensor) Interval() time.Duration {
	return 60 * time.Second
}

func (s *Sensor) Collect(ctx context.Context) (sensors.Observation, error) {
	start := time.Now()
	now := start.UTC()
	obs := sensors.Observation{
		SensorName: s.Name(),
		Timestamp:  now,
		Status:     sensors.StatusSuccess,
	}

	data, err := s.fs.ReadFile("/proc/mounts")
	if err != nil {
		if fs.IsPermission(err) {
			obs.Status = sensors.StatusUnknown
			obs.Reason = fmt.Sprintf("permission denied reading /proc/mounts: %v", err)
			return obs, nil
		}
		return obs, fmt.Errorf("failed reading /proc/mounts: %w", err)
	}

	var items []sensors.Item
	scanner := bufio.NewScanner(bytes.NewReader(data))
	seenMounts := make(map[string]bool)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			obs.Status = sensors.StatusUnknown
			obs.Reason = "collection cancelled or timed out"
			obs.Items = items
			return obs, nil
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		var device, mountPoint, fsType, opts string
		if strings.HasPrefix(fields[0], "/") && (len(fields) < 4 || !strings.HasPrefix(fields[1], "/")) {
			// First field is already the mount point (e.g. " / tmpfs ro,...")
			device = "none"
			mountPoint = fields[0]
			fsType = fields[1]
			opts = fields[2]
		} else if len(fields) >= 4 {
			device = fields[0]
			mountPoint = fields[1]
			fsType = fields[2]
			opts = fields[3]
		} else {
			continue
		}

		// Filter virtual pseudo-mounts (cgroup, sysfs, proc, devpts, tracefs, etc.)
		if IsPseudoFS(fsType, mountPoint) {
			continue
		}

		if seenMounts[mountPoint] {
			continue
		}
		seenMounts[mountPoint] = true

		isBlock := IsRealBlockMount(device, fsType, mountPoint)
		info := MountInfo{
			Device:        device,
			MountPoint:    mountPoint,
			FSType:        fsType,
			Options:       opts,
			ReadOnly:      strings.HasPrefix(opts, "ro,") || strings.Contains(opts, ",ro,") || strings.HasSuffix(opts, ",ro") || opts == "ro",
			IsBlockDevice: isBlock,
		}

		// Statfs for space and inode utilization
		realPath := s.fs.Path(mountPoint)
		var stat syscall.Statfs_t
		if err := syscall.Statfs(realPath, &stat); err == nil && stat.Blocks > 0 {
			info.TotalBytes = stat.Blocks * uint64(stat.Bsize)
			info.FreeBytes = stat.Bavail * uint64(stat.Bsize)
			if info.TotalBytes >= info.FreeBytes {
				info.UsedBytes = info.TotalBytes - info.FreeBytes
				info.UsageRatio = float64(info.UsedBytes) / float64(info.TotalBytes)
			}

			info.TotalInodes = stat.Files
			info.FreeInodes = stat.Ffree
			if info.TotalInodes > 0 && info.TotalInodes >= info.FreeInodes {
				info.UsedInodes = info.TotalInodes - info.FreeInodes
				info.InodeRatio = float64(info.UsedInodes) / float64(info.TotalInodes)
			}
		}

		items = append(items, sensors.Item{
			ID:   fmt.Sprintf("mount:%s", mountPoint),
			Type: "mount",
			Data: info,
			Evidence: []graph.Evidence{
				{
					Source:    "/proc/mounts",
					Collector: "storage",
					Raw:       line,
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

func IsPseudoFS(fsType, mountPoint string) bool {
	switch fsType {
	case "proc", "sysfs", "cgroup", "cgroup2", "devpts", "devtmpfs", "securityfs",
		"pstore", "bpf", "autofs", "tracefs", "debugfs", "hugetlbfs", "mqueue",
		"fusectl", "configfs", "ramfs":
		return true
	}
	if strings.HasPrefix(mountPoint, "/proc") || strings.HasPrefix(mountPoint, "/sys") || strings.HasPrefix(mountPoint, "/dev") {
		return true
	}
	return false
}

// IsRealBlockMount returns true if device and fstype represent a real physical/virtual block device mount.
func IsRealBlockMount(device, fsType, mountPoint string) bool {
	if IsPseudoFS(fsType, mountPoint) {
		return false
	}
	if fsType == "tmpfs" || fsType == "devtmpfs" {
		return false
	}
	// Real block devices are either under /dev/ (excluding loop/ram devices)
	if strings.HasPrefix(device, "/dev/") {
		if strings.HasPrefix(device, "/dev/loop") || strings.HasPrefix(device, "/dev/ram") {
			return false
		}
		return true
	}
	return false
}


// LargeDir captures size and entry count of inspected directory.
type LargeDir struct {
	Path       string `json:"path"`
	TotalBytes uint64 `json:"total_bytes"`
	Entries    int    `json:"entries"`
}

// BoundedDu computes on-demand disk usage of a directory with bounded item count and duration.
func BoundedDu(ctx context.Context, fs fs.FS, dirPath string, maxEntries int, maxDuration time.Duration) (LargeDir, error) {
	ctx, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()

	realPath := fs.Path(dirPath)
	res := LargeDir{Path: dirPath}

	err := filepath.WalkDir(realPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return filepath.SkipAll
		default:
		}
		if res.Entries >= maxEntries {
			return filepath.SkipAll
		}
		res.Entries++
		if !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				res.TotalBytes += uint64(fi.Size())
			}
		}
		return nil
	})

	return res, err
}
