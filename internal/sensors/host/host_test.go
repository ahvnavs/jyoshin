// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/fs"
)

func createHostFixture(t *testing.T, osRelease, cpuinfo, meminfo, dmiVendor, dmiProduct string) fs.FS {
	t.Helper()
	root := t.TempDir()

	mustWrite := func(relPath, content string) {
		full := filepath.Join(root, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite("/etc/hostname", "server-node-1\n")
	mustWrite("/proc/version", "Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org)\n")
	mustWrite("/proc/uptime", "12345.67 89012.34\n")
	mustWrite("/etc/os-release", osRelease)
	mustWrite("/proc/cpuinfo", cpuinfo)
	mustWrite("/proc/meminfo", meminfo)

	if dmiVendor != "" {
		mustWrite("/sys/class/dmi/id/sys_vendor", dmiVendor)
	}
	if dmiProduct != "" {
		mustWrite("/sys/class/dmi/id/product_name", dmiProduct)
	}

	return fs.NewRootedFS(root)
}

func TestHostSensor_Distros(t *testing.T) {
	tests := []struct {
		name         string
		osRelease    string
		dmiVendor    string
		dmiProduct   string
		expectDistro string
		expectFamily string
		expectCloud  string
	}{
		{
			name: "Debian 12 Bookworm",
			osRelease: `NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
HOME_URL="https://www.debian.org/"`,
			dmiVendor:    "Amazon EC2",
			dmiProduct:   "t3.medium",
			expectDistro: "Debian GNU/Linux",
			expectFamily: "debian",
			expectCloud:  "aws",
		},
		{
			name: "RHEL 9",
			osRelease: `NAME="Red Hat Enterprise Linux"
VERSION_ID="9.3"
ID="rhel"
ID_LIKE="fedora"`,
			dmiVendor:    "Google",
			dmiProduct:   "Google Compute Engine",
			expectDistro: "Red Hat Enterprise Linux",
			expectFamily: "rhel",
			expectCloud:  "gcp",
		},
		{
			name: "Alpine Linux",
			osRelease: `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.1
PRETTY_NAME="Alpine Linux v3.19"`,
			expectDistro: "Alpine Linux v3.19",
			expectFamily: "alpine",
			expectCloud:  "none",
		},
		{
			name: "Arch Linux",
			osRelease: `NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling`,
			expectDistro: "Arch Linux",
			expectFamily: "arch",
			expectCloud:  "none",
		},
	}

	cpuinfo := "processor\t: 0\nmodel name\t: AMD EPYC 7763 64-Core Processor\n\nprocessor\t: 1\nmodel name\t: AMD EPYC 7763 64-Core Processor\n"
	meminfo := "MemTotal:       16384000 kB\nSwapTotal:       2097152 kB\n"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rfs := createHostFixture(t, tt.osRelease, cpuinfo, meminfo, tt.dmiVendor, tt.dmiProduct)
			sensor := New(rfs)

			obs, err := sensor.Collect(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(obs.Items) != 1 {
				t.Fatalf("expected 1 item, got %d", len(obs.Items))
			}

			info, ok := obs.Items[0].Data.(HostInfo)
			if !ok {
				t.Fatalf("expected HostInfo type, got %T", obs.Items[0].Data)
			}

			if info.Distro != tt.expectDistro {
				t.Errorf("distro mismatch: got %q, want %q", info.Distro, tt.expectDistro)
			}
			if info.DistroFamily != tt.expectFamily {
				t.Errorf("distro family mismatch: got %q, want %q", info.DistroFamily, tt.expectFamily)
			}
			if info.CloudProvider != tt.expectCloud {
				t.Errorf("cloud provider mismatch: got %q, want %q", info.CloudProvider, tt.expectCloud)
			}
			if info.CPUCount != 2 {
				t.Errorf("cpu count mismatch: got %d, want 2", info.CPUCount)
			}
			if info.MemoryBytes != 16384000*1024 {
				t.Errorf("mem bytes mismatch: got %d", info.MemoryBytes)
			}
		})
	}
}
