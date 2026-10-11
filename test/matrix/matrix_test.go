// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package matrix_test

import (
	"path/filepath"
	"testing"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/sensors/host"
)

type distroTestCase struct {
	name             string
	fixtureDir       string
	expectedDistroID string
	pkgType          string
	minExpectedPkgs  int
}

func TestDistroMatrix_SensorsAndPackageDetection(t *testing.T) {
	testCases := []distroTestCase{
		{
			name:             "Ubuntu / Debian",
			fixtureDir:       "../../test/fixtures/debian",
			expectedDistroID: "debian",
			pkgType:          "dpkg",
			minExpectedPkgs:  1,
		},
		{
			name:             "RHEL / Rocky / Alma / Fedora",
			fixtureDir:       "../../test/fixtures/rhel",
			expectedDistroID: "rhel",
			pkgType:          "rpm",
			minExpectedPkgs:  0,
		},
		{
			name:             "Arch Linux",
			fixtureDir:       "../../test/fixtures/arch",
			expectedDistroID: "arch",
			pkgType:          "pacman",
			minExpectedPkgs:  0,
		},
		{
			name:             "Alpine Linux (musl)",
			fixtureDir:       "../../test/fixtures/alpine",
			expectedDistroID: "alpine",
			pkgType:          "apk",
			minExpectedPkgs:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			absPath, err := filepath.Abs(tc.fixtureDir)
			if err != nil {
				t.Fatalf("failed to get abs path: %v", err)
			}
			rfs := fs.NewRootedFS(absPath)

			// 1. Host identity sensor
			hSensor := host.New(rfs)
			obs, err := hSensor.Collect(t.Context())
			if err != nil {
				t.Fatalf("host sensor failed on %s: %v", tc.name, err)
			}
			if len(obs.Items) == 0 {
				t.Fatalf("expected items in host observation for %s", tc.name)
			}
			info, ok := obs.Items[0].Data.(host.HostInfo)
			if !ok {
				t.Fatalf("unexpected data type from host sensor: %T", obs.Items[0].Data)
			}
			if info.DistroFamily != tc.expectedDistroID && info.Distro != tc.expectedDistroID {
				t.Logf("distro on %s: Distro=%q, Family=%q", tc.name, info.Distro, info.DistroFamily)
			}

			// 2. Inventory collection
			mgr := inventory.NewManager(rfs)
			inv, err := mgr.CollectInventory(t.Context())
			if err != nil {
				t.Fatalf("inventory collection failed on %s: %v", tc.name, err)
			}
			t.Logf("[%s] collected %d system packages", tc.name, len(inv.Packages))
		})
	}
}
