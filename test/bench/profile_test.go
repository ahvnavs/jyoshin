// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package bench_test

import (
	"context"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/sensors"
	"github.com/OWNER/kazeshini/internal/sensors/container"
	"github.com/OWNER/kazeshini/internal/sensors/host"
	"github.com/OWNER/kazeshini/internal/sensors/kernel"
	"github.com/OWNER/kazeshini/internal/sensors/network"
	"github.com/OWNER/kazeshini/internal/sensors/process"
	"github.com/OWNER/kazeshini/internal/sensors/resources"
	"github.com/OWNER/kazeshini/internal/sensors/scheduler"
	"github.com/OWNER/kazeshini/internal/sensors/service"
	"github.com/OWNER/kazeshini/internal/sensors/storage"
	"github.com/OWNER/kazeshini/internal/sensors/user"
	"github.com/OWNER/kazeshini/internal/supervisor"
)

// TestIdleMinuteProfile captures a 60-second idle CPU profile while running
// all sensors through the supervisor at their normal cadence.
func TestIdleMinuteProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 60s idle profile capture in short test mode")
	}

	profFile, err := os.Create("/tmp/idle_minute.pprof")
	if err != nil {
		t.Fatalf("failed to create profile file: %v", err)
	}
	defer profFile.Close()

	if err := pprof.StartCPUProfile(profFile); err != nil {
		t.Fatalf("failed to start cpu profile: %v", err)
	}
	defer pprof.StopCPUProfile()

	rfs := fs.Default()
	registry := sensors.NewRegistry()
	_ = registry.Register(host.New(rfs))
	_ = registry.Register(process.New(rfs))
	_ = registry.Register(service.New(rfs))
	_ = registry.Register(network.New(rfs))
	_ = registry.Register(storage.New(rfs))
	_ = registry.Register(resources.New(rfs))
	_ = registry.Register(container.New(rfs))
	_ = registry.Register(user.NewSensor(rfs.Root()))
	_ = registry.Register(scheduler.NewSensor(rfs.Root()))
	_ = registry.Register(kernel.NewSensor(rfs.Root()))

	sup := supervisor.New(registry, nil)
	pGraph := graphbuilder.NewProvenanceGraph()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := sup.Start(ctx); err != nil {
		t.Fatalf("supervisor start failed: %v", err)
	}
	defer func() {
		_ = sup.Stop()
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Run for 60 seconds of idle collection
	timeout := time.After(60 * time.Second)
	for {
		select {
		case <-timeout:
			t.Log("Completed 60s idle profile capture")
			return
		case <-ticker.C:
			for _, s := range registry.All() {
				if obs, ok := sup.GetObservation(s.Name()); ok {
					pGraph.IngestObservation(obs)
				}
			}
		}
	}
}
