// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/OWNER/kazeshini/internal/api"
	"github.com/OWNER/kazeshini/internal/auth"
	"github.com/OWNER/kazeshini/internal/briefing"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/logging"
	"github.com/OWNER/kazeshini/internal/origin"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/report"
	"github.com/OWNER/kazeshini/internal/rules"
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
	"github.com/OWNER/kazeshini/internal/store"
	"github.com/OWNER/kazeshini/internal/supervisor"
	"github.com/OWNER/kazeshini/internal/verdict"
)

var (
	// Injected via ldflags
	Version   = "v0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func getVersionInfo() api.VersionInfo {
	return api.VersionInfo{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("subcommand required")
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "version":
		v := getVersionInfo()
		fmt.Printf("kazeshini %s (commit: %s, built: %s, %s)\n", v.Version, v.Commit, v.BuildDate, v.GoVersion)
		return nil

	case "doctor":
		return runDoctor()

	case "briefing":
		return runBriefing(subargs)

	case "snapshot":
		return runSnapshot()

	case "serve":
		return runServe(subargs)

	case "rules":
		return runRules(subargs)

	case "token":
		return runToken(subargs)

	case "report":
		return runReport(subargs)

	case "help", "-h", "--help":
		printUsage()
		return nil

	default:
		printUsage()
		return fmt.Errorf("unknown subcommand %q", subcmd)
	}
}

func printUsage() {
	fmt.Println(`Kazeshini (風死) — Read-only Server Truth Engine for Linux

Usage:
  kazeshini <command> [options]

Commands:
  briefing   Print plain-English server truth briefing in terminal (works over SSH)
  doctor     Inspect host sensor visibility and coverage honesty table
  serve      Start the local API and web dashboard
  report     Generate a standalone State of this Server report (html, json, md)
  token      Print the local API authentication token (0600)
  rules      Lint or evaluate declarative rules (e.g. kazeshini rules lint <file>)
  snapshot   Capture a point-in-time provenance snapshot (stub)
  version    Print binary version information

Run 'kazeshini serve --help' for serve flags.`)
}

func runToken(args []string) error {
	flags := flag.NewFlagSet("token", flag.ContinueOnError)
	var configPath string
	flags.StringVar(&configPath, "config", "", "Path to configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	authMgr, err := auth.NewManager(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to load token: %w", err)
	}

	fmt.Println(authMgr.Token())
	return nil
}

func runReport(args []string) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	var (
		formatFlag string
		configPath string
	)
	flags.StringVar(&formatFlag, "format", "html", "Report output format: html, json, or md")
	flags.StringVar(&configPath, "config", "", "Path to configuration file")

	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	rfs := fs.Default()
	pGraph := graphbuilder.NewProvenanceGraph()

	// Ingest current sensors for snapshot
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

	// Connect origin resolver
	invManager := inventory.NewManager(rfs)
	originResolver := origin.NewResolver(rfs, invManager)
	pGraph.SetOriginResolver(originResolver)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	allSensors := []string{
		"host", "process", "service", "network",
		"storage", "resources", "container", "user", "scheduler", "kernel",
	}

	for _, name := range allSensors {
		if s, ok := registry.Get(name); ok {
			if obs, err := s.Collect(ctx); err == nil {
				pGraph.IngestObservation(obs)
			}
		}
	}

	nodes, edges := pGraph.Snapshot()
	ruleEngine := rules.NewEngine(3 * time.Second)
	_, _ = ruleEngine.LoadDirectory(cfg.RulesDir)
	findings, _ := ruleEngine.Evaluate(ctx, nodes, edges)
	vSum := verdict.ComputeVerdict(nodes, findings, 0)

	gen := report.NewGenerator(
		pGraph,
		getVersionInfo().Version,
		vSum,
		findings,
		nil,
		diff.ChangeSet{},
	)

	switch strings.ToLower(formatFlag) {
	case "json":
		data, err := gen.RenderJSON()
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "md", "markdown":
		fmt.Println(gen.RenderMarkdown())
	case "html":
		fmt.Println(gen.RenderHTML())
	default:
		return fmt.Errorf("unsupported format %q (supported: html, json, md)", formatFlag)
	}

	return nil
}

func runRules(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kazeshini rules lint <file|directory>")
	}
	sub := args[0]
	if sub != "lint" {
		return fmt.Errorf("unknown rules subcommand %q (supported: lint)", sub)
	}
	if len(args) < 2 {
		return errors.New("usage: kazeshini rules lint <file|directory>")
	}

	target := args[1]
	fi, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cannot access %q: %w", target, err)
	}

	if fi.IsDir() {
		engine := rules.NewEngine(5 * time.Second)
		count, err := engine.LoadDirectory(target)
		if err != nil {
			return err
		}
		fmt.Printf("Successfully linted %d rules in %s\n", count, target)
		return nil
	}

	r, err := rules.LintRule(target)
	if err != nil {
		return err
	}
	fmt.Printf("[OK] Rule %s (%s) passed linting successfully.\n", r.ID, r.Name)
	return nil
}

func runDoctor() error {
	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI DOCTOR — SENSOR INSPECTION & COVERAGE HONESTY")
	fmt.Println("======================================================================")

	rfs := fs.Default()
	invManager := inventory.NewManager(rfs)
	originResolver := origin.NewResolver(rfs, invManager)
	orphanScanner := orphan.NewScanner(rfs, originResolver)

	// Run initial sensor collection to measure real visibility
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, s := range registry.All() {
		_, _ = sup.RunSensorSafe(ctx, s, 3*time.Second)
	}

	assessor := coverage.NewAssessor(sup, invManager, orphanScanner, rfs)
	cov := assessor.Assess(ctx)

	fmt.Printf("%-26s | %-12s | %-10s | %s\n", "SUBSYSTEM / SENSOR", "READABLE", "STATUS", "EXPLANATION")
	fmt.Println(strings.Repeat("-", 70))
	for _, it := range cov.Items {
		readableStr := fmt.Sprintf("%d / %d", it.Readable, it.Total)
		if it.Total == 0 && it.Readable == 0 {
			readableStr = "n/a"
		}
		statusTag := "[" + strings.ToUpper(it.Status) + "]"
		fmt.Printf("%-26s | %-12s | %-10s | %s\n", it.Name, readableStr, statusTag, it.Explanation)
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("OVERALL INSPECTION COVERAGE: %.1f%%\n", cov.OverallCoverage)
	fmt.Printf("VERDICT ADEQUACY:            %s\n", cov.SummaryNote)
	if cov.IsAdequate {
		fmt.Println("RESULT: [OK] Sensor coverage adequate for truth analysis.")
	} else {
		fmt.Println("RESULT: [PARTIAL] Some sensors have limited visibility (CALM verdict suspended).")
	}
	fmt.Println("======================================================================")
	return nil
}

func runBriefing(args []string) error {
	rfs := fs.Default()
	pGraph := graphbuilder.NewProvenanceGraph()

	invManager := inventory.NewManager(rfs)
	originResolver := origin.NewResolver(rfs, invManager)
	orphanScanner := orphan.NewScanner(rfs, originResolver)
	pGraph.SetOriginResolver(originResolver)

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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, s := range registry.All() {
		if obs, err := sup.RunSensorSafe(ctx, s, 3*time.Second); err == nil {
			pGraph.IngestObservation(obs)
		}
	}

	// Trigger bounded orphan scan for hand-installed programs (up to 500 files, 1s)
	scanRes := orphanScanner.RunScan(ctx, 1*time.Second, 500)

	assessor := coverage.NewAssessor(sup, invManager, orphanScanner, rfs)
	cov := assessor.Assess(ctx)

	nodes, edges := pGraph.Snapshot()
	cfg, _ := config.Load("")
	ruleEngine := rules.NewEngine(3 * time.Second)
	_, _ = ruleEngine.LoadDirectory(cfg.RulesDir)
	findings, _ := ruleEngine.Evaluate(ctx, nodes, edges)

	builder := briefing.NewBuilder()
	br := builder.Build(ctx, nodes, findings, []orphan.ScanResult{scanRes}, cov, time.Now().UTC())

	fmt.Print(br.RenderTerminal())
	return nil
}

func runSnapshot() error {
	fmt.Println("Kazeshini Snapshot: Point-in-time snapshot collection stub.")
	fmt.Println("Captured 0 nodes, 0 edges (sensors not yet registered).")
	return nil
}

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)

	var (
		hostFlag        string
		portFlag        int
		allowRemoteFlag bool
		configPathFlag  string
		logLevelFlag    string
		logFormatFlag   string
	)

	flags.StringVar(&hostFlag, "host", "", "Host address to bind (default: 127.0.0.1)")
	flags.IntVar(&portFlag, "port", 0, "Port to listen on (default: 7777)")
	flags.BoolVar(&allowRemoteFlag, "allow-remote", false, "Allow binding to non-loopback addresses")
	flags.StringVar(&configPathFlag, "config", "", "Path to configuration file")
	flags.StringVar(&logLevelFlag, "log-level", "", "Logging level (debug, info, warn, error)")
	flags.StringVar(&logFormatFlag, "log-format", "", "Logging format (text, json)")

	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(configPathFlag)
	if err != nil {
		return fmt.Errorf("configuration loading error: %w", err)
	}

	if hostFlag != "" {
		cfg.Host = hostFlag
	}
	if portFlag != 0 {
		cfg.Port = portFlag
	}
	if allowRemoteFlag {
		cfg.AllowRemote = true
	}
	if logLevelFlag != "" {
		cfg.LogLevel = logLevelFlag
	}
	if logFormatFlag != "" {
		cfg.LogFormat = logFormatFlag
	}

	// Validate configuration (including loopback check)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation error: %w", err)
	}

	// Loud warning if remote binding is enabled and non-loopback address is targeted
	ip := net.ParseIP(cfg.Host)
	isLoopback := cfg.Host == "localhost" || (ip != nil && ip.IsLoopback())
	if !isLoopback && cfg.AllowRemote {
		fmt.Fprintln(os.Stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		fmt.Fprintln(os.Stderr, "WARNING: Kazeshini is configured to listen on a non-loopback address:")
		fmt.Fprintf(os.Stderr, "         %s:%d\n", cfg.Host, cfg.Port)
		fmt.Fprintln(os.Stderr, "Ensure appropriate network firewalls and authentication layers protect")
		fmt.Fprintln(os.Stderr, "this host. Kazeshini exposes server truth and system diagnostics.")
		fmt.Fprintln(os.Stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	}

	logger := logging.Setup(logging.Config{
		Level:  cfg.LogLevel,
		Format: cfg.LogFormat,
	})

	// Lower process priority immediately before initializing sensors, inventory, or store
	supervisor.LowerProcessPriority()

	// Initialize RootedFS and Sensor Registry
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

	sup := supervisor.New(registry, logger)

	// Initialize Phase 3: Inventory, Origin Resolver, Orphan Scanner
	invManager := inventory.NewManager(rfs)
	originResolver := origin.NewResolver(rfs, invManager)
	orphanScanner := orphan.NewScanner(rfs, originResolver)

	// Initialize Phase 4: ProvenanceGraph and BoltStore
	pGraph := graphbuilder.NewProvenanceGraph()
	pGraph.SetOriginResolver(originResolver)
	bStore, err := store.Open(store.DefaultConfig(cfg.DataDir), logger)
	if err != nil {
		logger.Warn("could not open persistent store; running in memory", "error", err)
	} else if latestSnap, err := bStore.GetLatestSnapshot(context.Background()); err == nil && latestSnap != nil {
		pGraph.SeedFromSnapshot(latestSnap.Nodes)
		logger.Info("seeded provenance graph from persistent store", "nodes", len(latestSnap.Nodes))
	}
	defer func() {
		if bStore != nil {
			_ = bStore.Close()
		}
	}()

	// Initialize Phase 5: Rule Engine
	ruleEngine := rules.NewEngine(3 * time.Second)
	// Load rules from configured rules directory
	if count, err := ruleEngine.LoadDirectory(cfg.RulesDir); err == nil {
		logger.Info("loaded rules from directory", "dir", cfg.RulesDir, "count", count)
	}
	// Also attempt loading host rules from /etc/kazeshini/rules.d if present
	if _, err := os.Stat("/etc/kazeshini/rules.d"); err == nil {
		if count, err := ruleEngine.LoadDirectory("/etc/kazeshini/rules.d"); err == nil && count > 0 {
			logger.Info("loaded custom rules from /etc/kazeshini/rules.d", "count", count)
		}
	}

	server, err := api.NewServer(cfg, getVersionInfo(), sup, invManager, originResolver, orphanScanner, pGraph, bStore, ruleEngine, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize api server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("failed to start supervisor: %w", err)
	}
	defer func() {
		_ = sup.Stop()
	}()

	allSensors := []string{
		"host", "process", "service", "network",
		"storage", "resources", "container", "user", "scheduler", "kernel",
	}

	// Background loop ingesting sensor observations into pGraph, storing snapshots, diffing, and recording metric samples
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastSnap *store.Snapshot
		lastObsTimes := make(map[string]time.Time)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var hasNewData bool
				for _, sName := range allSensors {
					if obs, ok := sup.GetObservation(sName); ok {
						if prevTime, seen := lastObsTimes[sName]; !seen || obs.Timestamp.After(prevTime) {
							lastObsTimes[sName] = obs.Timestamp
							hasNewData = true
							pGraph.IngestObservation(obs)
						}
						// Record metrics for resource forecaster
						if sName == "host" {
							for _, it := range obs.Items {
								if info, ok := it.Data.(host.HostInfo); ok {
									if info.MemoryBytes > 0 {
										server.RecordSample("system_ram", float64(info.MemoryBytes)/(1024*1024))
									}
									if info.SwapBytes > 0 {
										server.RecordSample("swap", float64(info.SwapBytes)/(1024*1024))
									}
								}
							}
						} else if sName == "storage" {
							for _, it := range obs.Items {
								if m, ok := it.Data.(storage.MountInfo); ok {
									// Forecast only real block-device mounts, skip tmpfs/ro pseudo mounts
									if (m.IsBlockDevice || m.MountPoint == "/") && !m.ReadOnly && m.FSType != "tmpfs" {
										server.RecordSample(m.MountPoint, m.UsageRatio*100)
										if m.UsedInodes > 0 {
											server.RecordSample(m.MountPoint+"_inodes", float64(m.UsedInodes))
										}
									}
								}
							}
						} else if sName == "resources" {
							for _, it := range obs.Items {
								if r, ok := it.Data.(resources.ResourceSample); ok {
									server.RecordSample("load1", r.Load1)
									if r.MemUsageRatio > 0 {
										server.RecordSample("system_ram", r.MemUsageRatio*100)
									}
									if r.SwapUsageRatio > 0 {
										server.RecordSample("swap", r.SwapUsageRatio*100)
									}
								}
							}
						}
					}
				}

				if hasNewData {
					nodes, edges := pGraph.Snapshot()
					if len(nodes) > 0 && bStore != nil {
						newSnap := store.Snapshot{
							ID:        fmt.Sprintf("snap-%d", time.Now().Unix()),
							Timestamp: time.Now().UTC(),
							Nodes:     nodes,
							Edges:     edges,
						}
						_ = bStore.SaveSnapshot(ctx, newSnap)

						// Diff against previous snapshot and process watchers
						if lastSnap != nil {
							cs := server.DiffEngine().DiffSnapshots(*lastSnap, newSnap)
							server.Watchers().ProcessChangeSet(ctx, cs)
						}
						lastSnap = &newSnap
					}
				}
			}
		}
	}()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	select {
	case <-ctx.Done():
		logger.Info("received termination signal, initiating shutdown")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
		return nil
	case err := <-errChan:
		return err
	}
}
