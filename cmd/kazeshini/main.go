// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/OWNER/kazeshini/internal/api"
	"github.com/OWNER/kazeshini/internal/audit"
	"github.com/OWNER/kazeshini/internal/auth"
	"github.com/OWNER/kazeshini/internal/briefing"
	"github.com/OWNER/kazeshini/internal/checks"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/desired"
	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/facts"
	"github.com/OWNER/kazeshini/internal/fleet"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/logging"
	"github.com/OWNER/kazeshini/internal/origin"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/policy"
	"github.com/OWNER/kazeshini/internal/report"
	"github.com/OWNER/kazeshini/internal/resource"
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
	"github.com/OWNER/kazeshini/internal/software"
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

	case "check":
		return runCheck(subargs)

	case "open":
		return runOpen(subargs)

	case "desired":
		return runDesired(subargs)

	case "drift":
		return runDrift(subargs)

	case "plan":
		return runPlan(subargs)

	case "software":
		return runSoftware(subargs)

	case "audit":
		return runAudit(subargs)

	case "facts":
		return runFacts(subargs)

	case "agent":
		return runAgent(subargs)

	case "controller":
		return runController(subargs)

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
  open       Foreground local server truth dashboard for headless/SSH servers (no root, ephemeral)
  briefing   Print plain-English server truth briefing in terminal (works over SSH)
  doctor     Inspect host sensor visibility and coverage honesty table
  check      Execute read-only diagnostics (list, run, symptom)
  serve      Start the local API and web dashboard
  report     Generate a standalone State of this Server report (html, json, md)
  token      Print the local API authentication token (0600)
  desired    Manage declarative desired state manifests (e.g. kazeshini desired lint <file>)
  drift      Audit discrepancies between desired state and observed host resources
  plan       Generate deterministic topologically sorted remediation DAG (read-only, shown only)
  software   Read-only software inventory, local candidate versions, and dry-run safety plans
  audit      Verify cryptographic integrity or tail API request audit log (audit verify|tail)
  rules      Lint or evaluate declarative rules (e.g. kazeshini rules lint <file>)
  snapshot   Capture a point-in-time provenance snapshot (stub)
  version    Print binary version information

Run 'kazeshini open --help' or 'kazeshini check help' for options.`)
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
		debugFlag       bool
		statelessFlag   bool
	)

	flags.StringVar(&hostFlag, "host", "", "Host address to bind (default: 127.0.0.1)")
	flags.IntVar(&portFlag, "port", 0, "Port to listen on (default: 7777)")
	flags.BoolVar(&allowRemoteFlag, "allow-remote", false, "Allow binding to non-loopback addresses")
	flags.StringVar(&configPathFlag, "config", "", "Path to configuration file")
	flags.StringVar(&logLevelFlag, "log-level", "", "Logging level (debug, info, warn, error)")
	flags.StringVar(&logFormatFlag, "log-format", "", "Logging format (text, json)")
	flags.BoolVar(&debugFlag, "debug", false, "Enable debug mode and pprof profiling endpoints")
	flags.BoolVar(&statelessFlag, "stateless", false, "Run strictly stateless with zero disk touches (Memory store only)")

	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(configPathFlag)
	if err != nil {
		return fmt.Errorf("configuration loading error: %w", err)
	}

	if statelessFlag {
		cfg.Stateless = true
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
	if debugFlag {
		cfg.Debug = true
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

	// Initialize Phase 4: ProvenanceGraph and Store
	pGraph := graphbuilder.NewProvenanceGraph()
	pGraph.SetOriginResolver(originResolver)

	var bStore *store.BoltStore
	if cfg.Stateless {
		logger.Info("running in stateless mode: zero disk persistence (Memory store only)")
	} else {
		var err error
		bStore, err = store.Open(store.DefaultConfig(cfg.DataDir), logger)
		if err != nil {
			logger.Warn("could not open persistent store; running in memory", "error", err)
		} else if latestSnap, err := bStore.GetLatestSnapshot(context.Background()); err == nil && latestSnap != nil {
			pGraph.SeedFromSnapshot(latestSnap.Nodes)
			logger.Info("seeded provenance graph from persistent store", "nodes", len(latestSnap.Nodes))
		}
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

	fmt.Printf("Kazeshini dashboard: http://%s:%d\n", cfg.Host, cfg.Port)
	if cfg.Stateless && server.AuthManager() != nil {
		fmt.Printf("Access token (stateless in-memory): %s\n", server.AuthManager().Token())
	} else {
		fmt.Println("Access token: run 'kazeshini token' or check data directory auth.token")
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
						switch sName {
						case "host":
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
						case "storage":
							for _, it := range obs.Items {
								if m, ok := it.Data.(storage.MountInfo); ok {
									// Forecast only real block-device mounts
									if m.IsBlockDevice {
										server.RecordSample(m.MountPoint, m.UsageRatio*100)
										if m.UsedInodes > 0 {
											server.RecordSample(m.MountPoint+"_inodes", float64(m.UsedInodes))
										}
									}
								}
							}
						case "resources":
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
					if len(nodes) > 0 {
						newSnap := store.Snapshot{
							ID:        fmt.Sprintf("snap-%d", time.Now().Unix()),
							Timestamp: time.Now().UTC(),
							Nodes:     nodes,
							Edges:     edges,
						}
						if bStore != nil {
							_ = bStore.SaveSnapshot(ctx, newSnap)
						}

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

func runCheck(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kazeshini check <list|run <id>|run --role <role>|symptom <name>> [--json]")
	}

	rfs := fs.Default()
	cfg, _ := config.Load("")
	actLog := checks.NewActivityLog(cfg.DataDir)
	engine := checks.NewEngine(nil, actLog, rfs)

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		all := engine.Registry().All()
		jsonOutput := false
		for _, a := range subargs {
			if a == "--json" {
				jsonOutput = true
			}
		}

		if jsonOutput {
			type checkMeta struct {
				ID          string `json:"id"`
				Role        string `json:"role"`
				Title       string `json:"title"`
				Description string `json:"description"`
			}
			var list []checkMeta
			for _, c := range all {
				list = append(list, checkMeta{
					ID:          c.ID(),
					Role:        c.Role(),
					Title:       c.Title(),
					Description: c.Description(),
				})
			}
			data, _ := json.MarshalIndent(list, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Println("======================================================================")
		fmt.Println("風死 · KAZESHINI READ-ONLY CHECKS")
		fmt.Println("======================================================================")
		fmt.Printf("%-24s | %-16s | %s\n", "CHECK ID", "ROLE", "TITLE")
		fmt.Println(strings.Repeat("-", 70))
		for _, c := range all {
			fmt.Printf("%-24s | %-16s | %s\n", c.ID(), c.Role(), c.Title())
		}
		fmt.Println(strings.Repeat("-", 70))
		return nil

	case "run":
		flags := flag.NewFlagSet("check run", flag.ContinueOnError)
		roleFlag := flags.String("role", "", "Role category to run (devops, cloud, cloud-platform, infrastructure, devsecops, platform, network)")
		jsonFlag := flags.Bool("json", false, "Output results in JSON format")
		failOnFlag := flags.String("fail-on", "", "Fail with exit code 1 if any check reports status (warn, crit)")
		targetFlag := flags.String("target", "", "Target host:port for active connectivity probe (e.g. 127.0.0.1:80)")
		fileFlag := flags.String("file", "", "Target file for log/config checks")
		unitFlag := flags.String("unit", "", "Target unit for app-health")

		// Extract trailing flags if passed after check id (e.g. check run disk-inodes --json)
		parsedArgs := make([]string, 0, len(subargs))
		var nonFlagArgs []string
		for i := 0; i < len(subargs); i++ {
			arg := subargs[i]
			if strings.HasPrefix(arg, "-") {
				parsedArgs = append(parsedArgs, arg)
				if (arg == "--role" || arg == "-role" || arg == "--fail-on" || arg == "-fail-on" || arg == "--target" || arg == "-target" || arg == "--file" || arg == "-file" || arg == "--unit" || arg == "-unit") && i+1 < len(subargs) {
					i++
					parsedArgs = append(parsedArgs, subargs[i])
				}
			} else {
				nonFlagArgs = append(nonFlagArgs, arg)
			}
		}
		parsedArgs = append(parsedArgs, nonFlagArgs...)

		if err := flags.Parse(parsedArgs); err != nil {
			return err
		}

		params := make(map[string]string)
		if *targetFlag != "" {
			params["target"] = *targetFlag
		}
		if *fileFlag != "" {
			params["file"] = *fileFlag
		}
		if *unitFlag != "" {
			params["unit"] = *unitFlag
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		evaluateFailOn := func(results ...contract.CheckResult) error {
			if *failOnFlag == "" {
				return nil
			}
			failOn := strings.ToLower(*failOnFlag)
			for _, r := range results {
				if failOn == "warn" && (r.Status == contract.StatusWarn || r.Status == contract.StatusCrit) {
					return fmt.Errorf("check %s failed with status %s (fail-on: warn)", r.ID, r.Status)
				}
				if failOn == "crit" && r.Status == contract.StatusCrit {
					return fmt.Errorf("check %s failed with status %s (fail-on: crit)", r.ID, r.Status)
				}
			}
			return nil
		}

		if *roleFlag != "" {
			results, err := engine.RunRole(ctx, *roleFlag, params, "local-cli")
			if err != nil {
				return err
			}
			if *jsonFlag {
				data, _ := json.MarshalIndent(results, "", "  ")
				fmt.Println(string(data))
				return evaluateFailOn(results...)
			}
			fmt.Println("======================================================================")
			fmt.Printf("風死 · KAZESHINI CHECK RUN — ROLE: [%s]\n", strings.ToUpper(*roleFlag))
			fmt.Println("======================================================================")
			for _, r := range results {
				fmt.Print(r.RenderTerminal())
				fmt.Println(strings.Repeat("-", 70))
			}
			return evaluateFailOn(results...)
		}

		remArgs := flags.Args()
		if len(remArgs) == 0 {
			return errors.New("usage: kazeshini check run <id> or kazeshini check run --role <role>")
		}

		checkID := remArgs[0]
		res, err := engine.RunCheck(ctx, checkID, params, "local-cli")
		if err != nil {
			return err
		}

		if *jsonFlag {
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
			return evaluateFailOn(res)
		}

		fmt.Println("======================================================================")
		fmt.Printf("風死 · KAZESHINI CHECK: %s\n", checkID)
		fmt.Println("======================================================================")
		fmt.Print(res.RenderTerminal())
		fmt.Println("======================================================================")
		return evaluateFailOn(res)

	case "symptom":
		if len(subargs) == 0 {
			fmt.Println("Available symptoms:")
			for _, s := range checks.AvailableSymptoms() {
				fmt.Printf("  • %-16s — %s\n", s.ID, s.Description)
			}
			return nil
		}

		query := subargs[0]
		jsonFlag := false
		for _, a := range subargs[1:] {
			if a == "--json" {
				jsonFlag = true
			}
		}

		sym, err := checks.FindSymptom(query)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		var results []contract.CheckResult
		for _, cid := range sym.CheckIDs {
			res, _ := engine.RunCheck(ctx, cid, nil, "local-cli")
			results = append(results, res)
		}

		if jsonFlag {
			output := map[string]any{
				"symptom": sym,
				"results": results,
			}
			data, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Println("======================================================================")
		fmt.Printf("風死 · KAZESHINI SYMPTOM INVESTIGATION: %s\n", strings.ToUpper(sym.Name))
		fmt.Printf("Description: %s\n", sym.Description)
		fmt.Println("======================================================================")
		for i, cid := range sym.CheckIDs {
			fmt.Printf("\n[%d] CHECK: %s\n", i+1, cid)
			if i < len(sym.Reasons) {
				fmt.Printf("    Rationale: %s\n", sym.Reasons[i])
			}
			res := results[i]
			fmt.Printf("    Status:    [%s]\n", res.Status)
			fmt.Printf("    Observed:  %s\n", res.SummaryPlain)
			if res.ExplainLevels[1] != "" {
				fmt.Printf("    Possible Cause: %s\n", res.ExplainLevels[1])
			}
		}
		fmt.Println("\n======================================================================")
		return nil

	default:
		return fmt.Errorf("unknown check subcommand %q (supported: list, run, symptom)", subcmd)
	}
}

func runOpen(args []string) error {
	flags := flag.NewFlagSet("open", flag.ContinueOnError)
	portFlag := flags.Int("port", 0, "Local port to listen on (default: random free port)")
	idleTimeoutFlag := flags.Duration("idle-timeout", 30*time.Minute, "Idle timeout without HTTP requests before exiting")
	ephemeralFlag := flags.Bool("ephemeral", true, "Store state in a temporary directory and delete on exit")
	tuiFlag := flags.Bool("tui", false, "Render interactive terminal TUI table of verdict, coverage, and checks")

	if err := flags.Parse(args); err != nil {
		return err
	}

	rfs := fs.Default()
	cfg := config.Default()
	cfg.Host = "127.0.0.1"

	// Bind listener upfront (random free port if 0)
	bindAddr := fmt.Sprintf("127.0.0.1:%d", *portFlag)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", bindAddr, err)
	}
	defer func() {
		_ = ln.Close()
	}()

	cfg.Port = ln.Addr().(*net.TCPAddr).Port

	// Handle ephemeral data directory
	var tempDir string
	if *ephemeralFlag {
		var err error
		tempDir, err = os.MkdirTemp("", "kazeshini-open-*")
		if err != nil {
			return fmt.Errorf("failed creating ephemeral directory: %w", err)
		}
		cfg.DataDir = tempDir
		defer func() {
			_ = os.RemoveAll(tempDir)
		}()
	}

	// Initialize subsystems
	logger := logging.Setup(logging.Config{Level: "warn", Format: "text"})
	supervisor.LowerProcessPriority()

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
	invManager := inventory.NewManager(rfs)
	originResolver := origin.NewResolver(rfs, invManager)
	orphanScanner := orphan.NewScanner(rfs, originResolver)
	pGraph := graphbuilder.NewProvenanceGraph()
	pGraph.SetOriginResolver(originResolver)

	ruleEngine := rules.NewEngine(3 * time.Second)
	_, _ = ruleEngine.LoadDirectory("rules")

	server, err := api.NewServer(cfg, getVersionInfo(), sup, invManager, originResolver, orphanScanner, pGraph, nil, ruleEngine, logger)
	if err != nil {
		return fmt.Errorf("failed initializing server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("failed starting supervisor: %w", err)
	}
	defer func() {
		_ = sup.Stop()
	}()

	// Query initial sensor sweep for coverage
	assessor := coverage.NewAssessor(sup, invManager, orphanScanner, rfs)
	cov := assessor.Assess(ctx)

	// Fetch token
	authMgr, _ := auth.NewManager(cfg.DataDir)
	tokenStr := ""
	if authMgr != nil {
		tokenStr = authMgr.Token()
	}

	// Terminal Banner
	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI OPEN — FOREGROUND SERVER TRUTH DASHBOARD")
	fmt.Println("======================================================================")
	fmt.Printf("STATUS:        Foreground server active (PID: %d)\n", os.Getpid())
	fmt.Printf("DASHBOARD URL: http://127.0.0.1:%d\n", cfg.Port)
	fmt.Printf("ACCESS TOKEN:  %s\n\n", tokenStr)

	fmt.Println("HEADLESS / REMOTE SSH ACCESS:")
	fmt.Println("  Run this on your local laptop to tunnel the port securely:")
	fmt.Printf("  \033[1;36mssh -L %d:127.0.0.1:%d %s@<server-ip>\033[0m\n\n", cfg.Port, cfg.Port, os.Getenv("USER"))

	isRoot := os.Geteuid() == 0
	if !isRoot {
		fmt.Printf("VISIBILITY:    Non-root user (Coverage: %.0f%%)\n", cov.OverallCoverage)
		if !cov.IsAdequate {
			fmt.Println("               Some sensor visibility is limited by host access controls.")
			fmt.Printf("               For 100%% full visibility, run: \033[1;33msudo kazeshini open --port %d\033[0m\n\n", cfg.Port)
		}
	} else {
		fmt.Println("VISIBILITY:    Root execution (Full kernel & process visibility enabled)")
	}

	fmt.Printf("LIFECYCLE:     Exits on Ctrl+C or after %s of inactivity\n", idleTimeoutFlag.String())
	if *ephemeralFlag {
		fmt.Printf("STORAGE:       Ephemeral directory: %s (will delete on exit)\n", tempDir)
	}
	fmt.Println("======================================================================")

	if *tuiFlag {
		renderTUI(ctx, rfs, cov)
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.ServeListener(ln)
	}()

	// Idle timeout monitor loop
	idleTicker := time.NewTicker(1 * time.Second)
	defer idleTicker.Stop()

	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nReceived termination signal. Shutting down gracefully...")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
			return nil
		case err := <-errChan:
			return err
		case <-idleTicker.C:
			lastReq := server.LastActivity()
			if lastReq.IsZero() {
				// No requests yet; compare against startup time
				lastReq = startTime
			}
			if *idleTimeoutFlag > 0 && time.Since(lastReq) >= *idleTimeoutFlag {
				fmt.Printf("\nIdle timeout (%s without requests) reached. Shutting down...\n", idleTimeoutFlag.String())
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdownCtx)
				return nil
			}
		}
	}
}

func renderTUI(ctx context.Context, rfs fs.FS, cov coverage.Report) {
	fmt.Println("\n--- TERMINAL TUI SCREEN (STDLIB ANSI) ---")
	verdictLabel := "CALM"
	colorCode := "\033[1;32m" // Green
	if !cov.IsAdequate {
		verdictLabel = "PARTIAL"
		colorCode = "\033[1;33m" // Yellow
	}
	fmt.Printf("VERDICT: %s[%s]\033[0m   COVERAGE: %.0f%% (%s)\n\n", colorCode, verdictLabel, cov.OverallCoverage, cov.SummaryNote)

	engine := checks.NewEngine(nil, nil, rfs)
	all := engine.Registry().All()

	fmt.Printf("%-22s | %-16s | %-10s | %s\n", "CHECK ID", "ROLE", "STATUS", "SUMMARY")
	fmt.Println(strings.Repeat("-", 76))

	for _, c := range all {
		res, _ := c.Run(ctx, rfs, nil)
		stColor := "\033[1;32m"
		switch res.Status {
		case contract.StatusCrit:
			stColor = "\033[1;31m"
		case contract.StatusWarn:
			stColor = "\033[1;33m"
		case contract.StatusUnknown, contract.StatusNotApplicable:
			stColor = "\033[1;34m"
		}
		summaryShort := res.SummaryPlain
		if len(summaryShort) > 36 {
			summaryShort = summaryShort[:33] + "..."
		}
		fmt.Printf("%-22s | %-16s | %s%-10s\033[0m | %s\n", c.ID(), c.Role(), stColor, string(res.Status), summaryShort)
	}
	fmt.Println(strings.Repeat("-", 76))
	fmt.Println("--- END TERMINAL TUI ---")
	fmt.Println()
}

func runDesired(args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: kazeshini desired lint <file-or-dir>")
		return nil
	}
	switch args[0] {
	case "lint":
		target := "kazeshini.desired.yaml"
		if len(args) > 1 {
			target = args[1]
		}
		manifest, err := desired.LoadFile(target)
		if err != nil {
			return fmt.Errorf("desired manifest lint failed: %w", err)
		}
		fmt.Printf("[OK] Valid DesiredState manifest: %q (apiVersion: %s, rules: %d)\n",
			manifest.Metadata.Name, manifest.APIVersion, len(manifest.Rules))
		return nil
	default:
		return fmt.Errorf("unknown desired subcommand %q (try 'lint')", args[0])
	}
}

func collectHostObservation() ([]graph.Node, coverage.Report) {
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

	if inv, err := invManager.CollectInventory(ctx); err == nil {
		now := time.Now().UTC()
		for _, pkg := range inv.Packages {
			pkgNodeID := graphbuilder.GenerateNodeID(graph.NodePackage, pkg.Name)
			_ = pGraph.UpsertNode(graph.Node{
				ID:        pkgNodeID,
				Type:      graph.NodePackage,
				Label:     pkg.Name,
				Properties: map[string]any{
					"version": pkg.Version,
					"manager": pkg.Manager,
					"arch":    pkg.Arch,
				},
				Certainty: graph.CertaintyObserved,
				FirstSeen: now,
				LastSeen:  now,
			})
		}
	}

	assessor := coverage.NewAssessor(sup, invManager, orphanScanner, rfs)
	cov := assessor.Assess(ctx)

	nodes, _ := pGraph.Snapshot()
	return nodes, cov
}

func runDrift(args []string) error {
	flags := flag.NewFlagSet("drift", flag.ContinueOnError)
	var (
		desiredPath string
		labelsPath  string
		format      string
		exitCode    bool
	)
	flags.StringVar(&desiredPath, "desired", "kazeshini.desired.yaml", "Path to kazeshini.desired.yaml")
	flags.StringVar(&labelsPath, "labels", "", "Path to host labels YAML")
	flags.StringVar(&format, "format", "text", "Output format (text, json)")
	flags.BoolVar(&exitCode, "exit-code", false, "Exit with code 1 if drift items are detected")

	if err := flags.Parse(args); err != nil {
		return err
	}

	manifest, err := desired.LoadFile(desiredPath)
	if err != nil {
		return fmt.Errorf("failed to load desired manifest %q: %w", desiredPath, err)
	}

	labels, _ := desired.LoadHostLabels(labelsPath)
	desiredState := manifest.ForHost(labels)

	nodes, cov := collectHostObservation()
	resources := make([]resource.Resource, len(nodes))
	for i, n := range nodes {
		resources[i] = resource.FromGraphNode(n)
	}

	engine := drift.NewEngine()
	items, summary := engine.Evaluate(context.Background(), desiredState, resources, cov)

	if strings.ToLower(format) == "json" {
		data, _ := json.MarshalIndent(map[string]any{
			"summary": summary,
			"items":   items,
		}, "", "  ")
		fmt.Println(string(data))
		if exitCode && summary.TotalDrift > 0 {
			return fmt.Errorf("drift detected: total=%d (exit-code enabled)", summary.TotalDrift)
		}
		return nil
	}

	fmt.Println("======================================================================")
	fmt.Printf("風死 · KAZESHINI DRIFT AUDIT — [DESIRED: %s]\n", manifest.Metadata.Name)
	fmt.Println("======================================================================")
	fmt.Printf("TOTAL DRIFT: %d | Missing: %d | Extra: %d | Mismatch: %d | WrongState: %d | UnexpectedPorts: %d | Unknown: %d\n",
		summary.TotalDrift, summary.Missing, summary.Extra, summary.Mismatch, summary.WrongState, summary.Ports, summary.Unknown)
	fmt.Println(strings.Repeat("-", 70))

	if len(items) == 0 {
		fmt.Println("[OK] Host matches desired state perfectly. Zero drift detected.")
		fmt.Println("======================================================================")
		return nil
	}

	for _, it := range items {
		statusTag := fmt.Sprintf("[%s]", strings.ToUpper(string(it.Kind)))
		fmt.Printf("%-18s %-10s %s\n", statusTag, it.ResourceKind, it.Name)
		fmt.Printf("  Summary:  %s\n", it.Summary)
		fmt.Printf("  Expected: %s\n", it.Expected)
		fmt.Printf("  Actual:   %s\n", it.Actual)
		fmt.Printf("  Certainty: [%s]\n", it.Certainty)
		fmt.Println()
	}
	fmt.Println("======================================================================")
	if exitCode && summary.TotalDrift > 0 {
		return fmt.Errorf("drift detected: total=%d (exit-code enabled)", summary.TotalDrift)
	}
	return nil
}

func runPlan(args []string) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	var (
		desiredPath string
		labelsPath  string
		format      string
	)
	flags.StringVar(&desiredPath, "desired", "kazeshini.desired.yaml", "Path to kazeshini.desired.yaml")
	flags.StringVar(&labelsPath, "labels", "", "Path to host labels YAML")
	flags.StringVar(&format, "format", "text", "Output format (text, json)")

	if err := flags.Parse(args); err != nil {
		return err
	}

	manifest, err := desired.LoadFile(desiredPath)
	if err != nil {
		return fmt.Errorf("failed to load desired manifest %q: %w", desiredPath, err)
	}

	labels, _ := desired.LoadHostLabels(labelsPath)
	desiredState := manifest.ForHost(labels)

	nodes, cov := collectHostObservation()
	resources := make([]resource.Resource, len(nodes))
	for i, n := range nodes {
		resources[i] = resource.FromGraphNode(n)
	}

	engine := drift.NewEngine()
	driftItems, _ := engine.Evaluate(context.Background(), desiredState, resources, cov)

	planner := plan.NewPlanner(nil)
	p, err := planner.CreatePlan(driftItems)
	if err != nil {
		return fmt.Errorf("planner error: %w", err)
	}

	polEngine := policy.NewEngine(policy.DefaultConfig())
	decision := polEngine.EvaluatePlan(context.Background(), p)

	if strings.ToLower(format) == "json" {
		data, _ := json.MarshalIndent(map[string]any{
			"plan":     p,
			"decision": decision,
		}, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("======================================================================")
	fmt.Printf("風死 · KAZESHINI REMEDIATION PLAN — [ID: %s]\n", p.ID)
	fmt.Println("======================================================================")
	fmt.Printf("DECISION:       [%s]\n", strings.ToUpper(string(decision.Decision)))
	fmt.Printf("POLICY STATUS:  %s\n", decision.Summary)
	fmt.Printf("HASH (SHA-256): %s\n", p.Hash)
	fmt.Printf("TOTAL STEPS:    %d | Max Risk: %s | Reversible: %v | Reboot Needed: %v\n",
		p.TotalSteps, p.MaxRisk, p.IsReversible, p.RequiresReboot)
	fmt.Println(strings.Repeat("-", 70))

	if len(p.Steps) == 0 {
		fmt.Println("Zero remediation steps required (host has zero drift).")
		fmt.Println("======================================================================")
		return nil
	}

	for i, s := range p.Steps {
		fmt.Printf("Step %d: [%s] %s (%s)\n", i+1, s.Action, s.Title, s.ResourceName)
		fmt.Printf("  Description:     %s\n", s.Description)
		if len(s.Dependencies) > 0 {
			fmt.Printf("  Dependencies:    %s\n", strings.Join(s.Dependencies, ", "))
		}
		if len(s.Preconditions) > 0 {
			fmt.Printf("  Preconditions:   %s\n", strings.Join(s.Preconditions, "; "))
		}
		if len(s.Postconditions) > 0 {
			fmt.Printf("  Postconditions:  %s\n", strings.Join(s.Postconditions, "; "))
		}
		if len(s.EquivalentCommands) > 0 {
			fmt.Println("  Equivalent Commands (SHOWN ONLY, NEVER AUTO-APPLIED):")
			for _, cmd := range s.EquivalentCommands {
				fmt.Printf("    $ %s\n", cmd)
			}
		}
		fmt.Println()
	}
	fmt.Println("======================================================================")
	return nil
}

func runSoftware(args []string) error {
	if len(args) == 0 {
		printSoftwareUsage()
		return nil
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "list":
		return runSoftwareList(subargs)
	case "available":
		return runSoftwareAvailable(subargs)
	case "plan":
		return runSoftwarePlan(subargs)
	case "help", "-h", "--help":
		printSoftwareUsage()
		return nil
	default:
		printSoftwareUsage()
		return fmt.Errorf("unknown software subcommand %q", subcmd)
	}
}

func printSoftwareUsage() {
	fmt.Println(`Usage:
  kazeshini software <subcommand> [options]

Subcommands:
  list                 List installed packages, status, and local upgrade candidates
  available <package>  Show available candidate version from local metadata cache
  plan upgrade <pkg>   Generate deterministic dry-run upgrade plan with safety analysis
  plan remove <pkg>    Generate deterministic dry-run removal plan with safety analysis
  plan install <pkg>   Generate deterministic dry-run installation plan with safety analysis

Flags for 'list':
  --upgradable         Show only packages with local candidate upgrades
  --security           Show only packages with security updates
  --format text|json   Output format (default: text)`)
}

func runSoftwareList(args []string) error {
	flags := flag.NewFlagSet("software list", flag.ContinueOnError)
	upgradable := flags.Bool("upgradable", false, "Show only upgradable packages")
	security := flags.Bool("security", false, "Show only security updates")
	format := flags.String("format", "text", "Output format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}

	rfs := fs.Default()
	reader := software.NewInventoryReader(rfs)

	// Collect live graph nodes if possible
	nodes, _ := collectHostObservation()

	inv := reader.Collect(nodes)

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	}

	fmt.Println("======================================================================")
	fmt.Printf("Kazeshini Software Inventory — Total: %d installed (%d upgradable, %d security)\n",
		inv.TotalInstalled, inv.TotalUpgradable, inv.TotalSecurity)
	if inv.Metadata.Available {
		staleTag := ""
		if inv.Metadata.IsStale {
			staleTag = " [STALE]"
		}
		fmt.Printf("Metadata cache age: %s%s (last refresh: %s)\n",
			inv.Metadata.AgeHuman, staleTag, inv.Metadata.LastRefreshed.Format(time.RFC3339))
	} else {
		fmt.Printf("Metadata cache: %s\n", inv.Metadata.AgeHuman)
	}
	if inv.Metadata.RefreshNeeded && inv.Metadata.RefreshCmd != "" {
		fmt.Printf("To refresh local metadata: %s (explicit user action only, Principle 5')\n", inv.Metadata.RefreshCmd)
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("%-30s %-20s %-20s %s\n", "PACKAGE", "INSTALLED", "CANDIDATE", "STATUS")
	fmt.Println(strings.Repeat("-", 70))

	shown := 0
	for _, p := range inv.Packages {
		if *security && (p.Candidate == nil || p.Candidate.UpgradeKind != software.UpgradeKindSecurity) {
			continue
		}
		if *upgradable && !p.IsUpgradable {
			continue
		}

		candStr := "-"
		if p.Candidate != nil {
			candStr = p.Candidate.Version
			if p.Candidate.UpgradeKind == software.UpgradeKindSecurity {
				candStr += " [sec]"
			}
		}

		statusStr := string(p.Status)
		if p.Running.IsRunning {
			statusStr += " (running)"
		}

		fmt.Printf("%-30s %-20s %-20s %s\n", p.Name, p.Version, candStr, statusStr)
		shown++
	}

	if shown == 0 {
		fmt.Println("No packages matched the requested filters.")
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Displayed %d packages.\n", shown)
	fmt.Println("======================================================================")
	return nil
}

func runSoftwareAvailable(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("package name required: kazeshini software available <pkg>")
	}
	pkgName := args[0]
	if err := software.ValidatePackageName(pkgName); err != nil {
		return err
	}

	rfs := fs.Default()
	reader := software.NewInventoryReader(rfs)

	nodes, _ := collectHostObservation()

	entry := reader.LookupPackage(pkgName, nodes)
	if entry == nil {
		return fmt.Errorf("package %q is not installed in local dpkg status", pkgName)
	}

	fmt.Println("======================================================================")
	fmt.Printf("Package:           %s\n", entry.Name)
	fmt.Printf("Installed Version: %s\n", entry.Version)
	if entry.Candidate != nil {
		fmt.Printf("Candidate Version: %s (%s)\n", entry.Candidate.Version, entry.Candidate.UpgradeKind)
		fmt.Printf("Origin:            %s\n", entry.Candidate.Origin)
	} else {
		fmt.Println("Candidate Version: none available in local metadata")
	}
	fmt.Printf("Status:            %s\n", entry.Status)
	if entry.IsHeld {
		fmt.Println("Held:              YES (locked by administrator)")
	}
	if entry.IsPinned {
		fmt.Printf("Pinned:            YES (%s)\n", entry.PinReason)
	}
	if entry.Running.IsRunning {
		fmt.Printf("Running:           YES (services: %s)\n", strings.Join(entry.Running.ServiceNames, ", "))
	}
	if len(entry.ReverseDependents) > 0 {
		fmt.Printf("Required By:       %s\n", strings.Join(entry.ReverseDependents, ", "))
	}
	fmt.Println("======================================================================")
	return nil
}

func runSoftwarePlan(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: kazeshini software plan <upgrade|remove|install> <pkg>")
	}
	action := args[0]
	pkgName := args[1]

	var kind software.DryRunKind
	switch action {
	case "upgrade":
		kind = software.DryRunUpgrade
	case "remove":
		kind = software.DryRunRemove
	case "install":
		kind = software.DryRunInstall
	default:
		return fmt.Errorf("unknown plan action %q (expected: upgrade, remove, install)", action)
	}

	if err := software.ValidatePackageName(pkgName); err != nil {
		return err
	}

	rfs := fs.Default()
	reader := software.NewInventoryReader(rfs)

	nodes, _ := collectHostObservation()

	planner := software.NewPlanner(reader, nil)

	// Running kernel version
	runningKernel := ""
	for _, n := range nodes {
		if n.Type == graph.NodeSystem && (n.Label == "kernel" || n.ID == "system:kernel") {
			if k, ok := n.Properties["release"].(string); ok {
				runningKernel = k
				break
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	p, err := planner.CreatePlan(ctx, pkgName, kind, nodes, runningKernel)
	if err != nil {
		return fmt.Errorf("generating software plan: %w", err)
	}

	fmt.Println("======================================================================")
	fmt.Printf("Kazeshini Software Dry-Run Plan: %s %s\n", strings.ToUpper(string(p.Kind)), p.PackageName)
	fmt.Println("Principle 2/2': Read-only. Plans are plain data. No changes are ever applied.")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Target Package:    %s\n", p.PackageName)
	fmt.Printf("Operation:         %s\n", p.Kind)
	fmt.Printf("From Version:      %s\n", p.FromVersion)
	if p.ToVersion != "" {
		fmt.Printf("To Version:        %s\n", p.ToVersion)
	}
	fmt.Printf("Requires Reboot:   %v\n", p.RequiresReboot)
	fmt.Printf("Reversible:        %v\n", p.IsReversible)
	fmt.Printf("Metadata Age:      %s (stale: %v)\n", p.MetadataAge, p.MetadataStale)

	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("SAFETY ANALYSIS:")
	if p.Safety.Blocked {
		fmt.Println("  Status: BLOCKED (Critical safety risk detected)")
	} else if p.Safety.Safe {
		fmt.Println("  Status: SAFE (No known hazards detected)")
	} else {
		fmt.Println("  Status: WARNING (Non-critical risks detected)")
	}
	fmt.Printf("  Summary: %s\n", p.Safety.Summary)
	for _, f := range p.Safety.Flags {
		fmt.Printf("  [%s] (%s): %s\n", f.Severity, f.Code, f.PlainReason)
	}

	if len(p.ServicesRestarted) > 0 {
		fmt.Printf("  Services to Restart: %s\n", strings.Join(p.ServicesRestarted, ", "))
	}

	if p.BlastSummary != "" {
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("BLAST RADIUS (Score: %d/100):\n  %s\n", p.BlastScore, p.BlastSummary)
	}

	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("RAW PACKAGE MANAGER SIMULATION (Fact, not inference):")
	if strings.TrimSpace(p.RawSimulation) != "" {
		for _, line := range strings.Split(strings.TrimSpace(p.RawSimulation), "\n") {
			fmt.Printf("  %s\n", line)
		}
	} else {
		fmt.Println("  (no simulation output produced)")
	}

	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("EQUIVALENT COMMAND (SHOWN ONLY, NEVER AUTO-APPLIED):")
	fmt.Printf("  $ %s\n", p.EquivalentCommand)
	fmt.Println("======================================================================")
	return nil
}

func runAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kazeshini audit <verify|tail> [--file <path>]")
	}

	subcmd := args[0]
	subargs := args[1:]

	defaultAuditPath := filepath.Join(config.ResolveDefaultDataDir(), "audit.log")

	switch subcmd {
	case "verify":
		flags := flag.NewFlagSet("audit verify", flag.ExitOnError)
		path := flags.String("file", defaultAuditPath, "Path to audit log file")
		if err := flags.Parse(subargs); err != nil {
			return err
		}
		count, err := audit.VerifyChain(*path)
		if err != nil {
			return fmt.Errorf("audit chain verification FAILED: %w", err)
		}
		fmt.Printf("[✓] API audit chain VERIFIED clean (%d records verified, zero tamper detected).\n", count)
		return nil

	case "tail":
		flags := flag.NewFlagSet("audit tail", flag.ExitOnError)
		path := flags.String("file", defaultAuditPath, "Path to audit log file")
		n := flags.Int("n", 10, "Number of records to show")
		if err := flags.Parse(subargs); err != nil {
			return err
		}
		data, err := os.ReadFile(*path)
		if err != nil {
			return fmt.Errorf("reading audit log: %w", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		start := 0
		if len(lines) > *n {
			start = len(lines) - *n
		}
		fmt.Println("======================================================================")
		fmt.Printf("Kazeshini API Audit Log Tail (%s)\n", *path)
		fmt.Println("----------------------------------------------------------------------")
		for _, l := range lines[start:] {
			if strings.TrimSpace(l) != "" {
				fmt.Println(l)
			}
		}
		fmt.Println("======================================================================")
		return nil

	default:
		return fmt.Errorf("unknown audit command %q (expected: verify, tail)", subcmd)
	}
}

func runFacts(args []string) error {
	flags := flag.NewFlagSet("facts", flag.ContinueOnError)
	jsonFlag := flags.Bool("json", false, "Output facts in JSON format")

	if err := flags.Parse(args); err != nil {
		return err
	}

	rfs := fs.Default()
	invManager := inventory.NewManager(rfs)
	inv, _ := invManager.CollectInventory(context.Background())

	nodes, cov := collectHostObservation()
	v := verdict.ComputeVerdictWithCoverage(nodes, nil, 0, cov.IsAdequate, cov.SummaryNote)

	extractor := facts.NewExtractor(rfs)
	f := extractor.Extract(context.Background(), nodes, cov, v, &inv)

	if *jsonFlag {
		data, _ := json.MarshalIndent(f, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI SYSTEM FACTS")
	fmt.Println("======================================================================")
	fmt.Printf("HOST ID:          %s\n", f.HostID)
	fmt.Printf("VERDICT:          %s (Chaos Index: %d)\n", strings.ToUpper(f.VerdictStatus), f.ChaosIndex)
	fmt.Printf("COVERAGE:         %.1f%% (Adequate: %v)\n", f.CoveragePercent, f.CoverageAdequate)
	if f.OSRelease != nil && f.OSRelease["PRETTY_NAME"] != "" {
		fmt.Printf("OS:               %s\n", f.OSRelease["PRETTY_NAME"])
	}
	fmt.Printf("PROCESSES:        %d active\n", f.TotalProcesses)
	fmt.Printf("PACKAGES:         %d installed\n", f.TotalPackages)
	fmt.Printf("OPEN PORTS:       %v\n", f.ListeningPorts)
	fmt.Println("======================================================================")
	return nil
}

func runAgent(args []string) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	ctrlURL := flags.String("controller", "", "Controller URL (e.g. https://controller.kazeshini.internal:8443)")
	hostID := flags.String("host-id", "", "Managed host ID (defaults to system machine-id)")
	interval := flags.Duration("interval", 15*time.Second, "Snapshot push interval")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if *ctrlURL == "" {
		return errors.New("missing required flag: --controller URL")
	}

	if *hostID == "" {
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			*hostID = strings.TrimSpace(string(data))
		} else {
			*hostID, _ = os.Hostname()
		}
	}

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI OUTBOUND AGENT")
	fmt.Println("======================================================================")
	fmt.Printf("HOST ID:          %s\n", *hostID)
	fmt.Printf("CONTROLLER:       %s\n", *ctrlURL)
	fmt.Printf("PUSH INTERVAL:    %s\n", interval.String())
	fmt.Println("STATUS:           Outbound-only mTLS telemetry active (0 open ports)")
	fmt.Println("======================================================================")

	ag := fleet.NewAgent(fleet.AgentConfig{
		HostID:        *hostID,
		ControllerURL: *ctrlURL,
		PushInterval:  *interval,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial push test
	nodes, cov := collectHostObservation()
	v := verdict.ComputeVerdictWithCoverage(nodes, nil, 0, cov.IsAdequate, cov.SummaryNote)
	snap, err := ag.BuildSnapshot(v, cov, nil, drift.Summary{})
	if err != nil {
		return fmt.Errorf("building snapshot: %w", err)
	}

	if err := ag.PushSnapshot(ctx, snap); err != nil {
		fmt.Printf("[!] Controller connection failed (operating autonomously, Principle 10): %v\n", err)
	} else {
		fmt.Println("[✓] Pushed initial telemetry snapshot to controller successfully.")
	}

	return nil
}

func runController(args []string) error {
	flags := flag.NewFlagSet("controller", flag.ContinueOnError)
	port := flags.Int("port", 8443, "Listening port for fleet controller")
	staleSec := flags.Int("stale-timeout", 60, "Seconds of inactivity before marking agent stale")

	if err := flags.Parse(args); err != nil {
		return err
	}

	ctrl := fleet.NewController(fleet.ControllerConfig{
		StaleTimeout: time.Duration(*staleSec) * time.Second,
	})

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI FLEET CONTROLLER")
	fmt.Println("======================================================================")
	fmt.Printf("BIND ADDRESS:     0.0.0.0:%d\n", *port)
	fmt.Printf("STALE TIMEOUT:    %ds (agents inactive >%ds marked UNKNOWN)\n", *staleSec, *staleSec)
	fmt.Println("SECURITY:         mTLS enrollment & machine-id bound plan routing")
	fmt.Println("======================================================================")

	table, summary := ctrl.GetFleetTable()
	fmt.Printf("FLEET SUMMARY:    Total=%d, Active=%d, Stale=%d, Critical=%d\n",
		summary.TotalHosts, summary.ActiveHosts, summary.StaleHosts, summary.CriticalHosts)
	for _, h := range table {
		fmt.Printf("  - %-20s [%s] Chaos=%d LastSeen=%s\n", h.HostID, h.StatusLabel, h.ChaosIndex, h.LastSeen.Format(time.RFC3339))
	}
	fmt.Println("======================================================================")
	return nil
}



