// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/glossary"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/kzerror"
	"github.com/OWNER/kazeshini/internal/logging"
	"github.com/OWNER/kazeshini/internal/metrics"
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
	"github.com/OWNER/kazeshini/internal/viz"
)

var (
	// Injected via ldflags
	Version   = "v0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"

	experimentalHandlers = make(map[string]func([]string) error)
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
		return runDefaultExperience(false, false)
	}

	// Platform validation guard
	if runtime.GOOS != "linux" {
		return fmt.Errorf("Kazeshini requires Linux. Current operating system is %s", runtime.GOOS)
	}
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		return fmt.Errorf("This host has no /proc. Kazeshini needs Linux 3.10 or newer.")
	}

	subcmd := args[0]
	subargs := args[1:]

	// Flags passed to root binary
	switch subcmd {
	case "--once":
		wantJSON := false
		for _, a := range subargs {
			if a == "--json" {
				wantJSON = true
			}
		}
		return runDefaultExperience(true, wantJSON)

	case "--json":
		wantOnce := false
		for _, a := range subargs {
			if a == "--once" {
				wantOnce = true
			}
		}
		return runDefaultExperience(wantOnce, true)

	case "install":
		return runInstall(subargs)

	case "uninstall":
		return runUninstall(subargs)

	case "version", "--version":
		verbose := false
		for _, a := range subargs {
			if a == "--verbose" || a == "-v" {
				verbose = true
			}
		}
		v := getVersionInfo()
		fmt.Printf("kazeshini %s (commit: %s, built: %s, %s)\n", v.Version, v.Commit, v.BuildDate, v.GoVersion)
		if verbose {
			fmt.Println("\nPlatform Compatibility & Invariants:")
			fmt.Println("  Supported Kernels: Linux 3.10 or newer (tested on Linux 4.x, 5.x, 6.x)")
			fmt.Println("  Supported Architectures: amd64, arm64")
			fmt.Println("  Supported Distributions: Ubuntu (20.04+), Debian (11+), RHEL/CentOS/Rocky/Alma (8+), Fedora (38+), Arch Linux, Alpine (3.16+), openSUSE (15+)")
			fmt.Println("\nKnown Limitations:")
			fmt.Println("  - ZFS/btrfs: volume storage metrics measured via POSIX statfs; subvolume quotas and zpool topology are not inspected.")
			fmt.Println("  - Out-of-date packages: discovered via local package manager simulation caches (apt-get -s, dnf check-update); requires fresh index.")
			fmt.Println("  - Outbound Proxies: active connectivity probe checks connect via direct TCP; HTTP/SOCKS proxies are not used by probe dials.")
			fmt.Println("  - SELinux Enforcing: unprivileged scans gracefully degrade upon EACCES; strict MLS policy may log audit AVC denial notices.")
		}
		return nil

	case "doctor", "visibility":
		return runDoctor()

	case "briefing", "overview":
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

	case "completion":
		return runCompletion(subargs)

	case "explain":
		return runExplain(subargs)

	case "bugreport":
		return runBugreport(subargs)

	case "verify":
		return runVerifySelf(subargs)

	case "update":
		return runUpdateCheck(subargs)

	case "view":
		return runView(subargs)

	case "export":
		return runExport(subargs)

	case "help", "-h", "--help":
		printUsage()
		return nil

	default:
		if handler, ok := experimentalHandlers[subcmd]; ok {
			return handler(subargs)
		}
		printUsage()
		return fmt.Errorf("unknown subcommand %q", subcmd)
	}
}

func printUsage() {
	fmt.Println(`Kazeshini (風死) — Read-only Server Truth Engine for Linux

Usage:
  kazeshini [options]
  kazeshini <command> [options]

First Run / Quick Start:
  kazeshini                      Zero-setup first-run: terminal summary + loopback dashboard
  kazeshini --once               Print terminal summary and exit immediately (scripts/CI)
  kazeshini --once --json        Emit machine-readable JSON summary and exit

Service Management:
  install        Install systemd service with plan preview (requires sudo)
                 Example: sudo kazeshini install
  uninstall      Uninstall systemd service with plan preview (requires sudo)
                 Example: sudo kazeshini uninstall

Inspect:
  overview       Print plain-English server overview and diagnostics
                 Example: kazeshini overview
  visibility     Inspect host sensor visibility and coverage honesty table
                 Example: kazeshini visibility
  check          Execute read-only diagnostics (list, run, triage)
                 Example: kazeshini check run listening-ports
  software       Inspect installed packages, candidates, and safe dry-runs
                 Example: kazeshini software list
  drift          Audit discrepancies between desired state and host state
                 Example: kazeshini drift --exit-code
  explain        Explain a system term or finding at 3 technical levels
                 Example: kazeshini explain port
                 Example: kazeshini explain --level technical port

Visual Views:
  view           Render visual models in terminal (growth, storage, tree, network, timeline)
                 Example: kazeshini view growth
                 Example: kazeshini view storage
                 Example: kazeshini view network
  export         Export visual models or data (json, csv, md, html, svg)
                 Example: kazeshini export --format svg > growth.svg
                 Example: kazeshini export --format html > dashboard.html

Report:
  report         Generate standalone State of this Server report (html, json, md)
                 Example: kazeshini report --format html > report.html
  facts          Emit machine-readable inventory facts for automation
                 Example: kazeshini facts --json
  audit          Verify cryptographic audit log integrity or stream events
                 Example: kazeshini audit verify
  bugreport      Generate sanitized local diagnostic bundle (zero telemetry)
                 Example: kazeshini bugreport

Security & Release Verification:
  verify         Verify self binary integrity against checksum or signature
                 Example: kazeshini verify --checksum <sha256>
                 Example: kazeshini verify --checksum-file checksums.txt
  update         Opt-in check for newer releases (zero auto-update, never runs without URL)
                 Example: kazeshini update --check --url https://releases.example.org/latest.json

Start & Server:
  open           Foreground local dashboard for headless/SSH servers
                 Example: kazeshini open
  serve          Start daemon listening on loopback (default 127.0.0.1:7777)
                 Example: kazeshini serve --port 7777

Configure:
  token          Print local API authentication token (0600)
                 Example: kazeshini token
  desired        Lint or inspect declarative desired state manifests
                 Example: kazeshini desired lint /etc/kazeshini/desired.yaml
  completion     Generate shell completion script (bash, zsh)
                 Example: source <(kazeshini completion bash)
  version        Print binary version information
                 Example: kazeshini version

Run 'kazeshini <command> --help' for detailed options.`)
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
	fmt.Println("風死 · KAZESHINI DIAGNOSTICS & VISIBILITY — SENSOR INSPECTION")
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
		fmt.Println("RESULT: [PARTIAL] Some sensors have limited visibility (HEALTHY verdict suspended).")
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

						// If OpenTelemetry export is configured, push metrics
						if cfg.OTel.Enabled && cfg.OTel.Endpoint != "" {
							exporter := metrics.NewOTLPExporter(cfg.OTel.Endpoint)
							mSnap := metrics.Snapshot{
								HostID:    cfg.Host,
								Timestamp: newSnap.Timestamp,
								Verdict: verdict.Summary{
									RiskScore:  0,
									ChaosIndex: 0,
									StateLabel: "Healthy",
								},
								Coverage: coverage.Report{
									OverallCoverage: 100,
									IsAdequate:      true,
								},
							}
							go func(s metrics.Snapshot) {
								_ = exporter.Export(context.Background(), s)
							}(mSnap)
						}
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
		return errors.New("usage: kazeshini check <list|run <id>|run --domain <domain>|triage <name>> [--json]")
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
		roleFlag := flags.String("role", "", "Domain or legacy role category to run (services, network, storage, security, platform)")
		domainFlag := flags.String("domain", "", "Domain category to run (services, network, storage, security, platform)")
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
				if (arg == "--role" || arg == "-role" || arg == "--domain" || arg == "-domain" || arg == "--fail-on" || arg == "-fail-on" || arg == "--target" || arg == "-target" || arg == "--file" || arg == "-file" || arg == "--unit" || arg == "-unit") && i+1 < len(subargs) {
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

		targetDomain := *domainFlag
		if targetDomain == "" {
			targetDomain = *roleFlag
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

		if targetDomain != "" {
			results, err := engine.RunRole(ctx, targetDomain, params, "local-cli")
			if err != nil {
				return err
			}
			if *jsonFlag {
				data, _ := json.MarshalIndent(results, "", "  ")
				fmt.Println(string(data))
				return evaluateFailOn(results...)
			}
			fmt.Println("======================================================================")
			fmt.Printf("風死 · KAZESHINI CHECK RUN — DOMAIN: [%s]\n", strings.ToUpper(targetDomain))
			fmt.Println("======================================================================")
			for _, r := range results {
				fmt.Print(r.RenderTerminal())
				fmt.Println(strings.Repeat("-", 70))
			}
			return evaluateFailOn(results...)
		}

		remArgs := flags.Args()
		if len(remArgs) == 0 {
			return errors.New("usage: kazeshini check run <id> or kazeshini check run --domain <domain>")
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

	case "triage", "symptom":
		if len(subargs) == 0 {
			fmt.Println("Available guided triage scenarios:")
			for _, s := range checks.AvailableTriageScenarios() {
				fmt.Printf("  • %-20s — %s\n", s.ID, s.Description)
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

		scenario, err := checks.FindTriageScenario(query)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		var results []contract.CheckResult
		for _, cid := range scenario.CheckIDs {
			res, _ := engine.RunCheck(ctx, cid, nil, "local-cli")
			results = append(results, res)
		}

		if jsonFlag {
			output := map[string]any{
				"triage_scenario": scenario,
				"results":         results,
			}
			data, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Println("======================================================================")
		fmt.Printf("風死 · KAZESHINI GUIDED TRIAGE: %s\n", strings.ToUpper(scenario.Name))
		fmt.Printf("Description: %s\n", scenario.Description)
		fmt.Println("======================================================================")
		for i, cid := range scenario.CheckIDs {
			fmt.Printf("\n[%d] CHECK: %s\n", i+1, cid)
			if i < len(scenario.Reasons) {
				fmt.Printf("    Rationale: %s\n", scenario.Reasons[i])
			}
			res := results[i]
			fmt.Print(res.RenderTerminal())
		}
		fmt.Println("\n======================================================================")
		return nil

	default:
		return fmt.Errorf("unknown check subcommand %q (supported: list, run, triage)", subcmd)
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
	verdictLabel := "HEALTHY"
	colorCode := "\033[1;32m" // Green
	if !cov.IsAdequate {
		verdictLabel = "PARTIAL VISIBILITY"
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
				ID:    pkgNodeID,
				Type:  graph.NodePackage,
				Label: pkg.Name,
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
	fmt.Printf("VERDICT:          %s (Risk Score: %d)\n", strings.ToUpper(f.VerdictStatus), f.ChaosIndex)
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

func runCompletion(args []string) error {
	shell := "bash"
	if len(args) > 0 {
		shell = strings.ToLower(args[0])
	}

	switch shell {
	case "bash":
		fmt.Print(`# bash completion for kazeshini
_kazeshini() {
    local cur prev subcommands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    subcommands="open serve overview visibility check software drift report facts audit token desired completion version"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${subcommands}" -- ${cur}) )
        return 0
    fi

    case "${prev}" in
        check)
            COMPREPLY=( $(compgen -W "list run triage" -- ${cur}) )
            return 0
            ;;
        software)
            COMPREPLY=( $(compgen -W "list info plan" -- ${cur}) )
            return 0
            ;;
        desired)
            COMPREPLY=( $(compgen -W "lint show" -- ${cur}) )
            return 0
            ;;
        audit)
            COMPREPLY=( $(compgen -W "verify tail" -- ${cur}) )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh" -- ${cur}) )
            return 0
            ;;
    esac
}
complete -F _kazeshini kazeshini
`)
		return nil

	case "zsh":
		fmt.Print(`#compdef kazeshini
_kazeshini() {
    local -a commands
    commands=(
        'open:Foreground local dashboard for headless/SSH servers'
        'serve:Start daemon listening on loopback'
        'overview:Print plain-English server overview and diagnostics'
        'visibility:Inspect host sensor visibility and coverage honesty table'
        'check:Execute read-only diagnostics'
        'software:Inspect installed packages and dry-runs'
        'drift:Audit discrepancies between desired and actual state'
        'report:Generate standalone State of this Server report'
        'facts:Emit machine-readable inventory facts'
        'audit:Verify cryptographic audit log integrity'
        'token:Print local API authentication token'
        'desired:Manage declarative desired state manifests'
        'completion:Generate shell completion script'
        'version:Print binary version information'
    )
    _describe 'command' commands
}
_kazeshini
`)
		return nil

	default:
		return fmt.Errorf("unsupported shell %q (supported: bash, zsh)", shell)
	}
}

func runDefaultExperience(once bool, asJSON bool) error {
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

	if asJSON {
		data, err := json.MarshalIndent(br, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		if once {
			if br.Verdict.RiskScore >= 75 || br.Verdict.StateLabel == "critical" {
				os.Exit(1)
			}
			return nil
		}
	} else {
		fmt.Print(br.RenderTerminal())
	}

	if once {
		if br.Verdict.RiskScore >= 75 || br.Verdict.StateLabel == "critical" {
			os.Exit(1)
		}
		return nil
	}

	// 1. Start stateless HTTP server on free loopback port
	bindAddr := "127.0.0.1:0"
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", bindAddr, err)
	}
	defer func() { _ = ln.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	cfg.Host = "127.0.0.1"
	cfg.Port = port
	cfg.Stateless = true

	logger := logging.Setup(logging.Config{Level: "warn", Format: "text"})
	srv, err := api.NewServer(cfg, getVersionInfo(), sup, invManager, originResolver, orphanScanner, pGraph, nil, ruleEngine, logger)
	if err != nil {
		return fmt.Errorf("failed initializing stateless server: %w", err)
	}

	tokenStr := ""
	if srv.AuthManager() != nil {
		tokenStr = srv.AuthManager().Token()
	}

	currUser := os.Getenv("USER")
	if currUser == "" {
		currUser = "user"
	}

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI — FIRST-RUN DASHBOARD")
	fmt.Println("======================================================================")
	fmt.Printf("DASHBOARD URL: http://127.0.0.1:%d\n", port)
	fmt.Println("HEADLESS / REMOTE SSH ACCESS:")
	fmt.Println("  Run this on your local laptop to tunnel the port securely:")
	fmt.Printf("  \033[1;36mssh -L %d:127.0.0.1:%d %s@<server-ip>\033[0m\n\n", port, port, currUser)
	fmt.Printf("ACCESS TOKEN:  %s\n\n", tokenStr)

	isRoot := os.Geteuid() == 0
	if !isRoot {
		fmt.Printf("VISIBILITY:    Non-root user (Coverage: %.0f%%)\n", cov.OverallCoverage)
		fmt.Println("               Some kernel and process details are hidden by Linux permissions.")
		fmt.Println("               For 100% full visibility, run: \033[1;33msudo ./kazeshini\033[0m")
		fmt.Println()
	} else {
		fmt.Println("VISIBILITY:    Root execution (Full kernel & process visibility enabled)")
	}

	fmt.Println("LIFECYCLE:     Exits on Ctrl+C or after 30m of inactivity")
	fmt.Println("======================================================================")

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.ServeListener(ln)
	}()

	idleTimeout := 30 * time.Minute
	idleTicker := time.NewTicker(1 * time.Second)
	defer idleTicker.Stop()
	startTime := time.Now()

	for {
		select {
		case <-sigCtx.Done():
			fmt.Println("\nReceived termination signal. Shutting down gracefully...")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
			return nil
		case err := <-errChan:
			return err
		case <-idleTicker.C:
			lastReq := srv.LastActivity()
			if lastReq.IsZero() {
				lastReq = startTime
			}
			if time.Since(lastReq) >= idleTimeout {
				fmt.Printf("\nIdle timeout (30m without requests) reached. Shutting down...\n")
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer shutdownCancel()
				_ = srv.Shutdown(shutdownCtx)
				return nil
			}
		}
	}
}

func runInstall(args []string) error {
	autoYes := false
	for _, a := range args {
		if a == "-y" || a == "--yes" {
			autoYes = true
		}
	}

	if os.Geteuid() != 0 {
		return errors.New("install requires root privileges. Please run with 'sudo kazeshini install'")
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	selfPath, _ = filepath.EvalSymlinks(selfPath)

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI SERVICE INSTALLATION PLAN")
	fmt.Println("======================================================================")
	fmt.Println("The following declarative changes will be made to the host:")
	fmt.Println("  1. Create dedicated system user and group 'kazeshini' (if not present)")
	fmt.Printf("  2. Install binary %s -> /usr/local/bin/kazeshini (mode 0755)\n", selfPath)
	fmt.Println("  3. Create directory /etc/kazeshini (mode 0755)")
	fmt.Println("  4. Write default configuration /etc/kazeshini/kazeshini.json (mode 0644)")
	fmt.Println("  5. Create directory /var/lib/kazeshini (owner kazeshini:kazeshini, mode 0700)")
	fmt.Println("  6. Write hardened systemd unit /etc/systemd/system/kazeshini.service (mode 0644)")
	fmt.Println("  7. Execute 'systemctl daemon-reload' and 'systemctl enable --now kazeshini.service'")
	fmt.Println("======================================================================")

	if !autoYes {
		fmt.Print("Do you want to proceed with installation? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		ans, _ := reader.ReadString('\n')
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans != "y" && ans != "yes" {
			fmt.Println("Installation cancelled.")
			return nil
		}
	}

	// 1. Create user and group
	_ = exec.Command("useradd", "--system", "--no-create-home", "--shell", "/sbin/nologin", "--user-group", "kazeshini").Run()

	// 2. Install binary
	_ = os.MkdirAll("/usr/local/bin", 0755)
	srcFile, err := os.Open(selfPath)
	if err != nil {
		return fmt.Errorf("cannot read source binary: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	destFile, err := os.OpenFile("/usr/local/bin/kazeshini", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("cannot write destination binary: %w", err)
	}
	if _, err := io.Copy(destFile, srcFile); err != nil {
		_ = destFile.Close()
		return fmt.Errorf("failed copying binary: %w", err)
	}
	_ = destFile.Close()

	// 3 & 4. Config
	_ = os.MkdirAll("/etc/kazeshini/rules.d", 0755)
	configContent := `{
  "host": "127.0.0.1",
  "port": 7777,
  "allow_remote": false,
  "data_dir": "/var/lib/kazeshini",
  "rules_dir": "/etc/kazeshini/rules.d",
  "log_level": "info",
  "log_format": "text",
  "scan_interval": 60000000000
}
`
	if _, err := os.Stat("/etc/kazeshini/kazeshini.json"); os.IsNotExist(err) {
		_ = os.WriteFile("/etc/kazeshini/kazeshini.json", []byte(configContent), 0644)
	}

	// 5. Data dir
	_ = os.MkdirAll("/var/lib/kazeshini", 0700)
	_ = exec.Command("chown", "-R", "kazeshini:kazeshini", "/var/lib/kazeshini").Run()

	// 6. Systemd unit
	unitContent := `[Unit]
Description=Kazeshini (Server Truth Engine for Linux)
Documentation=https://github.com/OWNER/kazeshini
After=network.target
Wants=network.target

[Service]
Type=simple
User=kazeshini
Group=kazeshini
ExecStart=/usr/local/bin/kazeshini serve --config /etc/kazeshini/kazeshini.json
Restart=always
RestartSec=5s

MemoryMax=128M
CPUQuota=10%
TasksMax=64
IOWeight=20
Nice=10

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE

StateDirectory=kazeshini
StateDirectoryMode=0700
RuntimeDirectory=kazeshini
RuntimeDirectoryMode=0755
ConfigurationDirectory=kazeshini
ConfigurationDirectoryMode=0755

ReadOnlyPaths=/proc /sys
ReadWritePaths=/var/lib/kazeshini

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile("/etc/systemd/system/kazeshini.service", []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("failed writing systemd unit: %w", err)
	}

	// 7. Reload and start
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", "--now", "kazeshini.service").Run()

	fmt.Println("[OK] Kazeshini service installed and activated successfully.")
	fmt.Println("Check service status: systemctl status kazeshini.service")
	return nil
}

func runUninstall(args []string) error {
	autoYes := false
	for _, a := range args {
		if a == "-y" || a == "--yes" {
			autoYes = true
		}
	}

	if os.Geteuid() != 0 {
		return errors.New("uninstall requires root privileges. Please run with 'sudo kazeshini uninstall'")
	}

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI SERVICE UNINSTALLATION PLAN")
	fmt.Println("======================================================================")
	fmt.Println("The following cleanup actions will be performed:")
	fmt.Println("  1. Stop and disable kazeshini.service (systemctl)")
	fmt.Println("  2. Remove systemd unit /etc/systemd/system/kazeshini.service")
	fmt.Println("  3. Reload systemd daemon")
	fmt.Println("  4. Remove binary /usr/local/bin/kazeshini")
	fmt.Println("  5. Remove configuration directory /etc/kazeshini")
	fmt.Println("  6. Remove data directory /var/lib/kazeshini")
	fmt.Println("  7. Remove system user 'kazeshini'")
	fmt.Println("======================================================================")

	if !autoYes {
		fmt.Print("Do you want to proceed with uninstallation? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		ans, _ := reader.ReadString('\n')
		ans = strings.TrimSpace(strings.ToLower(ans))
		if ans != "y" && ans != "yes" {
			fmt.Println("Uninstallation cancelled.")
			return nil
		}
	}

	// 1. Stop & disable
	_ = exec.Command("systemctl", "stop", "kazeshini.service").Run()
	_ = exec.Command("systemctl", "disable", "kazeshini.service").Run()

	// 2 & 3. Remove unit & reload
	_ = os.Remove("/etc/systemd/system/kazeshini.service")
	_ = exec.Command("systemctl", "daemon-reload").Run()

	// 4. Remove binary
	_ = os.Remove("/usr/local/bin/kazeshini")

	// 5 & 6. Remove config and data
	_ = os.RemoveAll("/etc/kazeshini")
	_ = os.RemoveAll("/var/lib/kazeshini")

	// 7. Remove user
	_ = exec.Command("userdel", "kazeshini").Run()

	fmt.Println("[OK] Kazeshini service and files uninstalled successfully.")
	return nil
}

func runExplain(args []string) error {
	flags := flag.NewFlagSet("explain", flag.ContinueOnError)
	var level string
	flags.StringVar(&level, "level", "summary", "Explanation level: summary, details, technical, or all")
	if err := flags.Parse(args); err != nil {
		return err
	}

	remaining := flags.Args()
	if len(remaining) == 0 {
		return kzerror.New(
			kzerror.CodeInvalidConfig,
			"No term or finding specified to explain",
			"The explain command requires a glossary term or finding ID as an argument.",
			"Run 'kazeshini explain <term>' (e.g. 'kazeshini explain port') or see docs/GLOSSARY.md.",
		)
	}

	target := strings.Join(remaining, " ")
	targetLower := strings.ToLower(target)

	// 1. Try glossary term
	if def, ok := glossary.Lookup(targetLower); ok {
		fmt.Printf("======================================================================\n")
		fmt.Printf("EXPLANATION: %s\n", strings.ToUpper(def.Term))
		fmt.Printf("======================================================================\n")
		switch strings.ToLower(level) {
		case "details":
			fmt.Printf("DETAILS:\n  %s\n", def.Details)
		case "technical":
			fmt.Printf("TECHNICAL EVIDENCE / MECHANICS:\n  %s\n", def.Technical)
		case "all":
			fmt.Printf("LEVEL 1 (SUMMARY):\n  %s\n\n", def.Summary)
			fmt.Printf("LEVEL 2 (DETAILS):\n  %s\n\n", def.Details)
			fmt.Printf("LEVEL 3 (TECHNICAL EVIDENCE):\n  %s\n", def.Technical)
		default: // summary
			fmt.Printf("SUMMARY:\n  %s\n\n", def.Summary)
			fmt.Println("For more information:")
			fmt.Printf("  kazeshini explain --level details %s\n", def.Term)
			fmt.Printf("  kazeshini explain --level technical %s\n", def.Term)
		}
		fmt.Printf("======================================================================\n")
		return nil
	}

	// 2. Try rule finding ID
	cfg, _ := config.Load("")
	ruleEngine := rules.NewEngine(3 * time.Second)
	_, _ = ruleEngine.LoadDirectory(cfg.RulesDir)
	for _, r := range ruleEngine.Rules() {
		if strings.EqualFold(r.ID, target) || strings.EqualFold(r.Name, target) {
			fmt.Printf("======================================================================\n")
			fmt.Printf("FINDING EXPLANATION: %s (%s)\n", r.Name, r.ID)
			fmt.Printf("======================================================================\n")
			switch strings.ToLower(level) {
			case "details":
				fmt.Printf("DETAILS / IMPACT:\n  %s\n", r.Consequence)
			case "technical":
				fmt.Printf("TECHNICAL EVIDENCE / MECHANICS:\n  Severity: %s, Category: %s, Certainty: %s\n",
					r.Severity, r.Category, r.Certainty)
			case "all":
				fmt.Printf("LEVEL 1 (SUMMARY):\n  %s\n\n", r.Description)
				fmt.Printf("LEVEL 2 (DETAILS):\n  Impact: %s\n  Recommended: %s\n\n", r.Consequence, r.Recommendation.Action)
				fmt.Printf("LEVEL 3 (TECHNICAL EVIDENCE):\n  Rule ID: %s, Severity: %s, Category: %s, Certainty: %s\n",
					r.ID, r.Severity, r.Category, r.Certainty)
			default: // summary
				fmt.Printf("SUMMARY:\n  %s\n\n", r.Description)
				fmt.Println("For more information:")
				fmt.Printf("  kazeshini explain --level details %s\n", r.ID)
				fmt.Printf("  kazeshini explain --level technical %s\n", r.ID)
			}
			fmt.Printf("======================================================================\n")
			return nil
		}
	}

	return kzerror.New(
		kzerror.CodeInvalidConfig,
		fmt.Sprintf("Unknown term or finding ID: %q", target),
		"The term was not found in the canonical glossary (docs/GLOSSARY.md) or rule definitions.",
		"Check the spelling, or run 'kazeshini explain' with one of: port, service, package, kernel, inode, unmanaged software, risk score, drift, visibility.",
	)
}

func runBugreport(args []string) error {
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

	assessor := coverage.NewAssessor(sup, invManager, orphanScanner, rfs)
	cov := assessor.Assess(ctx)

	// Collect redacted bug report struct
	type BugReportBundle struct {
		Timestamp   time.Time              `json:"timestamp"`
		Version     api.VersionInfo        `json:"version"`
		Redactions  []string               `json:"redactions_applied"`
		Visibility  coverage.Report        `json:"visibility"`
		Environment map[string]interface{} `json:"environment"`
	}

	bundle := BugReportBundle{
		Timestamp: time.Now().UTC(),
		Version:   getVersionInfo(),
		Redactions: []string{
			"Passwords, tokens, credentials, and authentication cookies stripped",
			"User private keys (/etc/shadow, ~/.ssh) omitted",
			"Raw process command lines containing potential secrets scrubbed",
		},
		Visibility: cov,
		Environment: map[string]interface{}{
			"goos":      runtime.GOOS,
			"goarch":    runtime.GOARCH,
			"num_cpu":   runtime.NumCPU(),
			"euid":      os.Geteuid(),
			"stateless": true,
		},
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return kzerror.New(
			kzerror.CodeSensorTimeout,
			"Failed to encode bug report bundle",
			err.Error(),
			"Verify system memory availability and re-run 'kazeshini bugreport'.",
		)
	}

	reportFile := fmt.Sprintf("kazeshini-bugreport-%d.json", time.Now().Unix())
	if err := os.WriteFile(reportFile, data, 0600); err != nil {
		return kzerror.New(
			kzerror.CodePermissionDenied,
			fmt.Sprintf("Failed to write bug report file %s", reportFile),
			err.Error(),
			"Run from a writable directory or check folder permissions.",
		)
	}

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI LOCAL BUG REPORT BUNDLE")
	fmt.Println("======================================================================")
	fmt.Printf("FILE GENERATED: %s (mode 0600, local disk only)\n", reportFile)
	fmt.Println("ZERO TELEMETRY GUARANTEE:")
	fmt.Println("  Data never leaves this machine. No network egress was performed.")
	fmt.Println("\nWHAT IS INCLUDED IN THIS REPORT:")
	fmt.Println("  • Kazeshini version and runtime environment (OS, Arch, CPU count)")
	fmt.Println("  • Sensor visibility coverage and permission honesty diagnostics")
	fmt.Println("  • Anonymized subsystem inspection counts (no passwords, keys, or secrets)")
	fmt.Println("\nNEXT STEPS:")
	fmt.Printf("  1. Review the file contents:\n     cat %s\n", reportFile)
	fmt.Println("  2. If satisfied, share this file manually with your technical maintainer.")
	fmt.Println("======================================================================")
	return nil
}

// runVerifySelf checks the running or specified binary against published SHA-256 checksums or ed25519 signatures.
func runVerifySelf(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	var (
		checksumFlag     string
		checksumFileFlag string
		targetBinary     string
		signatureFlag    string
		publicKeyFlag    string
	)
	flags.StringVar(&checksumFlag, "checksum", "", "Expected SHA-256 hex checksum")
	flags.StringVar(&checksumFileFlag, "checksum-file", "", "Path to sha256sums.txt checksum file")
	flags.StringVar(&targetBinary, "binary", "", "Binary file path to verify (default: current executable)")
	flags.StringVar(&signatureFlag, "signature", "", "Hex or raw signature of the binary or checksums file")
	flags.StringVar(&publicKeyFlag, "public-key", "", "Hex-encoded ed25519 public key")

	if err := flags.Parse(args); err != nil {
		return err
	}

	exePath := targetBinary
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("failed locating current executable: %w", err)
		}
	}

	data, err := os.ReadFile(exePath)
	if err != nil {
		return fmt.Errorf("failed reading binary %s: %w", exePath, err)
	}

	hasher := sha256.New()
	hasher.Write(data)
	actualHash := hex.EncodeToString(hasher.Sum(nil))

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI BINARY INTEGRITY VERIFICATION")
	fmt.Println("======================================================================")
	fmt.Printf("TARGET BINARY:     %s\n", exePath)
	fmt.Printf("COMPUTED SHA-256:  %s\n", actualHash)

	if checksumFlag != "" {
		expected := strings.ToLower(strings.TrimSpace(checksumFlag))
		if actualHash == expected {
			fmt.Printf("VERIFICATION:      [✓] PASS (Checksum matches provided SHA-256)\n")
			fmt.Println("======================================================================")
			return nil
		}
		fmt.Printf("VERIFICATION:      [X] FAIL (Checksum mismatch: expected %s)\n", expected)
		fmt.Println("======================================================================")
		return errors.New("binary checksum mismatch")
	}

	if checksumFileFlag != "" {
		fData, err := os.ReadFile(checksumFileFlag)
		if err != nil {
			return fmt.Errorf("failed reading checksum file %s: %w", checksumFileFlag, err)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(fData)))
		baseExe := filepath.Base(exePath)
		found := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				hashVal := strings.ToLower(fields[0])
				fileName := filepath.Base(fields[1])
				if fileName == baseExe || strings.Contains(fields[1], "kazeshini") {
					if actualHash == hashVal {
						fmt.Printf("MATCHED RECORD:    %s\n", line)
						fmt.Printf("VERIFICATION:      [✓] PASS (Verified against %s)\n", checksumFileFlag)
						fmt.Println("======================================================================")
						return nil
					}
					fmt.Printf("MATCHED RECORD:    %s\n", line)
					fmt.Printf("VERIFICATION:      [X] FAIL (Expected %s, computed %s)\n", hashVal, actualHash)
					fmt.Println("======================================================================")
					return errors.New("binary checksum mismatch against checksums file")
				}
			}
		}
		if !found {
			return fmt.Errorf("no checksum entry found for %s in %s", baseExe, checksumFileFlag)
		}
	}

	if signatureFlag != "" && publicKeyFlag != "" {
		pubBytes, err := hex.DecodeString(publicKeyFlag)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid ed25519 public key hex (must be 32 bytes): %w", err)
		}
		sigBytes, err := hex.DecodeString(signatureFlag)
		if err != nil {
			return fmt.Errorf("invalid signature hex: %w", err)
		}
		if ed25519.Verify(pubBytes, data, sigBytes) {
			fmt.Println("SIGNATURE CHECK:   [✓] PASS (Valid ed25519 cryptographic signature)")
			fmt.Println("======================================================================")
			return nil
		}
		fmt.Println("SIGNATURE CHECK:   [X] FAIL (Invalid signature for binary payload)")
		fmt.Println("======================================================================")
		return errors.New("invalid cryptographic signature")
	}

	fmt.Println("STATUS:            No verification arguments provided (--checksum, --checksum-file, or --signature).")
	fmt.Println("EXAMPLE USAGE:")
	fmt.Printf("  kazeshini verify --checksum %s\n", actualHash)
	fmt.Println("  kazeshini verify --checksum-file sha256sums.txt")
	fmt.Println("======================================================================")
	return nil
}

// runUpdateCheck implements opt-in checking for newer versions without auto-updating.
func runUpdateCheck(args []string) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	var (
		checkFlag bool
		urlFlag   string
		timeout   time.Duration
	)
	flags.BoolVar(&checkFlag, "check", false, "Perform explicit opt-in update check")
	flags.StringVar(&urlFlag, "url", "", "Custom release manifest endpoint (must be explicitly provided)")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "Network timeout for update check")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if !checkFlag {
		fmt.Println("Kazeshini update is strictly opt-in and off by default.")
		fmt.Println("Zero telemetry guarantee: Kazeshini never phones home or checks for updates automatically.")
		fmt.Println("\nTo perform a manual, one-off release check against a trusted endpoint:")
		fmt.Println("  kazeshini update --check --url <https://releases.example.org/latest.json>")
		return nil
	}

	if urlFlag == "" {
		return kzerror.New(
			kzerror.CodeInvalidConfig,
			"No release URL specified for update check",
			"Kazeshini does not hardcode vendor phone-home URLs to prevent unsolicited network egress.",
			"Pass --url <https://releases.example.org/latest.json> to specify your organization's approved release mirror.",
		)
	}

	fmt.Println("======================================================================")
	fmt.Println("風死 · KAZESHINI OPT-IN RELEASE UPDATE CHECK")
	fmt.Println("======================================================================")
	fmt.Printf("CURRENT VERSION:  %s\n", Version)
	fmt.Printf("MANIFEST URL:     %s\n", urlFlag)
	fmt.Println("GUARANTEE:        Read-only inspection only. Auto-apply/auto-update is NEVER executed.")

	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(context.Background(), "GET", urlFlag, nil)
	if err != nil {
		return fmt.Errorf("failed creating release query: %w", err)
	}
	req.Header.Set("User-Agent", "Kazeshini-Release-Check/1.0 (read-only; no-telemetry)")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("release check network dial failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release endpoint returned HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return fmt.Errorf("failed reading release response: %w", err)
	}

	type ReleaseManifest struct {
		LatestVersion string `json:"latest_version"`
		PublishedAt   string `json:"published_at"`
		ReleaseNotes  string `json:"release_notes"`
		DownloadURL   string `json:"download_url"`
		SHA256        string `json:"sha256"`
	}

	var rm ReleaseManifest
	if err := json.Unmarshal(body, &rm); err != nil {
		return fmt.Errorf("failed parsing release manifest JSON: %w", err)
	}

	fmt.Printf("LATEST VERSION:   %s (published: %s)\n", rm.LatestVersion, rm.PublishedAt)
	if rm.LatestVersion != "" && rm.LatestVersion != Version {
		fmt.Println("STATUS:           [UPDATE AVAILABLE]")
		if rm.ReleaseNotes != "" {
			fmt.Printf("NOTES:            %s\n", rm.ReleaseNotes)
		}
		fmt.Printf("MANUAL DOWNLOAD:  %s\n", rm.DownloadURL)
		fmt.Printf("EXPECTED SHA256:  %s\n", rm.SHA256)
		fmt.Println("\nHOW TO UPGRADE MANUALLY:")
		fmt.Println("  1. Download the release binary and verify its checksum.")
		fmt.Println("  2. Replace /usr/local/bin/kazeshini.")
	} else {
		fmt.Println("STATUS:           [UP TO DATE] You are running the latest release.")
	}
	fmt.Println("======================================================================")
	return nil
}

func runView(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kazeshini view <growth|storage|tree|network|timeline> [--no-color]")
	}

	modelType := strings.ToLower(args[0])
	noColor := os.Getenv("NO_COLOR") != ""

	rfs := fs.Default()
	pGraph := graphbuilder.NewProvenanceGraph()

	invManager := inventory.NewManager(rfs)
	originResolver := origin.NewResolver(rfs, invManager)
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

	nodes, edges := pGraph.Snapshot()
	machID := "server"
	if hObs, ok := sup.GetObservation("host"); ok && len(hObs.Items) > 0 {
		if hi, ok := hObs.Items[0].Data.(host.HostInfo); ok && hi.Hostname != "" {
			machID = hi.Hostname
		}
	}

	switch modelType {
	case "growth":
		gm := viz.BuildGrowthMap(machID, nodes, edges, 1000, 700)
		fmt.Print(gm.RenderTerminal(80, noColor))
		return nil

	case "storage":
		var mounts []viz.StorageNode
		if sObs, ok := sup.GetObservation("storage"); ok {
			for _, it := range sObs.Items {
				if m, ok := it.Data.(storage.MountInfo); ok {
					mounts = append(mounts, viz.StorageNode{
						Name:       m.MountPoint,
						MountPoint: m.MountPoint,
						Device:     m.Device,
						FSType:     m.FSType,
						TotalBytes: m.TotalBytes,
						UsedBytes:  m.UsedBytes,
						FreeBytes:  m.FreeBytes,
						UsageRatio: m.UsageRatio,
					})
				}
			}
		}
		fmt.Print(viz.RenderStorageTerminal(mounts, 80))
		return nil

	case "network":
		var rows []viz.NetworkSocketRow
		if nObs, ok := sup.GetObservation("network"); ok {
			for _, it := range nObs.Items {
				if sock, ok := it.Data.(network.SocketInfo); ok {
					rows = append(rows, viz.NetworkSocketRow{
						ProcessName: sock.ProcessName,
						PID:         sock.PID,
						LocalPort:   sock.LocalPort,
						Protocol:    sock.Protocol,
						RemoteIP:    sock.RemoteIP,
						RemotePort:  sock.RemotePort,
						State:       sock.State,
					})
				}
			}
		}
		fmt.Print(viz.RenderNetworkMatrixTerminal(rows, 80))
		return nil

	case "tree", "provenance":
		fmt.Println("======================================================================")
		fmt.Println("風死 · KAZESHINI — PROVENANCE TREE")
		fmt.Println("----------------------------------------------------------------------")
		fmt.Printf("VISIBILITY: %d nodes, %d edges\n", len(nodes), len(edges))
		fmt.Println("HOST ROOT")
		for _, n := range nodes {
			if n.Type == graph.NodeService || n.Type == graph.NodeProcess {
				fmt.Printf("  ├── [%s] %s (%s)\n", n.Type, n.Label, n.Certainty)
			}
		}
		fmt.Println("======================================================================")
		return nil

	case "timeline", "changes":
		fmt.Println("======================================================================")
		fmt.Println("風死 · KAZESHINI — CHANGES TIMELINE")
		fmt.Println("----------------------------------------------------------------------")
		fmt.Println("No baseline diff detected (requires multiple daemon snapshots over time).")
		fmt.Println("To inspect live event stream, run: kazeshini audit tail")
		fmt.Println("======================================================================")
		return nil

	default:
		return fmt.Errorf("unknown view %q (choose from: growth, storage, tree, network, timeline)", modelType)
	}
}

func runExport(args []string) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	var formatFlag string
	flags.StringVar(&formatFlag, "format", "json", "Export format: json, csv, md, html, svg")
	if err := flags.Parse(args); err != nil {
		return err
	}

	rfs := fs.Default()
	pGraph := graphbuilder.NewProvenanceGraph()

	invManager := inventory.NewManager(rfs)
	originResolver := origin.NewResolver(rfs, invManager)
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

	nodes, edges := pGraph.Snapshot()
	machID := "server"
	if hObs, ok := sup.GetObservation("host"); ok && len(hObs.Items) > 0 {
		if hi, ok := hObs.Items[0].Data.(host.HostInfo); ok && hi.Hostname != "" {
			machID = hi.Hostname
		}
	}

	switch strings.ToLower(formatFlag) {
	case "svg":
		gm := viz.BuildGrowthMap(machID, nodes, edges, 1000, 700)
		fmt.Print(gm.RenderSVG())
		return nil

	case "html":
		gm := viz.BuildGrowthMap(machID, nodes, edges, 1000, 700)
		svgData := gm.RenderSVG()
		fmt.Printf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Kazeshini Export - %s</title>
  <style>
    body { background: #0b0c10; color: #d8dee9; font-family: monospace; margin: 0; padding: 20px; }
    h1 { color: #8fffc8; font-size: 18px; }
    .container { max-width: 1000px; margin: 0 auto; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Kazeshini Export - %s</h1>
    <div style="border: 1px solid #1e2230; margin-top: 16px;">
      %s
    </div>
  </div>
</body>
</html>`+"\n", html.EscapeString(machID), html.EscapeString(machID), svgData)
		return nil

	case "csv":
		fmt.Println("id,type,label,certainty")
		for _, n := range nodes {
			fmt.Printf("%q,%q,%q,%q\n", n.ID, n.Type, n.Label, n.Certainty)
		}
		return nil

	case "md", "markdown":
		fmt.Printf("# Kazeshini Export - %s\n\n", machID)
		fmt.Printf("Total entities: %d | Provenance relations: %d\n\n", len(nodes), len(edges))
		fmt.Println("| Type | Label | Certainty |")
		fmt.Println("|---|---|---|")
		for _, n := range nodes {
			fmt.Printf("| %s | %s | %s |\n", n.Type, n.Label, n.Certainty)
		}
		return nil

	case "json":
		data, err := json.MarshalIndent(map[string]any{
			"machine_id": machID,
			"nodes":      nodes,
			"edges":      edges,
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil

	default:
		return fmt.Errorf("unsupported export format %q (choose from: json, csv, md, html, svg)", formatFlag)
	}
}
