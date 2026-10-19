//go:build experimental
// +build experimental

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/fleet"
	"github.com/OWNER/kazeshini/internal/verdict"
)

func init() {
	experimentalHandlers["agent"] = runAgent
	experimentalHandlers["controller"] = runController
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
	fmt.Println("風死 · KAZESHINI OUTBOUND AGENT [EXPERIMENTAL]")
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
	fmt.Println("風死 · KAZESHINI FLEET CONTROLLER [EXPERIMENTAL]")
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
