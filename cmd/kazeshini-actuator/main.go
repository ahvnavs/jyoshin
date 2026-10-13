// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/OWNER/kazeshini/internal/actuator"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch subcmd {
	case "daemon":
		err = runDaemon(args)
	case "keygen":
		err = runKeygen(args)
	case "approve":
		err = runApprove(args)
	case "apply":
		err = runApply(args)
	case "status":
		err = runStatus(args)
	case "disable":
		err = runDisable(args)
	case "enable":
		err = runEnable(args)
	case "audit":
		err = runAudit(args)
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		printUsage()
		fmt.Fprintf(os.Stderr, "unknown command %q\n", subcmd)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`kazeshini-actuator — Separate, Opt-in Host Mutation Daemon (Phase 27)

Usage:
  kazeshini-actuator <command> [options]

Commands:
  daemon      Run the actuator service on root-owned unix domain socket
  keygen      Generate a fresh Ed25519 approver keypair
  approve     Cryptographically sign a remediation plan envelope
  apply       Submit a signed plan envelope to the actuator unix socket
  status      Query actuator daemon connectivity and current host identity
  disable     Engage the kill switch sentinel (halts plan execution)
  enable      Disengage the kill switch sentinel
  audit       Audit log inspection and tamper verification

Principles:
  - Separate binary, separate unit, disabled by default (Principle 2')
  - Root-owned unix socket (0600), zero HTTP listeners, zero egress
  - Exec allow-list only, no shell interpolation (Principle 13)
  - Preflights, step timeouts, stop-the-world on failure`)
}

func runDaemon(args []string) error {
	flags := flag.NewFlagSet("daemon", flag.ExitOnError)
	socketPath := flags.String("socket", "/run/kazeshini/actuator.sock", "Path to unix domain socket")
	pubKeyPath := flags.String("pubkey", "/etc/kazeshini/approver.pub", "Path to approver public key")
	auditPath := flags.String("audit-log", "/var/log/kazeshini/actuator-audit.log", "Path to append-only audit log")
	noncePath := flags.String("nonce-cache", "/var/lib/kazeshini/actuator-nonces.json", "Path to replay protection cache")
	sentinelPath := flags.String("sentinel", "/etc/kazeshini/actuator.disabled", "Kill-switch sentinel path")
	pkgMgr := flags.String("pkg-manager", "apt", "Host package manager (apt, dnf, pacman, apk)")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg := actuator.DefaultConfig()
	cfg.SocketPath = *socketPath
	cfg.AuditLogPath = *auditPath
	cfg.NonceStorePath = *noncePath
	cfg.SentinelPath = *sentinelPath
	cfg.PackageManager = *pkgMgr

	if *pubKeyPath != "" {
		if data, err := os.ReadFile(*pubKeyPath); err == nil {
			decoded, err := base64.StdEncoding.DecodeString(string(data))
			if err == nil && len(decoded) == ed25519.PublicKeySize {
				cfg.ApproverPubKey = ed25519.PublicKey(decoded)
			}
		}
	}

	auditLogger, err := actuator.NewAuditLogger(cfg.AuditLogPath)
	if err != nil {
		return fmt.Errorf("initializing audit logger: %w", err)
	}

	nonceStore, err := actuator.NewNonceStore(cfg.NonceStorePath, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("initializing nonce store: %w", err)
	}

	engine := actuator.NewEngine(cfg, auditLogger, nonceStore)
	server := actuator.NewServer(cfg.SocketPath, engine)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("kazeshini-actuator daemon starting on %s (host: %s)...\n", cfg.SocketPath, cfg.CurrentHostID)
	return server.Start(ctx)
}

func runKeygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := flags.String("out", "/etc/kazeshini", "Output directory for keypair")
	if err := flags.Parse(args); err != nil {
		return err
	}

	pub, priv, err := actuator.GenerateApproverKeypair()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		return err
	}

	pubFile := filepath.Join(*outDir, "approver.pub")
	privFile := filepath.Join(*outDir, "approver.key")

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	if err := os.WriteFile(pubFile, []byte(pubB64), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(privFile, []byte(privB64), 0600); err != nil {
		return err
	}

	fmt.Println("Generated Ed25519 approver keypair:")
	fmt.Printf("  Public key:  %s\n", pubFile)
	fmt.Printf("  Private key: %s (permissions: 0600)\n", privFile)
	return nil
}

func runApprove(args []string) error {
	flags := flag.NewFlagSet("approve", flag.ExitOnError)
	planFile := flags.String("plan", "", "Path to remediation plan JSON")
	keyFile := flags.String("key", "/etc/kazeshini/approver.key", "Path to approver private key")
	approver := flags.String("approver", "operator", "Approver identity")
	outFile := flags.String("out", "", "Output path for signed envelope JSON")
	expiryMin := flags.Int("expires-min", 15, "Expiration duration in minutes")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if *planFile == "" {
		return fmt.Errorf("--plan is required")
	}

	planData, err := os.ReadFile(*planFile)
	if err != nil {
		return err
	}

	var plan actuator.RemediationPlan
	if err := json.Unmarshal(planData, &plan); err != nil {
		return fmt.Errorf("parsing plan: %w", err)
	}

	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("reading private key: %w", err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key file")
	}
	privKey := ed25519.PrivateKey(privBytes)

	now := time.Now().UTC()
	env := &actuator.ExecutionEnvelope{
		EnvelopeVersion: "1.0",
		Plan:            plan,
		HostID:          actuator.ReadCurrentHostID(),
		Nonce:           fmt.Sprintf("%d-%s", now.UnixNano(), plan.ID),
		Approver:        *approver,
		ApprovedAt:      now,
		ExpiresAt:       now.Add(time.Duration(*expiryMin) * time.Minute),
	}

	if err := actuator.SignEnvelope(env, privKey); err != nil {
		return fmt.Errorf("signing envelope: %w", err)
	}

	outData, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	if *outFile != "" {
		return os.WriteFile(*outFile, outData, 0600)
	}
	fmt.Println(string(outData))
	return nil
}

func runApply(args []string) error {
	flags := flag.NewFlagSet("apply", flag.ExitOnError)
	envelopeFile := flags.String("envelope", "", "Path to signed execution envelope JSON")
	socketPath := flags.String("socket", "/run/kazeshini/actuator.sock", "Path to actuator unix socket")
	reallyApply := flags.Bool("apply", false, "Execute real mutations (default false: dry-run only)")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if *envelopeFile == "" {
		return fmt.Errorf("--envelope is required")
	}

	data, err := os.ReadFile(*envelopeFile)
	if err != nil {
		return err
	}

	var env actuator.ExecutionEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("parsing envelope: %w", err)
	}

	client := actuator.NewClient(*socketPath)
	res, err := client.SubmitEnvelope(&env, *reallyApply)
	if err != nil {
		return fmt.Errorf("actuator submission failed: %w", err)
	}

	fmt.Println("======================================================================")
	fmt.Printf("Kazeshini Actuator Run: Plan %s\n", res.PlanID)
	fmt.Printf("Status:         [%s]\n", res.Status)
	fmt.Printf("Executed Steps: %d / %d\n", res.ExecutedSteps, res.TotalSteps)
	if res.Error != "" {
		fmt.Printf("Error:          %s\n", res.Error)
	}
	fmt.Println("----------------------------------------------------------------------")
	for _, l := range res.OutputLogs {
		fmt.Println(l)
	}
	if res.RollbackPlan != nil {
		fmt.Println("----------------------------------------------------------------------")
		fmt.Println("ROLLBACK GUIDANCE (SHOWN ONLY, REQUIRE SEPARATE HUMAN APPROVAL):")
		rData, _ := json.MarshalIndent(res.RollbackPlan, "  ", "  ")
		fmt.Println(string(rData))
	}
	fmt.Println("======================================================================")
	return nil
}

func runStatus(args []string) error {
	flags := flag.NewFlagSet("status", flag.ExitOnError)
	socketPath := flags.String("socket", "/run/kazeshini/actuator.sock", "Path to actuator unix socket")
	if err := flags.Parse(args); err != nil {
		return err
	}

	client := actuator.NewClient(*socketPath)
	hostID, err := client.Ping()
	if err != nil {
		fmt.Printf("Actuator status: INACTIVE / UNREACHABLE (%v)\n", err)
		return nil
	}
	fmt.Printf("Actuator status: ACTIVE\n")
	fmt.Printf("Socket:          %s\n", *socketPath)
	fmt.Printf("Target Machine:  %s\n", hostID)
	return nil
}

func runDisable(args []string) error {
	flags := flag.NewFlagSet("disable", flag.ExitOnError)
	sentinel := flags.String("sentinel", "/etc/kazeshini/actuator.disabled", "Kill-switch sentinel path")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(*sentinel), 0755); err != nil {
		return err
	}
	content := fmt.Sprintf("disabled at %s\n", time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(*sentinel, []byte(content), 0644); err != nil {
		return err
	}
	fmt.Printf("Kill-switch engaged: %s created. All actuator operations are halted.\n", *sentinel)
	return nil
}

func runEnable(args []string) error {
	flags := flag.NewFlagSet("enable", flag.ExitOnError)
	sentinel := flags.String("sentinel", "/etc/kazeshini/actuator.disabled", "Kill-switch sentinel path")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if err := os.Remove(*sentinel); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Printf("Kill-switch disengaged: %s removed. Actuator enabled.\n", *sentinel)
	return nil
}

func runAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kazeshini-actuator audit verify [--file <path>]")
	}
	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "verify":
		flags := flag.NewFlagSet("audit verify", flag.ExitOnError)
		path := flags.String("file", "/var/log/kazeshini/actuator-audit.log", "Path to audit log file")
		if err := flags.Parse(subargs); err != nil {
			return err
		}
		count, err := actuator.VerifyAuditChain(*path)
		if err != nil {
			return fmt.Errorf("audit chain verification FAILED: %w", err)
		}
		fmt.Printf("[✓] Audit chain VERIFIED clean (%d records verified, zero tamper detected).\n", count)
		return nil
	default:
		return fmt.Errorf("unknown audit command %q (expected: verify)", subcmd)
	}
}

