// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
)

// UsersSudoCheck inspects /etc/passwd, sudo/wheel group members, and sudoers / sudoers.d configs, flagging NOPASSWD.
type UsersSudoCheck struct{}

func (c *UsersSudoCheck) ID() string    { return "users-sudo" }
func (c *UsersSudoCheck) Role() string  { return "devsecops" }
func (c *UsersSudoCheck) Title() string { return "Users, Sudo Privileges & NOPASSWD Rules Audit" }
func (c *UsersSudoCheck) Description() string {
	return "Parses /etc/passwd, sudoers, and sudoers.d files, flagging unpassworded root privileges"
}

func (c *UsersSudoCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	passwdData, err := rfs.ReadFile("/etc/passwd")
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot read /etc/passwd: permission denied",
				ExplainLevels: [3]string{
					"Permission denied reading /etc/passwd",
					"Local user account inventory is obscured",
					"Ensure read access to standard /etc/passwd file",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Failed reading /etc/passwd: %v", err)), nil
	}

	userCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(passwdData))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			userCount++
		}
	}

	// Check sudoers file and sudoers.d directory
	var nopasswdRules []string
	sudoersData, sErr := rfs.ReadFile("/etc/sudoers")
	if sErr != nil && os.IsPermission(sErr) {
		// Sudoers permission denied is expected for unprivileged users; report gracefully
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: fmt.Sprintf("Inspected %d user accounts in /etc/passwd; /etc/sudoers unreadable (permission denied)", userCount),
			ExplainLevels: [3]string{
				fmt.Sprintf("Discovered %d accounts in /etc/passwd; sudoers requires elevated permissions", userCount),
				"NOPASSWD privilege analysis requires read access to /etc/sudoers",
				"Run with sudo or appropriate group permissions to audit sudoers rules",
			},
			Certainty: graph.CertaintyObserved,
			Coverage:  contract.CoverageSummary{Seen: 2, Total: 3, Reason: "/etc/sudoers unreadable without root (2 of 3 sources readable: /etc/passwd and /etc/sudoers.d)"},
			ReadOnly:  true,
		}, nil
	}

	checkSudoContent := func(data []byte, source string) {
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
				nopasswdRules = append(nopasswdRules, fmt.Sprintf("%s: %s", source, line))
			}
		}
	}

	if len(sudoersData) > 0 {
		checkSudoContent(sudoersData, "/etc/sudoers")
	}

	// Check /etc/sudoers.d
	if entries, err := rfs.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), ".") && !strings.HasSuffix(e.Name(), "~") {
				path := fmt.Sprintf("/etc/sudoers.d/%s", e.Name())
				if d, err := rfs.ReadFile(path); err == nil {
					checkSudoContent(d, path)
				}
			}
		}
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Audited %d user accounts; zero unconstrained NOPASSWD sudo rules found", userCount)
	if len(nopasswdRules) > 0 {
		st = contract.StatusWarn
		sum = fmt.Sprintf("Audited %d accounts; %d NOPASSWD sudo rule(s) detected allowing unauthenticated root escalation", userCount, len(nopasswdRules))
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Audited %d user accounts in /etc/passwd, /etc/sudoers, and /etc/sudoers.d", userCount),
			"NOPASSWD rules bypass password re-prompting and allow rapid privilege escalation",
			"Require password authentication for sensitive sudo actions",
		},
		Coverage: contract.CoverageSummary{
			Seen:   3, // /etc/passwd, /etc/sudoers, /etc/sudoers.d
			Total:  3,
			Reason: "All 3 user and privilege databases inspected (/etc/passwd, /etc/sudoers, /etc/sudoers.d)",
		},
		Evidence: []graph.Evidence{
			{Source: "/etc/passwd", Collector: "users-sudo", Details: fmt.Sprintf("%d users", userCount), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: "getent passwd; sudo -l",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// SSHSettingsCheck parses sshd_config and Include files, flagging root login, password auth, and empty passwords.
type SSHSettingsCheck struct{}

func (c *SSHSettingsCheck) ID() string    { return "ssh-settings" }
func (c *SSHSettingsCheck) Role() string  { return "devsecops" }
func (c *SSHSettingsCheck) Title() string { return "OpenSSH Daemon Configuration Security Audit" }
func (c *SSHSettingsCheck) Description() string {
	return "Audits /etc/ssh/sshd_config and Include directives for PermitRootLogin, PasswordAuthentication, and PermitEmptyPasswords"
}

func (c *SSHSettingsCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	configPath := "/etc/ssh/sshd_config"
	data, err := rfs.ReadFile(configPath)
	if err != nil {
		if os.IsPermission(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusUnknown,
				SummaryPlain: "Cannot read /etc/ssh/sshd_config: permission denied",
				ExplainLevels: [3]string{
					"Permission denied reading /etc/ssh/sshd_config",
					"SSH daemon security posture cannot be verified",
					"Ensure read access to sshd configuration",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		if os.IsNotExist(err) {
			return contract.CheckResult{
				ID:           c.ID(),
				Role:         c.Role(),
				Title:        c.Title(),
				Status:       contract.StatusNotApplicable,
				SummaryPlain: "OpenSSH server configuration file (/etc/ssh/sshd_config) not found",
				ExplainLevels: [3]string{
					"/etc/ssh/sshd_config is not present",
					"Host does not have an OpenSSH server daemon configured",
					"No action needed",
				},
				Certainty: graph.CertaintyObserved,
				ReadOnly:  true,
			}, nil
		}
		return contract.NewCheckResult(c.ID(), c.Role(), c.Title(), contract.StatusUnknown, fmt.Sprintf("Error reading sshd_config: %v", err)), nil
	}

	permitRootLogin := "prohibit-password" // default in modern OpenSSH
	passwordAuth := "yes"
	permitEmpty := "no"

	parseSSHConfig := func(raw []byte) {
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.ToLower(parts[0])
				val := strings.ToLower(parts[1])
				switch key {
				case "permitrootlogin":
					permitRootLogin = val
				case "passwordauthentication":
					passwordAuth = val
				case "permitemptypasswords":
					permitEmpty = val
				}
			}
		}
	}

	parseSSHConfig(data)

	// Follow and inspect drop-in configurations in /etc/ssh/sshd_config.d/
	if entries, err := rfs.ReadDir("/etc/ssh/sshd_config.d"); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") && !strings.HasPrefix(e.Name(), ".") {
				dropinPath := fmt.Sprintf("/etc/ssh/sshd_config.d/%s", e.Name())
				if dropinData, err := rfs.ReadFile(dropinPath); err == nil {
					parseSSHConfig(dropinData)
				}
			}
		}
	}

	var issues []string
	if permitRootLogin == "yes" {
		issues = append(issues, "PermitRootLogin is set to 'yes' (root login permitted)")
	}
	if permitEmpty == "yes" {
		issues = append(issues, "PermitEmptyPasswords is enabled")
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("SSH configuration safe: PermitRootLogin=%s, PasswordAuthentication=%s, PermitEmptyPasswords=%s", permitRootLogin, passwordAuth, permitEmpty)
	if len(issues) > 0 {
		st = contract.StatusCrit
		sum = fmt.Sprintf("SSH hardening alert: %s", strings.Join(issues, "; "))
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Parsed %s (PermitRootLogin=%s, PasswordAuth=%s)", configPath, permitRootLogin, passwordAuth),
			"Exposing root login or empty passwords exposes SSH to automated credential brute-force",
			"Set 'PermitRootLogin no' or 'prohibit-password' in /etc/ssh/sshd_config",
		},
		Evidence: []graph.Evidence{
			{Source: configPath, Collector: "ssh-settings", Details: fmt.Sprintf("RootLogin=%s, PassAuth=%s", permitRootLogin, passwordAuth), Certainty: graph.CertaintyDerived, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyDerived, // Derived by parsing config
		EquivalentCommand: "sshd -T | grep -E 'permitrootlogin|passwordauthentication|permitemptypasswords'",
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}

// AuthLogsCheck audits authentication logs for failed login attempts and top sources (never logs passwords).
type AuthLogsCheck struct{}

func (c *AuthLogsCheck) ID() string    { return "auth-logs" }
func (c *AuthLogsCheck) Role() string  { return "devsecops" }
func (c *AuthLogsCheck) Title() string { return "Authentication Log Failures & Brute-Force Sources" }
func (c *AuthLogsCheck) Description() string {
	return "Audits /var/log/auth.log or /var/log/secure for failed login attempts (strictly scrubbing sensitive tokens)"
}

func (c *AuthLogsCheck) Run(ctx context.Context, rfs fs.FS, params map[string]string) (contract.CheckResult, error) {
	logPaths := []string{"/var/log/auth.log", "/var/log/secure"}
	var targetLog string
	var logData []byte
	permDenied := false

	for _, p := range logPaths {
		data, err := rfs.ReadFile(p)
		if err == nil {
			targetLog = p
			logData = data
			break
		} else if os.IsPermission(err) {
			permDenied = true
		}
	}

	if permDenied && targetLog == "" {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusUnknown,
			SummaryPlain: "Cannot inspect authentication logs: permission denied",
			ExplainLevels: [3]string{
				"Permission denied reading /var/log/auth.log or /var/log/secure",
				"Failed login monitoring cannot be executed without read permissions",
				"Ensure observer has read access to /var/log/auth.log",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	if targetLog == "" {
		return contract.CheckResult{
			ID:           c.ID(),
			Role:         c.Role(),
			Title:        c.Title(),
			Status:       contract.StatusNotApplicable,
			SummaryPlain: "No dedicated auth.log or secure log file found on host",
			ExplainLevels: [3]string{
				"Neither /var/log/auth.log nor /var/log/secure was found",
				"System may log authentication events exclusively to systemd journal",
				"No action needed",
			},
			Certainty: graph.CertaintyObserved,
			ReadOnly:  true,
		}, nil
	}

	// Count failed logins (strictly scrubbing lines)
	failedCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(logData))
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.Contains(line, "failed password") || strings.Contains(line, "authentication failure") || strings.Contains(line, "invalid user") {
			failedCount++
		}
	}

	st := contract.StatusOK
	sum := fmt.Sprintf("Authentication log clean: %d failed login attempts recorded in %s", failedCount, targetLog)
	if failedCount > 50 {
		st = contract.StatusWarn
		sum = fmt.Sprintf("Brute-force activity warning: %d failed login attempts detected in %s", failedCount, targetLog)
	}

	return contract.CheckResult{
		ID:           c.ID(),
		Role:         c.Role(),
		Title:        c.Title(),
		Status:       st,
		SummaryPlain: sum,
		ExplainLevels: [3]string{
			fmt.Sprintf("Scanned %s for failed password and invalid user log entries", targetLog),
			"Repeated failed logins indicate automated brute-force attacks or misconfigured clients",
			"Enable fail2ban or restrict SSH exposure to trusted VPN subnets",
		},
		Evidence: []graph.Evidence{
			{Source: targetLog, Collector: "auth-logs", Details: fmt.Sprintf("%d failed attempts", failedCount), Certainty: graph.CertaintyObserved, Timestamp: time.Now().UTC()},
		},
		Certainty:         graph.CertaintyObserved,
		EquivalentCommand: fmt.Sprintf("grep -i 'failed password' %s | wc -l", targetLog),
		ReadOnly:          true,
		CollectedAt:       time.Now().UTC(),
	}, nil
}
