// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package checks_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OWNER/kazeshini/internal/checks"
	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/fs"
)

// mockDeniedFS simulates an OS filesystem where specified paths return EACCES (Permission Denied).
type mockDeniedFS struct {
	realFS      fs.FS
	deniedPaths map[string]bool
}

func newMockDeniedFS(root string, denied ...string) *mockDeniedFS {
	m := &mockDeniedFS{
		realFS:      fs.NewRootedFS(root),
		deniedPaths: make(map[string]bool),
	}
	for _, p := range denied {
		m.deniedPaths[filepath.Clean(p)] = true
	}
	return m
}

func (m *mockDeniedFS) Root() string               { return m.realFS.Root() }
func (m *mockDeniedFS) Path(elem ...string) string { return m.realFS.Path(elem...) }

func (m *mockDeniedFS) ReadFile(name string) ([]byte, error) {
	if m.deniedPaths[filepath.Clean(name)] {
		return nil, os.ErrPermission
	}
	return m.realFS.ReadFile(name)
}

func (m *mockDeniedFS) ReadDir(name string) ([]os.DirEntry, error) {
	if m.deniedPaths[filepath.Clean(name)] {
		return nil, os.ErrPermission
	}
	return m.realFS.ReadDir(name)
}

func (m *mockDeniedFS) Stat(name string) (os.FileInfo, error) {
	if m.deniedPaths[filepath.Clean(name)] {
		return nil, os.ErrPermission
	}
	return m.realFS.Stat(name)
}

func (m *mockDeniedFS) Readlink(name string) (string, error) {
	if m.deniedPaths[filepath.Clean(name)] {
		return "", os.ErrPermission
	}
	return m.realFS.Readlink(name)
}

func (m *mockDeniedFS) Open(name string) (*os.File, error) {
	if m.deniedPaths[filepath.Clean(name)] {
		return nil, os.ErrPermission
	}
	return m.realFS.Open(name)
}

func TestChecks_AllRegisteredChecksExist(t *testing.T) {
	reg := checks.NewRegistry()
	all := reg.All()
	if len(all) < 20 {
		t.Fatalf("expected at least 20 checks, got %d", len(all))
	}

	expectedRoles := []string{"devops", "cloud", "cloud-platform", "infrastructure", "devsecops", "platform", "network"}
	for _, role := range expectedRoles {
		byRole := reg.ByRole(role)
		if len(byRole) == 0 {
			t.Errorf("role %q has 0 checks registered", role)
		}
	}
}

func TestChecks_DevOps(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	// Setup fake /proc and /var/log
	_ = os.MkdirAll(filepath.Join(tmp, "proc", "1"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "net", "tcp"), []byte(" sl local_address rem_address st\n  0: 00000000:0016 00000000:0000 0A \n"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "loadavg"), []byte("0.42 0.50 0.60 1/150 1234\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "meminfo"), []byte("MemTotal:        16384000 kB\nMemAvailable:    8192000 kB\n"), 0644)
	_ = os.MkdirAll(filepath.Join(tmp, "var", "log"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "var", "log", "syslog"), []byte("Oct 12 INFO starting\nOct 12 ERROR failed to connect secret=AKIAIOSFODNN7EXAMPLE\n"), 0644)

	realFS := fs.NewRootedFS(tmp)

	// 1. AppHealth
	ah := &checks.AppHealthCheck{}
	res, err := ah.Run(ctx, realFS, nil)
	if err != nil || res.Status != contract.StatusOK {
		t.Errorf("app-health positive test failed: status=%s, err=%v", res.Status, err)
	}
	// AppHealth Permission Denied
	deniedFS := newMockDeniedFS(tmp, "/proc")
	resDenied, _ := ah.Run(ctx, deniedFS, nil)
	if resDenied.Status != contract.StatusUnknown || !strings.Contains(resDenied.SummaryPlain, "permission denied") {
		t.Errorf("app-health permission denied test failed: status=%s, summary=%s", resDenied.Status, resDenied.SummaryPlain)
	}

	// 2. AppLogs
	al := &checks.AppLogsCheck{}
	resLogs, err := al.Run(ctx, realFS, map[string]string{"file": "/var/log/syslog"})
	if err != nil || resLogs.Status != contract.StatusWarn { // warning because of ERROR line
		t.Errorf("app-logs test failed: status=%s, err=%v", resLogs.Status, err)
	}
	if strings.Contains(resLogs.RawRedacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("app-logs secret not redacted: %s", resLogs.RawRedacted)
	}
	// AppLogs Not Applicable
	resLogsNA, _ := al.Run(ctx, realFS, map[string]string{"file": "/var/log/nonexistent.log"})
	if resLogsNA.Status != contract.StatusNotApplicable {
		t.Errorf("app-logs not applicable test failed: status=%s", resLogsNA.Status)
	}
	// AppLogs Permission Denied
	deniedLogFS := newMockDeniedFS(tmp, "/var/log/syslog")
	resLogDenied, _ := al.Run(ctx, deniedLogFS, map[string]string{"file": "/var/log/syslog"})
	if resLogDenied.Status != contract.StatusUnknown || !strings.Contains(resLogDenied.SummaryPlain, "permission denied") {
		t.Errorf("app-logs permission denied test failed: status=%s", resLogDenied.Status)
	}

	// 3. CPUMemory
	cpu := &checks.CPUMemoryCheck{}
	resCPU, err := cpu.Run(ctx, realFS, nil)
	if err != nil || resCPU.Status != contract.StatusOK {
		t.Errorf("cpu-memory test failed: status=%s, err=%v", resCPU.Status, err)
	}
	deniedCPUFS := newMockDeniedFS(tmp, "/proc/loadavg")
	resCPUDenied, _ := cpu.Run(ctx, deniedCPUFS, nil)
	if resCPUDenied.Status != contract.StatusUnknown {
		t.Errorf("cpu-memory denied test failed: status=%s", resCPUDenied.Status)
	}
}

func TestChecks_Cloud(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	// 1. CloudInit Positive
	_ = os.MkdirAll(filepath.Join(tmp, "run", "cloud-init"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "run", "cloud-init", "result.json"), []byte(`{"v1":{"stage":"final","errors":[]}}`), 0644)
	rfs := fs.NewRootedFS(tmp)

	ci := &checks.CloudInitCheck{}
	resCI, err := ci.Run(ctx, rfs, nil)
	if err != nil || resCI.Status != contract.StatusOK {
		t.Errorf("cloud-init positive test failed: status=%s, err=%v", resCI.Status, err)
	}

	// CloudInit Not Applicable
	emptyTmp := t.TempDir()
	emptyFS := fs.NewRootedFS(emptyTmp)
	resCINA, _ := ci.Run(ctx, emptyFS, nil)
	if resCINA.Status != contract.StatusNotApplicable {
		t.Errorf("cloud-init not applicable test failed: status=%s", resCINA.Status)
	}

	// CloudInit Permission Denied
	deniedCIFS := newMockDeniedFS(tmp, "/run/cloud-init/result.json", "/run/cloud-init/status.json")
	resCIDenied, _ := ci.Run(ctx, deniedCIFS, nil)
	if resCIDenied.Status != contract.StatusUnknown {
		t.Errorf("cloud-init permission denied test failed: status=%s", resCIDenied.Status)
	}

	// 2. CloudAgent Positive & NA
	ca := &checks.CloudAgentCheck{}
	resCANA, _ := ca.Run(ctx, emptyFS, nil)
	if resCANA.Status != contract.StatusNotApplicable {
		t.Errorf("cloud-agent not applicable test failed: status=%s", resCANA.Status)
	}

	_ = os.MkdirAll(filepath.Join(tmp, "usr", "sbin"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "usr", "sbin", "waagent"), []byte("#!/bin/sh\n"), 0755)
	resCA, _ := ca.Run(ctx, rfs, nil)
	if resCA.Status != contract.StatusOK || !strings.Contains(resCA.SummaryPlain, "walinuxagent") {
		t.Errorf("cloud-agent positive test failed: status=%s", resCA.Status)
	}

	// 3. AttachedStorage
	_ = os.MkdirAll(filepath.Join(tmp, "proc"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "mounts"), []byte("/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /data ext4 rw 0 0\n"), 0644)
	_ = os.MkdirAll(filepath.Join(tmp, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "etc", "fstab"), []byte("/dev/sda1 / ext4 defaults 0 0\n/dev/sdb1 /data ext4 defaults 0 0\n"), 0644)
	as := &checks.AttachedStorageCheck{}
	resAS, err := as.Run(ctx, rfs, nil)
	if err != nil || resAS.Status != contract.StatusOK {
		t.Errorf("attached-storage test failed: status=%s, err=%v", resAS.Status, err)
	}
	deniedASFS := newMockDeniedFS(tmp, "/proc/mounts")
	resASDenied, _ := as.Run(ctx, deniedASFS, nil)
	if resASDenied.Status != contract.StatusUnknown {
		t.Errorf("attached-storage permission denied failed: status=%s", resASDenied.Status)
	}
}

func TestChecks_CloudPlatform(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	ns := &checks.NodeServicesCheck{}
	// NA test
	emptyFS := fs.NewRootedFS(tmp)
	resNSNA, _ := ns.Run(ctx, emptyFS, nil)
	if resNSNA.Status != contract.StatusNotApplicable {
		t.Errorf("node-services NA test failed: status=%s", resNSNA.Status)
	}

	// Positive test with simulated containerd process
	_ = os.MkdirAll(filepath.Join(tmp, "proc", "100"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "100", "comm"), []byte("containerd\n"), 0644)
	rfs := fs.NewRootedFS(tmp)
	resNS, _ := ns.Run(ctx, rfs, nil)
	if resNS.Status != contract.StatusOK || !strings.Contains(resNS.SummaryPlain, "containerd") {
		t.Errorf("node-services positive test failed: status=%s, summary=%s", resNS.Status, resNS.SummaryPlain)
	}

	// Container Storage NA & Positive
	cs := &checks.ContainerStorageCheck{}
	resCSNA, _ := cs.Run(ctx, emptyFS, nil)
	if resCSNA.Status != contract.StatusNotApplicable {
		t.Errorf("container-storage NA test failed: status=%s", resCSNA.Status)
	}
	_ = os.MkdirAll(filepath.Join(tmp, "var", "lib", "docker"), 0755)
	resCS, _ := cs.Run(ctx, rfs, nil)
	if resCS.Status != contract.StatusOK || !strings.Contains(resCS.SummaryPlain, "/var/lib/docker") {
		t.Errorf("container-storage positive test failed: status=%s", resCS.Status)
	}
}

func TestChecks_Infrastructure(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	rfs := fs.NewRootedFS(tmp)

	// DiskInodes
	_ = os.MkdirAll(filepath.Join(tmp, "proc"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "mounts"), []byte("/dev/root / ext4 rw 0 0\n"), 0644)
	di := &checks.DiskInodesCheck{}
	resDI, err := di.Run(ctx, rfs, nil)
	if err != nil || (resDI.Status != contract.StatusOK && resDI.Status != contract.StatusWarn) {
		t.Errorf("disk-inodes test failed: status=%s, err=%v", resDI.Status, err)
	}

	// FailedServices Positive & Negative
	_ = os.MkdirAll(filepath.Join(tmp, "run", "systemd", "system"), 0755)
	fsCheck := &checks.FailedServicesCheck{}
	resFS, _ := fsCheck.Run(ctx, rfs, nil)
	if resFS.Status != contract.StatusOK {
		t.Errorf("failed-services zero failed test failed: status=%s", resFS.Status)
	}

	_ = os.MkdirAll(filepath.Join(tmp, "run", "systemd", "units"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "run", "systemd", "units", "bad.service"), []byte("ActiveState=failed\n"), 0644)
	resFSFailed, _ := fsCheck.Run(ctx, rfs, nil)
	if resFSFailed.Status != contract.StatusCrit || !strings.Contains(resFSFailed.SummaryPlain, "bad.service") {
		t.Errorf("failed-services crit test failed: status=%s, summary=%s", resFSFailed.Status, resFSFailed.SummaryPlain)
	}

	// TimeSync
	ts := &checks.TimeSyncCheck{}
	resTS, err := ts.Run(ctx, rfs, nil)
	if err != nil {
		t.Errorf("time-sync test errored: %v", err)
	}
	if resTS.Status == "" {
		t.Errorf("time-sync returned empty status")
	}
}

func TestChecks_DevSecOps(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tmp, "etc", "sudoers.d"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "etc", "sudoers"), []byte("%sudo ALL=(ALL:ALL) ALL\n"), 0644)

	rfs := fs.NewRootedFS(tmp)
	us := &checks.UsersSudoCheck{}

	// Positive test (clean sudo)
	resUS, err := us.Run(ctx, rfs, nil)
	if err != nil || resUS.Status != contract.StatusOK {
		t.Errorf("users-sudo clean test failed: status=%s, err=%v", resUS.Status, err)
	}

	// Negative test: NOPASSWD flagged
	_ = os.WriteFile(filepath.Join(tmp, "etc", "sudoers.d", "nopasswd"), []byte("deploy ALL=(ALL) NOPASSWD: ALL\n"), 0644)
	resUSWarn, _ := us.Run(ctx, rfs, nil)
	if resUSWarn.Status != contract.StatusWarn || !strings.Contains(resUSWarn.SummaryPlain, "NOPASSWD") {
		t.Errorf("users-sudo NOPASSWD warning test failed: status=%s, summary=%s", resUSWarn.Status, resUSWarn.SummaryPlain)
	}

	// Permission denied test
	deniedUSFS := newMockDeniedFS(tmp, "/etc/sudoers")
	resUSDenied, _ := us.Run(ctx, deniedUSFS, nil)
	t.Logf("Permission-denied fixture result: status=%s, summary=%s", resUSDenied.Status, resUSDenied.SummaryPlain)
	if resUSDenied.Status != contract.StatusUnknown || !strings.Contains(resUSDenied.SummaryPlain, "permission denied") {
		t.Errorf("users-sudo permission denied test failed: status=%s", resUSDenied.Status)
	}

	// SSH Settings
	_ = os.MkdirAll(filepath.Join(tmp, "etc", "ssh"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "etc", "ssh", "sshd_config"), []byte("PermitRootLogin yes\nPasswordAuthentication yes\n"), 0644)
	sshCheck := &checks.SSHSettingsCheck{}
	resSSH, _ := sshCheck.Run(ctx, rfs, nil)
	if resSSH.Status != contract.StatusCrit || !strings.Contains(resSSH.SummaryPlain, "PermitRootLogin") {
		t.Errorf("ssh-settings crit test failed: status=%s, summary=%s", resSSH.Status, resSSH.SummaryPlain)
	}

	// AuthLogs
	_ = os.MkdirAll(filepath.Join(tmp, "var", "log"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "var", "log", "auth.log"), []byte("Oct 12 10:00:00 sshd[1]: Failed password for root from 1.2.3.4\n"), 0644)
	authCheck := &checks.AuthLogsCheck{}
	resAuth, _ := authCheck.Run(ctx, rfs, nil)
	if resAuth.Status != contract.StatusOK || !strings.Contains(resAuth.SummaryPlain, "1 failed login") {
		t.Errorf("auth-logs test failed: status=%s, summary=%s", resAuth.Status, resAuth.SummaryPlain)
	}
}

func TestChecks_Platform(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	// ConfigValidation
	_ = os.MkdirAll(filepath.Join(tmp, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "etc", "valid.json"), []byte(`{"key":"value"}`), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "etc", "broken.json"), []byte(`{"key": broken json`), 0644)

	rfs := fs.NewRootedFS(tmp)
	cv := &checks.ConfigValidationCheck{}

	resValid, _ := cv.Run(ctx, rfs, map[string]string{"file": "/etc/valid.json"})
	if resValid.Status != contract.StatusOK {
		t.Errorf("config-validation valid test failed: status=%s", resValid.Status)
	}

	resBroken, _ := cv.Run(ctx, rfs, map[string]string{"file": "/etc/broken.json"})
	if resBroken.Status != contract.StatusCrit {
		t.Errorf("config-validation broken test failed: status=%s", resBroken.Status)
	}

	// ServicePermissions
	_ = os.MkdirAll(filepath.Join(tmp, "etc", "systemd", "system"), 0755)
	vulnPath := filepath.Join(tmp, "etc", "systemd", "system", "vulnerable.service")
	_ = os.WriteFile(vulnPath, []byte("[Service]\nExecStart=/bin/sh\n"), 0666)
	_ = os.Chmod(vulnPath, 0666) // Explicit chmod to bypass umask!
	sp := &checks.ServicePermissionsCheck{}
	resSP, _ := sp.Run(ctx, rfs, nil)
	if resSP.Status != contract.StatusCrit || !strings.Contains(resSP.SummaryPlain, "world-writable") {
		t.Errorf("service-permissions world-writable test failed: status=%s, summary=%s", resSP.Status, resSP.SummaryPlain)
	}
}

func TestChecks_NetworkAndProbe(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tmp, "proc", "net"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "net", "route"), []byte("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n"), 0644)
	_ = os.WriteFile(filepath.Join(tmp, "proc", "net", "tcp"), []byte(" sl local_address rem_address st\n  0: 00000000:0050 00000000:0000 0A \n"), 0644)
	_ = os.MkdirAll(filepath.Join(tmp, "etc"), 0755)
	_ = os.WriteFile(filepath.Join(tmp, "etc", "resolv.conf"), []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"), 0644)

	rfs := fs.NewRootedFS(tmp)

	// Routes
	ir := &checks.InterfacesRoutesCheck{}
	resIR, _ := ir.Run(ctx, rfs, nil)
	if resIR.Status != contract.StatusOK {
		t.Errorf("interfaces-routes positive test failed: status=%s", resIR.Status)
	}

	// Listening Ports
	lp := &checks.ListeningPortsCheck{}
	resLP, _ := lp.Run(ctx, rfs, nil)
	if resLP.Status != contract.StatusOK || !strings.Contains(resLP.SummaryPlain, "80") {
		t.Errorf("listening-ports test failed: status=%s, summary=%s", resLP.Status, resLP.SummaryPlain)
	}

	// DNS
	dns := &checks.DNSConfigCheck{}
	resDNS, _ := dns.Run(ctx, rfs, nil)
	if resDNS.Status != contract.StatusOK || !strings.Contains(resDNS.SummaryPlain, "1.1.1.1") {
		t.Errorf("dns-config test failed: status=%s", resDNS.Status)
	}

	// Connectivity Probe Opt-In
	cp := &checks.ConnectivityProbeCheck{}
	resCPNA, _ := cp.Run(ctx, rfs, nil)
	if resCPNA.Status != contract.StatusNotApplicable {
		t.Errorf("connectivity probe NA test failed: status=%s", resCPNA.Status)
	}

	// Probe invalid parameter injection test
	_, errInject := cp.Run(ctx, rfs, map[string]string{"target": "127.0.0.1:80; rm -rf /"})
	if errInject != checks.ErrInvalidParam {
		t.Errorf("expected injection rejection, got %v", errInject)
	}
}

func TestChecks_PathTraversalAndInjectionSanitization(t *testing.T) {
	unsafeParams := []string{
		"../../etc/shadow",
		"/var/log/syslog; cat /etc/passwd",
		"target.host:80 & ls",
		"unit`id`",
		"eval$(id)",
		"foo|bar",
	}

	for _, p := range unsafeParams {
		if checks.ValidateSafeParam(p) {
			t.Errorf("ValidateSafeParam unexpectedly accepted malicious string: %q", p)
		}
	}

	safeParams := []string{
		"/var/log/syslog",
		"127.0.0.1:8080",
		"my-service.service",
		"example.com:443",
	}

	for _, p := range safeParams {
		if !checks.ValidateSafeParam(p) {
			t.Errorf("ValidateSafeParam rejected safe string: %q", p)
		}
	}
}

func TestChecks_SymptomPicker(t *testing.T) {
	syms := checks.AvailableSymptoms()
	if len(syms) != 5 {
		t.Fatalf("expected 5 symptoms, got %d", len(syms))
	}

	for _, s := range syms {
		if len(s.CheckIDs) == 0 || len(s.Reasons) == 0 {
			t.Errorf("symptom %s has empty check IDs or reasons", s.ID)
		}
		if len(s.CheckIDs) != len(s.Reasons) {
			t.Errorf("symptom %s has mismatch between check IDs (%d) and reasons (%d)", s.ID, len(s.CheckIDs), len(s.Reasons))
		}
	}

	// Lookup
	sym, err := checks.FindSymptom("disk-full")
	if err != nil || sym.ID != "disk-full" {
		t.Fatalf("failed finding disk-full symptom: %v", err)
	}

	symSlow, err := checks.FindSymptom("slow")
	if err != nil || symSlow.ID != "slow" {
		t.Fatalf("failed finding slow symptom: %v", err)
	}
}

func TestChecks_ActivityLog(t *testing.T) {
	tmpDir := t.TempDir()
	log := checks.NewActivityLog(tmpDir)

	entry := checks.ActivityEntry{
		CheckID:     "disk-inodes",
		Role:        "infrastructure",
		TokenHolder: "local-cli",
		Status:      contract.StatusOK,
		Summary:     "All disks healthy",
	}

	if err := log.Log(entry); err != nil {
		t.Fatalf("failed to log activity entry: %v", err)
	}

	entries, err := log.Entries(10)
	if err != nil {
		t.Fatalf("failed to read entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].CheckID != "disk-inodes" || entries[0].TokenHolder != "local-cli" {
		t.Errorf("unexpected entry content: %+v", entries[0])
	}
}

type allDeniedFS struct {
	fs.FS
}

func (a *allDeniedFS) ReadFile(name string) ([]byte, error) { return nil, os.ErrPermission }
func (a *allDeniedFS) ReadDir(name string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
func (a *allDeniedFS) Stat(name string) (os.FileInfo, error) { return nil, os.ErrPermission }
func (a *allDeniedFS) Open(name string) (*os.File, error) { return nil, os.ErrPermission }
func (a *allDeniedFS) Readlink(name string) (string, error) { return "", os.ErrPermission }

func TestChecks_HonestyHarness_EmptyAndDenied(t *testing.T) {
	ctx := context.Background()
	reg := checks.NewRegistry()
	all := reg.All()

	// Case A: Empty Rooted FS
	emptyRoot := t.TempDir()
	emptyFS := fs.NewRootedFS(emptyRoot)

	t.Log("=== HONESTY HARNESS: EMPTY ROOTED FS ===")
	for _, c := range all {
		res, _ := c.Run(ctx, emptyFS, nil)
		if res.Status == contract.StatusOK {
			t.Errorf("HONESTY VIOLATION: check %q returned OK on empty filesystem! summary: %s", c.ID(), res.SummaryPlain)
		} else {
			t.Logf("  PASS empty-fs: %-22s -> [%s] %s", c.ID(), res.Status, res.SummaryPlain)
		}
	}

	// Case B: FS where every file is unreadable (os.ErrPermission)
	deniedFS := &allDeniedFS{emptyFS}

	t.Log("=== HONESTY HARNESS: PERMISSION DENIED FS ===")
	for _, c := range all {
		res, _ := c.Run(ctx, deniedFS, nil)
		if res.Status == contract.StatusOK {
			t.Errorf("HONESTY VIOLATION: check %q returned OK on permission-denied filesystem! summary: %s", c.ID(), res.SummaryPlain)
		} else {
			t.Logf("  PASS denied-fs: %-22s -> [%s] %s", c.ID(), res.Status, res.SummaryPlain)
		}
	}
}

