// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/fs"
	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------
// 1. Docker & Docker Swarm Adapter
// -----------------------------------------------------------------------------

type DockerSwarmInfo struct {
	Active        bool     `json:"active"`
	NodeID        string   `json:"node_id,omitempty"`
	NodeAddr      string   `json:"node_addr,omitempty"`
	LocalNodeRole string   `json:"role,omitempty"` // manager, worker
	ClusterID     string   `json:"cluster_id,omitempty"`
	Managers      int      `json:"managers,omitempty"`
	Nodes         int      `json:"nodes,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type DockerAdapter struct {
	fs fs.FS
}

func NewDockerAdapter(fs fs.FS) *DockerAdapter {
	return &DockerAdapter{fs: fs}
}

func (a *DockerAdapter) Inspect(ctx context.Context) DockerSwarmInfo {
	sockPath := a.fs.Path("/var/run/docker.sock")
	if fi, err := a.fs.Stat("/var/run/docker.sock"); err != nil || (fi.Mode()&0111 == 0 && fi.Mode().Type() == 0) {
		return DockerSwarmInfo{Active: false, Error: "docker.sock not accessible"}
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 2 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/info", nil)
	if err != nil {
		return DockerSwarmInfo{Active: false, Error: err.Error()}
	}

	resp, err := client.Do(req)
	if err != nil {
		return DockerSwarmInfo{Active: false, Error: fmt.Sprintf("cannot query docker daemon: %v", err)}
	}
	defer resp.Body.Close()

	var payload struct {
		Swarm struct {
			NodeID       string `json:"NodeID"`
			NodeAddr     string `json:"NodeAddr"`
			LocalNodeState string `json:"LocalNodeState"` // inactive, active
			ControlAvailable bool `json:"ControlAvailable"`
			Cluster struct {
				ID string `json:"ID"`
			} `json:"Cluster"`
			Managers int `json:"Managers"`
			Nodes    int `json:"Nodes"`
		} `json:"Swarm"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return DockerSwarmInfo{Active: false, Error: err.Error()}
	}

	isActive := strings.EqualFold(payload.Swarm.LocalNodeState, "active")
	role := "worker"
	if payload.Swarm.ControlAvailable {
		role = "manager"
	}

	return DockerSwarmInfo{
		Active:        isActive,
		NodeID:        payload.Swarm.NodeID,
		NodeAddr:      payload.Swarm.NodeAddr,
		LocalNodeRole: role,
		ClusterID:     payload.Swarm.Cluster.ID,
		Managers:      payload.Swarm.Managers,
		Nodes:         payload.Swarm.Nodes,
	}
}

// -----------------------------------------------------------------------------
// 2. Kubernetes Node View Adapter
// -----------------------------------------------------------------------------

type K8sNodeView struct {
	Present        bool         `json:"present"`
	KubeletActive  bool         `json:"kubelet_active"`
	StaticPods     []string     `json:"static_pods"`
	CertExpirations []CertExpiry `json:"cert_expirations"`
	Error          string       `json:"error,omitempty"`
}

type CertExpiry struct {
	Path       string    `json:"path"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	IsExpired  bool      `json:"is_expired"`
}

type K8sNodeAdapter struct {
	fs fs.FS
}

func NewK8sNodeAdapter(fs fs.FS) *K8sNodeAdapter {
	return &K8sNodeAdapter{fs: fs}
}

func (a *K8sNodeAdapter) Inspect(ctx context.Context) K8sNodeView {
	view := K8sNodeView{}

	// 1. Static pod manifests in /etc/kubernetes/manifests
	manifestDir := "/etc/kubernetes/manifests"
	if entries, err := a.fs.ReadDir(manifestDir); err == nil {
		view.Present = true
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				view.StaticPods = append(view.StaticPods, e.Name())
			}
		}
	} else if os.IsPermission(err) {
		view.Error = "permission denied reading /etc/kubernetes/manifests"
	}

	// 2. Read local TLS cert expiry dates from /etc/kubernetes/pki
	certPaths := []string{
		"/etc/kubernetes/pki/apiserver.crt",
		"/etc/kubernetes/pki/apiserver-kubelet-client.crt",
		"/etc/kubernetes/pki/front-proxy-client.crt",
		"/etc/kubernetes/pki/ca.crt",
	}

	for _, cp := range certPaths {
		data, err := a.fs.ReadFile(cp)
		if err != nil {
			continue
		}
		view.Present = true
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		now := time.Now().UTC()
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		view.CertExpirations = append(view.CertExpirations, CertExpiry{
			Path:      cp,
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			NotAfter:  cert.NotAfter,
			DaysLeft:  daysLeft,
			IsExpired: now.After(cert.NotAfter),
		})
	}

	return view
}

// -----------------------------------------------------------------------------
// 3. CI/CD Runner Adapters (Jenkins, GitLab Runner, GitHub Actions Runner)
// -----------------------------------------------------------------------------

type RunnerActivity struct {
	RunnerType   string    `json:"runner_type"`
	Version      string    `json:"version,omitempty"`
	ConfigPath   string    `json:"config_path,omitempty"`
	LastActivity time.Time `json:"last_activity,omitempty"`
	LastMessage  string    `json:"last_message,omitempty"`
	Status       string    `json:"status"` // "active", "idle", "unknown", "permission_denied"
	Error        string    `json:"error,omitempty"`
}

type CIRunnerAdapter struct {
	fs fs.FS
}

func NewCIRunnerAdapter(fs fs.FS) *CIRunnerAdapter {
	return &CIRunnerAdapter{fs: fs}
}

func (a *CIRunnerAdapter) InspectGitHubRunner(ctx context.Context) RunnerActivity {
	// GitHub runner stores metadata in .runner or /etc/actions-runner/.runner
	paths := []string{"/etc/actions-runner/.runner", "/var/lib/actions-runner/.runner"}
	for _, p := range paths {
		bytes, err := a.fs.ReadFile(p)
		if err == nil {
			var meta struct {
				AgentName string `json:"agentName"`
				PoolID    int    `json:"poolId"`
				ServerURL string `json:"serverUrl"`
			}
			_ = json.Unmarshal(bytes, &meta)
			return RunnerActivity{
				RunnerType:   "github-actions-runner",
				ConfigPath:   p,
				Status:       "configured",
				LastMessage:  fmt.Sprintf("Agent name: %s", meta.AgentName),
			}
		} else if os.IsPermission(err) {
			return RunnerActivity{
				RunnerType: "github-actions-runner",
				Status:     "permission_denied",
				Error:      "cannot read runner configuration: permission denied",
			}
		}
	}
	return RunnerActivity{RunnerType: "github-actions-runner", Status: "not_configured"}
}

func (a *CIRunnerAdapter) InspectGitLabRunner(ctx context.Context) RunnerActivity {
	cfgPath := "/etc/gitlab-runner/config.toml"
	data, err := a.fs.ReadFile(cfgPath)
	if err != nil {
		if os.IsPermission(err) {
			return RunnerActivity{
				RunnerType: "gitlab-runner",
				Status:     "permission_denied",
				Error:      "cannot read /etc/gitlab-runner/config.toml: permission denied",
			}
		}
		return RunnerActivity{RunnerType: "gitlab-runner", Status: "not_configured"}
	}

	lines := strings.Split(string(data), "\n")
	conc := "unknown"
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "concurrent =") {
			conc = strings.TrimSpace(l)
			break
		}
	}

	return RunnerActivity{
		RunnerType:  "gitlab-runner",
		ConfigPath:  cfgPath,
		Status:      "configured",
		LastMessage: fmt.Sprintf("Configuration active (%s)", conc),
	}
}

// -----------------------------------------------------------------------------
// 4. Config Management Adapters (Puppet, Chef, Ansible-Pull)
// -----------------------------------------------------------------------------

type ConfigMgmtRun struct {
	Tool        string    `json:"tool"`
	LastRunTime time.Time `json:"last_run_time"`
	Result      string    `json:"result"` // "success", "failed", "unknown"
	Summary     string    `json:"summary"`
	Error       string    `json:"error,omitempty"`
}

type ConfigMgmtAdapter struct {
	fs fs.FS
}

func NewConfigMgmtAdapter(fs fs.FS) *ConfigMgmtAdapter {
	return &ConfigMgmtAdapter{fs: fs}
}

func (a *ConfigMgmtAdapter) InspectPuppet(ctx context.Context) ConfigMgmtRun {
	summaryPath := "/opt/puppetlabs/puppet/cache/state/last_run_summary.yaml"
	data, err := a.fs.ReadFile(summaryPath)
	if err != nil {
		if os.IsPermission(err) {
			return ConfigMgmtRun{Tool: "puppet", Result: "unknown", Error: "permission denied reading Puppet summary"}
		}
		return ConfigMgmtRun{Tool: "puppet", Result: "not_configured"}
	}

	var summary struct {
		Time struct {
			LastRun int64 `yaml:"last_run"`
		} `yaml:"time"`
		Events struct {
			Failure int `yaml:"failure"`
			Success int `yaml:"success"`
		} `yaml:"events"`
	}

	if err := yaml.Unmarshal(data, &summary); err != nil {
		return ConfigMgmtRun{Tool: "puppet", Result: "unknown", Error: err.Error()}
	}

	lastTime := time.Unix(summary.Time.LastRun, 0).UTC()
	result := "success"
	if summary.Events.Failure > 0 {
		result = "failed"
	}

	return ConfigMgmtRun{
		Tool:        "puppet",
		LastRunTime: lastTime,
		Result:      result,
		Summary:     fmt.Sprintf("Last run %s (failures: %d)", lastTime.Format(time.RFC3339), summary.Events.Failure),
	}
}

func (a *ConfigMgmtAdapter) InspectChef(ctx context.Context) ConfigMgmtRun {
	reportPath := "/var/chef/cache/reports/last-run.json"
	data, err := a.fs.ReadFile(reportPath)
	if err != nil {
		if os.IsPermission(err) {
			return ConfigMgmtRun{Tool: "chef", Result: "unknown", Error: "permission denied reading Chef report"}
		}
		return ConfigMgmtRun{Tool: "chef", Result: "not_configured"}
	}

	var report struct {
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
		Success   bool   `json:"success"`
		TotalRes  int    `json:"total_resources"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return ConfigMgmtRun{Tool: "chef", Result: "unknown", Error: err.Error()}
	}

	res := "success"
	if !report.Success {
		res = "failed"
	}
	t, _ := time.Parse(time.RFC3339, report.EndTime)

	return ConfigMgmtRun{
		Tool:        "chef",
		LastRunTime: t,
		Result:      res,
		Summary:     fmt.Sprintf("Chef run %s: success=%v", report.EndTime, report.Success),
	}
}
