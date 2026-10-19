// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

// Package metrics implements Prometheus-format text generation and optional OTLP JSON export
// for Kazeshini health, verdict, coverage, drift, findings, and checks.
package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// Snapshot captures the observation values to export as metrics.
type Snapshot struct {
	HostID       string
	Verdict      verdict.Summary
	Coverage     coverage.Report
	Findings     []rules.Finding
	DriftSummary drift.Summary
	CheckResults []contract.CheckResult
	ActivePlans  int
	Timestamp    time.Time
}

// PrometheusExporter formats Snapshot into standard Prometheus text format exposition.
type PrometheusExporter struct{}

func NewPrometheusExporter() *PrometheusExporter {
	return &PrometheusExporter{}
}

func (e *PrometheusExporter) Format(snap Snapshot) string {
	var buf strings.Builder

	// Verdict & Chaos Score
	buf.WriteString("# HELP kazeshini_chaos_index Numerical chaos index (0-100)\n")
	buf.WriteString("# TYPE kazeshini_chaos_index gauge\n")
	fmt.Fprintf(&buf, "kazeshini_chaos_index{host=%q} %d\n\n", snap.HostID, snap.Verdict.ChaosIndex)

	buf.WriteString("# HELP kazeshini_verdict_status Host status (1 if matching verdict status)\n")
	buf.WriteString("# TYPE kazeshini_verdict_status gauge\n")
	statuses := []string{"calm", "messy", "critical", "unknown"}
	for _, st := range statuses {
		val := 0
		if strings.EqualFold(snap.Verdict.StateLabel, st) {
			val = 1
		}
		fmt.Fprintf(&buf, "kazeshini_verdict_status{host=%q,status=%q} %d\n", snap.HostID, st, val)
	}
	buf.WriteString("\n")

	// Coverage
	buf.WriteString("# HELP kazeshini_coverage_ratio Overall sensor visibility coverage ratio (0.0 - 1.0)\n")
	buf.WriteString("# TYPE kazeshini_coverage_ratio gauge\n")
	fmt.Fprintf(&buf, "kazeshini_coverage_ratio{host=%q} %.4f\n\n", snap.HostID, snap.Coverage.OverallCoverage/100.0)

	buf.WriteString("# HELP kazeshini_coverage_adequate Coverage adequacy boolean (1 if adequate)\n")
	buf.WriteString("# TYPE kazeshini_coverage_adequate gauge\n")
	adeq := 0
	if snap.Coverage.IsAdequate {
		adeq = 1
	}
	fmt.Fprintf(&buf, "kazeshini_coverage_adequate{host=%q} %d\n\n", snap.HostID, adeq)

	// Findings by severity
	buf.WriteString("# HELP kazeshini_findings_total Total findings grouped by severity\n")
	buf.WriteString("# TYPE kazeshini_findings_total gauge\n")
	sevCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range snap.Findings {
		s := strings.ToLower(string(f.Severity))
		sevCounts[s]++
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		fmt.Fprintf(&buf, "kazeshini_findings_total{host=%q,severity=%q} %d\n", snap.HostID, sev, sevCounts[sev])
	}
	buf.WriteString("\n")

	// Drift items
	buf.WriteString("# HELP kazeshini_drift_total Total detected drift items\n")
	buf.WriteString("# TYPE kazeshini_drift_total gauge\n")
	fmt.Fprintf(&buf, "kazeshini_drift_total{host=%q} %d\n", snap.HostID, snap.DriftSummary.TotalDrift)
	fmt.Fprintf(&buf, "kazeshini_drift_by_kind{host=%q,kind=\"missing\"} %d\n", snap.HostID, snap.DriftSummary.Missing)
	fmt.Fprintf(&buf, "kazeshini_drift_by_kind{host=%q,kind=\"extra\"} %d\n", snap.HostID, snap.DriftSummary.Extra)
	fmt.Fprintf(&buf, "kazeshini_drift_by_kind{host=%q,kind=\"mismatch\"} %d\n", snap.HostID, snap.DriftSummary.Mismatch)
	fmt.Fprintf(&buf, "kazeshini_drift_by_kind{host=%q,kind=\"wrong_state\"} %d\n", snap.HostID, snap.DriftSummary.WrongState)
	fmt.Fprintf(&buf, "kazeshini_drift_by_kind{host=%q,kind=\"ports\"} %d\n", snap.HostID, snap.DriftSummary.Ports)
	buf.WriteString("\n")

	// Active Plans
	buf.WriteString("# HELP kazeshini_plans_active Active proposed remediation plans\n")
	buf.WriteString("# TYPE kazeshini_plans_active gauge\n")
	fmt.Fprintf(&buf, "kazeshini_plans_active{host=%q} %d\n\n", snap.HostID, snap.ActivePlans)

	// Check Results
	if len(snap.CheckResults) > 0 {
		buf.WriteString("# HELP kazeshini_check_status Check execution outcome (0=ok, 1=warn, 2=crit, 3=unknown)\n")
		buf.WriteString("# TYPE kazeshini_check_status gauge\n")
		for _, c := range snap.CheckResults {
			code := 3
			switch c.Status {
			case contract.StatusOK:
				code = 0
			case contract.StatusWarn:
				code = 1
			case contract.StatusCrit:
				code = 2
			case contract.StatusUnknown:
				code = 3
			}
			fmt.Fprintf(&buf, "kazeshini_check_status{host=%q,check_id=%q,role=%q} %d\n", snap.HostID, c.ID, c.Role, code)
		}
		buf.WriteString("\n")
	}

	return buf.String()
}

// OTLPPayload represents OpenTelemetry metrics payload in standard OTLP/HTTP JSON format.
type OTLPPayload struct {
	ResourceMetrics []ResourceMetric `json:"resourceMetrics"`
}

type ResourceMetric struct {
	Resource     OTLPResource  `json:"resource"`
	ScopeMetrics []ScopeMetric `json:"scopeMetrics"`
}

type OTLPResource struct {
	Attributes []OTLPAttribute `json:"attributes"`
}

type OTLPAttribute struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

type ScopeMetric struct {
	Scope   map[string]string `json:"scope"`
	Metrics []OTLPMetric      `json:"metrics"`
}

type OTLPMetric struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Unit        string    `json:"unit"`
	Gauge       OTLPGauge `json:"gauge"`
}

type OTLPGauge struct {
	DataPoints []OTLPDataPoint `json:"dataPoints"`
}

type OTLPDataPoint struct {
	AsDouble     float64         `json:"asDouble,omitempty"`
	AsInt        int64           `json:"asInt,omitempty"`
	TimeUnixNano int64           `json:"timeUnixNano"`
	Attributes   []OTLPAttribute `json:"attributes,omitempty"`
}

// OTLPExporter exports Snapshot to an OTLP/HTTP JSON collector endpoint.
type OTLPExporter struct {
	Endpoint string
	Client   *http.Client
}

func NewOTLPExporter(endpoint string) *OTLPExporter {
	return &OTLPExporter{
		Endpoint: endpoint,
		Client:   &http.Client{Timeout: 3 * time.Second},
	}
}

func (e *OTLPExporter) BuildPayload(snap Snapshot) OTLPPayload {
	nowNano := snap.Timestamp.UnixNano()
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}

	return OTLPPayload{
		ResourceMetrics: []ResourceMetric{
			{
				Resource: OTLPResource{
					Attributes: []OTLPAttribute{
						{Key: "service.name", Value: map[string]any{"stringValue": "kazeshini"}},
						{Key: "host.id", Value: map[string]any{"stringValue": snap.HostID}},
					},
				},
				ScopeMetrics: []ScopeMetric{
					{
						Scope: map[string]string{"name": "kazeshini-core", "version": "v0.1.0"},
						Metrics: []OTLPMetric{
							{
								Name:        "kazeshini.chaos_index",
								Description: "Numerical chaos index (0-100)",
								Unit:        "1",
								Gauge: OTLPGauge{
									DataPoints: []OTLPDataPoint{
										{AsInt: int64(snap.Verdict.ChaosIndex), TimeUnixNano: nowNano},
									},
								},
							},
							{
								Name:        "kazeshini.coverage_ratio",
								Description: "Overall sensor visibility coverage ratio",
								Unit:        "1",
								Gauge: OTLPGauge{
									DataPoints: []OTLPDataPoint{
										{AsDouble: snap.Coverage.OverallCoverage / 100.0, TimeUnixNano: nowNano},
									},
								},
							},
							{
								Name:        "kazeshini.drift_total",
								Description: "Total detected drift items",
								Unit:        "1",
								Gauge: OTLPGauge{
									DataPoints: []OTLPDataPoint{
										{AsInt: int64(snap.DriftSummary.TotalDrift), TimeUnixNano: nowNano},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (e *OTLPExporter) Export(ctx context.Context, snap Snapshot) error {
	payload := e.BuildPayload(snap)
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal OTLP payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.Client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp post failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp collector returned non-2xx status: %d", resp.StatusCode)
	}
	return nil
}
