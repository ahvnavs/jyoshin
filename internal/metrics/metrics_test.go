// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package metrics_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/metrics"
	"github.com/OWNER/kazeshini/internal/verdict"
)

func TestMetrics_PrometheusFormat(t *testing.T) {
	snap := metrics.Snapshot{
		HostID: "test-server-01",
		Verdict: verdict.Summary{
			StateLabel: "CALM",
			ChaosIndex: 12,
		},
		Coverage: coverage.Report{
			OverallCoverage: 88.5,
			IsAdequate:      true,
		},
		DriftSummary: drift.Summary{
			TotalDrift: 2,
			Missing:    1,
			Extra:      1,
		},
		ActivePlans: 1,
		Timestamp:   time.Now().UTC(),
	}

	exporter := metrics.NewPrometheusExporter()
	out := exporter.Format(snap)

	expectedMetrics := []string{
		`kazeshini_chaos_index{host="test-server-01"} 12`,
		`kazeshini_verdict_status{host="test-server-01",status="calm"} 1`,
		`kazeshini_verdict_status{host="test-server-01",status="critical"} 0`,
		`kazeshini_coverage_ratio{host="test-server-01"} 0.8850`,
		`kazeshini_coverage_adequate{host="test-server-01"} 1`,
		`kazeshini_drift_total{host="test-server-01"} 2`,
		`kazeshini_plans_active{host="test-server-01"} 1`,
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(out, m) {
			t.Errorf("missing expected metric in Prometheus output: %s", m)
		}
	}

	t.Logf("[✓] Prometheus metrics format verified (%d bytes generated)", len(out))
}

func TestMetrics_OTLPExport(t *testing.T) {
	var mu sync.Mutex
	var receivedPayload metrics.OTLPPayload

	// Local fake OTLP collector
	fakeCollector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		_ = json.Unmarshal(body, &receivedPayload)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeCollector.Close()

	exporter := metrics.NewOTLPExporter(fakeCollector.URL)
	snap := metrics.Snapshot{
		HostID: "node-xyz",
		Verdict: verdict.Summary{
			StateLabel: "CALM",
			ChaosIndex: 5,
		},
		Coverage: coverage.Report{
			OverallCoverage: 95.0,
			IsAdequate:      true,
		},
		DriftSummary: drift.Summary{
			TotalDrift: 0,
		},
		Timestamp: time.Now().UTC(),
	}

	ctx := context.Background()
	if err := exporter.Export(ctx, snap); err != nil {
		t.Fatalf("failed exporting OTLP metrics: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedPayload.ResourceMetrics) == 0 {
		t.Fatalf("fake OTLP collector received no metrics")
	}

	metricsList := receivedPayload.ResourceMetrics[0].ScopeMetrics[0].Metrics
	foundChaos := false
	for _, m := range metricsList {
		if m.Name == "kazeshini.chaos_index" {
			foundChaos = true
		}
	}

	if !foundChaos {
		t.Errorf("expected kazeshini.chaos_index in exported OTLP metrics")
	}

	t.Logf("[✓] OTLP export verified against local fake collector endpoint (%d metrics transmitted)", len(metricsList))
}

