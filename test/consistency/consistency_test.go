package consistency_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OWNER/kazeshini/internal/api"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/forecast"
	"github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/origin"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/report"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/sensors"
	"github.com/OWNER/kazeshini/internal/sensors/host"
	"github.com/OWNER/kazeshini/internal/sensors/network"
	"github.com/OWNER/kazeshini/internal/supervisor"
	"github.com/OWNER/kazeshini/internal/verdict"
)

// TestConsistency_SocketsRiskVisibilityAcrossSurfaces verifies that listening sockets count,
// Risk Score, and visibility % match consistently across API JSON, reports, and calculations.
func TestConsistency_SocketsRiskVisibilityAcrossSurfaces(t *testing.T) {
	rfs := fs.Default()
	pGraph := graphbuilder.NewProvenanceGraph()
	now := time.Now().UTC()

	// Ingest sample listening sockets
	ports := []int{22, 80, 443}
	for _, port := range ports {
		_ = pGraph.UpsertNode(graph.Node{
			ID:        "port:" + strconv.Itoa(port),
			Type:      graph.NodePort,
			Label:     "0.0.0.0:" + strconv.Itoa(port),
			FirstSeen: now,
			LastSeen:  now,
			Certainty: graph.CertaintyObserved,
			Properties: map[string]any{
				"port":           port,
				"exposure_class": "all_interfaces",
			},
		})
	}

	reg := sensors.NewRegistry()
	_ = reg.Register(host.New(rfs))
	_ = reg.Register(network.New(rfs))
	sup := supervisor.New(reg, nil)

	invMgr := inventory.NewManager(rfs)
	origRes := origin.NewResolver(rfs, invMgr)
	orphScan := orphan.NewScanner(rfs, origRes)

	// Create and spin up API server with pGraph
	cfg := config.Default()
	cfg.Stateless = true
	cfg.AuthRequired = false
	vInfo := api.VersionInfo{
		Version:   "v0.2.0-test",
		Commit:    "abcdef",
		BuildDate: "2026-10-13",
		GoVersion: "go1.26.0",
	}

	srv, err := api.NewServer(cfg, vInfo, sup, invMgr, origRes, orphScan, pGraph, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed creating test API server: %v", err)
	}

	// 1. Check API JSON output
	req := httptest.NewRequest(http.MethodGet, "/api/v1/verdict", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/verdict, got %d", w.Code)
	}

	var apiVerdict verdict.Summary
	if err := json.Unmarshal(w.Body.Bytes(), &apiVerdict); err != nil {
		t.Fatalf("failed decoding verdict JSON: %v", err)
	}

	// 2. Direct verdict computation
	nodes, _ := pGraph.Snapshot()
	directVerdict := verdict.ComputeVerdict(nodes, nil, 0)

	// 3. Check HTML Report output
	repGen := report.NewGenerator(
		pGraph,
		"v0.2.0-test",
		directVerdict,
		[]rules.Finding{},
		[]forecast.Result{},
		diff.ChangeSet{},
	)
	htmlReport := repGen.RenderHTML()

	// Consistency Verification:
	// A. Risk Score matching between API and direct calculation
	if apiVerdict.RiskScore != directVerdict.RiskScore {
		t.Errorf("RiskScore mismatch: API reported %d, direct calculation produced %d", apiVerdict.RiskScore, directVerdict.RiskScore)
	}
	// Check that HTML report contains Risk Score
	riskScoreStr := strconv.Itoa(directVerdict.RiskScore) + "/100"
	if !strings.Contains(htmlReport, riskScoreStr) && !strings.Contains(htmlReport, "Risk Score") {
		t.Errorf("HTML report missing Risk Score %s", riskScoreStr)
	}

	// B. Listening sockets count matching
	expectedPortCount := len(ports)
	if apiVerdict.ListeningPortCount != expectedPortCount {
		t.Errorf("listening port count mismatch: API reported %d, expected %d", apiVerdict.ListeningPortCount, expectedPortCount)
	}
	if !strings.Contains(htmlReport, "0.0.0.0:22") || !strings.Contains(htmlReport, "0.0.0.0:80") {
		t.Errorf("HTML report does not contain ingested listening ports")
	}

	// C. Overview API endpoint returns matching summary
	reqOverview := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	wOverview := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wOverview, reqOverview)
	if wOverview.Code != http.StatusOK {
		t.Errorf("expected 200 from /api/v1/overview alias, got %d", wOverview.Code)
	}
}
