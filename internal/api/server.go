// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/auth"
	"github.com/OWNER/kazeshini/internal/blastradius"
	"github.com/OWNER/kazeshini/internal/briefing"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/decisions"
	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/forecast"
	internalfs "github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/origin"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/report"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/store"
	"github.com/OWNER/kazeshini/internal/supervisor"
	"github.com/OWNER/kazeshini/internal/verdict"
	"github.com/OWNER/kazeshini/internal/watchers"
	"github.com/OWNER/kazeshini/web"
)

// VersionInfo captures version metadata injected at build time.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
}

// Server encapsulates the HTTP server instance, supervisor, and router.
type Server struct {
	cfg             config.Config
	server          *http.Server
	version         VersionInfo
	supervisor      *supervisor.Supervisor
	inventory       *inventory.Manager
	resolver        *origin.Resolver
	orphanScan      *orphan.Scanner
	pGraph          *graphbuilder.ProvenanceGraph
	store           *store.BoltStore
	ruleEngine      *rules.Engine
	auth            *auth.Manager
	diffEngine      *diff.Engine
	forecaster      *forecast.Forecaster
	watchers        *watchers.Manager
	blastAnalyzer   *blastradius.Analyzer
	decisionsEngine *decisions.Engine
	samplesMu       sync.RWMutex
	samples         map[string][]forecast.Sample
	logger          *slog.Logger
}

// NewServer constructs a new HTTP API Server.
func NewServer(
	cfg config.Config,
	version VersionInfo,
	sup *supervisor.Supervisor,
	inv *inventory.Manager,
	res *origin.Resolver,
	orph *orphan.Scanner,
	pGraph *graphbuilder.ProvenanceGraph,
	st *store.BoltStore,
	reng *rules.Engine,
	logger *slog.Logger,
) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid server configuration: %w", err)
	}

	if logger == nil {
		logger = slog.Default()
	}

	authMgr, err := auth.NewManager(cfg.DataDir)
	if err != nil {
		logger.Warn("could not initialize persistent auth token; continuing in-memory", "error", err)
	}

	s := &Server{
		cfg:             cfg,
		version:         version,
		supervisor:      sup,
		inventory:       inv,
		resolver:        res,
		orphanScan:      orph,
		pGraph:          pGraph,
		store:           st,
		ruleEngine:      reng,
		auth:            authMgr,
		diffEngine:      diff.NewEngine(),
		forecaster:      forecast.NewForecaster(5),
		watchers:        watchers.NewManager(30 * time.Second),
		blastAnalyzer:   blastradius.NewAnalyzer(pGraph),
		decisionsEngine: decisions.NewEngine(pGraph),
		samples:         make(map[string][]forecast.Sample),
		logger:          logger,
	}

	// Pre-load persisted historical samples from store into memory cache
	if st != nil {
		targets := []string{"/", "system_ram", "/_inodes", "system_fds", "swap", "load1"}
		for _, tgt := range targets {
			if smps, err := st.ListSamples(context.Background(), tgt, 500); err == nil && len(smps) > 0 {
				s.samples[tgt] = smps
			}
		}
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.server = &http.Server{
		Addr:         cfg.Address(),
		Handler:      s.loggingMiddleware(s.authMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // SSE streaming requires unbounded write timeout
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Baseline routes
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)

	// Sensor observation & health routes
	mux.HandleFunc("GET /api/v1/sensors", s.handleSensors)
	mux.HandleFunc("GET /api/v1/observations/{sensor}", s.handleObservation)
	mux.HandleFunc("GET /api/v1/self", s.handleSelf)

	// Inventory & Origin routes
	mux.HandleFunc("GET /api/v1/inventory", s.handleInventory)
	mux.HandleFunc("GET /api/v1/origins", s.handleOrigins)
	mux.HandleFunc("GET /api/v1/runtimes", s.handleRuntimes)
	mux.HandleFunc("POST /api/v1/orphan/scan", s.handleOrphanScan)

	// Graph & Snapshot routes
	mux.HandleFunc("GET /api/v1/graph", s.handleGraph)
	mux.HandleFunc("GET /api/v1/graph/node/{id}", s.handleGraphNode)
	mux.HandleFunc("GET /api/v1/graph/why/{id}", s.handleGraphWhy)
	mux.HandleFunc("GET /api/v1/graph/dependents/{id}", s.handleGraphDependents)
	mux.HandleFunc("GET /api/v1/snapshots", s.handleSnapshots)

	// Findings routes
	mux.HandleFunc("GET /api/v1/findings", s.handleFindings)

	// Phase 6: Verdict & Real-Time SSE Stream
	mux.HandleFunc("GET /api/v1/verdict", s.handleVerdict)
	mux.HandleFunc("GET /api/v1/stream", s.handleStream)
	mux.HandleFunc("GET /api/v1/auth/status", s.handleAuthStatus)

	// Phase 7: Changes, Forecasts, Baselines
	mux.HandleFunc("GET /api/v1/changes", s.handleChanges)
	mux.HandleFunc("GET /api/v1/forecasts", s.handleForecasts)
	mux.HandleFunc("GET /api/v1/baselines", s.handleBaselines)

	// Phase 8: Blast Radius, Dependencies, Decommission, Migration, Report
	mux.HandleFunc("GET /api/v1/blastradius/{id}", s.handleBlastRadius)
	mux.HandleFunc("GET /api/v1/dependencies", s.handleDependencies)
	mux.HandleFunc("GET /api/v1/decommission", s.handleDecommission)
	mux.HandleFunc("GET /api/v1/migration", s.handleMigration)
	mux.HandleFunc("GET /api/v1/report", s.handleReport)

	// Phase 18: Coverage Honesty & Plain Briefing
	mux.HandleFunc("GET /api/v1/coverage", s.handleCoverage)
	mux.HandleFunc("GET /api/v1/briefing", s.handleBriefing)

	// Profiling endpoints (for external overhead inspection)
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	// Embedded web UI
	subFS, err := fs.Sub(web.Assets, ".")
	if err != nil {
		s.logger.Error("failed to create embedded sub-filesystem", "error", err)
		return
	}
	fileServer := http.FileServer(http.FS(subFS))
	mux.Handle("GET /", fileServer)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Permit health, version, auth status, and static web UI files without token
		path := r.URL.Path
		if path == "/api/v1/health" || path == "/api/v1/version" || path == "/api/v1/auth/status" || !strings.HasPrefix(path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// Enforce token authentication on API endpoints when auth is required
		if s.cfg.AuthRequired && s.auth != nil {
			authHeader := r.Header.Get("Authorization")
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader || !s.auth.Validate(token) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":  "unauthorized: valid bearer token required in Authorization header",
					"status": 401,
					"hint":   "run 'kazeshini token' to retrieve authentication token",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Debug("http request handled",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start),
		)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.version)
}

func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.supervisor == nil {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]any{})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.supervisor.GetSensorStates())
}

func (s *Server) handleObservation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	sensorName := r.PathValue("sensor")
	if sensorName == "" {
		http.Error(w, `{"error":"sensor parameter required"}`, http.StatusBadRequest)
		return
	}

	if s.supervisor == nil {
		http.Error(w, `{"error":"supervisor not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	obs, found := s.supervisor.GetObservation(sensorName)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "observation not found",
			"sensor": sensorName,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obs)
}

func (s *Server) handleSelf(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.supervisor == nil {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "no supervisor"})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.supervisor.GetSelfOverhead())
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.inventory == nil {
		http.Error(w, `{"error":"inventory manager not available"}`, http.StatusServiceUnavailable)
		return
	}

	inv, err := s.inventory.CollectInventory(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(inv)
}

func (s *Server) handleOrigins(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	targetPath := r.URL.Query().Get("path")
	if targetPath == "" {
		http.Error(w, `{"error":"missing required query parameter 'path'"}`, http.StatusBadRequest)
		return
	}

	if s.resolver == nil {
		http.Error(w, `{"error":"origin resolver not available"}`, http.StatusServiceUnavailable)
		return
	}

	orig := s.resolver.Resolve(r.Context(), targetPath)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(orig)
}

func (s *Server) handleRuntimes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.inventory == nil {
		http.Error(w, `{"error":"inventory manager not available"}`, http.StatusServiceUnavailable)
		return
	}

	inv, err := s.inventory.CollectInventory(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(inv.Runtimes)
}

func (s *Server) handleOrphanScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.orphanScan == nil {
		http.Error(w, `{"error":"orphan scanner not available"}`, http.StatusServiceUnavailable)
		return
	}

	// 5-second default off-peak on-demand budget
	res := s.orphanScan.RunScan(r.Context(), 5*time.Second, 1000)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.pGraph == nil {
		http.Error(w, `{"error":"graph not available"}`, http.StatusServiceUnavailable)
		return
	}
	nodeCount, edgeCount := s.pGraph.Summary()
	nodes, edges := s.pGraph.Snapshot()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"node_count": nodeCount,
		"edge_count": edgeCount,
		"nodes":      nodes,
		"edges":      edges,
	})
}

func (s *Server) handleGraphNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, `{"error":"id parameter required"}`, http.StatusBadRequest)
		return
	}
	if s.pGraph == nil {
		http.Error(w, `{"error":"graph not available"}`, http.StatusServiceUnavailable)
		return
	}
	node, found := s.pGraph.GetNode(id)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "node not found", "id": id})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(node)
}

func (s *Server) handleGraphWhy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, `{"error":"id parameter required"}`, http.StatusBadRequest)
		return
	}
	if s.pGraph == nil {
		http.Error(w, `{"error":"graph not available"}`, http.StatusServiceUnavailable)
		return
	}
	chain, err := s.pGraph.Why(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "id": id})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(chain)
}

func (s *Server) handleGraphDependents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, `{"error":"id parameter required"}`, http.StatusBadRequest)
		return
	}
	if s.pGraph == nil {
		http.Error(w, `{"error":"graph not available"}`, http.StatusServiceUnavailable)
		return
	}
	depNodes, depEdges, err := s.pGraph.Dependents(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "id": id})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"nodes": depNodes,
		"edges": depEdges,
	})
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.store == nil {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]any{})
		return
	}
	snaps, err := s.store.ListSnapshots(r.Context(), 50)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(snaps)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.ruleEngine == nil || s.pGraph == nil {
		http.Error(w, `{"error":"rule engine or graph not available"}`, http.StatusServiceUnavailable)
		return
	}

	nodes, edges := s.pGraph.Snapshot()
	findings, err := s.ruleEngine.Evaluate(r.Context(), nodes, edges)
	if err != nil {
		s.logger.Warn("rule evaluation error", "error", err)
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(findings)
}

func (s *Server) computeCurrentCoverage(ctx context.Context) coverage.Report {
	assessor := coverage.NewAssessor(s.supervisor, s.inventory, s.orphanScan, internalfs.Default())
	return assessor.Assess(ctx)
}

func (s *Server) computeCurrentVerdict(ctx context.Context) verdict.Summary {
	cov := s.computeCurrentCoverage(ctx)
	if s.pGraph == nil {
		return verdict.ComputeVerdictWithCoverage(nil, nil, 0, cov.IsAdequate, cov.SummaryNote)
	}
	nodes, edges := s.pGraph.Snapshot()
	var findings []rules.Finding
	if s.ruleEngine != nil {
		f, err := s.ruleEngine.Evaluate(ctx, nodes, edges)
		if err == nil {
			findings = f
		}
	}
	orphanCount := 0
	if s.orphanScan != nil {
		orphanCount = s.orphanScan.Count()
	}
	return verdict.ComputeVerdictWithCoverage(nodes, findings, orphanCount, cov.IsAdequate, cov.SummaryNote)
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	rep := s.computeCurrentCoverage(r.Context())
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rep)
}

func (s *Server) handleBriefing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	cov := s.computeCurrentCoverage(r.Context())
	var nodes []graph.Node
	var edges []graph.Edge
	if s.pGraph != nil {
		nodes, edges = s.pGraph.Snapshot()
	}
	var findings []rules.Finding
	if s.ruleEngine != nil {
		f, err := s.ruleEngine.Evaluate(r.Context(), nodes, edges)
		if err == nil {
			findings = f
		}
	}
	var orphans []orphan.ScanResult
	if s.orphanScan != nil {
		if last := s.orphanScan.LastResult(); last != nil {
			orphans = append(orphans, *last)
		}
	}

	builder := briefing.NewBuilder()
	br := builder.Build(r.Context(), nodes, findings, orphans, cov, time.Now().UTC())

	format := r.URL.Query().Get("format")
	if strings.ToLower(format) == "text" || strings.ToLower(format) == "terminal" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(br.RenderTerminal()))
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(br)
}

func (s *Server) handleVerdict(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	sum := s.computeCurrentVerdict(r.Context())
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(sum)
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	authenticated := false
	if s.auth != nil {
		authenticated = s.auth.Validate(token)
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authenticated": authenticated,
		"required":      s.auth != nil,
	})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Initial push
	v := s.computeCurrentVerdict(r.Context())
	data, _ := json.Marshal(v)
	fmt.Fprintf(w, "event: verdict\ndata: %s\n\n", data)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			current := s.computeCurrentVerdict(r.Context())
			d, err := json.Marshal(current)
			if err == nil {
				fmt.Fprintf(w, "event: verdict\ndata: %s\n\n", d)
				flusher.Flush()
			}
		}
	}
}

// AuthManager returns the underlying auth manager if initialized.
func (s *Server) AuthManager() *auth.Manager {
	return s.auth
}

// DiffEngine returns the underlying diff engine.
func (s *Server) DiffEngine() *diff.Engine {
	return s.diffEngine
}

// Forecaster returns the underlying statistical forecaster.
func (s *Server) Forecaster() *forecast.Forecaster {
	return s.forecaster
}

// Watchers returns the underlying event watcher manager.
func (s *Server) Watchers() *watchers.Manager {
	return s.watchers
}

// RecordSample records a time-series metric sample for forecasting.
func (s *Server) RecordSample(target string, value float64) {
	s.RecordSampleAt(target, value, time.Now().UTC())
}

// RecordSampleAt records a time-series metric sample with an explicit timestamp.
func (s *Server) RecordSampleAt(target string, value float64, ts time.Time) {
	s.samplesMu.Lock()
	smp := forecast.Sample{
		Timestamp: ts,
		Value:     value,
	}
	s.samples[target] = append(s.samples[target], smp)
	if len(s.samples[target]) > 500 {
		s.samples[target] = s.samples[target][len(s.samples[target])-500:]
	}
	s.samplesMu.Unlock()

	if s.store != nil {
		_ = s.store.SaveSample(context.Background(), target, smp)
	}
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.store == nil || s.diffEngine == nil {
		http.Error(w, `{"error":"store or diff engine not available"}`, http.StatusServiceUnavailable)
		return
	}

	fromID := r.URL.Query().Get("from")
	toID := r.URL.Query().Get("to")

	var (
		beforeSnap store.Snapshot
		afterSnap  store.Snapshot
	)

	// If neither specified, diff the two most recent snapshots
	if fromID == "" && toID == "" {
		snaps, err := s.store.ListSnapshots(r.Context(), 2)
		if err != nil || len(snaps) < 2 {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(diff.ChangeSet{
				Summary: "History builds over time. At least 2 snapshots are required to compute diffs.",
			})
			return
		}
		// snaps are returned newest first: snaps[0] is after, snaps[1] is before
		afterSnap = snaps[0]
		beforeSnap = snaps[1]
	} else {
		beforePtr, err := s.store.GetSnapshotByID(r.Context(), fromID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"from snapshot not found: %s"}`, fromID), http.StatusNotFound)
			return
		}
		beforeSnap = *beforePtr

		if toID == "" {
			latestPtr, err := s.store.GetLatestSnapshot(r.Context())
			if err != nil {
				http.Error(w, `{"error":"no latest snapshot available"}`, http.StatusNotFound)
				return
			}
			afterSnap = *latestPtr
		} else {
			afterPtr, err := s.store.GetSnapshotByID(r.Context(), toID)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"to snapshot not found: %s"}`, toID), http.StatusNotFound)
				return
			}
			afterSnap = *afterPtr
		}
	}

	cs := s.diffEngine.DiffSnapshots(beforeSnap, afterSnap)
	if s.watchers != nil {
		_ = s.watchers.ProcessChangeSet(r.Context(), cs)
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(cs)
}

func (s *Server) handleForecasts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.forecaster == nil {
		http.Error(w, `{"error":"forecaster not available"}`, http.StatusServiceUnavailable)
		return
	}

	s.samplesMu.RLock()
	defer s.samplesMu.RUnlock()

	var results []forecast.Result

	// Tracked static and dynamic targets
	defaultTargets := map[string]struct {
		kind     forecast.ResourceKind
		capacity float64
	}{
		"system_ram": {forecast.ResourceMemory, 100.0},
		"system_fds": {forecast.ResourceFDs, 65536.0},
		"swap":       {forecast.ResourceSwap, 100.0},
		"load1":      {forecast.ResourceLoad, 16.0},
	}

	seen := make(map[string]bool)

	// Check any disk mount targets present in recorded samples
	for target, smps := range s.samples {
		if _, isDefault := defaultTargets[target]; isDefault {
			continue
		}
		seen[target] = true
		kind := forecast.ResourceDisk
		capacity := 100.0
		if strings.HasSuffix(target, "_inodes") {
			kind = forecast.ResourceInodes
			capacity = 1000000.0
		}
		res := s.forecaster.Forecast(kind, target, capacity, smps)
		if s.watchers != nil {
			_ = s.watchers.ProcessForecast(res)
		}
		results = append(results, res)
	}

	// Always ensure standard targets are evaluated
	for target, def := range defaultTargets {
		smps := s.samples[target]
		res := s.forecaster.Forecast(def.kind, target, def.capacity, smps)
		if s.watchers != nil {
			_ = s.watchers.ProcessForecast(res)
		}
		results = append(results, res)
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) handleBaselines(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.forecaster == nil {
		http.Error(w, `{"error":"forecaster not available"}`, http.StatusServiceUnavailable)
		return
	}

	s.samplesMu.RLock()
	defer s.samplesMu.RUnlock()

	var baselines []forecast.Baseline
	targets := []struct {
		kind   forecast.ResourceKind
		target string
	}{
		{forecast.ResourceDisk, "/"},
		{forecast.ResourceMemory, "system_ram"},
		{forecast.ResourceInodes, "/_inodes"},
		{forecast.ResourceFDs, "system_fds"},
		{forecast.ResourceSwap, "swap"},
		{forecast.ResourceLoad, "load1"},
	}

	for _, t := range targets {
		samples := s.samples[t.target]
		base := s.forecaster.ComputeBaseline(t.kind, t.target, samples)
		baselines = append(baselines, base)
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(baselines)
}

func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, `{"error":"id parameter required"}`, http.StatusBadRequest)
		return
	}
	if s.blastAnalyzer == nil {
		http.Error(w, `{"error":"blast radius analyzer not available"}`, http.StatusServiceUnavailable)
		return
	}

	rep, err := s.blastAnalyzer.Analyze(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "id": id})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rep)
}

func (s *Server) handleDependencies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.decisionsEngine == nil {
		http.Error(w, `{"error":"decisions engine not available"}`, http.StatusServiceUnavailable)
		return
	}
	depMap := s.decisionsEngine.GetDependencies()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(depMap)
}

func (s *Server) handleDecommission(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.decisionsEngine == nil {
		http.Error(w, `{"error":"decisions engine not available"}`, http.StatusServiceUnavailable)
		return
	}
	rep := s.decisionsEngine.EvaluateDecommission()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rep)
}

func (s *Server) handleMigration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.decisionsEngine == nil {
		http.Error(w, `{"error":"decisions engine not available"}`, http.StatusServiceUnavailable)
		return
	}
	plan := s.decisionsEngine.PlanMigration()
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(plan)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "html"
	}

	vSum := s.computeCurrentVerdict(r.Context())
	var findings []rules.Finding
	if s.ruleEngine != nil && s.pGraph != nil {
		nodes, edges := s.pGraph.Snapshot()
		if f, err := s.ruleEngine.Evaluate(r.Context(), nodes, edges); err == nil {
			findings = f
		}
	}

	gen := report.NewGenerator(
		s.pGraph,
		s.version.Version,
		vSum,
		findings,
		nil,
		diff.ChangeSet{},
	)

	switch strings.ToLower(format) {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		data, err := gen.RenderJSON()
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	case "md", "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gen.RenderMarkdown()))
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gen.RenderHTML()))
	default:
		http.Error(w, fmt.Sprintf(`{"error":"unsupported format: %s"}`, format), http.StatusBadRequest)
	}
}

// Start begins listening and serving traffic on the configured address.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.server.Addr, err)
	}

	s.logger.Info("kazeshini api server started", "addr", s.server.Addr)
	if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failure: %w", err)
	}
	return nil
}

// Shutdown gracefully terminates the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down kazeshini api server...")
	return s.server.Shutdown(ctx)
}

// Handler exposes the internal HTTP handler for testing.
func (s *Server) Handler() http.Handler {
	return s.server.Handler
}
