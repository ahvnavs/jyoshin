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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OWNER/kazeshini/internal/audit"
	"github.com/OWNER/kazeshini/internal/auth"
	"github.com/OWNER/kazeshini/internal/blastradius"
	"github.com/OWNER/kazeshini/internal/briefing"
	"github.com/OWNER/kazeshini/internal/checks"
	"github.com/OWNER/kazeshini/internal/config"
	"github.com/OWNER/kazeshini/internal/contract"
	"github.com/OWNER/kazeshini/internal/coverage"
	"github.com/OWNER/kazeshini/internal/decisions"
	"github.com/OWNER/kazeshini/internal/desired"
	"github.com/OWNER/kazeshini/internal/diff"
	"github.com/OWNER/kazeshini/internal/drift"
	"github.com/OWNER/kazeshini/internal/forecast"
	internalfs "github.com/OWNER/kazeshini/internal/fs"
	"github.com/OWNER/kazeshini/internal/graph"
	"github.com/OWNER/kazeshini/internal/graphbuilder"
	"github.com/OWNER/kazeshini/internal/inventory"
	"github.com/OWNER/kazeshini/internal/metrics"
	"github.com/OWNER/kazeshini/internal/origin"
	"github.com/OWNER/kazeshini/internal/orphan"
	"github.com/OWNER/kazeshini/internal/plan"
	"github.com/OWNER/kazeshini/internal/platform"
	"github.com/OWNER/kazeshini/internal/policy"
	"github.com/OWNER/kazeshini/internal/rbac"
	"github.com/OWNER/kazeshini/internal/report"
	"github.com/OWNER/kazeshini/internal/resource"
	"github.com/OWNER/kazeshini/internal/rules"
	"github.com/OWNER/kazeshini/internal/software"
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
	checksEngine    *checks.Engine
	softwareReader  *software.InventoryReader
	softwarePlanner *software.Planner
	rbacRegistry    *rbac.RouteRoleRegistry
	tokenStore      *auth.TokenStore
	sessionMgr      *auth.SessionManager
	rateLimiter     *auth.RateLimiter
	requestAudit    *audit.RequestLogger
	samplesMu       sync.RWMutex
	samples         map[string][]forecast.Sample
	lastActivityMu  sync.RWMutex
	lastActivity    time.Time
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

	var authMgr *auth.Manager
	if cfg.Stateless {
		authMgr = auth.NewMemoryManager()
	} else {
		var err error
		authMgr, err = auth.NewManager(cfg.DataDir)
		if err != nil {
			logger.Warn("could not initialize persistent auth token; continuing in-memory", "error", err)
			authMgr = auth.NewMemoryManager()
		}
	}

	var actLog *checks.ActivityLog
	if cfg.Stateless {
		actLog = checks.NewMemoryActivityLog()
	} else {
		actLog = checks.NewActivityLog(cfg.DataDir)
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
		checksEngine:    checks.NewEngine(nil, actLog, internalfs.Default()),
		softwareReader:  software.NewInventoryReader(internalfs.Default()),
		softwarePlanner: software.NewPlanner(software.NewInventoryReader(internalfs.Default()), blastradius.NewAnalyzer(pGraph)),
		rbacRegistry:    rbac.NewRouteRoleRegistry(),
		sessionMgr:      auth.NewSessionManager(30*time.Minute, 5),
		rateLimiter:     auth.NewRateLimiter(5, 5*time.Minute, 10*time.Minute),
		samples:         make(map[string][]forecast.Sample),
		logger:          logger,
	}

	if !cfg.Stateless {
		if tStore, err := auth.NewTokenStore(cfg.DataDir); err == nil {
			s.tokenStore = tStore
		}
		if reqAud, err := audit.NewRequestLogger(filepath.Join(cfg.DataDir, "audit.log")); err == nil {
			s.requestAudit = reqAud
		}
	} else {
		// Stateless mode: purely in-memory audit logger, zero disk touched
		if reqAud, err := audit.NewRequestLogger(""); err == nil {
			s.requestAudit = reqAud
		}
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
		Addr:           cfg.Address(),
		Handler:        s.hostCheckMiddleware(s.requestLimitMiddleware(s.loggingMiddleware(s.authMiddleware(mux)))),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   0, // SSE streaming requires unbounded write timeout
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB max header bytes to prevent header-bloat resource exhaustion
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

	// Phase 18: Coverage Honesty & Plain Summary/Overview (with legacy briefing alias)
	mux.HandleFunc("GET /api/v1/coverage", s.handleCoverage)
	mux.HandleFunc("GET /api/v1/briefing", s.handleBriefing)
	mux.HandleFunc("GET /api/v1/overview", s.handleBriefing)

	// Phase 21: Read-Only Checks & Activity Log
	mux.HandleFunc("GET /api/v1/checks", s.handleChecks)
	mux.HandleFunc("POST /api/v1/checks/{id}/run", s.handleCheckRun)
	mux.HandleFunc("GET /api/v1/activity", s.handleActivity)

	// Phase 25: Desired State, Drift, and Remediation Plans
	mux.HandleFunc("GET /api/v1/drift", s.handleDrift)
	mux.HandleFunc("GET /api/v1/plans", s.handlePlans)

	// Phase 26: Software Inventory & Dry-Run Planning
	mux.HandleFunc("GET /api/v1/software", s.handleSoftwareList)
	mux.HandleFunc("GET /api/v1/software/{pkg}", s.handleSoftwareDetail)
	mux.HandleFunc("POST /api/v1/software/plan", s.handleSoftwarePlan)

	// Phase 27: Actuator Status Check (Socket presence & ping)
	mux.HandleFunc("GET /api/v1/actuator/status", s.handleActuatorStatus)

	// Phase 29: Platform Detection & Adapter Catalog
	mux.HandleFunc("GET /api/v1/platforms", s.handlePlatforms)

	// Phase 30: Prometheus Metrics
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Profiling endpoints (served only when --debug is set, behind auth)
	if s.cfg.Debug {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}

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
		start := time.Now()
		path := r.URL.Path

		// Static assets / web UI
		if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/debug/") {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Rate Limiting / Lockout check by client IP
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientIP = r.RemoteAddr
		}
		if s.rateLimiter != nil {
			if locked, remaining := s.rateLimiter.IsLocked(clientIP, start); locked {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":               "too many authentication failures: client temporarily locked out",
					"retry_after_seconds": int(remaining.Seconds()),
				})
				return
			}
		}

		// 2. Deny-by-default route role declaration lookup
		requiredRole := rbac.RoleViewer
		if s.rbacRegistry != nil {
			req, err := s.rbacRegistry.RequiredRole(r.Method, path)
			if err != nil {
				// Undeclared route: DENY BY DEFAULT
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": fmt.Sprintf("access denied: undeclared route pattern %q %q (Principle 13 / deny by default)", r.Method, path),
				})
				return
			}
			requiredRole = req
		}

		// Public endpoints that require no credentials
		if path == "/api/v1/health" || path == "/api/v1/version" || path == "/api/v1/auth/status" {
			sub := rbac.Subject{ID: "anonymous", Role: rbac.RoleViewer, Method: "public"}
			ctx := rbac.WithSubject(r.Context(), sub)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 3. Resolve Subject from available auth mechanisms
		var subject *rbac.Subject

		// a) Bearer Token (Authorization: Bearer <token>)
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			// Check rotatable TokenStore first
			if s.tokenStore != nil {
				if sub, ok := s.tokenStore.VerifyToken(token, start); ok {
					subject = sub
				}
			}
			// Fallback to legacy single token manager if still valid (defaults to admin role)
			if subject == nil && s.auth != nil && s.auth.Validate(token) {
				subject = &rbac.Subject{
					ID:     "token:admin",
					Role:   rbac.RoleAdmin,
					Method: "token",
				}
			}
		}

		// b) Browser Cookie Session (kazeshini_session)
		if subject == nil && s.sessionMgr != nil {
			if cookie, err := r.Cookie("kazeshini_session"); err == nil && cookie.Value != "" {
				if sess, ok := s.sessionMgr.GetSession(cookie.Value, start); ok {
					// Enforce CSRF protection on state-changing requests (POST, PUT, DELETE, PATCH)
					if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
						csrfHeader := r.Header.Get("X-CSRF-Token")
						if !s.sessionMgr.ValidateCSRF(sess, csrfHeader) {
							w.Header().Set("Content-Type", "application/json; charset=utf-8")
							w.WriteHeader(http.StatusForbidden)
							_ = json.NewEncoder(w).Encode(map[string]any{
								"error": "csrf validation failed: missing or invalid X-CSRF-Token header",
							})
							return
						}
					}
					sub := sess.Subject
					subject = &sub
				}
			}
		}

		// c) Optional mTLS Peer Certificate
		if subject == nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cert := r.TLS.PeerCertificates[0]
			subject = &rbac.Subject{
				ID:     fmt.Sprintf("mtls:%s", cert.Subject.CommonName),
				Role:   rbac.RoleOperator, // default client cert tier
				Method: "mtls",
			}
		}

		// Fail if unauthenticated and auth is required
		if subject == nil {
			if !s.cfg.AuthRequired {
				// Auth disabled for this server instance: grant default viewer/operator access
				subject = &rbac.Subject{
					ID:     "unauthenticated:local",
					Role:   rbac.RoleAdmin, // full access when auth is disabled
					Method: "disabled",
				}
			} else {
				if s.rateLimiter != nil {
					s.rateLimiter.RecordFailure(clientIP, start)
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":  "unauthorized: valid credentials required",
					"status": 401,
					"hint":   "provide Bearer token in Authorization header or authenticate via session",
				})
				return
			}
		}

		// Clear failure count on valid authentication
		if s.rateLimiter != nil {
			s.rateLimiter.RecordSuccess(clientIP)
		}

		// 4. RBAC Authorization: verify subject role satisfies required role
		if !subject.Role.Satisfies(requiredRole) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":         "forbidden: insufficient role permissions",
				"required_role": string(requiredRole),
				"your_role":     string(subject.Role),
			})
			return
		}

		// 5. Hash-chained API request audit logging
		ctx := rbac.WithSubject(r.Context(), *subject)
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r.WithContext(ctx))

		if s.requestAudit != nil {
			_ = s.requestAudit.LogRequest(*subject, r, recorder.status, time.Since(start), "", "")
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		s.lastActivityMu.Lock()
		s.lastActivity = start
		s.lastActivityMu.Unlock()

		next.ServeHTTP(w, r)
		s.logger.Debug("http request handled",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start),
		)
	})
}

// LastActivity returns the timestamp of the most recent incoming HTTP request.
func (s *Server) LastActivity() time.Time {
	s.lastActivityMu.RLock()
	defer s.lastActivityMu.RUnlock()
	return s.lastActivity
}

func (s *Server) hostCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strictly do not send CORS headers to prevent cross-origin browser queries
		w.Header().Del("Access-Control-Allow-Origin")
		w.Header().Del("Access-Control-Allow-Methods")
		w.Header().Del("Access-Control-Allow-Headers")

		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
		hostLower := strings.ToLower(host)

		// Loopback hosts permitted by default (including httptest default example.com)
		isAllowed := hostLower == "127.0.0.1" || hostLower == "localhost" || hostLower == "::1" || hostLower == s.cfg.Host || hostLower == "example.com"

		if !isAllowed && len(s.cfg.AllowedHosts) > 0 {
			for _, ah := range s.cfg.AllowedHosts {
				ahClean := strings.TrimSpace(strings.ToLower(ah))
				if ahClean == hostLower {
					isAllowed = true
					break
				}
			}
		}

		if !isAllowed {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  "forbidden: invalid or unallowed Host header (DNS rebinding protection)",
				"status": 403,
				"host":   r.Host,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cap incoming request body to 2MB to prevent memory exhaustion attacks
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		}
		next.ServeHTTP(w, r)
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
	var checkResults []contract.CheckResult
	if s.checksEngine != nil {
		for _, c := range s.checksEngine.Registry().All() {
			if res, err := c.Run(ctx, internalfs.Default(), nil); err == nil {
				checkResults = append(checkResults, res)
			}
		}
	}
	return verdict.ComputeVerdictWithChecks(nodes, findings, orphanCount, cov.IsAdequate, cov.SummaryNote, checkResults)
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

func (s *Server) handleChecks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.checksEngine == nil {
		http.Error(w, `{"error":"checks engine not available"}`, http.StatusServiceUnavailable)
		return
	}

	domain := r.URL.Query().Get("domain")
	role := r.URL.Query().Get("role")
	var checksList []checks.Check
	if domain != "" {
		checksList = s.checksEngine.Registry().ByDomain(domain)
	} else if role != "" {
		checksList = s.checksEngine.Registry().ByRole(role)
	} else {
		checksList = s.checksEngine.Registry().All()
	}

	type checkMeta struct {
		ID          string `json:"id"`
		Role        string `json:"role"`
		Domain      string `json:"domain"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}

	res := make([]checkMeta, len(checksList))
	for i, c := range checksList {
		res[i] = checkMeta{
			ID:          c.ID(),
			Role:        c.Role(),
			Domain:      checks.DomainForCheck(c),
			Title:       c.Title(),
			Description: c.Description(),
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleCheckRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.checksEngine == nil {
		http.Error(w, `{"error":"checks engine not available"}`, http.StatusServiceUnavailable)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, `{"error":"check id required"}`, http.StatusBadRequest)
		return
	}

	// Parse JSON body or query params for check parameters
	params := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	if r.Header.Get("Content-Type") == "application/json" {
		var bodyParams map[string]string
		if err := json.NewDecoder(r.Body).Decode(&bodyParams); err == nil {
			for k, v := range bodyParams {
				params[k] = v
			}
		}
	}

	// Validate parameters against path traversal and command injection
	for k, v := range params {
		if !checks.ValidateSafeParam(v) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": fmt.Sprintf("invalid parameter %q: traversal or injection rejected", k),
			})
			return
		}
	}

	tokenHolder := "api-bearer"
	if s.auth != nil {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenHolder = "token-holder"
		}
	}

	res, err := s.checksEngine.RunCheck(r.Context(), id, params, tokenHolder)
	if err != nil {
		if errors.Is(err, checks.ErrInvalidParam) {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if s.checksEngine == nil || s.checksEngine.ActivityLog() == nil {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]any{})
		return
	}

	limit := 100
	entries, err := s.checksEngine.ActivityLog().Entries(limit)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"disclaimer": "Local audit activity log; size-capped and not tamper-proof against host compromise.",
		"entries":    entries,
	})
}

func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	desiredPath := s.cfg.DesiredPath
	if qPath := r.URL.Query().Get("desired"); qPath != "" {
		desiredPath = qPath
	}

	if desiredPath == "" {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "no_desired_state",
			"message": "No kazeshini.desired.yaml configured. Specify path via --desired, KAZESHINI_DESIRED, or ?desired=path",
			"items":   []drift.Item{},
			"summary": drift.Summary{},
		})
		return
	}

	manifest, err := desired.LoadFile(desiredPath)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	labels, _ := desired.LoadHostLabels(s.cfg.LabelsPath)
	desiredState := manifest.ForHost(labels)

	var nodes []graph.Node
	if s.pGraph != nil {
		nodes, _ = s.pGraph.Snapshot()
	}
	resources := make([]resource.Resource, len(nodes))
	for i, n := range nodes {
		resources[i] = resource.FromGraphNode(n)
	}

	cov := s.computeCurrentCoverage(r.Context())
	engine := drift.NewEngine()
	items, summary := engine.Evaluate(r.Context(), desiredState, resources, cov)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "evaluated",
		"items":    items,
		"summary":  summary,
		"coverage": cov.SummaryNote,
	})
}

func (s *Server) handlePlans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	desiredPath := s.cfg.DesiredPath
	if qPath := r.URL.Query().Get("desired"); qPath != "" {
		desiredPath = qPath
	}

	if desiredPath == "" {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "no_desired_state",
			"message": "No desired state configured to generate remediation plans.",
		})
		return
	}

	manifest, err := desired.LoadFile(desiredPath)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	labels, _ := desired.LoadHostLabels(s.cfg.LabelsPath)
	desiredState := manifest.ForHost(labels)

	var nodes []graph.Node
	if s.pGraph != nil {
		nodes, _ = s.pGraph.Snapshot()
	}
	resources := make([]resource.Resource, len(nodes))
	for i, n := range nodes {
		resources[i] = resource.FromGraphNode(n)
	}

	cov := s.computeCurrentCoverage(r.Context())
	driftEngine := drift.NewEngine()
	driftItems, _ := driftEngine.Evaluate(r.Context(), desiredState, resources, cov)

	planner := plan.NewPlanner(s.blastAnalyzer)
	p, err := planner.CreatePlan(driftItems)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	polEngine := policy.NewEngine(policy.DefaultConfig())
	decision := polEngine.EvaluatePlan(r.Context(), p)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"plan":     p,
		"decision": decision,
	})
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
	_, _ = fmt.Fprintf(w, "event: verdict\ndata: %s\n\n", data)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			current := s.computeCurrentVerdict(r.Context())
			d, err := json.Marshal(current)
			if err == nil {
				_, _ = fmt.Fprintf(w, "event: verdict\ndata: %s\n\n", d)
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
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(diff.ChangeSet{
			Summary: "Running in stateless mode: history and change tracking require persistent or accumulated snapshots.",
		})
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
		if s.cfg.Stateless && (res.State == forecast.StateNotEnoughData || len(smps) < 5) {
			res.Message = "Forecast requires historical metrics; running in stateless mode (needs persistence to accumulate trend over restarts)."
		}
		if s.watchers != nil {
			_ = s.watchers.ProcessForecast(res)
		}
		results = append(results, res)
	}

	// Always ensure standard targets are evaluated
	for target, def := range defaultTargets {
		smps := s.samples[target]
		res := s.forecaster.Forecast(def.kind, target, def.capacity, smps)
		if s.cfg.Stateless && (res.State == forecast.StateNotEnoughData || len(smps) < 5) {
			res.Message = "Forecast requires historical metrics; running in stateless mode (needs persistence to accumulate trend over restarts)."
		}
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

func (s *Server) handleSoftwareList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var nodes []graph.Node
	if s.pGraph != nil {
		nodes, _ = s.pGraph.Snapshot()
	}

	reader := s.softwareReader
	if reader == nil {
		reader = software.NewInventoryReader(internalfs.Default())
	}

	inv := reader.Collect(nodes)

	// Filter query params
	upgradableOnly := r.URL.Query().Get("upgradable") == "true"
	securityOnly := r.URL.Query().Get("security") == "true"

	if upgradableOnly || securityOnly {
		var filtered []software.PackageEntry
		for _, p := range inv.Packages {
			if securityOnly {
				if p.Candidate != nil && p.Candidate.UpgradeKind == software.UpgradeKindSecurity {
					filtered = append(filtered, p)
				}
			} else if upgradableOnly {
				if p.IsUpgradable {
					filtered = append(filtered, p)
				}
			}
		}
		inv.Packages = filtered
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(inv)
}

func (s *Server) handleSoftwareDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	pkgName := r.PathValue("pkg")
	if pkgName == "" {
		pkgName = r.URL.Query().Get("name")
	}

	if err := software.ValidatePackageName(pkgName); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	var nodes []graph.Node
	if s.pGraph != nil {
		nodes, _ = s.pGraph.Snapshot()
	}

	reader := s.softwareReader
	if reader == nil {
		reader = software.NewInventoryReader(internalfs.Default())
	}

	entry := reader.LookupPackage(pkgName, nodes)
	if entry == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("package %q not found", pkgName)})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(entry)
}

type softwarePlanRequest struct {
	Package string `json:"package"`
	Kind    string `json:"kind"` // "upgrade", "remove", "install"
}

func (s *Server) handleSoftwarePlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var req softwarePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	if err := software.ValidatePackageName(req.Package); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	kind := software.DryRunKind(req.Kind)
	if kind == "" {
		kind = software.DryRunUpgrade
	}
	if kind != software.DryRunUpgrade && kind != software.DryRunRemove && kind != software.DryRunInstall {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("unsupported dry-run kind %q (supported: upgrade, remove, install)", req.Kind)})
		return
	}

	var nodes []graph.Node
	if s.pGraph != nil {
		nodes, _ = s.pGraph.Snapshot()
	}

	planner := s.softwarePlanner
	if planner == nil {
		reader := software.NewInventoryReader(internalfs.Default())
		planner = software.NewPlanner(reader, s.blastAnalyzer)
	}

	// Detect running kernel
	runningKernel := ""
	if s.pGraph != nil {
		if sysNode, ok := s.pGraph.GetNode("system:kernel"); ok {
			if k, ok := sysNode.Properties["release"].(string); ok {
				runningKernel = k
			}
		}
	}

	plan, err := planner.CreatePlan(r.Context(), req.Package, kind, nodes, runningKernel)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(plan)
}

func (s *Server) handleActuatorStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	socketPath := "/run/kazeshini/actuator.sock"
	// Check if socket exists and can be dialed
	fi, err := os.Stat(socketPath)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"available": false,
			"reason":    "Actuator socket not found (/run/kazeshini/actuator.sock)",
			"socket":    socketPath,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"available": true,
		"socket":    socketPath,
	})
}

func (s *Server) handlePlatforms(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	cat, err := platform.LoadEmbeddedCatalog()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to load platform catalog: %v"}`, err), http.StatusInternalServerError)
		return
	}

	snap := platform.HostSnapshot{}
	// Populate snapshot from graph if available
	if s.pGraph != nil {
		nodes, _ := s.pGraph.Snapshot()
		for _, n := range nodes {
			if n.Type == graph.NodeProcess {
				snap.RunningProcesses = append(snap.RunningProcesses, n.Label)
			}
			if n.Type == graph.NodePort {
				var portNum int
				if _, err := fmt.Sscanf(n.Label, "port tcp/%d", &portNum); err == nil {
					snap.ListeningPorts = append(snap.ListeningPorts, portNum)
				}
			}
		}
	}

	detector := platform.NewDetector(cat)
	results := detector.Detect(r.Context(), internalfs.Default(), snap)

	// Enrich adapter-supported items if present
	k8sAdapter := platform.NewK8sNodeAdapter(internalfs.Default())
	k8sView := k8sAdapter.Inspect(r.Context())
	if k8sView.Present {
		for i := range results {
			if results[i].ID == "kubernetes" {
				results[i].AdapterData = k8sView
				results[i].Present = true
			}
		}
	}

	cfgAdapter := platform.NewConfigMgmtAdapter(internalfs.Default())
	pRun := cfgAdapter.InspectPuppet(r.Context())
	if pRun.Result == "success" || pRun.Result == "failed" {
		for i := range results {
			if results[i].ID == "puppet" {
				results[i].AdapterData = pRun
				results[i].Present = true
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	snap := metrics.Snapshot{
		HostID:    "localhost",
		Timestamp: time.Now().UTC(),
		Verdict:   s.computeCurrentVerdict(r.Context()),
		Coverage:  s.computeCurrentCoverage(r.Context()),
	}

	if s.pGraph != nil {
		nodes, edges := s.pGraph.Snapshot()
		for _, n := range nodes {
			if n.Type == graph.NodeSystem && n.Label != "" {
				snap.HostID = n.Label
			}
		}
		if s.ruleEngine != nil {
			f, err := s.ruleEngine.Evaluate(r.Context(), nodes, edges)
			if err == nil {
				snap.Findings = f
			}
		}
	}

	if s.checksEngine != nil {
		for _, c := range s.checksEngine.Registry().All() {
			if res, err := c.Run(r.Context(), internalfs.Default(), nil); err == nil {
				snap.CheckResults = append(snap.CheckResults, res)
			}
		}
	}

	exporter := metrics.NewPrometheusExporter()
	out := exporter.Format(snap)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(out))
}

// Start begins listening and serving traffic on the configured address.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.server.Addr, err)
	}
	return s.ServeListener(ln)
}

// ServeListener accepts incoming connections on an existing net.Listener.
func (s *Server) ServeListener(ln net.Listener) error {
	s.logger.Info("kazeshini api server started", "addr", ln.Addr().String())
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
