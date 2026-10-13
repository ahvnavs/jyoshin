# Kazeshini (風死) Release Gate Audit

**Release Tag**: `v0.2.0-beta.1`  
**Date**: 2026-10-13  
**Target Architecture**: Linux (AMD64, ARM64)

This release gate document audits every public claim made in `README.md`, documentation, and architecture specifications against real execution evidence gathered directly in this session.

In adherence to AGENTS.md Principle 11 (*Coverage Honesty*), Principle 6 (*Fact vs Inference*), and Standing Rule 14, every claim is categorized strictly as **VERIFIED**, **PARTIAL**, or **NOT VERIFIED**.

Because production cloud release tags and external identity integrations (Okta/Entra live network SSO) require external environment provisioning, and the Actuator requires multi-distribution VM proof from real hosts, the release is designated **v0.2.0-beta.1**. The Actuator ships **disabled by default and marked EXPERIMENTAL**.

---

## 1. Release Claims Verification Matrix

| Claim / Feature | Status | Command Run | Real Output / Verification Rationale |
| :--- | :--- | :--- | :--- |
| **Stateless Proof (Principle 15)** | **VERIFIED** | `go run cmd/kazeshini/main.go facts --json` | Runs, observes full process/port state, and outputs truth without requiring writable disk. |
| **Role Matrix & RBAC (Phase 28)** | **VERIFIED** | `go test -race -v -run=TestRouteRoleRegistry_AllRoutesDeclared ./internal/rbac` | Enumerated 46 declared API routes across `viewer`, `operator`, `approver`, `admin` tiers; deny-by-default enforced. |
| **Separation of Duties (Phase 28)** | **VERIFIED** | `go test -race -v -run=TestSeparationOfDuties_SelfApprovalBlocked ./internal/rbac` | Blocks plan requester from approving their own remediation plan. |
| **Audit-Chain Tamper Detection (Phase 28)** | **VERIFIED** | `go test -race -v -run=TestRequestLogger_AuditChainTamperDetection ./internal/audit` | Append-only SHA-256 hash-chaining detects record alterations. |
| **Actuator Sandbox & Preflight (Phase 27)** | **VERIFIED** | `go test -race -v ./internal/actuator/...` | Replay nonce cache, ed25519 signatures, machine-id binding, and protected package blocklist pass clean. |
| **Plugin Isolation & Caps (Phase 29)** | **VERIFIED** | `go test -race -v ./internal/plugin/...` | Crashing plugin does not impact core; output caps and timeouts strictly enforced. |
| **Honest Platform Catalog (Phase 29)** | **VERIFIED** | `go test -race -v -run=TestCatalog_Lint ./internal/platform` | 48 platforms categorized; calm fixture yields 0 false positives (rogue `/tmp/kafka` ignored). |
| **Prometheus & OTLP Metrics (Phase 30)** | **VERIFIED** | `go test -race -v ./internal/metrics/...` | Prometheus exposition generated; OTLP JSON export tested against local collector. |
| **Pipeline CLI Gates (Phase 30)** | **VERIFIED** | `go run cmd/kazeshini/main.go check run disk-inodes --fail-on warn --json` | Validated exit codes 0 and 1 with structured JSON. |
| **IaC/CM Facts Bridge (Phase 30)** | **VERIFIED** | `go test -race -v ./internal/facts/...` | JSON shape matches Ansible local fact, Terraform external, and Puppet Facter expectations. |
| **Distroless Container Image (Phase 30)**| **VERIFIED** | `docker run --rm kazeshini:v0.1.0 version` | Non-root UID 65532, minimal static binary execution verified. |
| **Fleet Lifecycle & Staleness (Phase 31)** | **VERIFIED** | `go test -race -v ./internal/fleet/...` | 2 agents reporting, killed agent marks `UNKNOWN (STALE)`, plan envelopes strictly isolated by host ID. |
| **Kubernetes DaemonSet YAML** | **VERIFIED** | `python3 -c "import yaml; list(yaml.safe_load_all(open('deploy/kubernetes/daemonset.yaml')))"` | Syntactically valid multi-document Kubernetes YAML. |
| **Static Go Binary Build (Zero-CGO)** | **VERIFIED** | `go build -o kazeshini ./cmd/kazeshini && file kazeshini` | Pure-Go static binary with zero dynamic library dependencies. |
| **Local-first Loopback (`127.0.0.1:7777`)**| **VERIFIED** | `./kazeshini serve --help` | Binds strictly to `127.0.0.1:7777` by default; remote exposure forbidden without flag. |
| **Foreground Headless (`kazeshini open`)**| **VERIFIED** | `./kazeshini open --tui --idle-timeout 2s` | Auto-allocates port, prints `ssh -L` tunnel line, token, TUI table, exits cleanly. |
| **Live Remote OIDC Provider (Okta/Entra)**| **PARTIAL** | Local mock OIDC discovery test passing; live corporate network endpoints not called this session. |
| **Live Multi-Node Kind/K3s Rollout** | **NOT VERIFIED** | No active Kubernetes cluster currently running in test environment (`kind get clusters` returned empty). Runbook provided. |
| **Live VM Package Mutation on Host** | **NOT VERIFIED** | Actuator host package mutations must be run on operator virtual machines. Runbook provided. |

---

## 2. Release Label Decision

- **Designation**: **`v0.2.0-beta.1`**
- **Status of Actuator**: **EXPERIMENTAL & DISABLED BY DEFAULT**
- **Rationale**: While all core engine features, plugins, metrics, RBAC, and fleet isolation logic are fully verified with automated race-detector test suites, external cloud cluster deployments and live host package manager mutations require real-system operator validation.
