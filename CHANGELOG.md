# Changelog

All notable changes to Kazeshini will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-rc.1] - 2026-10-19

### Release Candidate 1: Full Server Truth Engine Consolidation

#### Added
- **Space Colonization Growth Map (`kazeshini view growth`, SVG export, Web UI)**:
  - Deterministic space colonization algorithm mapping host entities (processes, services, ports, unmanaged software) to real provenance edges.
  - Byte-identical reproducibility seeded by `sha256(machine-id)`.
  - Accessible SVG with `<title>`, `<desc>`, `role="img"`, and hidden screen-reader table equivalent.
  - Chunked browser animation (< 40ms/frame) with automatic bypass when `prefers-reduced-motion` is active.
- **Visual Domain Views & View Switchers**:
  - Overview: Tree $\leftrightarrow$ SVG Growth Map.
  - Storage: Checks Table $\leftrightarrow$ Filesystem Treemap bar allocation view.
  - Network: Checks Table $\leftrightarrow$ Process $\times$ Remote Endpoint socket matrix.
  - Services: Checks Table $\leftrightarrow$ Provenance unit hierarchy.
  - Persistent active view per domain in `localStorage`.
- **Export Framework (`kazeshini export`, Web UI Export Menu)**:
  - Export machine state to JSON, CSV, Markdown, standalone HTML, and SVG vector formats.
- **Canonical Wording & 11 Domains**:
  - Overview, Software, Services, Network, Storage, Security, Logs, Platforms, Drift, Audit Log, Settings.
  - Standardized states: Healthy, Degraded, Critical, Partial visibility, Unknown.
  - Risk Score (0–100) with top risk contributors.
  - Standardized 8-field check cards with plain summaries, impact statements, and equivalent inspection commands.
- **Zero-Argument First-Run Experience**:
  - Running `kazeshini` with no arguments starts stateless in-memory, binds loopback, outputs terminal summary and SSH tunnel instructions, and auto-exits after 30m idle.
- **Packaging, Governance & Supply Chain Security**:
  - Reproducible static builds, Cosign keyless signatures, SPDX SBOM, and offline binary verification (`kazeshini verify`).

## [0.1.0-beta.1] - 2026-10-12

### Beta 1 Release: Server Truth Engine for Linux

#### Added
- **Read-Only Checks Engine & Diagnostic Catalog**:
  - Standardized `CheckResult` inspection contract across 22 read-only diagnostic checks (DevOps, Cloud, Cloud Platform, Infrastructure, DevSecOps, Platform, Network).
  - Symptom investigation workflows (`kazeshini check symptom <name>`) mapping high-level problems (slow, service down, can't connect, disk full, looks hacked) to targeted read-only checks with plain-English rationales.
  - Active network connectivity probe with rate-limiting (max 1 probe every 2s) and opt-in user target specification.
  - Local append-only check audit log (`activity.log`, 0600, 2MB size cap).
- **Headless & Foreground Usability (`kazeshini open`)**:
  - Foreground server binding loopback with random free port allocation.
  - Automatic `ssh -L` command rendering and one-time token display.
  - Activity-based `--idle-timeout` auto-exit (default 30m) and `--ephemeral` temporary state directory cleanup.
  - Stdlib ANSI terminal dashboard (`--tui`) rendering verdict, coverage, and check tables without dependencies.
- **Embedded Web App Shell & Navigation**:
  - Left-rail navigation (`Overview`, `Briefing`, 7 check categories, `Activity`, `Styleguide`).
  - Top bar with live status, verdict, coverage %, and stale data detector (>60s transitions to UNKNOWN).
  - Command palette (`Ctrl+K`), quick filter (`/`), keyboard shortcuts dialog (`?`), and bottom htop-style key hints.
  - Check cards with status glyphs, plain summaries, "Run check" buttons, and expandable quad-disclosure details.
- **TSUMUJI (Wind-Wisp) Companion**:
  - ASCII wind-wisp idle companion appearing after 90s idle and hiding on user input.
  - Zero network egress (strict offline local logic), max one 500ms ticker, and zero timers when `document.hidden`.
  - Verdict-reactive mood states and local keyboard reflex petting mini-game.
  - Configurable toggle (`:pet off` / `:pet on`) persisted in `localStorage`.
- **Coverage Honesty & Plain-English Briefing**:
  - Sensor visibility coverage quantification (`kazeshini doctor` terminal table and `/api/v1/coverage`).
  - Deterministic verdict state engine enforcing that `CALM` is never rendered when sensor visibility is inadequate (`PARTIAL` or `UNKNOWN`).
  - Human-first Plain English Server Truth Briefing (`/api/v1/briefing`).
- **Product Rebranding & Unification**:
  - Unified naming: Kazeshini (風死), binary `kazeshini`, unit `kazeshini.service`, module `github.com/OWNER/kazeshini`.
  - Non-root first run fallback to `$XDG_STATE_HOME/kazeshini` or `~/.local/state/kazeshini`.
  - Hardened systemd unit with allow-listed `SystemCallFilter` avoiding SIGSYS termination.
- **Repository & Architecture Foundation**:
  - Rooted filesystem abstraction (`fs.FS`) enabling isolated and deterministic testing against fixture trees.
  - Zero-CGO, static binary build system with reproducible build flags.
  - Hardened priority drop (`nice 19`, `ionice idle`) upon supervisor initialization.
- **Sensors Framework**:
  - Independent goroutine isolation, panic recovery, circuit breakers, and exponential backoff.
  - Linux `/proc` host identity, process tree, and socket listener sensors.
  - Systemd D-Bus and unit status sensor with graceful non-systemd fallback.
- **Software Inventory & Provenance Detection**:
  - Direct database parsers for system packages (`dpkg`, `pacman`, `apk`, `rpm`).
  - Language ecosystems discovery (`pip`, `npm`, `cargo`, `gem`).
  - Container and runtime detection (`docker`, `podman`, `python`, `node`, `java`, `go`).
  - Bounded memory file-to-package attribution indexing.
- **Provenance Graph**:
  - Incremental directed graph builder linking files, origins, processes, services, and ports.
  - Deterministic node ID hashing stable across reboots.
  - Graph traversal engine for "Why does this exist?" and "What depends on this?".
  - Pure-Go embedded database (`bbolt`) persistence with bounded snapshot retention.
- **Deterministic Rules Engine**:
  - Declarative YAML rule engine evaluating hygiene, security, operations, and efficiency.
  - Fact-based finding generation with explicit certainty labels (`OBSERVED`, `DERIVED`, `INFERRED`).
  - Dollar-waste calculation and 0–100 Chaos Index scoring.
- **Monospace Web Interface**:
  - Embedded JetBrains Mono UI (`web/`) with box-drawing borders and dark monospace theme.
  - Zero CDN dependencies, zero external network egress.
  - Real-time Server-Sent Events (SSE) stream for live updates.
- **Statistical Forecasting & Memory**:
  - Rolling snapshot diffing engine detecting unauthorized changes and regressions.
  - Pure-math linear regression and seasonal baselining forecaster predicting resource exhaustion without ML/AI.
- **Decision Support & Remediation Safety**:
  - Blast Radius analyzer computing impact across units, libraries, and connected clients.
  - Decommission readiness and migration export planner.
  - Secret redaction filter ensuring zero credentials or private tokens leak into reports or logs.
- **Distribution & Standards Readiness**:
  - POSIX `sh` one-command installer and uninstaller.
  - Hardened systemd unit with `ProtectSystem=strict`, `NoNewPrivileges`, and minimal capability bounding set.
  - Native packaging definitions (`NFPM`, `PKGBUILD`, `APKBUILD`, scratch Dockerfile).
  - OpenSSF Gold tier alignment, CodeQL, and Cosign keyless container signing workflows.

