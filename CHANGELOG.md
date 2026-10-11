# Changelog

All notable changes to Kazeshini will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-10

### Initial Release: Server Truth Engine for Linux

#### Added
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

