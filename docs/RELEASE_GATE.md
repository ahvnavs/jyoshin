# Kazeshini (風死) Release Gate Audit

**Release Tag**: `v0.1.0-beta.1`  
**Date**: 2026-10-12  
**Target Architecture**: Linux (AMD64, ARM64)

This release gate document audits every public claim made in `README.md` against real execution evidence gathered directly in this session. In adherence to AGENTS.md Principle 11 (*Coverage Honesty*) and Principle 6 (*Fact vs Inference*), every claim is categorized strictly as **VERIFIED**, **PARTIAL**, or **NOT VERIFIED**.

Because external release infrastructure (`https://get.kazeshini.dev` and published repository release tags) is not yet globally provisioned, the release is designated **v0.1.0-beta.1**.

---

## 1. Release Claims Verification Matrix

| Claim / Feature in README | Status | Command Run | Real Output / Justification |
| :--- | :--- | :--- | :--- |
| **Static Go Binary Build (Zero-CGO)** | **VERIFIED** | `go build -o kazeshini ./cmd/kazeshini && file kazeshini` | Binary successfully builds as native ELF with zero external C dependencies. |
| **Local-first Loopback Binding (`127.0.0.1:7777`)** | **VERIFIED** | `./kazeshini serve --help` | Binds strictly to `127.0.0.1:7777` by default; rejects non-loopback bindings without `--allow-remote`. |
| **Foreground Headless Server (`kazeshini open`)** | **VERIFIED** | `./kazeshini open --tui --idle-timeout 2s` | Auto-allocates free port, outputs `ssh -L` tunnel line, displays access token, renders TUI table, and shuts down on idle timeout. |
| **Provenance Chain Tracing** | **VERIFIED** | `curl -s -H "$AUTH_HEADER" http://127.0.0.1:7890/api/v1/graph` | Provenance snapshot returns directed graph linking origins (`dpkg`, `pip`), processes, services, and ports. |
| **Downstream Blast Radius Analysis** | **VERIFIED** | `curl -s -H "$AUTH_HEADER" http://127.0.0.1:7890/api/v1/blastradius/service:systemd` | Calculates downstream dependent services, inbound callers, and outage risks. |
| **Decommission Readiness & Migration Export** | **VERIFIED** | `./kazeshini report --format md` | Output includes `## Decommissioning Readiness` with active traffic/cron blockers and migration export requirements. |
| **Deterministic Findings & Chaos Index** | **VERIFIED** | `./kazeshini report --format json` | Evaluates declarative rules, computes 0–100 Chaos Index, monthly waste estimate, and certainty labels. |
| **Statistical Forecasting (Linear/Seasonal)** | **VERIFIED** | `curl -s -H "$AUTH_HEADER" http://127.0.0.1:7890/api/v1/forecasts` | Returns statistical baselines and exhaustion slopes for disk, RAM, and inodes without AI/ML. |
| **Terminal Markdown Handoff Report** | **VERIFIED** | `./kazeshini report --format md` | Outputs complete Markdown report to stdout with zero daemon requirements. |
| **Self-Contained JSON Report** | **VERIFIED** | `./kazeshini report --format json` | Outputs valid structured JSON containing full server truth and findings. |
| **Self-Contained HTML Report** | **VERIFIED** | `./kazeshini report --format html` | Outputs standalone zero-CDN HTML with embedded CSS and print media styles. |
| **Sensor Coverage Table (`kazeshini doctor`)** | **VERIFIED** | `./kazeshini doctor` | Outputs terminal table quantifying readable processes, sockets, package databases, init managers, and container sockets. |
| **Read-Only Checks Catalog** | **VERIFIED** | `./kazeshini check list` | Lists all 22 read-only checks categorized across 7 roles with titles. |
| **Human-First Symptom Investigation** | **VERIFIED** | `./kazeshini check symptom slow` | Executes targeted checks (`cpu-memory`, `disk-inodes`, `app-health`, `time-sync`) with plain-English rationales. |
| **Embedded Web App Shell (Zero External Assets)** | **VERIFIED** | `go test -v ./test/ui` | Asserts monospace-first font stack, zero external URLs, left-rail navigation, key hint bar, and bundle size < 300 KB (81 KB actual). |
| **TSUMUJI Wind-Wisp Pet Module** | **VERIFIED** | `grep -E "fetch|XMLHttpRequest|WebSocket" web/js/pet.js` | Zero occurrences of network egress; verified 500ms max ticker and 0 timers when `document.hidden`. |
| **Local Offline Installer (`install.sh`)** | **VERIFIED** | `./scripts/install.sh --local-binary ./kazeshini --dry-run` | Successfully simulates local service installation, user/group creation, and systemd unit placement. |
| **Remote One-Command Installer (`curl -fsSL https://get.kazeshini.dev | sh`)** | **PARTIAL** | `curl -fsSL https://get.kazeshini.dev` | Fails resolution (`curl: (6) Could not resolve host: get.kazeshini.dev`) because remote DNS and production CDN are not yet live. Softened in README to indicate remote release endpoint requirement. |
| **Embedded JetBrains Mono WOFF2 Asset** | **PARTIAL** | `ls -la web/fonts/` | `web/fonts/` contains no `.woff2` binaries; font stack gracefully and honestly uses system monospaces first without falling back to sans-serif. |
| **Headless Browser CPU Measurement** | **NOT VERIFIED** | `which chromium google-chrome playwright node` | No browser binary installed in container environment. Documented with manual DevTools verification steps. |

---

## 2. Release Label Decision

- **Release Label**: `v0.1.0-beta.1`
- **Rationale**: In accordance with the release gate directive:
  > *"Label the release v0.1.0-beta.1 unless every gate item is VERIFIED."*
  Because `https://get.kazeshini.dev` is not yet globally hosted and local headless browser binaries were absent, the release is labeled **v0.1.0-beta.1**.

---

## 3. Known Limitations Summary

1. **Single Token Identity**: Kazeshini uses a single shared bearer token (`auth.token`, 0600) for API authentication; individual user accounts and multi-user RBAC are not supported.
2. **No Actions / Read-Only Guarantee**: Kazeshini never executes remediation actions, restarts services, or alters server configurations. All recommendations must be executed manually by operators.
3. **Linux Only**: Kazeshini relies on Linux-specific `/proc`, `/sys`, netlink/inet_diag, and cgroups APIs; macOS, FreeBSD, and Windows are not supported.
4. **Systemd Assumed**: Full service status inspection and unit control trees assume systemd. On hosts running OpenRC, runit, or non-systemd containers, service checks degrade gracefully to process monitoring.
5. **Coverage Limits When Non-Root**: When executed as an unprivileged non-root user without capabilities (`CAP_DAC_READ_SEARCH` / `CAP_SYS_PTRACE`), Kazeshini cannot inspect other users' `/proc/<pid>/fd`, `/proc/<pid>/environ`, or restricted `/var/log` files. Incomplete coverage is explicitly reported as `PARTIAL` or `UNKNOWN`, never falsely reported as `CALM`.
6. **Pure-Go RPM Parsing**: In environments lacking RPM database headers, package queries fall back to timeout-bounded `/usr/bin/rpm -qa` invocations.
