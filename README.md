# Kazeshini (風死)

[![CI](https://github.com/OWNER/kazeshini/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/kazeshini/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-OpenSSF_Gold_Ready-success.svg)](docs/STANDARDS.md)

> **Server Truth Engine for Linux.**
> Open-source, read-only, local-first engine showing what a Linux server actually is and does. Zero AI. Deterministic provenance.

---

## What is Kazeshini?

One static Go binary. One command installs it. It runs as an unprivileged systemd service and hosts a local web dashboard (`127.0.0.1:7777` strictly by default) that shows, with zero user configuration:
- **How did this get here?** Full provenance chain tracing every process, listener, and service back to its origin package, language ecosystem (`pip`, `npm`, `cargo`, `gem`), container, or manual drop.
- **Is it safe to touch?** Blast radius calculation quantifying downstream dependent services, libraries, and external network clients.
- **Is it safe to turn off?** Decommission readiness and migration export plans.
- **What is risky or wasteful?** Deterministic rule-based findings with calculated monthly dollar waste and calm-to-critical chaos indices.
- **What will break or exhaust?** Linear and seasonal forecasting with time-to-exhaustion confidence intervals for disks, memory, inodes, and file descriptors.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ KAZESHINI // SERVER TRUTH ENGINE                                                │
│ STATUS: [●] CALM   CHAOS INDEX: 12/100   HOST: prod-web-01 (Ubuntu 24.04 LTS)    │
│ PORTS: 3 (0 public)   SERVICES: 42 (0 failed)   WASTE: $0.00/mo                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│ [PROVENANCE CHAIN]                                                              │
│ ├─ [deb] nginx (1.24.0-2ubuntu7)                                                │
│ │   └─ [service] nginx.service (active, loaded)                                 │
│ │       └─ [process] nginx (pid: 1402, user: www-data)                          │
│ │           └─ [listener] 127.0.0.1:8080 (loopback, private)                    │
│ └─ [pip] gunicorn (21.2.0 in /srv/api/.venv)                                    │
│     └─ [process] python3 -m gunicorn (pid: 1891, user: app)                     │
│         └─ [listener] 127.0.0.1:5000 (loopback)                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Non-Negotiable Principles

1. **NO AI / LLM / ML**: Deterministic, explainable logic only (rules + statistics).
2. **READ-ONLY**: Never modify the host. Never execute remediation. Recommend only.
3. **NEVER HARM THE HOST**: Low priority (`nice 19`, `ionice idle`), hard CPU/memory caps, bounded work cycles.
4. **ISOLATION**: Independent sensors; failure or denial in one never affects others or the host.
5. **NO NETWORK EGRESS**: Zero telemetry. Data never leaves the machine.
6. **FACT vs INFERENCE**: Strict evidence and certainty attribution (`OBSERVED`, `DERIVED`, `INFERRED`).
7. **BLAME-FREE TONE**: Describes the machine, never the person who configured it.
8. **SELF-CONTAINED**: Embedded store (`bbolt`, zero CGO) and embedded web UI (`go:embed`, zero external CDN).
9. **STDLIB-FIRST**: Minimal dependencies justified in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).
10. **GRACEFUL DEGRADATION**: Missing permissions report "unknown, here's why", never crash.
11. **COVERAGE HONESTY**: Never say healthy/calm unless the sensors that matter could actually see. "Found nothing" and "couldn't look" must look different.
12. **HUMAN-FIRST**: Plain sentences, human units (GB, days, "3 hours ago"), no raw keys or jargon without a one-line gloss.

---

### Installation

Install via the POSIX install script:

```bash
# Download the release archive and verify sha256 checksums:
curl -fsSLO https://github.com/OWNER/kazeshini/releases/download/v0.1.0-beta.1/kazeshini_v0.1.0-beta.1_linux_amd64.tar.gz
sha256sum -c kazeshini_v0.1.0-beta.1_linux_amd64.tar.gz.sha256
tar -xzf kazeshini_v0.1.0-beta.1_linux_amd64.tar.gz

# Run install script:
sudo ./scripts/install.sh --local-binary ./kazeshini
```

### Accessing the Dashboard via SSH Tunnel
Kazeshini strictly binds to `127.0.0.1:7777` and refuses remote exposure by default. Forward port 7777 over SSH:

```bash
ssh -L 7777:127.0.0.1:7777 user@your-server
```
Then visit `http://127.0.0.1:7777` in your local browser, or use `kazeshini open` for automated port allocation and tunneling instructions.

### Inspect the Server Truth Immediately
Generate a full terminal state handoff report or export clean JSON / self-contained HTML:

```bash
kazeshini report --format md
kazeshini report --format html > server-report.html
kazeshini report --format json > server-report.json
kazeshini doctor
```

---

## Known Limitations

We document our operational boundaries and known gaps honestly:
1. **Single Token Identity**: Kazeshini uses a single shared bearer token (`auth.token`, 0600) for API authentication; individual user accounts and multi-user RBAC are not supported.
2. **No Actions / Read-Only Guarantee**: Kazeshini never executes remediation actions, restarts services, or alters server configurations. All recommendations must be executed manually by operators.
3. **Linux Only**: Kazeshini relies on Linux-specific `/proc`, `/sys`, netlink/inet_diag, and cgroups APIs; macOS, FreeBSD, and Windows are not supported.
4. **Systemd Assumed**: Full service status inspection and unit control trees assume systemd. On hosts running OpenRC, runit, or non-systemd containers, service checks degrade gracefully to process monitoring.
5. **Coverage Limits When Non-Root**: When executed as an unprivileged non-root user without capabilities (`CAP_DAC_READ_SEARCH` / `CAP_SYS_PTRACE`), Kazeshini cannot inspect other users' `/proc/<pid>/fd`, `/proc/<pid>/environ`, or restricted `/var/log` files. Incomplete coverage is explicitly reported as `PARTIAL` or `UNKNOWN`, never falsely reported as `CALM`.
6. **Pure-Go RPM Parsing**: In environments lacking RPM database headers, package queries fall back to timeout-bounded `/usr/bin/rpm -qa` invocations.

---

## Documentation

- [Distribution Compatibility Matrix](docs/COMPATIBILITY.md)
- [Performance Benchmarks & Overhead](docs/BENCHMARKS.md)
- [OpenSSF Standards & Security Design](docs/STANDARDS.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Security & Degradation Design](docs/SECURITY_DESIGN.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Declarative Rules Guide](docs/RULES.md)
- [Contributing Rules](docs/CONTRIBUTING-RULES.md)
- [OpenAPI Specification](docs/API.md)
- [Installation Guide](docs/INSTALL.md)
- [Upgrade Guide](docs/UPGRADE.md)
- [Uninstallation Guide](docs/UNINSTALL.md)

---

## License

[Apache 2.0](LICENSE)
