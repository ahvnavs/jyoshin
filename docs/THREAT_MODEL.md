# Threat Model for Kazeshini

## 1. System Assets
1. **Host Stability & Performance**: Host must never experience CPU thrashing, memory exhaustion, or disk starvation from inspection tasks.
2. **Host Privacy & Confidentiality**: Passwords, private keys, API secrets, and connection credentials residing on the host must never leak.
3. **Engine Integrity**: Rules, findings, and provenance graphs must be deterministic and untampered.

## 2. Adversary Model & Attack Surfaces
- **Untrusted Network Entities**:
  - Kazeshini binds to `127.0.0.1` by default. Remote exposure requires an explicit `--allow-remote` flag.
  - API token authentication (`/var/lib/kazeshini/auth.token`, `0600`) guards sensitive endpoints.
- **Malicious Local Processes**:
  - Malicious processes attempting to exhaust sensor time budgets or trigger panics are isolated via `recover()` circuits and per-cycle execution timeouts.
- **Data Tampering**:
  - Persistent storage (`bbolt`) resides in a `0700` directory owned by the unprivileged `kazeshini` user with `0600` file permissions.

## 3. Mitigation Strategies
- **Read-Only Invariant**: Zero remediation actions, zero modification tools, and `ReadOnlyPaths=/proc /sys`.
- **Secret Redaction**: Every string, environment variable, and finding is scrubbed by the redaction engine before persistence, API exposure, or report generation.
- **Resource Caps**: Enforced by systemd cgroups (`MemoryMax=128M`, `CPUQuota=10%`).

