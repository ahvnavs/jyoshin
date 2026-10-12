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

## 4. Privilege Model & Capability Trade-offs
### `CAP_SYS_PTRACE`
- **Purpose**: Required on Linux kernels with `yama.ptrace_scope >= 1` or restricted `/proc` configurations to inspect `/proc/<pid>/fd/*` socket symlinks and `/proc/<pid>/exe` targets of processes owned by other users or daemons. Without this capability, non-root `kazeshini` maps only own sockets to PIDs, reducing socket-to-process coverage (`doctor` reports `PARTIAL`).
- **Risk Assessment**: `CAP_SYS_PTRACE` confers the ability to trace or inspect memory of other processes on the host. In untrusted hands, arbitrary memory reading could disclose in-process secrets.
- **Mitigation & Sandboxing**:
  - The service unit enforces `SystemCallFilter=~@debug`, explicitly disabling the `ptrace(2)` and `process_vm_readv(2)` syscalls while allowing `/proc` read-only traversal.
  - `NoNewPrivileges=true` prevents privilege elevation.
  - Strict absence of telemetry or egress network capabilities ensures read values remain strictly local.
  - Optional unprivileged mode: Users who refuse `CAP_SYS_PTRACE` can run unprivileged, accepting partial socket coverage honest reports.


