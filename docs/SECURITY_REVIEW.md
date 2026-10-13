# Kazeshini Security Review & Threat Models (Phase 32)

**Scope:** Actuator, Fleet Controller, Outbound Agents, and Out-of-Process Plugins.

---

## 1. Threat Model: Actuator Service (`kazeshini-actuator`)

See [`docs/ACTUATOR_THREAT_MODEL.md`](ACTUATOR_THREAT_MODEL.md) for full formal specification.
- **Boundary**: Root-owned unix socket `/run/kazeshini/actuator.sock` (0600 / 0660). Zero HTTP listeners, zero network egress.
- **Attacker 1 (Compromised Core Web Daemon)**: Core cannot command Actuator. Every plan requires an ed25519 signature from an external approver key, valid nonce, unexpired timestamp, and machine-id binding.
- **Attacker 2 (Rogue Administrator / Shell Injection)**: Fixed `execve` argument allow-list, zero shell interpolation (`sh -c` forbidden), regex-validated package and unit names, and hardcoded protected package blocklist (`libc6`, `systemd`, `openssh-server`, active kernel).
- **Attacker 3 (Replay / TOCTOU)**: 15-minute signature expiry, persistent replay nonce cache, preflight re-observation verifying exact `from_version`, free disk space (>200 MB), and lockfile state before execution.
- **Attacker 4 (Audit Tampering)**: Append-only hash-chained audit log with `kazeshini-actuator audit verify`.

---

## 2. Threat Model: Fleet Controller & Outbound Agents (`kazeshini controller` & `kazeshini agent`)

- **Boundary**: Outbound-only agent connection over mTLS to the Controller URL.
- **Threat: Rogue Controller commanding unapproved mutations**:
  - The controller *never* issues raw commands or execution shell scripts.
  - The controller only delivers signed `ExecutionEnvelope` objects approved by human approver keys.
  - The agent executes its own local preflight policies (`LocalPolicyPreflight`) and rejects any plan violating local host invariants.
- **Threat: Plan Cross-Contamination (Plan for Host A executed by Host B)**:
  - Every envelope explicitly binds to `plan.target_host_id` and `envelope.host_id` matching `/etc/machine-id`.
  - The agent verifies `target_host_id == local_machine_id` upon pulling; any mismatch immediately aborts with `ErrHostMismatch`.
- **Threat: Unauthorized Agent Enrollment**:
  - Enrollment requires single-use, cryptographically random, expiring tokens (`GenerateEnrollmentToken`).
  - Public keys are registered on first enrollment and bound to host ID.
  - Revocation: The controller maintains a certificate and host revocation list (`RevokeCert`), immediately rejecting revoked identities.
- **Threat: Controller Outage or Denial of Service**:
  - Agents degrade gracefully; failure to reach the controller triggers autonomous local monitoring with zero host disruption.

---

## 3. Threat Model: Out-of-Process Plugins

- **Boundary**: Child processes launched with `exec.CommandContext`, communicating over stdio JSON-RPC.
- **Threat: Rogue or Crashing Plugin impacting Core**:
  - Core supervisor wraps process in strict context timeout (`SIGKILL` on expiry).
  - Bounded stdout reading with `io.LimitReader(r, max_output_bytes)` preventing memory exhaustion.
  - Process crashes (exit code non-zero, SIGSEGV, panic) are isolated: Core marks status `crashed` and continues normal operation.
- **Threat: Supply Chain & Untrusted Binaries**:
  - Plugins require signed manifests.
  - Unsigned plugins are rejected unless `--allow-unsigned-plugins` is explicitly configured.

---

## 4. Static Analysis & Vulnerability Scan Audit

### A. `govulncheck` Results (2026-10-13)
- **Application Code**: 0 vulnerabilities found in Kazeshini codebase.
- **Standard Library**: Reported Go stdlib warnings from the build toolchain (`net/http`, `crypto/tls`, `crypto/x509`); mitigated by loopback binding (`127.0.0.1`), strict timeouts (`ReadHeaderTimeout`), and non-root execution.

### B. `gosec` Security Static Analysis
- **Scanned**: 94 Go files, 26,042 lines of code.
- **Results**:
  - `G115` (integer conversions): Verified bounds on port numbers and PID conversions.
  - `G204` (subprocesses): Confirmed strictly restricted to allow-listed package managers (`/usr/bin/apt-get`, `/usr/bin/dnf`, `/usr/bin/pacman`, `/sbin/apk`, `/bin/systemctl`) with fixed argument vectors and zero shell expansion.
  - `G304` (file path reads): Audited; read-only operations constrained by `fs.RootedFS` or absolute allow-listed system file paths.
  - `G306` (file permissions): Enforced `0600` on audit logs and token files.

---

## 5. Approved Dependencies & Licenses Matrix

| Dependency | Version | License | Justification |
| :--- | :--- | :--- | :--- |
| `go.etcd.io/bbolt` | `v1.4.0` | MIT | Pure-Go embedded ACID KV store, zero CGO. |
| `gopkg.in/yaml.v3` | `v3.0.1` | MIT / Apache-2.0 | Pure-Go YAML parser for rules and desired state. |
| `github.com/coreos/go-oidc/v3/oidc` | `v3.21.0` | Apache-2.0 | Security-vetted generic OIDC discovery, PKCE, and JWKS verification. |
| `golang.org/x/oauth2` | `v0.36.0` | BSD-3-Clause | OAuth2 token exchange primitives. |
| `github.com/go-jose/go-jose/v4` | `v4.1.4` | Apache-2.0 | Cryptographic JSON Web Signature (JWS/JWT) parsing. |
| `golang.org/x/sys` | `v0.29.0` | BSD-3-Clause | Low-level Linux syscalls (`nice`, `ionice`, `prctl`). |

