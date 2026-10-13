# Kazeshini Actuator Threat Model & Security Architecture

**Status:** Normative / Architecture Decision  
**Principles Enforced:** 2, 2', 3, 5, 6, 13, 14, 16, 17  
**Scope:** Phase 27 - Host Remediation Actuator Service

---

## 1. Executive Summary & Security Boundary

In strict adherence to **Principle 2'** (*"Core is read-only. Any change to the host happens only in the separate opt-in Actuator process, never in core"*), Kazeshini strictly segregates observation and analysis from execution:
- **`kazeshini` (Core)**: Always unprivileged, strictly read-only, serves HTTP/API/UI. It possesses **zero capability** to mutate files, system services, or host packages.
- **`kazeshini-actuator` (Actuator)**: An opt-in, disabled-by-default, separate systemd service executing with minimal necessary host privileges. It possesses **zero network egress**, **no HTTP listeners**, and communicates exclusively via a root-owned Unix domain socket (`/run/kazeshini/actuator.sock`, mode `0600` or `0660` for a dedicated authorized group).

```
+------------------------------------+          +-----------------------------------------+
|          kazeshini (Core)          |          |        kazeshini-actuator (Host)        |
|  - Unprivileged user (kazeshini)   |          |  - Separate process & systemd unit      |
|  - Strictly READ-ONLY              |          |  - Opt-in, disabled by default          |
|  - Observes, diffs, plans          |          |  - Root / elevated capabilities         |
|  - Ed25519 signature verification  |          |  - Unix socket only (0600 / 0660)       |
|  - Serves HTTP / Web UI            |          |  - ZERO HTTP listeners, ZERO egress     |
+------------------------------------+          +-----------------------------------------+
                  |                                                  |
                  |  Signed Execution Envelope (ed25519 + Nonce)     |
                  +=================================================>+
                    /run/kazeshini/actuator.sock
```

---

## 2. Threat Analysis & Attacker Personas

### Attacker Persona A: Compromised Core Web / API Service
* **Vector:** Remote attacker gains arbitrary code execution inside the `kazeshini` unprivileged core daemon via a web/API vulnerability.
* **Goal:** Escalate privileges to root and modify the operating system.
* **Mitigation:**
  1. The Actuator does not accept arbitrary instructions from Core.
  2. Every plan sent to the Actuator must be cryptographically signed with an Ed25519 Approver private key (`kazeshini-actuator approve`). The private key is never stored in Core memory or on disk accessible by Core.
  3. The Actuator strictly re-verifies all preflights (target host machine ID, plan hash, expiry timestamp, replay nonce, and drift check).
  4. Even if an attacker compromises Core, they cannot mint valid signed plans.

### Attacker Persona B: Malicious or Compromised Administrator / Rogue Plan
* **Vector:** An operator or rogue script attempts to remove protected system components (e.g. `systemd`, `libc6`, `openssh-server`, active kernel) or inject destructive shell commands.
* **Goal:** Cripple the server or establish persistence.
* **Mitigation:**
  1. **Strict Operation Allow-List**: No shell (`sh -c`) is ever invoked. Commands are executed via absolute paths with fixed, immutable argument templates.
  2. **Invariant Package Blocklist**: `protectedPackages` (kernel in use, sshd, libc, init, apt/dpkg) are enforced in Actuator preflight; any plan touching them is unconditionally rejected.
  3. **No Network/Firewall/SSH mutations in v1**: Any operation targeting network interfaces, SSH configuration, or firewall rules is rejected by policy.

### Attacker Persona C: Replay & Race Conditions (TOCTOU)
* **Vector:** An attacker intercepts a previously authorized valid signed plan from audit logs and replays it later, or host state drifts between approval and execution.
* **Goal:** Trigger state changes outside maintenance windows or when packages are incompatible.
* **Mitigation:**
  1. **Nonce Tracking**: The Actuator maintains a persistent replay cache of observed nonces. Replaying a signed envelope fails immediately.
  2. **Short-Lived Expiry**: Approval signatures carry a strict expiry (default 15 minutes). Expired plans fail preflight.
  3. **Mandatory Preflight Re-Observation**: The Actuator re-reads host state before touching a package. If host state has drifted from the plan's preconditions (e.g. package version changed, package manager locked, disk space insufficient), the entire run aborts before executing any step.

### Attacker Persona D: Audit Tampering
* **Vector:** An operator executes a plan and attempts to delete or alter evidence of the change.
* **Mitigation:**
  1. Append-only, SHA-256 hash-chained JSON Lines audit log (`/var/log/kazeshini/actuator-audit.log`, mode `0600`).
  2. Every entry embeds the previous record's cryptographic hash, the approver identity, plan hash, step argv, exit status, and duration.
  3. Offline verification tool: `kazeshini-actuator audit verify` validates chain integrity.

---

## 3. Cryptographic Specification: Plan Signing & Envelopes

Every mutation submitted to `/run/kazeshini/actuator.sock` must be wrapped in an `ExecutionEnvelope`:

```json
{
  "envelope_version": "1.0",
  "plan_hash": "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
  "plan": { ... },
  "host_id": "7f8b9e... (matches /etc/machine-id)",
  "nonce": "9f21ac6a-f2b7-4a09-90b9-11234b3e8c90",
  "approver": "ops-admin@infra.internal",
  "approved_at": "2026-10-13T13:50:00Z",
  "expires_at": "2026-10-13T14:05:00Z",
  "signature": "base64-encoded ed25519 signature over canonical envelope digest"
}
```

### Verification Rules:
1. `expires_at > now()` (default 15 minute lifetime).
2. `host_id == /etc/machine-id`.
3. `nonce` has not been seen before in the actuator replay cache.
4. `plan_hash == sha256(canonical(plan))`.
5. `ed25519_verify(approver_pubkey, canonical(envelope_fields), signature) == true`.

---

## 4. Operation Allow-List & Sandbox Constraints

The Actuator executes commands **only** using direct `execve`-style invocations without shell interpolation.

| Action Category | Permitted Binaries | Permitted Arguments / Pattern | Blocked Invariants |
| :--- | :--- | :--- | :--- |
| **Package Upgrade** | `/usr/bin/apt-get`, `/usr/bin/dnf`, `/usr/bin/pacman`, `/sbin/apk` | Fixed dry-run and apply arguments with regex-validated package name | Shell metacharacters, option flags (`-o`, `--`), protected packages |
| **Package Install** | Package manager binaries | Fixed install arguments with validated package name | Unapproved repositories, arbitrary binary paths |
| **Package Removal** | Package manager binaries | Fixed purge/remove arguments with validated package name | Protected system components (`libc6`, `systemd`, `sshd`, active kernel) |
| **Service Control** | `/usr/bin/systemctl` | `start <unit>`, `stop <unit>`, `restart <unit>`, `enable <unit>`, `disable <unit>` | Regex-validated unit names; `systemd-journald`, `ssh`, `kazeshini-actuator` units protected |

---

## 5. Execution Lifecycle & Stop-The-World Safety

1. **Preflight Step**:
   - Check sentinel kill-switch (`/etc/kazeshini/actuator.disabled`).
   - Check package manager lock (`/var/lib/dpkg/lock-frontend`, etc.).
   - Verify minimum root filesystem disk capacity (at least 200 MB free).
   - Re-observe target package version; assert it equals `plan.from_version`.
2. **Step Execution**:
   - Execute strictly 1 step at a time.
   - Enforce bounded step timeout (default 300s).
   - Stream sanitized/redacted stdout/stderr to audit recorder.
3. **Failure Policy**:
   - On non-zero exit code or timeout: **IMMEDIATELY HALT**. Do not continue to downstream steps.
   - If contact with child process is interrupted or state is ambiguous: return status `UNCERTAIN` and alert operator to manually inspect machine state.
4. **Kill Switch**:
   - `kazeshini-actuator disable` or presence of `/etc/kazeshini/actuator.disabled`.
   - Running executions check the sentinel before every step boundary and abort immediately if present.
5. **Rollback Policy**:
   - In accordance with Principle 17 (*"Never auto-apply"*), the Actuator **never automatically rolls back**.
   - Upon failure, it outputs a concrete, human-actionable `RollbackPlan` which must be signed and approved by the human operator.

---

## 6. Audit Trail Architecture

All operations are recorded to an append-only log `/var/log/kazeshini/actuator-audit.log`:
- File permissions `0600`, owned by `root:root`.
- Hash-chained: each record includes `prev_hash: sha256(previous_record_bytes)`.
- Format: JSON Lines.
- Fields: `timestamp`, `plan_id`, `plan_hash`, `approver`, `step_index`, `action`, `argv`, `exit_code`, `duration_ms`, `status`, `prev_hash`, `entry_hash`.
- CLI Verification: `kazeshini-actuator audit verify` computes and validates the entire cryptographic chain.

