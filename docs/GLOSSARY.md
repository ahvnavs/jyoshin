# Kazeshini Terminology & Wording Glossary

> **Single Source of Truth for Terminology**:
> Kazeshini strictly describes the machine, never the person who configured it. All user-facing surfaces (CLI, API, UI, and exported reports) strictly use standardized terms defined in [`data/wording.yaml`](../data/wording.yaml) and [`internal/wording/wording.go`](../internal/wording/wording.go).

---

## 1. Primary Navigation Domains

User interfaces and inspection categories are organized strictly by functional system domain, not by job role:

| Canonical Domain | Key | Description |
| :--- | :--- | :--- |
| **Overview** | `overview` | High-level system health, Risk Score, visibility summary, and top findings. |
| **Software** | `software` | Installed software inventory, package sources, update candidate versions, and blast radius. |
| **Services** | `services` | Systemd service units, daemon process states, restart counts, and dependencies. |
| **Network** | `network` | Network interfaces, routing table, listening sockets, external exposure, and DNS configuration. |
| **Storage** | `storage` | Block storage devices, mount points, filesystem usage, and inode saturation. |
| **Security** | `security` | Authentication logs, sudo privileges, SSH daemon configuration, and file permissions. |
| **Logs** | `logs` | Application logs and system service logs (bounded and secrets-redacted). |
| **Platforms** | `platforms` | Detected platforms, container runtimes, orchestration engines, and CI runners. |
| **Drift** | `drift` | Discrepancies between declarative desired state and observed actual state. |
| **Audit Log** | `audit` | Cryptographically verified append-only local activity and execution log. |
| **Settings** | `settings` | Local configuration options, API authentication token, and display preferences. |

---

## 2. Health & State Attribution

The top-level operational health of the host is categorized into one of five deterministic states:

| Health State | Definition |
| :--- | :--- |
| **Healthy** | All sensors report normal operation with zero critical or high-risk findings. |
| **Degraded** | System exhibits warning-level issues, unmanaged software, or performance bottlenecks. |
| **Critical** | Immediate attention required: active security exposures, failing units, or capacity exhaustion. |
| **Partial visibility** | One or more sensors were denied access or could not inspect host state (`PARTIAL`). |
| **Unknown** | Insufficient telemetry or uninitialized sensors; state cannot be determined honestly (`UNKNOWN`). |

---

## 3. Risk & Scoring Terms

- **Risk Score (0–100)**: Quantitative measure of host risk and entropy. `0` indicates optimal safety, while `100` represents critical risk.
- **Risk Contributors**: Enumerated list of specific observations contributing points to the Risk Score.
- **Summary**: Concise one-line factual verdict explaining host condition.
- **Diagnostics and Visibility**: Honest reporting of sensor coverage showing `N of M` resources inspected.
- **Guided Triage**: Deterministic diagnostic workflows mapping observed symptoms to specific read-only checks.
- **Unmanaged Software**: Executables or packages installed outside package manager control.
- **Impact Analysis**: Evaluation of blast radius and downstream dependencies before modifying services.

---

## 4. Severities

Standardized finding and check severities:
- **Critical** (`CRITICAL`)
- **High** (`HIGH`)
- **Medium** (`MEDIUM`)
- **Low** (`LOW`)
- **Info** (`INFO`)

---

## 5. Confidence & Attribution (Principle 6)

- **Observed** (`[✓] OBSERVED`): Direct factual evidence from `/proc`, `/sys`, or package databases.
- **Derived** (`[≈] DERIVED`): Deterministically calculated fact from observed states.
- **Inferred** (`[?] INFERRED`): Statistical or heuristic inference accompanied by confidence score.

---

## 6. Prohibited Wording (Phase 34 Ban List)

The following terms and playful phrases are strictly removed from all user-facing surfaces:
- `DevOps`, `DevSecOps`, `Cloud Platform` (Replaced by domain groupings: `Services`, `Network`, `Storage`, `Security`)
- `Chaos` / `Chaos Index` (Replaced by `Risk Score`)
- `Calm` (Replaced by `Healthy`)
- `Briefing` (Replaced by `Overview` / `Summary`)
- `Doctor` (Replaced by `Visibility` / `Diagnostics`)
- `Symptom` (Replaced by `Guided Triage`)
- `Tsumuji-first copy` and playful phrasing (Kept strictly as optional background ASCII pet, default off)

