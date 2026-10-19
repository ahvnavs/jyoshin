# Kazeshini Project Status (Post-Phase 33 Cleanup)

> **Core Purpose:**
> *"Kazeshini tells you, on any Linux server with no setup, what is installed, what is running, what is exposed, what is out of date, and what changed, and how sure it is. Read-only, one binary."*

---

## 1. Executive Summary

Kazeshini has undergone a comprehensive repository-wide inventory and pruning pass according to the approved plan in [`docs/PRUNE_PLAN.md`](docs/PRUNE_PLAN.md).

- **Core Engine**: Fully read-only, deterministic, zero-AI, zero-telemetry server truth engine.
- **Single-Binary Default Build**: All experimental multi-node and mutation subsystems (`kazeshini-actuator`, `fleet`, `plugin`, `oidc`) are strictly gated behind the `experimental` Go build tag. The default binary contains **zero** actuator, controller, plugin, or OIDC code/symbols (`go tool nm` and `strings` verified).
- **Consolidated Documentation**: Fragmented architectural decision records and redundant design guides have been consolidated into foundational documents (`docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/CHAOS_INDEX.md`, `docs/WORDING.md`, `docs/CONFIGURATION.md`).

---

## 2. Quantitative Verification Metrics

| Metric | Before Cleanup | After Cleanup | Change / Notes |
| :--- | :--- | :--- | :--- |
| **Go Code Lines (Default Build)** | 36,386 | 36,307 | Cleaned up dead references and split experimental commands |
| **Binary Size (Default Build)** | 13.50 MB (14,158,947 B) | 13.50 MB (14,158,803 B) | Zero experimental symbols linked into default output |
| **Dependencies (`go.mod`)** | 6 | 6 (3 core runtime: `bbolt`, `sys`, `yaml.v3`) | OIDC stack isolated behind `experimental` build tag |
| **Platform Signatures** | 48 | 42 | Removed 6 cloud-only/non-Linux tools (`windows-dsc`, `aws-cdk`, etc.) |
| **UI Views / Panels** | 14 | 13 | Removed dead `styleguide` developer view |
| **Active Rules** | 20 | 20 | All deterministic detection and forecasting rules active |
| **Documentation Files** | 31 | 27 | Merged redundant ADR, ranking, security, and identity guides |

---

## 3. Subsystem Status & Build Constraints

| Component | Default Build | Experimental Tag (`-tags experimental`) | Role / Purpose |
| :--- | :---: | :---: | :--- |
| **Core Truth Engine (`kazeshini`)** | **Active** | **Active** | Sensors, Provenance Graph, Software Inventory, Local Candidates, Forecasts, Declarative Drift, Diagnostics |
| **Out-of-Process Actuator (`kazeshini-actuator`)** | *Excluded* | **Active** | Optional mutation daemon for applying cryptographically signed plans |
| **Fleet Agent (`kazeshini agent`)** | *Excluded* | **Active** | Outbound-only mTLS snapshot pushing agent |
| **Fleet Controller (`kazeshini controller`)** | *Excluded* | **Active** | Centralized aggregator for fleet status |
| **Plugin Runner (`internal/plugin`)** | *Excluded* | **Active** | Out-of-process sensor plugin isolation runner |
| **OIDC Identity Provider (`internal/auth/oidc.go`)** | *Excluded* | **Active** | Enterprise identity provider and PKCE token exchange |

---

## 4. Verification Evidence

- Full test suite passes cleanly with zero race conditions:
  - Default: `go test -race -count=1 ./...` (56 packages `ok`)
  - Experimental: `go test -race -count=1 -tags experimental ./...` (59 packages `ok`)
- Default binary symbol verification:
  - `go tool nm ./kazeshini | grep -E "(fleet|actuator|plugin|oidc)"` returns **empty**.
  - `strings ./kazeshini | grep -E "kazeshini-actuator|github.com/OWNER/kazeshini/internal/(actuator|fleet|plugin)"` returns **empty**.

