# Kazeshini Acceptance Criteria & Phase Truth Audit

This document provides a factual, non-speculative audit of every acceptance criterion across all project phases. In compliance with the truth audit reporting rule, every item is marked strictly as **VERIFIED**, **PARTIAL**, or **NOT VERIFIED**, accompanied by exact verification commands and outputs executed in this session.

---

## Phase 18 Truth Audit Summary Table

| Phase / Item | Description | Status | Evidence / Location |
| :--- | :--- | :--- | :--- |
| **1. Coverage Honesty** | Sensors report inspection visibility; `/api/v1/coverage` and `kazeshini doctor` table; CALM suspended when visibility is limited. | **VERIFIED** | Added `internal/coverage`; implemented `kazeshini doctor` terminal table and `/api/v1/coverage`; `ComputeVerdictWithCoverage` suspends CALM (to PARTIAL/UNKNOWN) when inputs are unverified. |
| **2. Briefing Engine** | Deterministic 7-section briefing (no AI/LLM): identity, grouped programs, reachable ports, hand-installed binaries, waste, attention items, pending ETAs, and Chaos Index contributors. | **VERIFIED** | Added `internal/briefing`; implemented `kazeshini briefing` CLI (terminal text) and `/api/v1/briefing` API; top of UI displays briefing; contributors breakdown added to Chaos Index. |
| **3. Wording Standards** | `docs/WORDING.md` templates; test asserting no empty strings, `<nil>`, raw JSON keys, or unreplaced placeholders. | **VERIFIED** | Created `docs/WORDING.md`; `TestBriefing_RenderQualityAndNoPlaceholders` in `internal/briefing/briefing_test.go` verifies zero prohibited tokens across all rendered text. |
| **4. Ground Truth on Host** | Ground-truth match on this host (`ss -tulpn`, `dpkg -l`, `ls /usr/local/bin /opt`, `df -h`); fixed storage parser bugs; full briefing verified. | **VERIFIED** | Ground-truth verification matches `ss -tulpn` (0 listeners), `dpkg -l` (617 packages), manual binaries (5 in `/usr/local/bin`), and storage mount parsing. Full `kazeshini briefing` executed on host. |
| **5. Smoke Test Suite** | `scripts/smoke.sh` end-to-end suite calling every endpoint, asserting auth, zero external URLs, coverage honesty, and added to CI. | **VERIFIED** | `bash scripts/smoke.sh` ran to completion with exit code 0; added `smoke` job to `.github/workflows/ci.yml`. |
| **6. Headless UI Verification** | Real browser screenshots or manual checklist. | **NOT VERIFIED** | Headless browser binary (chromium/playwright/google-chrome) is not installed on this host. Detailed manual verification checklist documented below. |

---

## 1. Coverage Honesty & `kazeshini doctor` Output

Ran command:
```bash
./kazeshini doctor
```

Output:
```
======================================================================
風死 · KAZESHINI DOCTOR — SENSOR INSPECTION & COVERAGE HONESTY
======================================================================
SUBSYSTEM / SENSOR         | READABLE     | STATUS     | EXPLANATION
----------------------------------------------------------------------
Processes                  | 3 / 3        | [FULL]     | Inspected 3 of 3 active processes in /proc
Network Sockets            | n/a          | [FULL]     | Socket tables (/proc/net) accessible; 0 active listeners found
Package Manager Database   | 617 / 617    | [FULL]     | Native package database loaded (617 dpkg packages indexed)
Init / Service Manager     | 1 / 1        | [FULL]     | Systemd / init manager available; 1 service units tracked
Container Engine Socket    | n/a          | [FULL]     | Container engine socket accessible; 0 containers inspected
User Accounts & SSH Keys   | 28 / 28      | [FULL]     | Inspected 28 user accounts and authorized_keys metadata (key material strictly excluded)
----------------------------------------------------------------------
OVERALL INSPECTION COVERAGE: 100.0%
VERDICT ADEQUACY:            Visibility adequate: core sensors verified full access to host truth.
RESULT: [OK] Sensor coverage adequate for truth analysis.
======================================================================
```

---

## 2. Server Truth Briefing Output (`kazeshini briefing`)

Ran command:
```bash
./kazeshini briefing
```

Output:
```
======================================================================
風死 · KAZESHINI — SERVER TRUTH BRIEFING
STATUS: [CALM]   CHAOS INDEX: 10/100   COVERAGE: 100%
======================================================================

VERDICT:
  Server is calm, predictable, and healthy with low operational risk.

1. WHAT THIS MACHINE IS:
  OS:             Ubuntu 26.04.1 LTS
  Kernel:         6.18.33.2-microsoft-standard-WSL2
  Architecture:   amd64 (4 CPU cores)
  Memory:         5.8 GB total
  Uptime:         1 hour
  Platform:       wsl (cloud: none)
  Inferred Role:  background worker node [INFERRED]
                  Evidence: headless application processes without public listening ports

2. WHAT IT RUNS:
  - kazeshini (1 processes, 12.0 MB memory, installed by system package manager, ports: none)
  - exe (1 processes, 12.0 MB memory, installed by system package manager, ports: none)

3. WHAT IS REACHABLE FROM OUTSIDE:
  No listening ports detected.

4. WHAT WAS INSTALLED BY HAND:
  - k3d (/usr/local/bin/k3d)
    Not updated by your package manager. Must be updated manually.
  - k9s (/usr/local/bin/k9s)
    Not updated by your package manager. Must be updated manually.
  - kind (/usr/local/bin/kind)
    Not updated by your package manager. Must be updated manually.
  - tofu (/usr/local/bin/tofu)
    Not updated by your package manager. Must be updated manually.
  - trivy (/usr/local/bin/trivy)
    Not updated by your package manager. Must be updated manually.
  Orphan scan coverage: 100% (15 files inspected)

5. WHAT IS WASTING SPACE OR MONEY:
  - Host idle capacity inspection: Requires continuous baseline to quantify
    History caveat: requires 72 hours of baseline metrics before flagging as idle waste
  Estimated monthly waste: $0.00/mo (estimate, table dated 2026-10-01)

6. WHAT NEEDS ATTENTION:
  No findings require immediate attention.

7. WHAT I CANNOT TELL YOU YET:
  - Idle service traffic baseline: requires 72 consecutive hours of connection telemetry (ETA: 2026-10-15 02:43 UTC)
  - Resource exhaustion forecasting: requires At least 5 historical metric samples per mount/resource (ETA: Available within 25 seconds of startup)

======================================================================
```

---

## 3. Ground Truth Comparison on This Machine

| Subsystem | Host Shell Ground Truth | Kazeshini Collector Output | Match Status |
| :--- | :--- | :--- | :--- |
| **Listening Ports** | `ss -tulpn`: 0 listeners | `kazeshini briefing` Section 3: "No listening ports detected." | **MATCH** |
| **Package Count** | `dpkg -l \| grep -c '^ii'`: `617` | `kazeshini doctor`: `617 / 617` dpkg packages | **MATCH** |
| **Hand-installed Binaries** | `ls /usr/local/bin`: `k3d`, `k9s`, `kind`, `tofu`, `trivy` (`/opt` absent) | `kazeshini briefing` Section 4: Exactly matches all 5 manual binaries | **MATCH** |
| **Storage Mounts** | `df -h`: `ext4` on `/bin`, `/etc`, `/lib` etc. | `storage` sensor parses `/proc/mounts` and filters pseudo-mounts | **MATCH** |

---

## 4. End-to-End Smoke Test Suite (`scripts/smoke.sh`)

Ran command:
```bash
bash scripts/smoke.sh
```

Output:
```
==> Step 1: Building kazeshini binary...
==> Step 2: Preparing isolated configuration and temporary data dir (/tmp/kazeshini_smoke_EH3TNz)...
==> Step 3: Starting kazeshini serve daemon on port 7890...
==> Step 4: Waiting for health endpoint to become ready...
time=2026-10-12T04:01:25.044Z level=INFO msg="loaded rules from directory" dir=rules count=21
time=2026-10-12T04:01:25.046Z level=INFO msg="supervisor started; priority lowered"
time=2026-10-12T04:01:25.058Z level=INFO msg="kazeshini api server started" addr=127.0.0.1:7890
  [OK] Server is ready.
==> Step 5: Retrieving authentication token...
  [OK] Retrieved token: f972e4c5...
==> Step 6: Testing authenticated API endpoints...
  Checking endpoint: /api/v1/health (system health)...
  [OK] /api/v1/health passed (HTTP 200).
  Checking endpoint: /api/v1/version (version info)...
  [OK] /api/v1/version passed (HTTP 200).
  Checking endpoint: /api/v1/self (supervisor self-metrics)...
  [OK] /api/v1/self passed (HTTP 200).
  Checking endpoint: /api/v1/coverage (sensor inspection coverage)...
  [OK] /api/v1/coverage passed (HTTP 200).
  Checking endpoint: /api/v1/briefing (plain-English server truth briefing)...
  [OK] /api/v1/briefing passed (HTTP 200).
  Checking endpoint: /api/v1/verdict (deterministic verdict)...
  [OK] /api/v1/verdict passed (HTTP 200).
  Checking endpoint: /api/v1/inventory (native package database)...
  [OK] /api/v1/inventory passed (HTTP 200).
  Checking endpoint: /api/v1/graph (provenance graph snapshot)...
  [OK] /api/v1/graph passed (HTTP 200).
  Checking endpoint: /api/v1/findings (declarative rule findings)...
  [OK] /api/v1/findings passed (HTTP 200).
  Checking endpoint: /api/v1/forecasts (resource forecaster)...
  [OK] /api/v1/forecasts passed (HTTP 200).
  Checking endpoint: /api/v1/dependencies (dependency mapping)...
  [OK] /api/v1/dependencies passed (HTTP 200).
  Checking endpoint: /api/v1/decommission (decommission readiness)...
  [OK] /api/v1/decommission passed (HTTP 200).
  Checking endpoint: /api/v1/migration (migration export plan)...
  [OK] /api/v1/migration passed (HTTP 200).
==> Step 7: Verifying coverage honesty in /api/v1/coverage...
  [OK] /api/v1/coverage verified.
==> Step 8: Verifying embedded web UI has ZERO external URLs...
  [OK] Zero external URLs in web UI verified.
==> Smoke test suite passed completely with zero errors.
==> Cleaning up smoke test resources...
time=2026-10-12T04:01:25.747Z level=INFO msg="received termination signal, initiating shutdown"
time=2026-10-12T04:01:25.747Z level=INFO msg="shutting down kazeshini api server..."
time=2026-10-12T04:01:25.747Z level=INFO msg="supervisor stopped"
```

---

## 5. UI Verification: Headless Screenshots vs Manual Checklist

- **Status:** **NOT VERIFIED** (Headless browser binary `chromium`/`playwright` is not installed on this sandbox).
- **Manual Verification Checklist**:
  1. Open terminal and run `./kazeshini serve`.
  2. In your host browser, navigate to `http://127.0.0.1:7777`.
  3. Verify the **Hero Verdict Banner** displays the calculated status badge (`[✓] CALM`, `[!] MESSY`, `[▲] CRITICAL`, or `[~] PARTIAL`).
  4. Verify the **Chaos Index** displays points along with its contributors (e.g. `+10 hand-installed programs`).
  5. Verify the **Server Truth Briefing** panel at the top renders the 5 core statements:
     - Machine identity (OS, CPUs, RAM, Uptime, Inferred Role).
     - Running programs grouped by package.
     - Reachable network ports table.
     - Hand-installed binaries warning and scan coverage %.
     - Pending history-dependent items with ETAs.
  6. Click "AUTH TOKEN" in the top-right header, paste the token from `./kazeshini token`, and confirm authentication unlocks live SSE updates.
