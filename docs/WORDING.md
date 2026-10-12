# Kazeshini Wording Standards & Deterministic Templates

This document specifies the exact language, human-centric units, and deterministic formatting rules applied across Kazeshini CLI outputs, API briefing payloads, and web UI screens.

---

## Non-Negotiable Human-First Wording Principles

1. **No Raw Jargon or Unrendered Artifacts**:
   - Zero occurrences of `<nil>`, raw JSON keys (`null`, `undefined`), empty strings (`""`), or unpopulated template markers (`{placeholder}`).
   - Every metric or technical status code carries a plain-English explanation or human unit.
2. **Human Units by Default**:
   - Storage and Memory: Bytes are rendered as `B`, `KB`, `MB`, `GB`, `TB` (e.g., `1.2 GB`, `943.0 GB`).
   - Durations & Time deltas: Rendered as plain sentences (e.g. `"3 hours ago"`, `"12 days"`, `"45 minutes"`, `"just now"`).
   - CPU: Core counts rendered as `4 CPU cores`.
3. **Fact vs Inference Transparency**:
   - Inferred roles or heuristics are labeled explicitly with `[INFERRED]` or `INFERRED`, accompanied by the underlying evidence (e.g., `INFERRED: database (listening on port 5432, 1 postgres process)`).
   - Provenance certainty labels: `[OBSERVED]`, `[DERIVED]`, `[INFERRED]`.
4. **Coverage Honesty**:
   - "Found nothing" is distinguished from "couldn't look".
   - If inspection coverage is inadequate, the verdict status reports `PARTIAL` or `UNKNOWN` with a clear explanation of limited visibility instead of claiming `CALM`.

---

## 7 Core Briefing Sections & Exact Templates

### 1. What This Machine Is
- **Template**:
  ```
  OS: {Distro} ({DistroVersion})
  Kernel: {KernelVersion}
  Architecture: {Arch} ({CPUCount} CPU cores)
  Memory: {UsedRAM} / {TotalRAM} ({RAMPercent}% used)
  Uptime: {HumanUptime} (booted {BootTimeAgo})
  Platform: {Virtualization} / {CloudProvider}
  Role: {InferredRole} [INFERRED] (evidence: {RoleEvidence})
  ```

### 2. What It Runs
- **Grouped Process Entities**:
  Processes sharing identical program binaries, services, or package origins are grouped:
  - **Template**:
    ```
    {ProgramName} {Version} ({ProcessCount} processes, {RSSMemory}, listening on {Ports}, installed by {Origin}, running since {Duration})
    ```

### 3. What Is Reachable From Outside
- **Table of Exposed Ports**:
  ```
  Port      | Protocol | Program / Process | Exposure Class | Interface
  ---------------------------------------------------------------------
  {Port}    | {Proto}  | {Program}         | {Class}        | {Address}
  ```

### 4. What Was Installed By Hand
- **Orphan / Manual Drops**:
  - **Template**:
    ```
    {BinaryName} ({Path}) — Not updated by your package manager ({Manager}). Inspect or package manually.
    ```
  - **Scan Coverage**:
    ```
    Orphan scan coverage: {CoveragePercent}% ({FilesInspected} files inspected in high-risk directories).
    ```

### 5. What Is Wasting Space or Money
- **Reclaimable Disk**:
  ```
  Old kernel images: {ReclaimableKernelsCount} reclaimable ({ReclaimableDiskGB} GB in /boot).
  Log files & caches: {ReclaimableLogsGB} GB reclaimable across /var/log.
  ```
- **Idle Capacity & Financial Estimates**:
  ```
  Idle host capacity: {IdleSummary} (History caveat: requires 72h baseline history to confirm).
  Estimated waste: ${EstimatedUSD}/mo (Estimate, table dated 2026-10-01).
  ```

### 6. What Needs Attention
- **At Most 5 Findings (Rest Collapsed)**:
  Each finding renders the strict triple format:
  ```
  [{SEVERITY}] {What}
    So what:  {SoWhat}
    Now what: {CopyableCommand} (Risk: {RiskLevel}, Reversible: {Reversible})
    Proof:    [{CERTAINTY}] {EvidenceSummary} (confidence: {Confidence})
  ```

### 7. What I Can't Tell You Yet
- **History-Dependent Telemetry**:
  ```
  Idle service detection: Needs 72h traffic baseline ({RemainingHours}h remaining, ETA: {ETA}).
  Resource exhaustion forecasting: Needs >= 5 samples ({CollectedSamples}/5 collected, ETA: {ForecastETA}).
  ```

