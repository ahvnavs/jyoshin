# What Kazeshini Does and Does Not Do

---

## What It Does
1. **Reads System State Directly:** Queries `/proc`, `/sys`, socket descriptors, and local package managers without modifying any files.
2. **Deterministic Provenance Attribution:** Strict evidence and certainty tagging (`OBSERVED`, `DERIVED`, `INFERRED`).
3. **Explains Every Finding:** Provides plain-English 3-level explanations (Summary, Details, Technical evidence) with actionable commands for human operators.
4. **Protects the Host:** Runs at lowest priority (`nice 19`, `ionice idle`), bounds CPU/memory usage, and exits automatically after inactivity.

---

## What It Does NOT Do
1. **Never Modifies the Host:** Kazeshini is strictly read-only. It never executes remediation commands or alters system configuration.
2. **No AI / LLM / ML in Core:** All analysis is deterministic, rule-based, and explainable.
3. **Zero Network Egress:** Kazeshini has no telemetry, no tracking beacons, no analytics, and does not phone home.
4. **No Vendor Lock-In:** Single static binary with zero external CDN dependencies and embedded SQLite/bbolt storage.

