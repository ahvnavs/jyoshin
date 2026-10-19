# Understanding the Results

---

## 1. Health Status & Verdict
- **Healthy `[✓]`:** No critical or high severity findings. Visibility is adequate.
- **Degraded `[!]`:** Non-critical warnings, configuration drift, or unmanaged packages detected.
- **Critical `[▲]`:** High-severity exposures (e.g. world-writable service files, exposed unauthenticated databases).
- **Partial Visibility `[?]`:** Sensor inspection was restricted by Linux permissions; "Healthy" status is deliberately suspended to remain honest.

---

## 2. Risk Score (0 - 100)
Calculated deterministically from weighted finding severities, open exposure counts, failed units, and unmanaged executables:
- `0 - 25`: Normal operations.
- `26 - 69`: Action recommended.
- `70 - 100`: Urgent attention needed.

---

## 3. The 8-Field Finding Card Standard
Every finding follows one consistent layout:
1. **Severity:** Critical, High, Medium, Low, Info.
2. **Title:** Plain-English issue description.
3. **Result:** One-sentence summary.
4. **Impact:** What happens if left unaddressed.
5. **Recommended Action:** Exact shell command to resolve (shown only, never run).
6. **Evidence:** Provenance source file or syscall descriptor.
7. **Confidence:** Attribution label (`OBSERVED`, `DERIVED`, `INFERRED`).
8. **Visibility:** Coverage fraction (N of M inspected entities).

