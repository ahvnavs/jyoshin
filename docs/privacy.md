# Privacy, Safety and Telemetry Policy

---

## 1. Zero Telemetry
Kazeshini **never transmits telemetry, analytics, usage metrics, or error reports**.
Data never leaves your machine unless you explicitly configure an export destination.

---

## 2. Read-Only Safety Guarantee
- Kazeshini operates with read-only filesystem descriptors.
- In stateless mode (default), zero bytes are written to persistent disk.
- Remediation commands are presented for human execution only; Kazeshini never invokes modification commands.

---

## 3. Secret Scrubbing in Export Bundles
When running `kazeshini bugreport` or exporting summaries:
- Passwords, authentication tokens, API secrets, and private keys (`/etc/shadow`, `id_rsa`) are stripped.
- The output file is written with strict `0600` permissions (owner read/write only).

