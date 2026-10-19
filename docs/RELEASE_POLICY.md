# Kazeshini Release, Versioning & Deprecation Policy

Kazeshini adheres strictly to Semantic Versioning (SemVer 2.0.0).

---

## 1. Release Cadence & Versioning

- **Patch Releases (`vX.Y.Z`):** Bi-weekly or as needed for critical CVEs and bug fixes. Backwards-compatible bug fixes only; zero API/CLI breaking changes.
- **Minor Releases (`vX.Y.0`):** Monthly or quarterly milestones. Adds new read-only inspection sensors or platform signatures. Fully backwards-compatible.
- **Major Releases (`vX.0.0`):** Reserved for fundamental architectural shifts. Breaking changes require a minimum 6-month advance notice.

---

## 2. Deprecation Policy

- Any CLI flag, REST API endpoint, or wording identifier marked for deprecation must remain functional with a clear warning for at least **one full minor release cycle** before removal.
- Removed APIs must return structured `KZ-1xxx` errors directing users to replacement mechanisms.

---

## 3. Maintenance Support Windows

- The latest minor version receives active bug fixes and security backports.
- Previous minor releases receive critical security backports for a minimum of 6 months following the release of the succeeding minor version.

