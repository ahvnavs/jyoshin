# Legal & Compliance Notices

---

## 1. Trademark & Name Disclaimers
- **Project Name:** *Kazeshini* (風死) is an open-source software project dedicated to read-only Linux system observability and server truth.
- **Anime / Manga Disclaimers:** *Kazeshini* is an independent open-source software project and is **not affiliated, associated, authorized, endorsed by, or in any way officially connected** with Tite Kubo, Shueisha, Studio Pierrot, TV Tokyo, or any of their subsidiaries or affiliates concerning the manga/anime franchise *Bleach*.
- **Linux:** Linux® is the registered trademark of Linus Torvalds in the U.S. and other countries.
- All product names, logos, brands, and registered trademarks mentioned within Kazeshini rules and platform signatures are property of their respective owners. Their mention does not imply endorsement or affiliation.

---

## 2. Privacy Policy & Zero Telemetry Guarantee
- **What We Collect:** Nothing. Zero bytes of operational, telemetry, analytics, or behavioral data are collected.
- **What We Transmit:** Nothing leaves the host machine by default. Kazeshini does not contact remote servers, registries, crash collection endpoints, or phone-home beacons.
- **Sanitized Sharing:** When operators generate bug reports (`kazeshini bugreport`) or technical summaries, sensitive secrets (passwords, auth tokens, SSH keys) are stripped before saving to local disk only.

---

## 3. Cryptography & Export Compliance Notice
Kazeshini includes standard, open-source cryptographic capabilities implemented using standard Go cryptography libraries:
- **Algorithms Used:**
  - `SHA-256` / `SHA-512` (FIPS 180-4) for data integrity verification and cryptographic audit logging.
  - `Ed25519` (RFC 8032) for signature verification of published releases and signed manifests.
  - `TLS 1.3` (RFC 8446) for authenticated HTTPS daemon endpoints and opt-in queries.
- **Classification Notice:** This software is provided under open-source license Apache-2.0 and is publicly available under U.S. Export Administration Regulations (EAR) § 742.15(b) and License Exception TSU / ENC.

