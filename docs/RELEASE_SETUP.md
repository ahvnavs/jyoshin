# Production Release Setup & Verification Guide

This guide documents the procedures and placeholders for signing, verifying, and publishing official releases of Kazeshini.

---

## 1. Configured Domains & Registries (Placeholders)
Do not hardcode production domains or credentials until ownership is verified and secrets are provisioned in GitHub Actions:

- **Download Host / Repository:** `https://releases.example.org`
- **Container Registry:** `ghcr.io/OWNER/kazeshini`
- **Security Contact:** `security@example.org`
- **GPG Signing Key ID:** `<GPG_RELEASE_KEY_ID>`
- **Cosign Identity Issuer:** `https://token.actions.githubusercontent.com`

---

## 2. Verifying a Release in 3 Copy-Paste Lines

A user can verify the authenticity and integrity of their downloaded Kazeshini binary using standard shell utilities without installing any extra tooling:

```bash
curl -fsSLO https://releases.example.org/kazeshini-linux-amd64
curl -fsSL https://releases.example.org/checksums.txt | sha256sum --check --ignore-missing
./kazeshini-linux-amd64 verify --checksum-file checksums.txt
```

---

## 3. Supply Chain Security Invariants

Official releases generated via GitHub Actions produce:
1. **Reproducible Static Binaries:** Built with `CGO_ENABLED=0`, `-trimpath`, and empty `-buildid=`.
2. **SHA-256 Checksums:** Written to `checksums.txt`.
3. **Cosign Keyless Signature:** Attested with Sigstore Fulcio/Rekor and stored in `checksums.bundle`.
4. **Software Bill of Materials (SBOM):** Both CycloneDX (`kazeshini-sbom.cyclonedx.json`) and SPDX (`kazeshini-sbom.spdx.json`).
5. **SLSA Provenance:** Cryptographically attested build provenance.

