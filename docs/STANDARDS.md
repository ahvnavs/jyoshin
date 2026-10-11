# OpenSSF Best Practices and Standards Alignment (Targeted)

Kazeshini is designed toward alignment with OpenSSF Best Practices (targeting the Gold tier criteria) and adheres to Open Source Security Foundation recommendations.

> [!NOTE]
> Formal badge certification has not yet been applied for or granted. The items below represent internal architectural alignment, self-assessment, and automated CI checks implemented in the repository.

## 1. Security Architecture & Threat Model
- **Threat Model**: Documented in [`docs/THREAT_MODEL.md`](file:///home/ahvnav/workspace/kazeshini/docs/THREAT_MODEL.md).
- **Security Design**: Documented in [`docs/SECURITY_DESIGN.md`](file:///home/ahvnav/workspace/kazeshini/docs/SECURITY_DESIGN.md).
- **Redaction Engine**: Secrets and credentials are automatically scrubbed via [`internal/redact`](file:///home/ahvnav/workspace/kazeshini/internal/redact/redact.go).

## 2. Cryptographic Signing & Provenance
- **SLSA Level 3 Provenance (Targeted)**: Release workflows define provenance generation steps via GitHub Actions.
- **Keyless Signature**: Release checksums and container images configured for signing with Sigstore Cosign via OIDC GitHub Actions identity.
- **Reproducible Builds**: All binary assets compiled with `-trimpath` and reproducible timestamps.

## 3. Sandboxing & Systemd Hardening
- **User Separation**: Runs as dedicated unprivileged `kazeshini` user with no login shell (`/sbin/nologin`).
- **Filesystem Isolation**: `ProtectSystem=strict`, `ProtectHome=read-only`, and `PrivateTmp=true`.
- **Capability Minimization**: Bounded to strictly read-only capabilities (`CAP_DAC_READ_SEARCH` where available), zero ambient capabilities.
- **Resource Constraints**: `MemoryMax=128M`, `CPUQuota=10%`, `IOWeight=20`.

## 4. Automated CI Audits
- **CodeQL Static Analysis**: Nightly and PR static scanning.
- **govulncheck**: Automated Go vulnerability checking in GitHub Actions.
- **Pinned Action SHAs**: All GitHub Actions workflows pin immutable commit hashes.
- **Dependabot**: Automated weekly dependency PRs.

