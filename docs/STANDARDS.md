# OpenSSF Best Practices and Standards Compliance

Jyōshin is designed to achieve the OpenSSF Best Practices (Gold tier) and adheres strictly to the Open Source Security Foundation standards.

## 1. Security Architecture & Threat Model
- **Threat Model**: Documented in [`docs/THREAT_MODEL.md`](file:///home/ahvnav/workspace/jyoshin/docs/THREAT_MODEL.md).
- **Security Design**: Documented in [`docs/SECURITY_DESIGN.md`](file:///home/ahvnav/workspace/jyoshin/docs/SECURITY_DESIGN.md).
- **Redaction Engine**: Secrets and credentials are automatically scrubbed via [`internal/redact`](file:///home/ahvnav/workspace/jyoshin/internal/redact/redact.go).

## 2. Cryptographic Signing & Provenance
- **SLSA Level 3 Provenance**: Official SLSA generation integrated in release pipelines.
- **Keyless Signature**: Release checksums and container images signed with Sigstore Cosign via OIDC GitHub Actions identity.
- **Reproducible Builds**: All binary assets compiled with `-trimpath` and reproducible timestamps.

## 3. Sandboxing & Systemd Hardening
- **User Separation**: Runs as dedicated unprivileged `jyoshin` user with no login shell (`/sbin/nologin`).
- **Filesystem Isolation**: `ProtectSystem=strict`, `ProtectHome=read-only`, and `PrivateTmp=true`.
- **Capability Minimization**: Bounded to strictly read-only capabilities (`CAP_DAC_READ_SEARCH` where available), zero ambient capabilities.
- **Resource Constraints**: `MemoryMax=128M`, `CPUQuota=10%`, `IOWeight=20`.

## 4. Automated CI Audits
- **CodeQL Static Analysis**: Nightly and PR static scanning.
- **govulncheck**: Automated Go vulnerability checking in GitHub Actions.
- **Pinned Action SHAs**: All GitHub Actions workflows pin immutable commit hashes.
- **Dependabot**: Automated weekly dependency PRs.

