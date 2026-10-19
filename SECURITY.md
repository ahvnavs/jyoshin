# Security Policy & Coordinated Vulnerability Disclosure

Kazeshini adheres strictly to Principle 2 ("READ-ONLY"), Principle 3 ("NEVER HARM THE HOST"), and Principle 5 ("NO NETWORK EGRESS"). Any bug that compromises host safety, exposes unauthorized endpoints, leaks host data, or introduces remote command execution is prioritized at maximum severity.

---

## 1. Supported Versions

| Version Branch | Status | Security Patches |
|---|---|---|
| `v0.1.x` | Supported | Active SLA |
| `< v0.1.0` | EOL | Unsupported |

---

## 2. Response SLAs

- **Initial Acknowledgment:** Within **24 hours** of private submission.
- **Triage & Reproduction:** Within **48 hours**.
- **Fix & Advisory Draft (GHSA):** Within **7 business days** for Critical/High severity.
- **Coordinated Public Release:** Within **14 business days** or agreed disclosure window.

---

## 3. Reporting a Vulnerability

**DO NOT** file public GitHub issues for security vulnerabilities.

1. **GitHub Security Advisory (Preferred):** Open a draft advisory under GitHub Repository Security Advisories.
2. **Encrypted Security Contact:** Email `security@<CONFIGURED_DOMAIN>` (see [`docs/RELEASE_SETUP.md`](file:///home/ahvnav/workspace/jyoshin/docs/RELEASE_SETUP.md)).

---

## 4. CVE / GHSA Process

- All verified vulnerabilities are assigned a GitHub Security Advisory (GHSA) and official CVE number.
- Fixes are backported to all active release branches with reproducible release tags.
