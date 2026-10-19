# Configuration Guide

Kazeshini reads its configuration from `/etc/kazeshini/kazeshini.json` (or `/etc/kazeshini/kazeshini.yaml`) or command line flags.

## Configuration Schema

```json
{
  "host": "127.0.0.1",
  "port": 7777,
  "allow_remote": false,
  "data_dir": "/var/lib/kazeshini",
  "rules_dir": "/etc/kazeshini/rules.d",
  "log_level": "info",
  "log_format": "text",
  "scan_interval": 60000000000,
  "otel": {
    "enabled": false,
    "endpoint": "localhost:4317",
    "protocol": "grpc"
  }
}
```

## Options Reference

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `host` | string | `127.0.0.1` | Network interface to bind. Refuses non-loopback addresses unless `allow_remote` is `true`. |
| `port` | int | `7777` | TCP port for API and web dashboard. |
| `allow_remote`| bool | `false` | Explicit permission required to listen on non-loopback IP addresses. |
| `data_dir` | string | `/var/lib/kazeshini` | Directory storing local SQLite/bbolt database and token. Permissions: `0700`. |
| `rules_dir` | string | `/etc/kazeshini/rules.d` | Directory containing custom user rule files. |
| `log_level` | string | `info` | Logging verbosity: `debug`, `info`, `warn`, `error`. |
| `log_format` | string | `text` | Logging format: `text` or `json`. |
| `scan_interval`| duration| `60s` | Polling frequency for background sensor scans. |
| `otel.enabled` | bool | `false` | Optional OpenTelemetry metrics export (disabled by default). |
| `otel.endpoint`| string | `localhost:4317` | Local OTLP collector address. |

## Environment Variables
All options can be configured via environment variables:
- `KAZESHINI_HOST`
- `KAZESHINI_PORT`
- `KAZESHINI_ALLOW_REMOTE`
- `KAZESHINI_DATA_DIR`
- `KAZESHINI_RULES_DIR`
- `KAZESHINI_LOG_LEVEL`



---

## Enterprise Identity & Reverse Proxy Authentication

# Enterprise Identity Integration Guide (SAML / Kerberos / LDAP)

**Architecture Directive**: Kazeshini does **NOT** implement complex legacy enterprise protocols (SAML 2.0, Kerberos SPNEGO, LDAP/Active Directory) directly in core code (STDLIB-FIRST, Principle 9). 

Instead, Kazeshini provides first-class support for **Trusted Proxy Header Authentication Mode** and **OpenID Connect (OIDC)**. Modern enterprise identity providers (Okta, Microsoft Entra ID, Ping Identity, Keycloak) natively support OIDC. For legacy environments requiring SAML or Kerberos, a dedicated reverse proxy (such as `oauth2-proxy`, Authelia, Envoy, or an enterprise API Gateway) handles the federation and passes authenticated identity via secured headers to Kazeshini.

---

## 1. Architecture Overview

```
                                  +------------------------------------+
                                  | Enterprise IdP (SAML / Active Dir) |
                                  +------------------------------------+
                                                    ^
                                                    | (SAML 2.0 / SPNEGO)
                                                    v
+------------------+                     +----------------------+                     +---------------------+
|   User Browser   | === HTTPS =========>|   Auth Reverse Proxy | === Unix / mTLS ===>|      Kazeshini      |
|                  |                     |  (oauth2-proxy, etc) |                     |    (Trusted Proxy)  |
+------------------+                     +----------------------+                     +---------------------+
                                            Validates SAML/AD                           Asserts Trusted IP,
                                            Injects Headers:                            Validates HMAC/Secret,
                                            - X-Forwarded-User                          Maps Groups to Roles
                                            - X-Forwarded-Role
                                            - X-Forwarded-Signature
```

---

## 2. Configuration Parameters

In `kazeshini` configuration or flags:

```yaml
auth:
  trusted_proxy:
    enabled: true
    # Strict allow-list of upstream reverse proxy IP addresses or subnets (CIDR)
    # Requests with proxy headers from any other address are immediately REJECTED.
    allowed_proxies:
      - "127.0.0.1/32"
      - "::1/128"
      - "10.0.1.50/32"

    # Header containing the authenticated username/email
    user_header: "X-Forwarded-User"

    # Header containing groups or roles (comma-separated or multiple headers)
    groups_header: "X-Forwarded-Groups"

    # Optional shared secret or HMAC key for signature validation
    shared_secret: "env:KAZESHINI_PROXY_SHARED_SECRET"

    # Role mapping from enterprise groups to Kazeshini roles
    # Roles: viewer, operator, approver, admin
    role_mappings:
      "Domain Admins": "admin"
      "SRE-Approvers": "approver"
      "Operations": "operator"
      "*": "viewer"
```

---

## 3. Setup with `oauth2-proxy` (Example: SAML via Keycloak or Entra ID)

### Step 1: Run `oauth2-proxy`
```bash
oauth2-proxy \
  --provider=keycloak-oidc \
  --client-id=kazeshini \
  --client-secret=$CLIENT_SECRET \
  --oidc-issuer-url=https://idp.internal/realms/corp \
  --upstream=http://127.0.0.1:8080/ \
  --http-address=0.0.0.0:443 \
  --pass-user-headers=true \
  --set-xauthrequest=true
```

### Step 2: Start Kazeshini with Trusted Proxy Mode
```bash
kazeshini serve \
  --trusted-proxy-enabled \
  --trusted-proxy-ip=127.0.0.1 \
  --trusted-proxy-user-header=X-Forwarded-User \
  --trusted-proxy-groups-header=X-Forwarded-Groups
```

---

## 4. Security Guarantees
1. **Spoofing Prevention**: Requests containing proxy authentication headers that originate from unlisted IP addresses are unconditionally rejected (HTTP 403 Forbidden).
2. **Signature Validation**: When `shared_secret` is configured, headers must be accompanied by an HMAC-SHA256 signature calculated over the user and group fields.
3. **Audit Transparency**: The proxy identity, remote client IP, authenticated user, and derived role are written directly to the append-only audit log.

