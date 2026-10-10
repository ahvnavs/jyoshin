# Security Design Specification

## Principles
1. **Unprivileged by Default**: Jyōshin never runs as `root`. The installer provisions a dedicated `jyoshin` system user.
2. **Deterministic & Explainable**: Rules are purely declarative YAML. No AI, LLM, or dynamic script interpreters are permitted.
3. **Local-First Zero Egress**: Jyōshin never connects outbound to external telemetry servers. All assets are embedded locally.

## Kernel Capabilities & Graceful Degradation
| Capability | Purpose | Behavior When Denied / Withheld |
| :--- | :--- | :--- |
| `CAP_DAC_READ_SEARCH` | Inspect `/proc/<pid>/fd` and `/proc/<pid>/environ` of other users | Degrades gracefully: skips process file descriptors and reports status as `unknown`, with reason `permission_denied`. |
| `CAP_NET_ADMIN` | Read detailed socket inode ownership in netlink | Degrades to `/proc/net/tcp` socket parsing without inode translation. |

## Redaction Architecture
Every API response, event watcher alert, and generated report passes through [`internal/redact`](file:///home/ahvnav/workspace/jyoshin/internal/redact/redact.go):
- Passwords, Bearer tokens, private keys (`id_rsa`, `id_ed25519`, `*.pem`), and cloud credentials are substituted with `[REDACTED]`.
- Non-secret metadata (such as file paths and ownership) is retained for auditability.

