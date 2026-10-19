# Kazeshini Standard Error Codes & Diagnostics (docs/ERRORS.md)

Every error reported by Kazeshini adheres to Principle 10 (*"Graceful degradation"*) and Principle 12 (*"Human-first"*).
No error reaches the user as an unformatted Go runtime error string, stack trace, or raw syscall number.

Every error follows a strict 3-part format:
1. **What happened**: A plain-English factual statement of what failed.
2. **Why**: The root cause (e.g. Linux permission barrier, missing kernel interface, invalid user input).
3. **What to do next**: The exact command or step the user can run to proceed.

---

## Error Catalog (KZ-1xxx Series)

| Error Code | Error Title | What Happened | Why | What To Do Next |
| :--- | :--- | :--- | :--- | :--- |
| **KZ-1001** | Platform Incompatible | Operating system is not Linux. | Kazeshini inspects Linux procfs and sysfs directly. | Run Kazeshini on a Linux server (kernel 3.10 or newer). |
| **KZ-1002** | Procfs Unavailable | `/proc` filesystem was not found. | Kernel procfs mount is absent, or running in an unmounted minimal container. | Mount procfs (`mount -t proc proc /proc`) or run container with `/proc` mounted. |
| **KZ-1003** | Permission Denied | Cannot read protected system database or socket table. | Current unprivileged user account lacks read permissions for this resource. | Run `sudo kazeshini` for full root visibility, or continue with degraded partial visibility. |
| **KZ-1004** | Port Binding Failed | Cannot bind local HTTP server to requested port. | The port is already held by another application on `127.0.0.1`. | Run `kazeshini serve --port <free-port>` or use default port auto-allocation `kazeshini open`. |
| **KZ-1005** | Manifest Invalid | Desired state manifest could not be parsed. | Syntax error or schema violation in YAML file. | Run `kazeshini desired lint <file>` to view exact validation errors. |
| **KZ-1006** | Invalid Parameter | Command parameter rejected by security safety guard. | Parameter contains forbidden characters (`;`, `\|`, `&`, `..`, or shell metacharacters). | Use plain alphanumeric names without shell syntax or path traversal. |
| **KZ-1007** | Network Probe Blocked | Outbound probe dial was blocked by security policy. | Destination IP is a forbidden target (cloud metadata `169.254.169.254`, loopback, or link-local). | Probes are only permitted to explicit, user-specified public or corporate gateway targets. |
| **KZ-1008** | Authentication Failure | Missing or invalid API access token. | Bearer token provided in header does not match active session or token store. | Run `kazeshini token` to display the valid local authentication token. |
| **KZ-1009** | Rate Limited | Too many failed requests from client IP. | Brute-force protection temporarily locked the connecting IP. | Wait for the lockout period (60 seconds) to expire before retrying. |
| **KZ-1010** | Request Entity Too Large | Request body exceeds memory safety limits. | Request body sent to endpoint exceeded the 2 MB security threshold. | Ensure uploaded configuration or log payloads are under 2 MB. |

