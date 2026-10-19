# Network Egress & Telemetry Policy

Kazeshini strictly adheres to Directive 5 ("NO NETWORK EGRESS") and Directive 5' ("No egress by default").
**Kazeshini never collects telemetry, never reports usage metrics, and never phones home.**

---

## Exhaustive List of Allowed Outbound Network Dials

Kazeshini will **only** establish outbound network connections in the following four explicit, user-governed cases:

| Egress Trigger | Target Destination | Transport | Default State | Audit Logging |
|---|---|---|---|---|
| **Active Connectivity Probe** | User-specified destination IP / host (e.g. `probe 1.1.1.1:53`) | Raw TCP dial with 3s timeout | Off (Triggered only when operator explicitly clicks or runs probe) | Logged to local audit log with client token identity |
| **Opt-in Release Check** | User-configured URL (`kazeshini update --check --url <url>`) | HTTPS GET with bounded 1 MB limit | Off (Requires explicit flag and user URL parameter) | Logged to terminal |
| **Configured OpenTelemetry Exporter** | User-configured endpoint in `otel.endpoint` | OTLP HTTP/gRPC metric push | Disabled by default (`otel.enabled: false`) | Logged at startup if active |
| **Local Container Engine Socket** | `/var/run/docker.sock` | Local Unix domain socket HTTP | Local filesystem only; no network packets generated | Logged to sensor activity registry |

**Under no circumstances will Kazeshini make any other outbound network request.**
There are zero analytics SDKs, zero crash reporters, zero license checks, and zero background update checks.

