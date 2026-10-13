# Kazeshini Plugin Contract (v1)

## Architecture Overview
Kazeshini plugins are **out-of-process, read-only observer programs**. They communicate with the Kazeshini core process over standard input/output (`stdio`) or a local root-owned Unix domain socket using versioned JSON-RPC / line-delimited JSON.

Under Kazeshini Non-Negotiable Directives (AGENTS.md):
- **Principle 1**: NO AI / LLM / ML. Deterministic observation logic only.
- **Principle 2 & 2'**: READ-ONLY. Plugins in v1 are observers only. They emit `Resource` objects (or check findings). They never execute remediation or mutate host state.
- **Principle 3 & 4**: NEVER HARM THE HOST & ISOLATION. Plugins run with low execution priority, strict timeouts, bounded memory caps, bounded output limits, and process cancellation. A crashing or misbehaving plugin must never crash the core or impact other plugins.
- **Principle 5**: NO NETWORK EGRESS. Plugins declare whether network egress is requested in their manifest. By default, network egress is disabled and forbidden.

---

## 1. Plugin Manifest Specification

Every plugin executable or directory provides a manifest (`plugin.yaml` or `plugin.json`):

```yaml
name: "k8s-node-observer"
version: "1.0.0"
api_version: "v1"
description: "Inspects local kubelet and containerd static manifests and TLS cert expiry"

# Kinds of declarative resources emitted by this plugin (e.g. Platform, Check, Package)
emits:
  - "Platform"
  - "Check"

# Declared capabilities (least privilege)
capabilities:
  read_paths:
    - "/etc/kubernetes"
    - "/var/lib/kubelet"
    - "/run/containerd"
  exec_allowlist:
    - "/usr/bin/crictl info"
  network:
    enabled: false
    allowed_hosts: []

# Resource caps enforced by Kazeshini Core
limits:
  timeout_seconds: 5
  max_memory_bytes: 67108864 # 64 MB
  max_output_bytes: 1048576  # 1 MB
  cpu_quota_us: 50000        # 50ms per 100ms cycle (where cgroups v2 is available)

# Integrity verification
signature: "" # ed25519 signature of manifest bytes; if missing/unverified, status is marked UNSIGNED
```

### Unsigned vs Signed Plugins
- **Signed Manifests**: Verified against trusted keys loaded in configuration.
- **Unsigned Plugins**: Labeled as `UNSIGNED` in the UI and API. They are rejected unless `--allow-unsigned-plugins` is explicitly passed to the core daemon.

---

## 2. IPC Protocol Specification (v1)

Communication happens via **JSON Lines over stdio** (or Unix socket).

### Request (Core -> Plugin):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "observe",
  "params": {
    "host_id": "demo-server-01",
    "timestamp": "2026-10-13T14:45:00Z"
  }
}
```

### Response (Plugin -> Core):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resources": [
      {
        "kind": "Platform",
        "name": "kubernetes-node",
        "metadata": {
          "labels": {
            "category": "orchestration",
            "support": "adapter"
          }
        },
        "spec": {
          "component": "kubelet",
          "runtime": "containerd"
        },
        "status": {
          "conditions": [
            {
              "type": "Present",
              "status": "True",
              "reason": "KubeletConfigObserved",
              "message": "kubelet configuration active"
            }
          ],
          "observedAt": "2026-10-13T14:45:00Z"
        },
        "provenance": [
          {
            "source": "/etc/kubernetes/kubelet.conf",
            "collector": "plugin:k8s-node-observer",
            "certainty": "OBSERVED"
          }
        ]
      }
    ]
  }
}
```

---

## 3. Core Enforcement & Isolation Guarantees

The Kazeshini Core plugin supervisor guarantees:
1. **Bounded Timeout**: Executions exceed `timeout_seconds` are terminated (`SIGKILL`).
2. **Output Cap**: Output streams are wrapped in `io.LimitReader(r, max_output_bytes)`. Excess output aborts the execution with `ErrOutputExceeded`.
3. **Crash Resilience**: If a plugin panics, segfaults, or exits non-zero, the core catches the exit status, marks the plugin observation `UNKNOWN`, records the failure in the audit log, and continues uninterrupted.
4. **Memory / CPU Limits**: On Linux hosts where cgroup v2 controller delegation is configured, child plugin processes are assigned to transient cgroup scopes with hard memory and CPU limits.

