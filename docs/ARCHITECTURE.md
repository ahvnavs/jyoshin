# Kazeshini Architecture

## High-Level Architecture

Kazeshini is designed as a unidirectional, pipelined "server truth engine":

```
+-------------------------------------------------------------------+
|                           SUPERVISOR                              |
|   (Scheduling, Priority Caps, Panic Recovery, Isolation Bounds)   |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                         READ-ONLY SENSORS                         |
|   /proc  |  /sys  |  systemd  |  package managers  |  sockets     |
+---------------------------------+---------------------------------+
                                  | (Nodes, Edges, Evidence)
                                  v
+-------------------------------------------------------------------+
|                              CORE                                 |
|  * Provenance Graph (Nodes, Edges, Certainty, Proof Chains)       |
|  * Rule Engine (Declarative YAML, Deterministic Findings)         |
|  * Diff Engine (Snapshot Mutations)                               |
|  * Forecaster (Linear Regression, Baseline Drift)                 |
|  * Embedded Store (Zero External DB)                              |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                             SURFACE                               |
|  * Versioned Local REST API (/api/v1)                             |
|  * Real-Time Server-Sent Events (SSE)                             |
|  * Embedded Web Dashboard (Cyber-retro dark ASCII grid)           |
+-------------------------------------------------------------------+
```

## Provenance Graph

The graph represents how things came to be on the server:

$$\text{File} \longrightarrow \text{Origin} \longrightarrow \text{Process} \longrightarrow \text{Service} \longrightarrow \text{Port} \longrightarrow \text{Connection} \longrightarrow \text{Resource Usage}$$

### Fact vs. Inference
- **OBSERVED**: Read directly from kernel or filesystem interfaces (`/proc`, `/sys`).
- **DERIVED**: Deterministically computed from observed facts (e.g., aggregating socket counts).
- **INFERRED**: Heuristically deduced, always accompanied by a confidence score $c \in [0.0, 1.0]$.

## Core Components
- **`internal/supervisor`**: Manages sensor isolation, schedules execution intervals, enforces timeouts, and catches panics.
- **`internal/sensors`**: Modular collection plugins reading host state without mutating the system.
- **`internal/graph`**: Represents graph vertices (Node), relationships (Edge), and backing proof (Evidence, Certainty).
- **`internal/rules`**: Evaluates static YAML rules and creates blame-free 4-part findings (What, So What, Now What, Proof).
- **`internal/store`**: Pure-Go embedded storage engine.
- **`internal/api`**: Local-only HTTP server bound to loopback by default.

