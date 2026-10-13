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



---

## Architectural Decision Records

# ADR-0001: Kazeshini Control Model and Module Boundaries

## Status
Accepted

## Context
Kazeshini (風死) is a deterministic, explainable server truth engine designed to give operators immediate, unvarnished visibility into the state of Linux hosts. To preserve host safety, integrity, and operational predictability, Kazeshini must strictly govern how desired state, observed facts, planning, and execution interact. 

We require an explicit architectural control loop and crisp module boundaries separating read-only inspection from any host mutation.

## The Control Loop

The complete control loop maps across modules as follows (one line per step):

1. **store desired**: `internal/state` (or declarative file/git input) loads and retains user-declared intent without inventiveness. *(Read-only)*
2. **observe actual**: `internal/sensors` and `internal/supervisor` passively sample host truth (/proc, /sys, sockets, packages) under strict resource bounds. *(Read-only)*
3. **compare**: `internal/diff` evaluates discrepancies between observed actual snapshots and baseline states. *(Read-only)*
4. **plan**: `internal/rules` and `internal/decisions` generate deterministic, explainable recommendations and action plans. *(Read-only)*
5. **schedule**: `internal/events` and `internal/state` sequence plans pending approval, emitting event notifications. *(Read-only)*
6. **execute**: Actuator process carries out approved mutations via isolated, allow-listed tasks with explicit authorization. *(Requires Actuator)*
7. **monitor**: `internal/watchers` tracks runtime impact, drift, and post-execution stability. *(Read-only)*
8. **repeat**: `internal/supervisor` triggers continuous bounded periodic observation cycles. *(Read-only)*

```
+-----------------------------------------------------------------------------------------+
|                                    KAZESHINI CORE                                       |
|                                                                                         |
|   +---------------------+        +--------------------+        +--------------------+   |
|   | 1. Store Desired    |        | 2. Observe Actual  |        | 3. Compare         |   |
|   |    (internal/state) |        | (internal/sensors) |        |    (internal/diff) |   |
|   +----------+----------+        +---------+----------+        +---------+----------+   |
|              |                             |                             |              |
|              +----------------------+      |      +----------------------+              |
|                                     v      v      v                                     |
|                                  +--------------------+                                 |
|                                  | 4. Plan            |                                 |
|                                  |   (rules/decisions)|                                 |
|                                  +---------+----------+                                 |
|                                            |                                            |
|                                            v                                            |
|                                  +--------------------+                                 |
|                                  | 5. Schedule        |                                 |
|                                  | (events/approval)  |                                 |
|                                  +---------+----------+                                 |
|                                            |                                            |
|   +---------------------+                  |                                            |
|   | 8. Repeat           |                  |                                            |
|   | (internal/sup)      |                  |                                            |
|   +----------^----------+                  |                                            |
|              |                             |                                            |
|   +----------+----------+                  |                                            |
|   | 7. Monitor          |                  |                                            |
|   | (internal/watchers) |                  |                                            |
|   +----------^----------+                  |                                            |
+--------------|-----------------------------|--------------------------------------------+
               |                             | (Plan approved by operator)
               |                             v
+--------------|--------------------------------------------------------------------------+
|              |                     ACTUATOR BOUNDARY                                    |
|              |                   (Separate Process)                                     |
|              |                                                                          |
|              |                   +--------------------+                                 |
|              +-------------------| 6. Execute         |                                 |
|                                  |  (Actuator Daemon) |                                 |
|                                  +--------------------+                                 |
+-----------------------------------------------------------------------------------------+
| PLUGINS: Store (Memory, File, Bolt) | Schedulers | Exporters                            |
+-----------------------------------------------------------------------------------------+
| CONTROLLER (Deferred): Multi-node fleet coordination, leader election, HA agents        |
+-----------------------------------------------------------------------------------------+
```

## Module Ownership & Boundary Isolation

### 1. Kazeshini Core (Read-Only)
- **Ownership**: Owns steps 1 (store desired), 2 (observe actual), 3 (compare), 4 (plan), 5 (schedule), 7 (monitor), and 8 (repeat).
- **Invariants**: Principle 2 & 2': Core is strictly read-only. It never modifies the host, touches sysctls, restarts units, or edits configuration files. Core operates fully stateless by default (`--stateless` / Memory store).

### 2. Actuator (Separate Opt-In Process)
- **Ownership**: Owns step 6 (execute).
- **Invariants**:
  - Exists as an independent binary or subprocess running only when explicitly invoked by an operator.
  - Never auto-applies actions. Modes are strictly `observe` | `plan` | `apply-with-approval` (Principle 17).
  - All host interactions are gated behind strict allow-lists and cryptographic audit records.

### 3. Plugins
- **Ownership**: Pluggable storage providers (`MemoryStore`, `FileStore`, `BoltStore`), custom rule packs, and optional metrics exporters.
- **Invariants**: Pluggable components implement clean Go interfaces without CGO or external system daemons. Default is zero-disk `MemoryStore`.

### 4. Controller (Explicitly Deferred)
- Fleet-level leader election, distributed consensus (Raft/etcd), High Availability failover, and multi-tenant controller/agent topologies are intentionally **deferred**.
- Kazeshini is single-host truth first. Multi-node coordination will sit on top of standalone host engines rather than complicating single-node clarity.

## What We Deliberately Do NOT Copy

1. **Kubernetes: Asynchronous Reconciliation Loops & Eventual Consistency**
   - *Why*: Kubernetes controllers continuously drive the world toward a spec in an infinite level-triggered loop, masking flapping failures, race conditions, and transient crashes. Kazeshini never silently drives or reconciles state. If actual drifts from desired, Kazeshini declares the drift honestly, calculates the blast radius, and stops.
2. **Ansible: Ad-hoc SSH Push & Implicit Host Mutation**
   - *Why*: Ansible blends observation and mutation across Python scripts executed via SSH, producing side effects without formal mathematical verification of host stability. Kazeshini isolates read-only sensing into unprivileged, bounded sensors and rejects push-based mutation.
3. **Terraform: Opaque State Files as Source of Truth**
   - *Why*: Terraform treats a local or remote `terraform.tfstate` blob as truth; when real infrastructure changes out-of-band, Terraform attempts to destroy or recreate resources to match stale state. In Kazeshini, the real host hardware and kernel (/proc, /sys) is always the primary truth.
4. **Chef/Puppet: Heavy Ruby/JVM Agents with Unbounded Host Access**
   - *Why*: Heavy convergence daemons consume 200MB+ RAM and periodically execute unbounded root scripts. Kazeshini consumes < 15MB RSS, runs under `nice 19` / `ionice idle`, drops privileges, and executes zero remediation scripts.

