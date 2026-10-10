# Declarative Rule Authoring Guide

Jyōshin uses a deterministic, transparent, and declarative YAML-based query engine to inspect the provenance graph.

**Rule Engine Invariants**:
1. **Zero AI / ML**: Every finding must be explainable via direct graph evidence.
2. **Deterministic Evaluation**: Re-running the engine on the identical graph snapshot yields identical findings and scores.
3. **Bounded Execution**: Rules execute within a hard bounded time budget (default 500ms).
4. **Safety**: Rules can never execute host commands or mutate state.

---

## 1. Rule Specification Schema

Each rule is defined as a YAML file (typically stored in `rules/*.yaml` or `/etc/jyoshin/rules.d/*.yaml`):

```yaml
id: RUL-001-MANUAL-BIN
title: Manual Unmanaged Binary in System Path
category: hygiene          # hygiene | security | reliability | compliance
severity: high            # critical | high | medium | low | info
applies_to: process       # process | file | service | port | container

condition:
  match_node:
    type: file
    properties:
      path_prefix: "/usr/local/bin/"
  edge_traversal:
    type: INSTALLED_BY
    target_type: origin
    must_not_exist: true  # Finding triggered if origin edge is absent
  thresholds:
    min_confidence: 0.8

what: "A binary was manually placed in /usr/local/bin outside the system package manager."
so_what: "Unmanaged binaries bypass OS security updates and patch management."
now_what:
  action: "Audit executable origin and package via OS distribution or remove."
  risk_level: "low"
  reversible: true
proof:
  - "File node {{.Node.ID}} has path {{.Node.Properties.path}}"
  - "Zero package origin relationships resolved in provenance graph"

certainty:
  level: OBSERVED         # OBSERVED | DERIVED | INFERRED
  confidence: 1.0
```

---

## 2. Condition Types & Matching

### Node Attribute Matching (`match_node`)
- `type`: Target node type (`file`, `process`, `service`, `port`, `connection`, `user`, `cgroup`).
- `properties`:
  - `path_prefix`: Matches beginning of file path string.
  - `name`: Exact or regex string matching.
  - `uid`, `gid`: Numeric equality or inequality.
  - `listening_addr`: IPv4/IPv6 pattern matching (`0.0.0.0`, `::`).

### Graph Traversal Joins (`edge_traversal`)
- `type`: Edge type (`SPAWNED_BY`, `INSTALLED_BY`, `LISTENS_ON`, `WRITES_TO`, `DEPENDS_ON`).
- `target_type`: Required node type on opposite side of edge.
- `must_exist`: Boolean (`true` asserts edge must exist; `false` asserts edge must NOT exist).

### Exposure Classes
- `exposure: public` (`0.0.0.0/0`, wildcard listener)
- `exposure: private` (RFC 1918 internal networks)
- `exposure: loopback` (`127.0.0.1`, `::1`)

---

## 3. Templating & Proof Formats

Finding descriptions and proof elements use Go text templates with access to the matching node and context:
- `{{.Node.ID}}`: Deterministic hash ID of the node.
- `{{.Node.Name}}`: Human-readable identifier.
- `{{.Node.Properties.<key>}}`: Attribute values.

Every rule must declare actionable remediation:
- `what`: Plain-language explanation of what is present.
- `so_what`: Plain-language explanation of impact and why it matters.
- `now_what.action`: Recommended operator intervention.
- `now_what.risk_level`: `none`, `low`, `medium`, `high`.
- `now_what.reversible`: `true` or `false`.
- `proof`: List of verifiable factual claims backed by graph nodes/edges.

---

## 4. Linting Rules

Before submitting rules, validate syntax and schema invariants using the built-in CLI:

```bash
jyoshin rules lint rules/my-new-rule.yaml
```

The linter verifies:
1. Valid rule identifier syntax (`RUL-XXX-[A-Z0-9_-]+`).
2. Valid category and severity values.
3. Non-empty `what`, `so_what`, `now_what`, and `proof` fields.
4. Syntactically valid conditions and traversal criteria.

