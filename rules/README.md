# Rules Specification

Jyōshin evaluates declarative, deterministic rule files against the server's
provenance graph to detect waste, risk, unmanaged state, and structural bottlenecks.

## Principles
1. **NO AI/LLM/ML**: Rules are deterministic logic definitions evaluated statically
   against the graph.
2. **DATA FILES ONLY**: Rules are defined as YAML data files located in this directory (`rules/` or `/etc/jyoshin/rules.d/`). No executable scripts or shell calls.
3. **READ-ONLY**: Rules never apply changes or remediate issues. They only produce findings.
4. **BLAME-FREE**: Findings describe machine state and technical consequences, never
   the humans who deployed or configured them.
5. **CALM HOST GUARANTEE**: Healthy, standard Linux servers produce **zero** findings above `info`. Rules must never alert on routine root daemons or standard cloud environments.

## Rule Schema

Each rule YAML definition adheres to the following declarative schema:

```yaml
id: "SEC-ROOT-LISTENER"
name: "Unnecessary root service listening on public network"
description: "Process running as UID 0 listening on all network interfaces."
category: "security"        # cost | security | efficiency | operations | change
severity: "high"            # info | low | medium | high | critical
match:
  node_type: "port"         # Target node type in provenance graph
  properties:               # Direct property match
    exposure_class:
      equals: "all_interfaces"
  join:                     # Edge join condition along graph edges
    relation: "listens_on"  # listens_on, executes, installed_by, owns, etc.
    direction: "in"         # "in" (target <- source) or "out" (source -> target)
    node_type: "process"    # Joined node type
    properties:
      uid:
        equals: 0
consequence: "Network-facing root processes expose the host to remote root compromise if vulnerable."
recommendation:
  action: "Configure service to drop privileges to an unprivileged system user or bind to private interfaces."
  risk_level: "medium"     # none | low | medium | high
  reversible: true         # Individually evaluated per recommendation
certainty: "OBSERVED"       # OBSERVED | DERIVED | INFERRED
confidence: 1.0             # 1.0 for facts, [0.0, 1.0] for inferences
```

### Supported Match Conditions

1. **Property Matches (`properties`)**:
   - `equals`: exact string, boolean, or numeric match.
   - `contains`: substring match.
   - `starts_with`: prefix match.
   - `in`: membership in a list of values (e.g. `[6379, 5432, 3306]`).
   - `greater_than`: numeric threshold comparison (`>`).
   - `less_than`: numeric threshold comparison (`<`).

2. **Graph Joins (`join`)**:
   - Traverses incoming or outgoing provenance edges (e.g. `port -> process`, `process -> file -> origin`).
   - `relation`: edge relation identifier.
   - `direction`: `"in"` or `"out"`.
   - `node_type`: joined node type.
   - `properties`: match criteria on the joined node.

3. **Aggregates (`aggregate`)**:
   - Computes counts across grouped nodes.
   - `group_by`: property name to partition by.
   - `count_distinct`: property name to count unique occurrences of.
   - `greater_than`: threshold to trigger a finding.

4. **Duration Conditions (`duration`)**:
   - `min_hours`: requires condition to be sustained for >= N hours.
   - `min_seconds`: requires uptime or duration >= N seconds.

5. **Dataset Checks**:
   - `check_eol: true`: evaluates operating system and runtime versions against embedded `data/eol.yaml`.

6. **Cost Findings Integration**:
   - Cost findings automatically reference `data/prices.yaml` and append `"estimate, table dated 2026-01-01"`.

## Finding Output Contract

Every finding emitted by the rule engine conforms strictly to the 4-part structure:
- **What**: The factual verdict of the condition found on the target node.
- **So What**: The operational, cost, or security consequence.
- **Now What**: Actionable recommendation, assessed risk level, and reversibility.
- **Proof**: Supporting evidence list, certainty level (`OBSERVED`, `DERIVED`, `INFERRED`), and confidence score.
