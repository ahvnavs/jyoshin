# Rules Specification

Jyōshin evaluates declarative, deterministic rule files against the server's
provenance graph to detect waste, risk, unmanaged state, and structural bottlenecks.

## Principles
1. **NO AI/LLM/ML**: Rules are deterministic logic definitions evaluated statically
   against the graph.
2. **DATA FILES**: Rules are defined as YAML files located in this directory (`rules/`).
3. **READ-ONLY**: Rules never apply changes or remediate issues. They only produce findings.
4. **BLAME-FREE**: Findings describe machine state and technical consequences, never
   the humans who deployed or configured them.

## Rule Schema

Each rule YAML definition adheres to the following structure:

```yaml
id: "SEC-SSH-PORT"
category: "security"      # cost | security | efficiency | operations | change
severity: "medium"        # info | low | medium | high | critical
name: "SSH exposed on standard port"
description: "Evaluates whether SSH daemon listens on default port 22 on all network interfaces."
match:
  node:
    type: "port"
    properties:
      port: 22
      protocol: "tcp"
consequence: "Publicly visible SSH port invites high-volume automated credential scans."
recommendation:
  action: "Bind SSH to internal management interfaces or adopt key-only authentication with non-standard port."
  risk_level: "low"       # none | low | medium | high
  reversible: true
```

## Finding Output

When a rule matches graph patterns, Jyōshin emits a `Finding` conforming to the 4-part structure:
- **What**: The verdict of what is currently occurring.
- **So What**: The operational, cost, or security consequence.
- **Now What**: Recommended next steps, risk level, and reversibility.
- **Proof**: Supporting evidence list, certainty level (`OBSERVED`, `DERIVED`, `INFERRED`), and confidence score.

