> Kazeshini tells you, on any Linux server with no setup, what is installed, what is running, what is exposed, what is out of date, and what changed, and how sure it is. Read-only, one binary.

# Kazeshini Agent Directives & Architecture Principles

## Non-Negotiable Principles

1. **NO AI / LLM / ML**: Deterministic, explainable logic only (rules + statistics).
2. **READ-ONLY**: Never modify the host. Never execute remediation. Recommend only.
2'. Core is read-only. Any change to the host happens only in the separate opt-in Actuator process, never in core.
3. **NEVER HARM THE HOST**: Low priority (`nice 19`, `ionice idle`), hard CPU/memory caps, bounded work cycles.
4. **ISOLATION**: Independent sensors; failure or denial in one never affects others or the host.
5. **NO NETWORK EGRESS**: Zero telemetry. Data never leaves the machine.
5'. No egress by default. Allowed egress: user-clicked probes, explicit online refresh, and configured exporters, each off by default and logged.
6. **FACT vs INFERENCE**: Strict evidence and certainty attribution (`OBSERVED`, `DERIVED`, `INFERRED`).
7. **BLAME-FREE TONE**: Describes the machine, never the person who configured it.
8. **SELF-CONTAINED**: Embedded store (`bbolt`, zero CGO) and embedded web UI (`go:embed`, zero external CDN).
9. **STDLIB-FIRST**: Minimal dependencies justified in `docs/DEPENDENCIES.md`.
10. **GRACEFUL DEGRADATION**: Missing permissions report "unknown, here's why", never crash.
11. **COVERAGE HONESTY**: Never say healthy/calm unless the sensors that matter could actually see. "Found nothing" and "couldn't look" must look different.
12. **HUMAN-FIRST**: Plain sentences, human units (GB, days, "3 hours ago"), no raw keys or jargon without a one-line gloss.
13. **CHECKS ARE READ-ONLY. EXEC ONLY VIA ALLOW-LIST. THE ONLY EGRESS IS A USER-CLICKED ACTIVE PROBE TO A USER-NAMED TARGET.**
14. **STANDING RULES**:
 - Paste only output of commands you ran this session; else NOT VERIFIED + reason.
 - Run go test -race -count=1 ./... to completion; paste grep -c "^ok", FAIL lines, tail.
 - Never claim an integration works unless it ran against the real product.
15. **STATELESS BY DEFAULT**: the core must start, run and give full answers with no writable disk. Durable state is an optional Store plugin.
16. **DECLARATIVE**: desired state is user-owned input (file or git), never something Kazeshini invents or silently applies.
17. **NEVER AUTO-APPLY**: modes are observe | plan | apply-with-approval. Default is observe.


