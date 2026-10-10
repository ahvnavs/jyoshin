## Description
Provide a concise explanation of the change and the rationale behind it.

## Type of Change
- [ ] Sensor implementation (read-only)
- [ ] Rule or graph improvement
- [ ] Bug fix
- [ ] Documentation update
- [ ] CI / Tooling improvement

## Principles Checklist
- [ ] **NO AI/LLM/ML**: Deterministic logic only.
- [ ] **READ-ONLY**: Never executes remediation or mutates host state.
- [ ] **NEVER HARM THE HOST**: Low overhead, bounded work cycle.
- [ ] **FACT vs INFERENCE**: Evidence list and certainty specified correctly.
- [ ] **STDLIB-FIRST**: No unapproved 3rd party dependencies.
- [ ] **BLAME-FREE**: Non-accusatory descriptions.
- [ ] **SPDX Headers**: Present on all newly added source files.
- [ ] **DCO**: Signed-off-by included in all commits.

## Testing Performed
Describe unit/integration tests run (`make test`, `make lint`).

