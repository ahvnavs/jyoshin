# Contributing Rules to Jyōshin

We welcome community rule contributions that help administrators identify hygiene, security, and stability risks on Linux servers!

---

## 1. Principles for New Rules

1. **No Speculation**: Rules must be backed by concrete, observable facts or deterministic graph derivations.
2. **Actionable Remediation**: Every rule must have clear `now_what` recommendations detailing whether action is reversible and the risk of intervention.
3. **No Flapping**: Conditions must not flip back and forth on minor transient state changes.
4. **Calm by Default**: Do not flag standard Linux system behavior as high severity. Reserve `critical` and `high` for actionable risks or security exposures.

---

## 2. Rule Checklist

Before submitting a PR with new rules in `rules/*.yaml`:

- [ ] Rule ID follows naming format: `RUL-<NUM>-<DESCRIPTIVE_UPPERCASE_NAME>`.
- [ ] Category is one of `hygiene`, `security`, `reliability`, `compliance`.
- [ ] Severity is appropriate (`info`, `low`, `medium`, `high`, `critical`).
- [ ] `what`, `so_what`, `now_what.action`, and `proof` are populated.
- [ ] Validated with `jyoshin rules lint <path-to-rule>`.
- [ ] Unit tests or fixture graphs added in `internal/rules/` or `test/fixtures/`.

---

## 3. Testing Your Rule

Run the Jyōshin rule test suite:

```bash
go test -v ./internal/rules/...
```

To run the rule against a local machine or test fixture graph:

```bash
go run ./cmd/jyoshin rules lint rules/*.yaml
```

