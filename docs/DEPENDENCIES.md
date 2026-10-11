# Kazeshini Dependencies & Justifications

Principle 9: **STDLIB-FIRST**.
> Add a third-party dependency only with written justification in `docs/DEPENDENCIES.md`
> (license must be Apache-2.0/MIT/BSD compatible).

## Policy
1. If the standard library (`net/http`, `os`, `encoding/json`, `log/slog`, `flag`, etc.) can achieve the goal with reasonable complexity, use the standard library.
2. Every third-party dependency must be documented here with:
   - Module name & version
   - License
   - Technical justification
   - Alternatives considered and why they were rejected

---

## Approved Third-Party Dependencies

### 1. `go.etcd.io/bbolt` (v1.4.0)
- **License**: MIT (Apache-2.0 compatible)
- **Purpose**: Pure-Go embedded key-value storage engine (B+ tree with ACID transactions and write-ahead log) for graph snapshots, time-series metrics, and event storage.
- **Justification**:
  - Requires **zero CGO** (`CGO_ENABLED=0`), enabling single static binary compilation across `linux/amd64` and `linux/arm64`.
  - Self-contained: single database file on disk with `0600` permissions.
  - Crash-resilient ACID single-writer, multi-reader architecture with instant startup and zero external service dependency.
- **Alternatives Considered**:
  - *Standard library JSON files*: Vulnerable to corruption on sudden system power failure, poor performance for indexing/retention compaction over time.
  - *SQLite (`mattn/go-sqlite3`)*: Requires CGO and dynamic libc linking, violating Principle 8 and static binary requirements.
  - *Pure-Go SQLite (`modernc.org/sqlite`)*: Significant binary bloat (>10MB), complex virtual machine transpilation overhead.

### 2. `gopkg.in/yaml.v3` (v3.0.1)
- **License**: MIT / Apache-2.0 compatible
- **Purpose**: Parsing and validating declarative YAML rule files, price tables (`data/prices.yaml`), and EOL datasets (`data/eol.yaml`).
- **Justification**:
  - Standard industry parser for YAML 1.2 in Go with strict syntax error diagnostics and line-number reporting for `kazeshini rules lint`.
  - Pure-Go with zero CGO dependencies.
- **Alternatives Considered**:
  - *Custom ad-hoc line parser*: Fragile, error-prone for nested structures and block scalars.
  - *Strict JSON rules*: Rules are designed to be human-authored data files with comments and multiline descriptions; YAML is the standard operator syntax.
