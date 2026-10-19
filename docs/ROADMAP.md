# Kazeshini Project Roadmap

The guiding mission of Kazeshini is:
> "Kazeshini tells you, on any Linux server with no setup, what is installed, what is running, what is exposed, what is out of date, and what changed, and how sure it is. Read-only, one binary."

---

## Short-Term Milestones (v0.1.x - Current)
- [x] Zero-setup terminal summary on first launch (`kazeshini`).
- [x] Ephemeral stateless loopback dashboard with session bearer token.
- [x] Human-first terminology, plain English definitions, and Flesch-Kincaid Grade <= 8 readability tests.
- [x] WCAG 2.2 AA accessibility and internationalization pseudo-locale test harness.
- [x] Multi-architecture reproducible builds (amd64, arm64, armv7, ppc64le, s390x, riscv64).
- [x] Self-verification command (`kazeshini verify`) and opt-in update check (`kazeshini update --check`).

---

## Medium-Term Milestones (v0.2.0)
- [ ] eBPF read-only tracepoint sensor for short-lived ephemeral process accounting (behind optional tag, strictly read-only).
- [ ] Direct kernel netlink socket parsing for zero-procfs containers.
- [ ] Extended package manager support for Nix and Guix store indexing.
- [ ] Sub-second provenance graph snapshot differential compression.

---

## Long-Term Milestones (v1.0.0)
- [ ] Production enterprise multi-cluster federation via signed, air-gapped evidence bundles.
- [ ] Formally verified rules engine using stateful invariant checking.
- [ ] Long-term LTS binary compatibility guarantees.

