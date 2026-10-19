## Summary of Changes
Provide a brief, human-first description of what this pull request modifies and why.

## Checklist
- [ ] Code adheres to the 17 non-negotiable architectural principles in `AGENTS.md`.
- [ ] Read-only guarantee preserved: no code modifies the host, touches disks without permission, or executes remediation.
- [ ] Zero telemetry preserved: no egress dials, phone-homes, or analytics added.
- [ ] Flesch-Kincaid Grade <= 8.0 preserved on all user-facing Summary strings (`go test ./internal/readability`).
- [ ] All commits signed off with Developer Certificate of Origin (`git commit -s`).
- [ ] `go test -race -count=1 ./...` runs to completion with zero failures.
- [ ] `golangci-lint run ./...` reports 0 issues.
