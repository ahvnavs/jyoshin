> Kazeshini tells you, on any Linux server with no setup, what is installed, what is running, what is exposed, what is out of date, and what changed, and how sure it is. Read-only, one binary.

# Kazeshini (風死)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Read--Only-success.svg)](SECURITY.md)

Kazeshini is a read-only server truth engine for Linux. It runs with zero setup, makes zero modifications to the host, and never sends data over the network.

---

## Run it in 3 Steps

1. **Get the binary**:
   Download the latest release binary for your architecture from your release store or build from source:
   ```bash
   go build -trimpath -o kazeshini ./cmd/kazeshini
   ```

2. **Run it**:
   ```bash
   ./kazeshini
   ```
   Kazeshini starts stateless (writes nothing to disk), discovers system state, prints a terminal summary, and opens an unprivileged loopback web dashboard.

3. **Open the Dashboard**:
   - On a local machine: open the printed URL (`http://127.0.0.1:<port>/?token=<token>`).
   - On a remote server with no screen: copy and run the printed `ssh -L` line on your laptop:
     ```bash
     ssh -L <port>:127.0.0.1:<port> user@your-server
     ```

For scripts or CI/CD, run once and exit immediately:
```bash
./kazeshini --once
./kazeshini --once --json
```

---

## What It Does and Does Not Do

- **Read-Only**: Core is strictly read-only. It never modifies configurations, packages, or services.
- **Stateless by Default**: Does not require disk storage or database installation.
- **Zero Network Egress**: Telemetry is zero. Server data never leaves the machine.
- **Deterministic**: Logic is driven by verifiable rules and statistics—no AI or external cloud dependencies.
- **Honest Visibility**: Missing permissions report "unknown, here is why" instead of falsely reporting calm or healthy.

---

## Commands

| Command | Purpose |
|---|---|
| `kazeshini` | Starts loopback web UI, prints terminal summary and SSH tunnel command |
| `kazeshini --once` | One-shot terminal summary and exit (ideal for terminal login and CI) |
| `kazeshini view <growth\|storage\|tree\|network>` | Inspect visual models (space colonization map, storage treemap, sockets) |
| `kazeshini export --format json\|csv\|md\|html\|svg` | Export machine state, SVG growth vector, or standalone report |
| `kazeshini explain <term\|finding-id>` | Look up plain-language definitions and technical evidence |
| `kazeshini bugreport` | Generate sanitized diagnostic bundle stripped of secrets |
| `sudo kazeshini install` | Opt-in persistent systemd service (previews plan before install) |

---

## If Something Looks Wrong

- **Visibility Percentage**: Non-root users cannot read certain kernel `/proc` paths. Kazeshini displays an exact visibility fraction (`Visibility N of M`). Run `sudo kazeshini` to enable full hardware and network sensor coverage.
- **Error Codes**: All errors use structured codes (`KZ-1xxx`). Run `kazeshini explain <error-code>` or see [`docs/ERRORS.md`](docs/ERRORS.md).

---

## Known Limitations

- **Linux Only**: Requires Linux 3.10+ (`/proc`, `/sys`). macOS and Windows are not supported.
- **ZFS & btrfs Subvolumes**: Standard POSIX `statfs` is used for capacity; specialized subvolume pools are not tracked.
- **Outdated Package Caches**: Package upgrade checks read local manager metadata caches (`apt`, `dnf`, `pacman`, `apk`). Cache age is explicitly stated.

---

## Security & License

- **Security Disclosures**: Follow instructions in [`SECURITY.md`](SECURITY.md).
- **License**: [Apache 2.0](LICENSE).
