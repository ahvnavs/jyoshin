# Security Design Specification

## Principles
1. **Unprivileged by Default**: Kazeshini never runs as `root`. The installer provisions a dedicated `kazeshini` system user.
2. **Deterministic & Explainable**: Rules are purely declarative YAML. No AI, LLM, or dynamic script interpreters are permitted.
3. **Local-First Zero Egress**: Kazeshini never connects outbound to external telemetry servers. All assets are embedded locally.

## Per-Sensor Privilege Model & Minimum Capabilities

Kazeshini enforces the principle of least privilege. The daemon operates as the unprivileged `kazeshini` user with a minimal capability set (`CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE` and `AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE`). `CAP_SYS_PTRACE` is granted alongside `CAP_DAC_READ_SEARCH` to allow inspecting `/proc/<pid>/exe`, `/proc/<pid>/cmdline`, and `/proc/<pid>/fd/*` across unprivileged user namespaces and Yama ptrace scopes.

| Sensor | Minimum Capabilities / Privileges | Purpose | Behavior When Denied / Missing |
| :--- | :--- | :--- | :--- |
| **host** | None (unprivileged read on `/etc/os-release`, `/proc/version`, `/proc/uptime`, `/proc/meminfo`) | Host identity & basic uptime | Returns standard observation |
| **process** | `CAP_SYS_PTRACE` (or `CAP_DAC_READ_SEARCH`) | Read `/proc/<pid>/exe`, `/proc/<pid>/cmdline`, and `/proc/<pid>/stat` across users | Degrades gracefully: falls back to `/proc/<pid>/comm` and unprivileged stat, reports status `unknown, permission` on restricted targets with reduced visibility. |
| **network** | `CAP_DAC_READ_SEARCH` (or `CAP_SYS_PTRACE`) | Inspect `/proc/<pid>/fd/*` socket inodes to map listening ports to owning PIDs | Socket table parsing (`/proc/net/{tcp,tcp6,udp,udp6}`) succeeds; unreadable process fd directories degrade to status `unknown`, with reason `unknown, permission: unreadable /proc/<pid>/fd...` and reduced visibility. |
| **service** | None (connect to `/run/systemd/system/private` or D-Bus system bus via unprivileged socket; reads `/etc/systemd/system`) | Discover systemd service states, active status, restart counts | In non-systemd or restricted environments, gracefully marks observation `unknown (non-systemd)` without failure. |
| **storage** | None (unprivileged `statfs` syscalls and `/proc/mounts`) | Filesystem mount points, disk usage, inode counts | Returns mounted filesystem capacities; unmounted private namespaces return `status: unknown`. |
| **resources** | None (unprivileged `/proc/stat`, `/proc/loadavg`, `/proc/pressure/*`) | System-wide CPU, load, and PSI metrics | Returns telemetry samples; missing PSI returns zeroed pressure metrics without crashing. |
| **container** | Group membership: `docker` or `podman` group (read-only socket access to `/var/run/docker.sock` or `/run/podman/podman.sock`) | Container list, images, ports, mounts | Without socket group permission, logs access error and sets sensor status `unknown (socket permission denied)`. |
| **user** | None (unprivileged `/etc/passwd`, `/etc/group`, `/var/log/wtmp`, authorized_keys metadata) | User accounts, sudoers presence, key age | If specific home directories have 0700 permissions of other users, key inspection is skipped and logged with reduced visibility. |
| **scheduler** | None (read `/etc/cron*`, `/var/spool/cron/crontabs`, `/etc/systemd/system/*.timer`) | Cron jobs and systemd timer schedules | Unreadable cron spools gracefully skipped with `status: unknown, permission`. |
| **kernel** | None (read `/boot`, `uname -r`, `/proc/modules`) | Running vs installed kernels and reclaimable images | Returns kernel status; restricted `/boot` directories gracefully degrade. |

## Redaction Architecture
Every API response, event watcher alert, and generated report passes through [`internal/redact`](file:///home/ahvnav/workspace/kazeshini/internal/redact/redact.go):
- Passwords, Bearer tokens, private keys (`id_rsa`, `id_ed25519`, `*.pem`), and cloud credentials are substituted with `[REDACTED]`.
- Non-secret metadata (such as file paths and ownership) is retained for auditability.

## Exec Allow-List (Principle 13)
In strict compliance with Principle 13 (*"Checks are read-only. Exec only via allow-list."*), Kazeshini permits command execution solely against a strictly controlled, hardcoded allow-list with invariant safety constraints:

| Binary (Absolute Path) | Fixed Arguments | Invariant Constraints & Sandbox | Purpose |
| :--- | :--- | :--- | :--- |
| `/usr/bin/systemctl` (or `/bin/systemctl`) | `show --property=Id,ActiveState,SubState,NRestarts,MainPID,LoadState -- <validated_units...>` | Absolute path only; unit names strictly validated against regex `^[a-zA-Z0-9._@-]+$`; cleared environment (`LC_ALL=C`, `PATH=/usr/bin:/bin`); 3s execution timeout; 1 MB output cap. | Query real runtime service state (ActiveState, restart count, main PID) |
| `/usr/bin/rpm` (or `/bin/rpm`) | `-qa --queryformat %{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n` | Absolute path only; immutable query arguments; cleared environment; 3s timeout; 10 MB output cap. | Query installed RPM package database when pure-Go db parser is absent. |
| `/usr/bin/apt-get` | `-s -o Debug::NoLocking=1 install [--only-upgrade] <validated_pkg>` / `-s -o Debug::NoLocking=1 purge <validated_pkg>` | Absolute path only; non-root simulation mode; package names strictly validated against regex `^[a-zA-Z0-9][a-zA-Z0-9.+~:_-]*$`; no shell expansion; cleared environment (`LANG=C`, `LC_ALL=C`, `PATH=/usr/bin:/bin`, `DEBIAN_FRONTEND=noninteractive`); 10s execution timeout; 1 MB output cap. | Deterministic dry-run simulation for package upgrades, installations, and removals (Phase 26). |
| `/usr/bin/dnf` | `--assumeno upgrade <validated_pkg>` / `--assumeno remove <validated_pkg>` | Absolute path only; non-root simulation mode; validated package name regex; cleared environment; 10s timeout; 1 MB output cap. | DNF dry-run simulation for RPM-based systems (Phase 26). |
| `/usr/bin/pacman` | `-Sup <validated_pkg>` / `-Rsp <validated_pkg>` | Absolute path only; print targets simulation; validated package name regex; cleared environment; 10s timeout; 1 MB output cap. | Pacman dry-run simulation for Arch systems (Phase 26). |
| `/sbin/apk` | `--simulate upgrade <validated_pkg>` / `--simulate del <validated_pkg>` | Absolute path only; simulation mode; validated package name regex; cleared environment; 10s timeout; 1 MB output cap. | APK dry-run simulation for Alpine systems (Phase 26). |

Zero other binaries, shells, interpreters, or user-supplied command strings are permitted to execute.


