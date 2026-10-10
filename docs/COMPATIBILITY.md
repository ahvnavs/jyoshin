# Distribution Compatibility Matrix

Jyōshin is designed to run unprivileged on any modern Linux distribution without external dependencies.
Compatibility is validated across packaging, host identification, process and network telemetry, service management, package inventory parsing, and report generation.

| Distribution | Release / Arch | Packaging Tested | Host & Kernel Telemetry | Package DB Sensor | Systemd / Service Sensor | Overall Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Ubuntu** | 24.04 LTS (Noble) / amd64, arm64 | `.deb`, `install.sh` | Verified (`/proc`, os-release) | Verified (`dpkg status`) | Verified (systemd unit) | **PASS** |
| **Ubuntu** | 22.04 LTS (Jammy) / amd64, arm64 | `.deb`, `install.sh` | Verified (`/proc`, os-release) | Verified (`dpkg status`) | Verified (systemd unit) | **PASS** |
| **Debian** | 12 (Bookworm) / amd64, arm64 | `.deb`, `install.sh` | Verified (`/proc`, os-release) | Verified (`dpkg status`) | Verified (systemd unit) | **PASS** |
| **Fedora** | 40 / amd64, arm64 | `.rpm`, `install.sh` | Verified (`/proc`, os-release) | Verified (`rpmdb` / `rpm -qa`) | Verified (systemd unit) | **PASS** |
| **Rocky / Alma** | 9 / amd64, arm64 | `.rpm`, `install.sh` | Verified (`/proc`, os-release) | Verified (`rpmdb` / `rpm -qa`) | Verified (systemd unit) | **PASS** |
| **Arch Linux** | Rolling / amd64 | `PKGBUILD`, `install.sh` | Verified (`/proc`, os-release) | Verified (`pacman/local`) | Verified (systemd unit) | **PASS** |
| **Alpine Linux** | 3.19+ (musl) / amd64, arm64 | `APKBUILD`, `install.sh` | Verified (`/proc`, os-release) | Verified (`apk/db/installed`) | Verified (OpenRC graceful degradation) | **PASS** |
| **openSUSE** | Leap 15.5 / Tumbleweed / amd64 | `.rpm`, `install.sh` | Verified (`/proc`, os-release) | Verified (`rpmdb` / `zypper`) | Verified (systemd unit) | **PASS** |
| **Kali Linux** | Rolling / amd64 | `.deb`, `install.sh` | Verified (`/proc`, os-release) | Verified (`dpkg status`) | Verified (systemd unit) | **PASS** |

---

## Verification Methodology
- **Container Smoke Runs**: Multi-distro matrix tested with `test/matrix/matrix_runner.sh`.
- **Systemd Isolation**: Non-systemd environments (e.g. standard Alpine musl containers or containerized chroots) cleanly degrade with `status: unknown` and explicit explanation without panics or unhandled errors.
- **Package DB Parsers**: Direct read-only database parsing for `dpkg`, `pacman`, and `apk` tested with rooted filesystem mock trees in `test/fixtures/`.

