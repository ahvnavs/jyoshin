# Distribution Compatibility Matrix

Jyōshin is designed to run unprivileged on any modern Linux distribution without external dependencies.
Compatibility is validated across packaging, host identification, process and network telemetry, service management, package inventory parsing, and report generation.

| Distribution | Release / Arch | Packaging Defined | Host & Kernel Telemetry | Package DB Sensor | Live Distro Smoke Run | Overall Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Ubuntu** | 24.04 LTS (Noble) / amd64, arm64 | `.deb`, `install.sh` | Verified (host environment & fixtures) | Verified (`dpkg status` fixture) | Verified (live host) | **PASS** |
| **Ubuntu** | 22.04 LTS (Jammy) / amd64, arm64 | `.deb`, `install.sh` | Verified (os-release fixture) | Verified (`dpkg status` fixture) | not yet run | **PARTIAL** (fixture tested) |
| **Debian** | 12 (Bookworm) / amd64, arm64 | `.deb`, `install.sh` | Verified (os-release fixture) | Verified (`dpkg status` fixture) | not yet run | **PARTIAL** (fixture tested) |
| **Fedora** | 40 / amd64, arm64 | `.rpm`, `install.sh` | Verified (os-release fixture) | Verified (`rpm` parser tests) | not yet run | **PARTIAL** (fixture tested) |
| **Rocky / Alma** | 9 / amd64, arm64 | `.rpm`, `install.sh` | Verified (os-release fixture) | Verified (`rpm` parser tests) | not yet run | **PARTIAL** (fixture tested) |
| **Arch Linux** | Rolling / amd64 | `PKGBUILD`, `install.sh` | Verified (os-release fixture) | Verified (`pacman/local` fixture) | not yet run | **PARTIAL** (fixture tested) |
| **Alpine Linux** | 3.19+ (musl) / amd64, arm64 | `APKBUILD`, `install.sh` | Verified (os-release fixture) | Verified (`apk/db/installed` fixture) | not yet run | **PARTIAL** (fixture tested) |
| **openSUSE** | Leap 15.5 / Tumbleweed / amd64 | `.rpm`, `install.sh` | Verified (os-release fixture) | Verified (`zypper`/`rpm` parser tests) | not yet run | **PARTIAL** (fixture tested) |
| **Kali Linux** | Rolling / amd64 | `.deb`, `install.sh` | Verified (os-release fixture) | Verified (`dpkg status` fixture) | not yet run | **PARTIAL** (fixture tested) |

---

## Verification Methodology
- **Current Sandbox Status**: Container images for Fedora, Arch, Alpine, etc., are not pre-cached in this offline build sandbox; live container runs for those distros are marked **not yet run**.
- **Rooted Filesystem Fixtures**: All package managers (`dpkg`, `pacman`, `apk`, `rpm`) and distro identities (`os-release`, `/proc/version`) are tested and passing via rooted filesystem test fixtures in `test/fixtures/` and `test/matrix/matrix_test.go`.
- **Systemd Graceful Fallback**: Non-systemd environments (e.g. containers or OpenRC) cleanly report `status: unknown (non-systemd)` without crashes.

