# Installation Guide

Jyōshin is installed via a single command as an unprivileged system service.

## One-Command Quickstart
```bash
curl -sSL https://raw.githubusercontent.com/OWNER/jyoshin/main/scripts/install.sh | sudo sh
```

### Options
- `--version <tag>`: Install specific release version (default: latest).
- `--no-start`: Install binaries and configuration without starting systemd service.
- `--dry-run`: Test installation steps without modifying system state.

```bash
curl -sSL https://raw.githubusercontent.com/OWNER/jyoshin/main/scripts/install.sh | sudo sh -s -- --dry-run
```

## Accessing the Dashboard
Jyōshin strictly binds to `127.0.0.1:7777` by default.

### Local Access
Open [http://127.0.0.1:7777/](http://127.0.0.1:7777/) in your browser.

### Remote Access (Secure SSH Port Forwarding)
```bash
ssh -N -L 7777:127.0.0.1:7777 user@your-server-ip
```
Then visit [http://localhost:7777/](http://localhost:7777/) on your local workstation.

