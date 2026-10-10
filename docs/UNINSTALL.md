# Uninstallation Guide

To completely remove Jyōshin, its configuration, and its service user:

```bash
curl -sSL https://raw.githubusercontent.com/OWNER/jyoshin/main/scripts/uninstall.sh | sudo sh
```

Or run the script locally if you have cloned the repository:
```bash
sudo ./scripts/uninstall.sh
```

### What is Removed
- Systemd service unit (`/etc/systemd/system/jyoshin.service`)
- Executable binary (`/usr/local/bin/jyoshin`)
- Configuration directory (`/etc/jyoshin/`)
- Persistent snapshot database (`/var/lib/jyoshin/`)
- System user and group (`jyoshin:jyoshin`)

