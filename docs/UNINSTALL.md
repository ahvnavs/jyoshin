# Uninstallation Guide

To completely remove Kazeshini, its configuration, and its service user:

```bash
curl -sSL https://raw.githubusercontent.com/OWNER/kazeshini/main/scripts/uninstall.sh | sudo sh
```

Or run the script locally if you have cloned the repository:
```bash
sudo ./scripts/uninstall.sh
```

### What is Removed
- Systemd service unit (`/etc/systemd/system/kazeshini.service`)
- Executable binary (`/usr/local/bin/kazeshini`)
- Configuration directory (`/etc/kazeshini/`)
- Persistent snapshot database (`/var/lib/kazeshini/`)
- System user and group (`kazeshini:kazeshini`)

