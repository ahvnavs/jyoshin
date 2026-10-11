# Upgrade Guide

Kazeshini installations are completely idempotent. Upgrading to the latest release uses the exact same installer script:

```bash
curl -sSL https://raw.githubusercontent.com/OWNER/kazeshini/main/scripts/install.sh | sudo sh
```

The script will:
1. Download the new release binary and verify checksums.
2. Replace `/usr/local/bin/kazeshini`.
3. Preserve existing configuration in `/etc/kazeshini/kazeshini.json`.
4. Preserve historical snapshot databases in `/var/lib/kazeshini/kazeshini.db`.
5. Gracefully restart `kazeshini.service` via `systemctl`.

