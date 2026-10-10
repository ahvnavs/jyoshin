# Upgrade Guide

Jyōshin installations are completely idempotent. Upgrading to the latest release uses the exact same installer script:

```bash
curl -sSL https://raw.githubusercontent.com/OWNER/jyoshin/main/scripts/install.sh | sudo sh
```

The script will:
1. Download the new release binary and verify checksums.
2. Replace `/usr/local/bin/jyoshin`.
3. Preserve existing configuration in `/etc/jyoshin/jyoshin.json`.
4. Preserve historical snapshot databases in `/var/lib/jyoshin/jyoshin.db`.
5. Gracefully restart `jyoshin.service` via `systemctl`.

