# Configuration Guide

Kazeshini reads its configuration from `/etc/kazeshini/kazeshini.json` (or `/etc/kazeshini/kazeshini.yaml`) or command line flags.

## Configuration Schema

```json
{
  "host": "127.0.0.1",
  "port": 7777,
  "allow_remote": false,
  "data_dir": "/var/lib/kazeshini",
  "rules_dir": "/etc/kazeshini/rules.d",
  "log_level": "info",
  "log_format": "text",
  "scan_interval": 60000000000,
  "otel": {
    "enabled": false,
    "endpoint": "localhost:4317",
    "protocol": "grpc"
  }
}
```

## Options Reference

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `host` | string | `127.0.0.1` | Network interface to bind. Refuses non-loopback addresses unless `allow_remote` is `true`. |
| `port` | int | `7777` | TCP port for API and web dashboard. |
| `allow_remote`| bool | `false` | Explicit permission required to listen on non-loopback IP addresses. |
| `data_dir` | string | `/var/lib/kazeshini` | Directory storing local SQLite/bbolt database and token. Permissions: `0700`. |
| `rules_dir` | string | `/etc/kazeshini/rules.d` | Directory containing custom user rule files. |
| `log_level` | string | `info` | Logging verbosity: `debug`, `info`, `warn`, `error`. |
| `log_format` | string | `text` | Logging format: `text` or `json`. |
| `scan_interval`| duration| `60s` | Polling frequency for background sensor scans. |
| `otel.enabled` | bool | `false` | Optional OpenTelemetry metrics export (disabled by default). |
| `otel.endpoint`| string | `localhost:4317` | Local OTLP collector address. |

## Environment Variables
All options can be configured via environment variables:
- `KAZESHINI_HOST`
- `KAZESHINI_PORT`
- `KAZESHINI_ALLOW_REMOTE`
- `KAZESHINI_DATA_DIR`
- `KAZESHINI_RULES_DIR`
- `KAZESHINI_LOG_LEVEL`

