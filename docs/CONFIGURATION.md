# Configuration Guide

Jyōshin reads its configuration from `/etc/jyoshin/jyoshin.json` (or `/etc/jyoshin/jyoshin.yaml`) or command line flags.

## Configuration Schema

```json
{
  "host": "127.0.0.1",
  "port": 7777,
  "allow_remote": false,
  "data_dir": "/var/lib/jyoshin",
  "rules_dir": "/etc/jyoshin/rules.d",
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
| `data_dir` | string | `/var/lib/jyoshin` | Directory storing local SQLite/bbolt database and token. Permissions: `0700`. |
| `rules_dir` | string | `/etc/jyoshin/rules.d` | Directory containing custom user rule files. |
| `log_level` | string | `info` | Logging verbosity: `debug`, `info`, `warn`, `error`. |
| `log_format` | string | `text` | Logging format: `text` or `json`. |
| `scan_interval`| duration| `60s` | Polling frequency for background sensor scans. |
| `otel.enabled` | bool | `false` | Optional OpenTelemetry metrics export (disabled by default). |
| `otel.endpoint`| string | `localhost:4317` | Local OTLP collector address. |

## Environment Variables
All options can be configured via environment variables:
- `JYOSHIN_HOST`
- `JYOSHIN_PORT`
- `JYOSHIN_ALLOW_REMOTE`
- `JYOSHIN_DATA_DIR`
- `JYOSHIN_RULES_DIR`
- `JYOSHIN_LOG_LEVEL`

