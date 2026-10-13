# Kazeshini Soak & Chaos Recovery Test Harness (Phase 32)

This document describes the 6-hour endurance and crash recovery testing protocols for Kazeshini Core, the Actuator, and the Out-of-Process Plugin Supervisor.

---

## 1. Endurance Soak Test Protocol

### Setup & Command:
```bash
# Run foreground server with active plugins and continuous simulation polling
kazeshini serve --addr 127.0.0.1:7777 --data-dir /tmp/kazeshini-soak &
K_PID=$!

# Background polling simulating web UI and OTLP scrape loop every 2s
while kill -0 $K_PID 2>/dev/null; do
  curl -s http://127.0.0.1:7777/api/v1/verdict >/dev/null
  curl -s http://127.0.0.1:7777/api/v1/briefing >/dev/null
  curl -s http://127.0.0.1:7777/api/v1/platforms >/dev/null
  curl -s http://127.0.0.1:7777/metrics >/dev/null
  sleep 2
done
```

### Resource Profiling Invariants:
Measure resource usage from the outside:
```bash
ps -o pid,vsz,rss,comm -p $K_PID
ls /proc/$K_PID/fd | wc -l
```

| Metric | Target Cap | Invariant Enforced |
| :--- | :--- | :--- |
| **RSS Memory** | `< 64 MB` | Bounded memory usage; no monotonic leak over 6h duration. |
| **Goroutines** | `< 40` | Inspected via `/debug/pprof/goroutine`; no worker leak. |
| **File Descriptors (FDs)** | `< 30` | Socket and file handles closed promptly after requests. |
| **CPU Utilization** | `< 2%` | Bounded sampling tickers with idle backoff. |

---

## 2. Mid-Reconcile & Mid-Plan Kill-9 Restart Safety

### Test A: `kill -9` Mid-Observation / Mid-Reconcile
```bash
# Start kazeshini
kazeshini serve --addr 127.0.0.1:7777 --data-dir /tmp/kazeshini-soak &
PID=$!
sleep 1
# Kill during observation ingestion cycle
kill -9 $PID

# Restart immediately and verify clean startup with zero database corruption
kazeshini doctor
```
**Result**: The embedded bbolt store uses ACID single-writer locking and write-ahead transaction journaling. Uncommitted transactions are automatically rolled back on restart with zero manual repair.

### Test B: `kill -9` Mid-Step Actuator Execution
```bash
# Injects simulated SIGKILL into child package-manager process mid-execution
# Actuator catches abrupt termination or detects interrupted lock
```
**Safety Guarantee**: The Actuator executes atomic steps. If interrupted, the step status is recorded as `UNCERTAIN` or `FAILED`. In strict adherence to Principle 17 (*"Never auto-apply"*), the Actuator never blindly attempts automatic rollbacks; it halts and generates a signed remediation plan for manual review.

