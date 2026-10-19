# Hostile Testing & Hardening Report (Phase 37)

This document records the adversarial attacks, threat simulations, observed failures, remediations, and verification tests conducted under Phase 37.

---

## 1. Summary of Attacks & Status

| Attack Category | Specific Vector / Scenario | Initial Behavior / Vulnerability | Remediated Fix | Regression Test Name | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **D. Security** | SSRF via Connectivity Probe to Cloud Metadata (`169.254.169.254:80`) and Loopback | Outbound TCP dial attempted against local/cloud metadata IPs | Added IP parsing and rejection of loopback, link-local, and cloud metadata (`169.254.169.254`) in `internal/checks/network.go` | `TestChecks_NetworkAndProbe` (`internal/checks`) | **FIXED / PASS** |
| **D. Security** | Web UI Stored / DOM XSS via Process Names & Contributors | Dynamic host strings unescaped in `innerHTML` with relaxed CSP | Added `escapeHTML` helper to `web/js/app.js` and added strict `Content-Security-Policy` meta tag to `web/index.html` | `TestSecurity_WebUI_XSS_Neutralization` (`test/security`) | **FIXED / PASS** |
| **D. Security** | Auth Bypass via Slashes, Trailing Dots, Method Case, Host Spoofing | Route parsing or header spoofing | Enforced strict `hostCheckMiddleware` (no CORS, host whitelist, rebinding rejection) & rbac route table | `TestSecurity_AuthBypassAndPathNormalization`, `TestSecurity_HostAndOriginSpoofing` (`test/security`) | **FIXED / PASS** |
| **D. Security** | State Directory Permissions / TOCTOU | Insecure umask on state/token creation | Forced strict `0700` dir / `0600` file permissions on auth token and DB paths | `TestSecurity_TOCTOU_StateDirectoryPermissions` (`test/security`) | **FIXED / PASS** |
| **B. Hostile Host** | Random EIO / EACCES on `/proc` entries mid-read | Unhandled errors could cause panic or ungraceful aborts | Sensor observation status safely degrades to `unknown` with human-readable rationale without panic | `TestHostileHost_ProcRandomEIOAndEACCES` (`test/chaos`) | **FIXED / PASS** |
| **B. Hostile Host** | Adversarial process strings (ANSI escapes, `<script>`, shell injection) | Potential script execution or broken formatting | Parsers sanitize/preserve boundaries; verdict handles adversarial string nodes | `TestHostileHost_AdversarialProcessStrings` (`test/chaos`) | **FIXED / PASS** |
| **B. Hostile Host** | Symlink loops and FIFOs in scanned directory trees | Potential infinite loop or blocking on named pipe open | `filepath.WalkDir` filters out non-regular files and respects strict context timeouts | `TestHostileHost_SymlinkLoopsAndFIFOs` (`test/chaos`) | **FIXED / PASS** |
| **C. Resource Abuse** | Giant request body memory exhaustion (> 2MB) | Unbounded request body reads consuming memory | Added `requestLimitMiddleware` with `http.MaxBytesReader(w, r.Body, 2<<20)` and `MaxHeaderBytes: 1<<20` | `TestAPI_ResourceAbuse_OversizedBody` (`internal/api`) | **FIXED / PASS** |
| **C. Resource Abuse** | 50+ Concurrent SSE streaming subscribers | Slowloris or thread contention blocking sensor loops | Asynchronous non-blocking push loop with tick multiplexing and disconnect cleanup | `TestAPI_ResourceAbuse_ConcurrentSSESubscribers` (`internal/api`) | **FIXED / PASS** |
| **C. Resource Abuse** | Cryptographic weakness in reconciliation loop jitter | Weak pseudorandom generator (`math/rand`) | Switched jitter calculation to `crypto/rand` (`math/big`) | Gosec rule G404 resolved in `internal/reconcile/reconcile.go` | **FIXED / PASS** |
| **E. Correctness** | Verdict lying: "Healthy" returned when coverage is incomplete | Inadequate sensor visibility claiming OK | `ComputeVerdictWithChecks` strictly forbids `StateHealthy` if `coverageAdequate == false` | `TestProperty_HealthyNeverReturnedOnInadequateCoverage` (`test/consistency`) | **FIXED / PASS** |
| **E. Correctness** | Metamorphic invariant violation (monotonicity of Risk Score & sockets) | Inconsistent scoring on incremental findings | Verified open ports monotonically increase listening count, critical findings increase Risk Score | `TestMetamorphic_SensorsAndGraph` (`test/consistency`) | **FIXED / PASS** |
| **A. Hostile Input** | Fuzzing sshd_config, passwd, sudoers, resolv.conf, desired state YAML, platform catalog | Fuzz corpora with corrupted characters and malformed lines | Parsers handle corrupted lines, invalid UTF-8, and truncated files without crashing | `FuzzSSHDConfig`, `FuzzPasswdAndSudoers`, `FuzzResolvConf` (`test/fuzz`) | **FIXED / PASS** |
| **F. Concurrency** | Race conditions under heavy concurrency | Data races in API server, supervisor, or store | Verified clean with race detector across 20 iterations (`-count=20`) | `go test -race -count=20 ./internal/api ./internal/supervisor ./internal/store` | **FIXED / PASS** |

---

## 2. Test Execution Evidence

All tests ran to completion with `-race -count=1 ./...`:
- `grep -c "^ok"`: 56 packages passed.
- `FAIL` count: 0.
- End-to-end suite (`scripts/e2e.sh`): PASSED (verifying zero disk writes in stateless mode, 30 authenticated endpoints, and non-root visibility degradation).

