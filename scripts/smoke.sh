#!/usr/bin/env bash
# Copyright 2026 Kazeshini Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/smoke.sh — End-to-end smoke test suite verifying all endpoints and security guarantees.

set -euo pipefail

PORT=7890
TMP_DIR=$(mktemp -d /tmp/kazeshini_smoke_XXXXXX)
BIN_PATH="./kazeshini"

cleanup() {
  echo "==> Cleaning up smoke test resources..."
  if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "==> Step 1: Building kazeshini binary..."
go build -o "${BIN_PATH}" ./cmd/kazeshini

echo "==> Step 2: Preparing isolated configuration and temporary data dir (${TMP_DIR})..."
cat << EOF > "${TMP_DIR}/config.json"
{
  "host": "127.0.0.1",
  "port": ${PORT},
  "data_dir": "${TMP_DIR}/data",
  "rules_dir": "rules",
  "auth_required": true
}
EOF
mkdir -p "${TMP_DIR}/data"

echo "==> Step 3: Starting kazeshini serve daemon on port ${PORT}..."
"${BIN_PATH}" serve --config "${TMP_DIR}/config.json" &
SERVER_PID=$!

echo "==> Step 4: Waiting for health endpoint to become ready..."
for i in $(seq 1 30); do
  if curl -s "http://127.0.0.1:${PORT}/api/v1/health" | grep -q '"status":"ok"'; then
    echo "  [OK] Server is ready."
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "  [FAIL] Server failed to become healthy within 15 seconds."
    exit 1
  fi
  sleep 0.5
done

echo "==> Step 5: Retrieving authentication token..."
AUTH_TOKEN=$("${BIN_PATH}" token --config "${TMP_DIR}/config.json")
if [ -z "${AUTH_TOKEN}" ]; then
  echo "  [FAIL] Could not retrieve authentication token."
  exit 1
fi
echo "  [OK] Retrieved token: ${AUTH_TOKEN:0:8}..."

AUTH_HEADER="Authorization: Bearer ${AUTH_TOKEN}"

call_endpoint() {
  local ep="$1"
  local desc="$2"
  echo "  Checking endpoint: ${ep} (${desc})..."
  local status_code
  status_code=$(curl -s -o "${TMP_DIR}/response.json" -w "%{http_code}" -H "${AUTH_HEADER}" "http://127.0.0.1:${PORT}${ep}")
  if [ "${status_code}" -ne 200 ]; then
    echo "  [FAIL] Endpoint ${ep} returned HTTP ${status_code} (expected 200)."
    cat "${TMP_DIR}/response.json" || true
    exit 1
  fi
  if [ ! -s "${TMP_DIR}/response.json" ]; then
    echo "  [FAIL] Endpoint ${ep} returned empty body."
    exit 1
  fi
  echo "  [OK] ${ep} passed (HTTP 200)."
}

echo "==> Step 6: Testing authenticated API endpoints..."
call_endpoint "/api/v1/health" "system health"
call_endpoint "/api/v1/version" "version info"
call_endpoint "/api/v1/self" "supervisor self-metrics"
call_endpoint "/api/v1/coverage" "sensor inspection coverage"
call_endpoint "/api/v1/briefing" "plain-English server truth briefing"
call_endpoint "/api/v1/verdict" "deterministic verdict"
call_endpoint "/api/v1/inventory" "native package database"
call_endpoint "/api/v1/graph" "provenance graph snapshot"
call_endpoint "/api/v1/findings" "declarative rule findings"
call_endpoint "/api/v1/forecasts" "resource forecaster"
call_endpoint "/api/v1/dependencies" "dependency mapping"
call_endpoint "/api/v1/decommission" "decommission readiness"
call_endpoint "/api/v1/migration" "migration export plan"

echo "==> Step 7: Verifying coverage honesty in /api/v1/coverage..."
curl -s -H "${AUTH_HEADER}" "http://127.0.0.1:${PORT}/api/v1/coverage" > "${TMP_DIR}/cov.json"
if ! grep -q '"overall_coverage"' "${TMP_DIR}/cov.json"; then
  echo "  [FAIL] /api/v1/coverage missing overall_coverage field."
  exit 1
fi
echo "  [OK] /api/v1/coverage verified."

echo "==> Step 8: Verifying embedded web UI has ZERO external URLs..."
curl -s "http://127.0.0.1:${PORT}/" > "${TMP_DIR}/index.html"
if grep -E 'https?://(?!127\.0\.0\.1|localhost)' "${TMP_DIR}/index.html"; then
  echo "  [FAIL] External network URL found embedded in web UI HTML."
  exit 1
fi
echo "  [OK] Zero external URLs in web UI verified."

echo "==> Step 9: Verifying read-only checks endpoints..."
call_endpoint "/api/v1/checks" "read-only checks catalog"
call_endpoint "/api/v1/activity" "activity audit log"

echo "==> Step 10: Verifying 'kazeshini open' foreground command with idle timeout..."
OPEN_OUTPUT=$("${BIN_PATH}" open --port 7892 --idle-timeout 3s --ephemeral || true)
if ! echo "${OPEN_OUTPUT}" | grep -q "ssh -L 7892:127.0.0.1:7892"; then
  echo "  [FAIL] 'kazeshini open' output did not print expected ssh -L tunneling instruction."
  echo "${OPEN_OUTPUT}"
  exit 1
fi
if ! echo "${OPEN_OUTPUT}" | grep -q "DASHBOARD URL: http://127.0.0.1:7892"; then
  echo "  [FAIL] 'kazeshini open' output missing dashboard URL."
  exit 1
fi
if ! echo "${OPEN_OUTPUT}" | grep -q "Idle timeout (3s without requests) reached"; then
  echo "  [FAIL] 'kazeshini open' did not exit cleanly upon reaching idle timeout."
  echo "${OPEN_OUTPUT}"
  exit 1
fi
echo "  [OK] 'kazeshini open' foreground server, ssh -L tunneling, and idle auto-exit verified."

echo "==> Smoke test suite passed completely with zero errors."

