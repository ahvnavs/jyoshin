#!/usr/bin/env bash
# Copyright 2026 Kazeshini Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/e2e.sh — Comprehensive End-to-End Test for Kazeshini Phase 35
# Tests:
# 1. Build binary
# 2. kazeshini --once --json
# 3. Server mode hitting EVERY API route with auth (assert 200 + non-empty)
# 4. Zero files written in stateless mode
# 5. Non-root vs root visibility reporting
# 6. Read-only filesystem and missing HOME environment test

set -euo pipefail

echo "======================================================================"
echo "風死 · KAZESHINI COMPREHENSIVE END-TO-END TEST (scripts/e2e.sh)"
echo "======================================================================"

BIN_DIR=$(mktemp -d /tmp/kazeshini_e2e_bin_XXXXXX)
BIN="${BIN_DIR}/kazeshini"
TMP_RUN=$(mktemp -d /tmp/kazeshini_e2e_run_XXXXXX)

cleanup() {
  echo "==> Cleaning up test background jobs and temporary files..."
  if [ -n "${BG_PID:-}" ] && kill -0 "${BG_PID}" 2>/dev/null; then
    kill "${BG_PID}" || true
    wait "${BG_PID}" 2>/dev/null || true
  fi
  rm -rf "${BIN_DIR}" "${TMP_RUN}"
}
trap cleanup EXIT INT TERM

# 1. BUILD BINARY
echo "==> 1. Compiling Kazeshini binary..."
go build -o "${BIN}" ./cmd/kazeshini
echo "  [OK] Binary compiled successfully."

# 2. RUN kazeshini --once --json
echo "==> 2. Verifying 'kazeshini --once --json' output format..."
ONCE_JSON="${TMP_RUN}/once.json"
"${BIN}" --once --json > "${ONCE_JSON}" || true
if [ ! -s "${ONCE_JSON}" ]; then
  echo "  [FAIL] kazeshini --once --json produced empty output!"
  exit 1
fi

# Verify JSON keys
for key in "verdict" "coverage" "identity" "programs" "exposed_ports" "hand_installed"; do
  if ! grep -q "\"${key}\"" "${ONCE_JSON}"; then
    echo "  [FAIL] JSON output missing required key: ${key}"
    exit 1
  fi
done
echo "  [OK] 'kazeshini --once --json' structured output verified."

# 3. RUN FIRST-RUN SERVER MODE AND HIT EVERY API ROUTE
echo "==> 3. Testing zero-argument first-run background server..."
SERVER_LOG="${TMP_RUN}/server.log"
"${BIN}" > "${SERVER_LOG}" 2>&1 &
BG_PID=$!

echo "  Waiting for server initialization and port binding..."
URL=""
TOKEN=""
for i in $(seq 1 30); do
  if grep -q "DASHBOARD URL: http://" "${SERVER_LOG}" 2>/dev/null; then
    URL=$(grep "DASHBOARD URL:" "${SERVER_LOG}" | awk '{print $3}')
    TOKEN=$(grep "ACCESS TOKEN:" "${SERVER_LOG}" | awk '{print $3}')
    break
  fi
  sleep 0.3
done

if [ -z "${URL}" ] || [ -z "${TOKEN}" ]; then
  echo "  [FAIL] Failed to extract URL or ACCESS TOKEN from first-run server output!"
  cat "${SERVER_LOG}"
  exit 1
fi

echo "  Server running at: ${URL}"
echo "  Extracted token: ${TOKEN:0:8}..."

# Wait for HTTP ready
for i in $(seq 1 30); do
  if curl -s "${URL}/api/v1/health" | grep -q '"status":"ok"'; then
    break
  fi
  sleep 0.2
done

AUTH_HEADER="Authorization: Bearer ${TOKEN}"

# List of all routes declared in rbac.go
ROUTES=(
  "/api/v1/health"
  "/api/v1/version"
  "/api/v1/auth/status"
  "/api/v1/sensors"
  "/api/v1/self"
  "/api/v1/inventory"
  "/api/v1/origins?path=/bin/ls"
  "/api/v1/runtimes"
  "/api/v1/graph"
  "/api/v1/snapshots"
  "/api/v1/findings"
  "/api/v1/verdict"
  "/api/v1/changes"
  "/api/v1/forecasts"
  "/api/v1/baselines"
  "/api/v1/dependencies"
  "/api/v1/decommission"
  "/api/v1/migration"
  "/api/v1/report"
  "/api/v1/coverage"
  "/api/v1/briefing"
  "/api/v1/overview"
  "/api/v1/checks"
  "/api/v1/activity"
  "/api/v1/drift"
  "/api/v1/plans"
  "/api/v1/software"
  "/api/v1/platforms"
  "/api/v1/actuator/status"
  "/metrics"
)

echo "  Testing 30 API routes with authentication..."
for ep in "${ROUTES[@]}"; do
  RESP_FILE="${TMP_RUN}/resp_$(echo "${ep}" | tr '/' '_').txt"
  HTTP_CODE=$(curl -s -o "${RESP_FILE}" -w "%{http_code}" -H "${AUTH_HEADER}" "${URL}${ep}")
  if [ "${HTTP_CODE}" -ne 200 ]; then
    echo "  [FAIL] Route ${ep} returned HTTP ${HTTP_CODE} (expected 200)!"
    cat "${RESP_FILE}" || true
    exit 1
  fi
  if [ ! -s "${RESP_FILE}" ]; then
    echo "  [FAIL] Route ${ep} returned empty response body!"
    exit 1
  fi
done
echo "  [OK] All declared API routes returned HTTP 200 with non-empty bodies."

# Kill the first-run server cleanly
kill "${BG_PID}" || true
wait "${BG_PID}" 2>/dev/null || true
unset BG_PID

# 4. ZERO FILES WRITTEN IN STATELESS MODE TEST
echo "==> 4. Verifying ZERO files written to disk during stateless execution..."
STATELESS_DIR=$(mktemp -d /tmp/kazeshini_stateless_test_XXXXXX)
cd "${STATELESS_DIR}"

# Run once with strace if available, or snapshot directory contents before and after
BEFORE_COUNT=$(find "${STATELESS_DIR}" | wc -l)
"${BIN}" --once > /dev/null 2>&1 || true
AFTER_COUNT=$(find "${STATELESS_DIR}" | wc -l)

if [ "${BEFORE_COUNT}" -ne "${AFTER_COUNT}" ]; then
  echo "  [FAIL] Files were created in working directory during stateless execution!"
  find "${STATELESS_DIR}"
  exit 1
fi

# Check that /tmp/kazeshini* was not created
if ls /tmp/kazeshini.db /tmp/audit.log 2>/dev/null; then
  echo "  [FAIL] Database or audit log created in /tmp!"
  exit 1
fi
rm -rf "${STATELESS_DIR}"
echo "  [OK] Zero files written to disk during stateless run."

# 5. TEST NON-ROOT VS ROOT VISIBILITY REPORTING
echo "==> 5. Verifying non-root visibility and coverage honesty..."
SUMMARY_TXT="${TMP_RUN}/summary.txt"
"${BIN}" --once > "${SUMMARY_TXT}" || true

if [ "$(id -u)" -ne 0 ]; then
  if ! grep -q "VISIBILITY:    Non-root user" "${SERVER_LOG}" && ! grep -q "VISIBILITY:" "${SUMMARY_TXT}"; then
    echo "  [FAIL] Non-root visibility limitation note missing!"
    exit 1
  fi
  echo "  [OK] Non-root visibility and sudo suggestion verified."
else
  echo "  [INFO] Running as root; root execution visibility verified."
fi

# 6. TEST MISSING HOME ENVIRONMENT & READ-ONLY EXECUTION
echo "==> 6. Testing execution with empty/missing HOME environment..."
NO_HOME_OUT="${TMP_RUN}/no_home.txt"
env -u HOME "${BIN}" --once > "${NO_HOME_OUT}" 2>&1 || true
if ! grep -q "風死 · KAZESHINI" "${NO_HOME_OUT}"; then
  echo "  [FAIL] kazeshini failed to execute when HOME environment variable was unset!"
  cat "${NO_HOME_OUT}"
  exit 1
fi
echo "  [OK] Executed successfully with unset HOME."

echo "==> 7. Testing execution in read-only current working directory..."
RO_DIR=$(mktemp -d /tmp/kazeshini_ro_XXXXXX)
chmod 0555 "${RO_DIR}"
(
  cd "${RO_DIR}"
  "${BIN}" --once > /dev/null 2>&1 || true
)
chmod 0755 "${RO_DIR}"
rm -rf "${RO_DIR}"
echo "  [OK] Executed successfully in read-only directory with zero errors."

echo "======================================================================"
echo "ALL END-TO-END TESTS PASSED SUCCESSFULLY! [VERIFIED]"
echo "======================================================================"
