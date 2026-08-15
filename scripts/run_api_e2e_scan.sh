#!/usr/bin/env bash
set -euo pipefail

# Runs a scan through backend API and polls until completion.
# Requires backend API already running (use scripts/start_platform_stack.sh).

API_BASE="${API_BASE:-http://localhost:8000}"
TARGET_URL="${1:-http://localhost:3001}"
TIMEOUT_SECS="${TIMEOUT_SECS:-1800}"

echo "[1/3] Starting scan via API"
START_JSON="$(curl -sS -X POST "$API_BASE/api/scan" \
  -H 'Content-Type: application/json' \
  -d "{\"target_url\":\"$TARGET_URL\",\"timeout\":$TIMEOUT_SECS}")"

SCAN_ID="$(printf '%s' "$START_JSON" | sed -n 's/.*"scan_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [[ -z "$SCAN_ID" ]]; then
  echo "[ERR] Could not parse scan_id from API response:"
  echo "$START_JSON"
  exit 1
fi

echo "scan_id=$SCAN_ID"
echo "[2/3] Polling status"

while true; do
  STATUS_JSON="$(curl -sS "$API_BASE/api/scan/$SCAN_ID")"
  STATUS="$(printf '%s' "$STATUS_JSON" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

  if [[ "$STATUS" == "completed" ]]; then
    echo "[OK] Scan completed"
    echo "$STATUS_JSON"
    break
  fi

  if [[ "$STATUS" == "error" ]]; then
    echo "[ERR] Scan failed"
    echo "$STATUS_JSON"
    exit 1
  fi

  echo "... status=$STATUS"
  sleep 2
done

echo "[3/3] Done"
