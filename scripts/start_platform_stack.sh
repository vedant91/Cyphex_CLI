#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"

if [[ ! -x "$PY" ]]; then
  echo "[ERR] Python venv not found at $PY"
  exit 1
fi

cd "$ROOT"
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

cleanup() {
  echo ""
  echo "[INFO] Stopping platform services..."
  if [[ -n "${FRONTEND_PID:-}" ]]; then kill "$FRONTEND_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "${API_PID:-}" ]]; then kill "$API_PID" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT INT TERM

echo "[1/3] Starting FastAPI backend on http://localhost:8000"
(
  cd backend/backend
  "$PY" api.py
) &
API_PID=$!

echo "[2/3] Starting frontend on http://localhost:5173"
(
  cd frontend
  if [[ ! -d node_modules ]]; then
    npm install
  fi
  npm run dev -- --host 0.0.0.0 --port 5173
) &
FRONTEND_PID=$!

echo "[3/3] Platform running"
echo "Backend:  http://localhost:8000"
echo "Frontend: http://localhost:5173"
echo "Press Ctrl+C to stop both."

wait -n "$API_PID" "$FRONTEND_PID"
