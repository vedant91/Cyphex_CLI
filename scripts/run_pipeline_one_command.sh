#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"

# Args:
#   $1 = target source path to scan (default: backend/sandbox/vulncorp)
#   $2 = output file (default: cyphex_output.txt)
TARGET_PATH="${1:-$ROOT/backend/sandbox/vulncorp}"
OUTPUT_FILE="${2:-$ROOT/cyphex_output.txt}"
GENERATIONS="${GENERATIONS:-10}"
PULL_MODELS="${PULL_MODELS:-1}"

if [[ ! -x "$PY" ]]; then
  echo "[ERR] Python venv not found at $PY"
  echo "Create it and install deps first:"
  echo "  python3 -m venv .venv && .venv/bin/pip install -r backend/backend/requirements.txt"
  exit 1
fi

cd "$ROOT"
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

echo "[1/5] Runtime doctor"
"$PY" cyphex_cli.py doctor

if [[ "$PULL_MODELS" == "1" ]]; then
  if command -v ollama >/dev/null 2>&1; then
    echo "[2/5] Ensuring required Ollama models"
    ollama pull deepseek-coder:1.3b
    ollama pull phi3:mini
    ollama pull llama3.2:1b
    ollama pull cyphex-patch
  else
    echo "[WARN] ollama is not installed; continuing with degraded AI behavior"
  fi
else
  echo "[2/5] Skipping model pull (PULL_MODELS=$PULL_MODELS)"
fi

echo "[3/5] Council doctor (non-blocking)"
"$PY" cyphex_cli.py council-doctor || true

echo "[4/5] Running full CYPHEX scan+patch pipeline"
echo "      target: $TARGET_PATH"
echo "      output: $OUTPUT_FILE"
"$PY" cyphex_cli.py scan \
  --path "$TARGET_PATH" \
  --generations "$GENERATIONS" \
  --output "$OUTPUT_FILE" \
  --non-interactive

echo "[5/5] Done"
echo "Report written to: $OUTPUT_FILE"
