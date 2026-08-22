"""
CYPHEX — Observability Event Log

A scan today leaves three uncoordinated, ephemeral traces of what happened:
Rich console prints that vanish once the terminal scrolls, a cumulative
per-repo session-memory JSON that records fix *lessons* but not phase
timings or infra health, and nothing at all for some failure paths (a cognee
recall failure is currently silent). This module adds a fourth, durable one:
an append-only JSONL event stream, one file per scan sandbox, that a health
report (backend.observability.health) or a future live dashboard can read
back.

Storage mirrors backend/patch/manifest.py's convention exactly — one file
under <scan_sandbox>/.cyphex/, discoverable the same way
backend/patch/verify_health.py discovers patches.json — so both can be swept
with the same backend/sandboxes/*/.cyphex/* glob.

Contract: emit() NEVER raises. Observability must not be able to break a
scan — a full disk, a read-only filesystem, or a bad field value degrades to
a silent no-op, never a crash mid-pipeline.
"""

import json
import os
import time
from typing import Optional

# Cap: an events.jsonl that grows unbounded on a long-lived sandbox (repeat
# scans of the same repo) is itself an observability hazard. Once a file
# crosses this many lines, emit() drops the oldest half before appending —
# keeps the file bounded without needing a background rotation job.
_MAX_LINES = 4000
_TRIM_TO = 2000


def _events_path(target_dir: str) -> str:
    return os.path.join(target_dir, ".cyphex", "events.jsonl")


def _trim_if_large(path: str) -> None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return
    if len(lines) <= _MAX_LINES:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines[-_TRIM_TO:])
    except Exception:
        pass


def emit(target_dir: Optional[str], event: str, scan_id: Optional[str] = None, **fields) -> None:
    """
    Append one structured event. Best-effort, silent on any failure.

    target_dir: the scan sandbox directory (typically WORK_DIR/scan_id in
      cli_engine.py) — events.jsonl is written under <target_dir>/.cyphex/.
      A falsy target_dir is a no-op (nothing to key the log to).
    event:      short event-type string, e.g. "scan_start", "phase_start",
      "deepagent_result", "deepagent_timeout", "deepagent_error",
      "cognee_recall_result", "cognee_persist_result", "patch_verdict",
      "scan_end". Not an enforced enum — new event types are free to add at
      any call site; consumers should tolerate unknown types.
    scan_id:    denormalized onto every record so a reader never has to
      cross-reference the containing directory name to know which scan an
      event belongs to.
    **fields:   arbitrary JSON-serializable event-specific payload.
    """
    if not target_dir:
        return
    try:
        d = os.path.join(target_dir, ".cyphex")
        os.makedirs(d, exist_ok=True)
        path = _events_path(target_dir)
        record = {"ts": time.time(), "event": event, "scan_id": scan_id, **fields}
        line = json.dumps(record, default=str)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        # Trim is itself best-effort and cheap to skip most calls — only
        # worth the stat+read cost occasionally, not on every single emit.
        if int(time.time()) % 37 == 0:
            _trim_if_large(path)
    except Exception:
        pass  # observability must never break the scan it's observing
