"""
CYPHEX — System Observability

CYPHEX has always had three separate, uncoordinated telemetry surfaces: the
Verify Gate's own patch-manifest history (backend/patch/verify_health.py),
ad-hoc Rich console prints for cognee recall/persist and DeepAgents swarm
status (ephemeral, some paths entirely silent on failure), and
cyphex/doctor.py's static pre-flight check (no runtime/scan awareness at
all). None of them talk to each other and none expose a single answer to
"is the pipeline healthy right now, and what happened on the last scan."

This module is that single answer. It reads the event log this package
writes during a scan (backend.observability.events) alongside the Verify
Gate's own health report, and reconstructs a maintainer-facing picture: how
long each phase took, how the DeepAgents swarm performed, whether cognee
memory is actually persisting, and a tail of recent errors — with concrete
next steps. Read-only; never mutates state; tolerates a missing or partial
event log the same way verify_health.py tolerates a missing manifest.
"""

import glob
import json
import os
from collections import Counter
from typing import Optional

from backend.patch.verify_health import get_verify_health, SANDBOX_ROOT

# Event types that represent a failure/degraded outcome — used to build the
# recent-errors tail without a maintainer having to know every event name.
_ERROR_SUFFIXES = ("_error", "_timeout")


def discover_event_logs(target_dir: Optional[str] = None) -> list:
    """
    Find every events.jsonl the observability layer has ever written.
    Mirrors backend/patch/verify_health.py's discover_manifests() exactly —
    same sandbox root, same "one directory or sweep everything" contract.
    """
    if target_dir:
        p = os.path.join(target_dir, ".cyphex", "events.jsonl")
        return [p] if os.path.isfile(p) else []
    if not os.path.isdir(SANDBOX_ROOT):
        return []
    paths = glob.glob(os.path.join(SANDBOX_ROOT, "*", ".cyphex", "events.jsonl"))
    return sorted(paths, key=os.path.getmtime, reverse=True)


def _read_events(paths: list, limit_per_file: Optional[int] = 500) -> list:
    """
    Read + parse every JSONL line across the given files, newest files first.

    Deduped by exact line content across ALL files: a native-sandbox deploy
    (cli_engine.py's Priority-2/3 path) copies the whole source_dir into a
    sibling "<scan_id>_run" directory mid-scan to build/run the app without
    touching the clone — that copy carries a frozen snapshot of
    .cyphex/events.jsonl as it stood at copy time, so the same scan_id can
    legitimately show up under two sandbox directories. Byte-identical JSON
    lines are the same event observed twice, not two events; two genuinely
    distinct events colliding on timestamp+full payload is not realistic.
    """
    events = []
    seen_lines = set()
    for p in paths:
        scan_dir = os.path.basename(os.path.dirname(os.path.dirname(p)))
        try:
            with open(p, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            continue
        if limit_per_file:
            lines = lines[-limit_per_file:]
        for raw in lines:
            raw = raw.strip()
            if not raw or raw in seen_lines:
                continue
            seen_lines.add(raw)
            try:
                ev = json.loads(raw)
            except Exception:
                continue
            if not isinstance(ev, dict):
                continue
            ev.setdefault("_scan_dir", scan_dir)
            events.append(ev)
    return events


def _last_scan_summary(events: list) -> Optional[dict]:
    """
    Reconstruct the most recently active scan's timeline from its events:
    phase durations (derived from consecutive phase_start timestamps, since
    phases don't currently emit their own end-marker), DeepAgents swarm
    outcome counts, cognee recall/persist success rates, and patch-verdict
    tally. Returns None when there is no event history at all.
    """
    by_scan = {}
    for e in events:
        key = e.get("scan_id") or e.get("_scan_dir") or "?"
        by_scan.setdefault(key, []).append(e)
    if not by_scan:
        return None

    def _last_ts(evs):
        return max((e.get("ts", 0) or 0 for e in evs), default=0)

    scan_id = max(by_scan, key=lambda k: _last_ts(by_scan[k]))
    evs = sorted(by_scan[scan_id], key=lambda e: e.get("ts", 0) or 0)

    start = next((e for e in evs if e.get("event") == "scan_start"), None)
    end = next((e for e in evs if e.get("event") == "scan_end"), None)

    phases = [e for e in evs if e.get("event") == "phase_start"]
    phase_timings = []
    for i, p in enumerate(phases):
        next_ts = phases[i + 1]["ts"] if i + 1 < len(phases) else (end["ts"] if end else p.get("ts", 0))
        phase_timings.append({
            "title": p.get("title") or p.get("num") or "?",
            "duration_s": round(max(0.0, (next_ts or 0) - (p.get("ts") or 0)), 1),
        })

    agent_ok = [e for e in evs if e.get("event") == "deepagent_result"]
    agent_timeout = [e for e in evs if e.get("event") == "deepagent_timeout"]
    agent_error = [e for e in evs if e.get("event") == "deepagent_error"]

    recalls = [e for e in evs if e.get("event") == "cognee_recall_result"]
    persists = [e for e in evs if e.get("event") == "cognee_persist_result"]

    verdicts = Counter(e.get("verdict", "?") for e in evs if e.get("event") == "patch_verdict")

    # Waypoint trace, reconstructed from the trace_* events the recorder
    # mirrored into this log. This is what makes the trace outlive the
    # terminal: the live deck is gone once the scan ends, but a maintainer
    # asking "what did that scan actually do, and where did it slow down or
    # fail?" gets the whole goal/step tree back from here.
    trace = []
    by_num = {}
    for e in evs:
        ev = e.get("event")
        if ev == "trace_waypoint_start":
            wp = {"num": e.get("num", "?"), "title": e.get("title", ""),
                  "goal": e.get("goal", ""), "highlight": bool(e.get("highlight")),
                  "status": "running", "duration_s": None, "steps": []}
            trace.append(wp)
            by_num[wp["num"]] = wp
        elif ev == "trace_waypoint_end":
            wp = by_num.get(e.get("num"))
            if wp is not None:
                wp["status"] = e.get("status", "ok")
                wp["duration_s"] = e.get("duration_s")
        elif ev == "trace_step_end":
            wp = by_num.get(e.get("waypoint"))
            if wp is not None:
                wp["steps"].append({
                    "label": e.get("label", ""),
                    "detail": e.get("detail", ""),
                    "status": e.get("status", "ok"),
                    "duration_s": e.get("duration_s"),
                })

    return {
        "scan_id": scan_id,
        "started": start is not None,
        "completed": end is not None,
        "duration_s": round((end["ts"] - start["ts"]), 1) if start and end else None,
        "phase_timings": phase_timings,
        "agents": {
            "succeeded": len(agent_ok),
            "timed_out": len(agent_timeout),
            "errored": len(agent_error),
        },
        "cognee": {
            "recall_ok": sum(1 for e in recalls if e.get("ok")),
            "recall_total": len(recalls),
            "persist_ok": sum(1 for e in persists if e.get("ok")),
            "persist_total": len(persists),
        },
        "patch_verdicts": dict(verdicts),
        "trace": trace,
    }


def get_system_health(target_dir: Optional[str] = None) -> dict:
    """
    Build the full System Observability report:
      verify_gate      — the existing Verify Gate maintainability report
                          (backend.patch.verify_health.get_verify_health())
      event_logs_found / events_recorded — how many distinct SCANS have
        telemetry (by scan_id, after dedup — see _read_events) and how many
        events were recorded across them; not a raw file count, since a
        native-sandbox deploy can leave a second frozen snapshot file under
        the same scan_id (see _read_events' docstring)
      last_scan        — reconstructed timeline of the most recent scan
      recent_errors    — the newest failure-type events across all scans
      next_steps       — actionable maintainer guidance
    """
    verify_report = get_verify_health(target_dir)
    event_paths = discover_event_logs(target_dir)
    events = _read_events(event_paths)
    last_scan = _last_scan_summary(events)
    distinct_scans = len({e.get("scan_id") or e.get("_scan_dir") for e in events}) if events else 0

    recent_errors = [
        e for e in events
        if str(e.get("event", "")).endswith(_ERROR_SUFFIXES)
        or (e.get("event") == "cognee_recall_result" and e.get("ok") is False)
        or (e.get("event") == "cognee_persist_result" and e.get("ok") is False)
    ]
    recent_errors.sort(key=lambda e: e.get("ts", 0) or 0, reverse=True)

    next_steps = list(verify_report.get("next_steps", []))
    if not event_paths:
        next_steps.insert(0, "No observability event log found yet — run a scan "
                              "(`cyphex scan <target>`) to start recording phase timings, "
                              "DeepAgents swarm outcomes, and cognee status.")
    elif last_scan and not last_scan["completed"]:
        next_steps.insert(0, f"Most recent scan ({last_scan['scan_id']}) has a scan_start event "
                              "but no scan_end — it may have crashed or been interrupted "
                              "before reaching the final banner.")
    if last_scan:
        stalled = last_scan["agents"]["timed_out"] + last_scan["agents"]["errored"]
        if stalled:
            next_steps.insert(0, f"Last scan: {last_scan['agents']['timed_out']} DeepAgent(s) timed out, "
                                  f"{last_scan['agents']['errored']} errored — check Ollama load/timeouts "
                                  "if this is frequent.")
        recall_total = last_scan["cognee"]["recall_total"]
        if recall_total and last_scan["cognee"]["recall_ok"] == 0:
            next_steps.insert(0, "Last scan: 0/%d cognee memory recalls succeeded — cross-scan "
                                  "fix memory is not being used." % recall_total)

    return {
        "verify_gate": verify_report,
        "event_logs_found": distinct_scans,
        "events_recorded": len(events),
        "last_scan": last_scan,
        "recent_errors": recent_errors[:10],
        "next_steps": next_steps,
    }
