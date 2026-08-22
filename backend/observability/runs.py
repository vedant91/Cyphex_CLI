"""
CYPHEX — Run Registry

Every scan already leaves a durable footprint on disk: a patch manifest
(<sandbox>/.cyphex/patches.json) and an event log
(<sandbox>/.cyphex/events.jsonl). What was missing was anything that read
them as a *series*. The maintainability panel could tell you that 52
patches across 22 manifests were 100% durable — a true statement that
answers almost nothing a maintainer actually asks:

    "What did the last five runs score?"
    "Did the run I kicked off after that refactor get worse?"
    "Which runs never finished?"
    "What exactly happened in the run from this morning?"

This module turns that pile of sandboxes into an ordered history. One
Run per scan, reconstructed from what is already written — no new storage
format, no migration, and older scans that predate a given event type
degrade to partial records rather than disappearing.

A run's identity is its sandbox directory (cli_<8 hex>), which is also its
scan_id, so the registry and the trace/verify views all key on the same
thing.

Read-only. Nothing here mutates a manifest or an event log.
"""

import glob
import json
import os
from collections import Counter
from typing import Optional

from backend.patch.verify_health import SANDBOX_ROOT, _load_entries

# A run that recorded a start but never an end. Distinguished from
# "completed" because an interrupted run's numbers are not comparable to a
# finished one's — treating them the same is how a crashed scan quietly
# drags a trend line down.
COMPLETED = "completed"
INTERRUPTED = "interrupted"
UNKNOWN = "unknown"


def _read_events(path: str, limit: Optional[int] = 4000) -> list:
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return out
    if limit:
        lines = lines[-limit:]
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except Exception:
            continue
        if isinstance(ev, dict):
            out.append(ev)
    return out


def _first(events, name):
    for e in events:
        if e.get("event") == name:
            return e
    return None


def _last(events, name):
    for e in reversed(events):
        if e.get("event") == name:
            return e
    return None


class Run:
    """One scan, reconstructed from its durable footprint."""

    __slots__ = ("scan_id", "sandbox", "started_at", "ended_at", "status",
                 "target", "score", "score_before", "severities", "patches",
                 "verdicts", "waypoints", "events", "agents", "has_events",
                 "has_manifest")

    def __init__(self, scan_id, sandbox):
        self.scan_id = scan_id
        self.sandbox = sandbox
        self.started_at = None
        self.ended_at = None
        self.status = UNKNOWN
        self.target = ""
        self.score = None
        self.score_before = None
        self.severities = {}
        self.patches = {"applied": 0, "total": 0}
        self.verdicts = {}
        self.waypoints = []
        self.events = 0
        self.agents = {"ok": 0, "timeout": 0, "error": 0}
        self.has_events = False
        self.has_manifest = False

    @property
    def duration_s(self) -> Optional[float]:
        if self.started_at and self.ended_at:
            return round(self.ended_at - self.started_at, 1)
        return None

    @property
    def total_findings(self) -> int:
        return sum(self.severities.values()) if self.severities else 0

    @property
    def durability_rate(self) -> Optional[float]:
        total = sum(self.verdicts.values())
        if not total:
            return None
        return self.verdicts.get("PASS", 0) / total * 100.0

    @property
    def score_delta(self) -> Optional[int]:
        if self.score is None or self.score_before is None:
            return None
        return self.score - self.score_before

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_s": self.duration_s,
            "target": self.target,
            "score": self.score,
            "score_before": self.score_before,
            "score_delta": self.score_delta,
            "severities": self.severities,
            "total_findings": self.total_findings,
            "patches": self.patches,
            "verdicts": self.verdicts,
            "durability_rate": self.durability_rate,
            "waypoints": self.waypoints,
            "agents": self.agents,
            "events": self.events,
            "has_events": self.has_events,
            "has_manifest": self.has_manifest,
        }


def _build_run(sandbox: str) -> Run:
    scan_id = os.path.basename(sandbox)
    run = Run(scan_id, sandbox)

    ev_path = os.path.join(sandbox, ".cyphex", "events.jsonl")
    if os.path.isfile(ev_path):
        run.has_events = True
        events = _read_events(ev_path)
        run.events = len(events)

        start = _first(events, "scan_start")
        end = _last(events, "scan_end")
        score_ev = _last(events, "scan_score")

        if start:
            run.started_at = start.get("ts")
            run.target = str(start.get("local_path") or start.get("repo_url") or "")
        if end:
            run.ended_at = end.get("ts")

        if start and end:
            run.status = COMPLETED
        elif start:
            run.status = INTERRUPTED

        if score_ev:
            run.score = score_ev.get("score")
            run.score_before = score_ev.get("score_before")
            run.severities = {
                "Critical": score_ev.get("critical", 0),
                "High": score_ev.get("high", 0),
                "Medium": score_ev.get("medium", 0),
                "Low": score_ev.get("low", 0),
            }
            run.patches = {
                "applied": score_ev.get("patches_applied", 0),
                "total": score_ev.get("patches_total", 0),
            }
            if score_ev.get("target"):
                run.target = str(score_ev["target"])

        run.waypoints = _waypoints_from(events)
        run.agents = {
            "ok": sum(1 for e in events if e.get("event") == "deepagent_result"),
            "timeout": sum(1 for e in events if e.get("event") == "deepagent_timeout"),
            "error": sum(1 for e in events if e.get("event") == "deepagent_error"),
        }

    # Verdicts come from the manifest, which is authoritative and exists for
    # scans far older than the event log — that is why they are not read off
    # patch_verdict events.
    man = os.path.join(sandbox, ".cyphex", "patches.json")
    if os.path.isfile(man):
        entries = _load_entries([man])
        if entries:
            run.has_manifest = True
            run.verdicts = dict(Counter(e.get("verdict", "?") for e in entries))
            if run.started_at is None:
                stamps = sorted(e.get("patched_at", "") for e in entries if e.get("patched_at"))
                if stamps:
                    run.target = run.target or ""
                    try:
                        from datetime import datetime
                        run.started_at = datetime.fromisoformat(stamps[0]).timestamp()
                        run.ended_at = datetime.fromisoformat(stamps[-1]).timestamp()
                    except Exception:
                        pass

    return run


def _waypoints_from(events: list) -> list:
    """Rebuild the waypoint/step tree recorded by backend.observability.trace."""
    wps, by_num = [], {}
    for e in events:
        ev = e.get("event")
        if ev == "trace_waypoint_start":
            wp = {"num": e.get("num", "?"), "title": e.get("title", ""),
                  "goal": e.get("goal", ""), "highlight": bool(e.get("highlight")),
                  "status": "running", "duration_s": None, "steps": []}
            wps.append(wp)
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
    return wps


def discover_runs(limit: Optional[int] = None, root: Optional[str] = None) -> list:
    """Every run on disk, newest first.

    Ordered by the run's own recorded start time where available, falling
    back to directory mtime — a sandbox can be touched long after its scan
    (a later scan reusing the target's genome cache, say), so mtime alone
    would shuffle the history.
    """
    base = root or SANDBOX_ROOT
    if not os.path.isdir(base):
        return []
    runs = []
    for d in glob.glob(os.path.join(base, "*")):
        if not os.path.isdir(os.path.join(d, ".cyphex")):
            continue
        # "<scan_id>_run" directories are the native-deploy working copies of
        # a scan, not scans of their own; counting them would double every
        # run in the history.
        if os.path.basename(d).endswith("_run"):
            continue
        try:
            run = _build_run(d)
        except Exception:
            continue
        if run.has_events or run.has_manifest:
            runs.append(run)

    def sort_key(r):
        if r.started_at:
            return r.started_at
        try:
            return os.path.getmtime(r.sandbox)
        except Exception:
            return 0

    runs.sort(key=sort_key, reverse=True)
    return runs[:limit] if limit else runs


def get_run(scan_id: str, root: Optional[str] = None) -> Optional[Run]:
    """One run in full, by scan_id. Accepts a bare or partial id."""
    base = root or SANDBOX_ROOT
    if not scan_id:
        return None
    candidates = [scan_id, f"cli_{scan_id}"]
    for c in candidates:
        d = os.path.join(base, c)
        if os.path.isdir(os.path.join(d, ".cyphex")):
            return _build_run(d)
    # Prefix match, so a maintainer can type the first few characters.
    for run in discover_runs(root=root):
        if run.scan_id.startswith(scan_id) or run.scan_id.replace("cli_", "").startswith(scan_id):
            return run
    return None


def history_summary(limit: int = 10, root: Optional[str] = None) -> dict:
    """The run history plus the deltas that make a series worth reading."""
    runs = discover_runs(root=root)
    scored = [r for r in runs if r.score is not None]

    regression = None
    if len(scored) >= 2:
        newest, prev = scored[0], scored[1]
        delta = newest.score - prev.score
        regression = {
            "current": newest.score,
            "previous": prev.score,
            "delta": delta,
            "current_id": newest.scan_id,
            "previous_id": prev.scan_id,
            # Only a real drop counts. Equal scores are not a regression, and
            # a run that scored better obviously isn't one either.
            "regressed": delta < 0,
        }

    return {
        "runs": [r.as_dict() for r in runs[:limit]],
        "total_runs": len(runs),
        "completed": sum(1 for r in runs if r.status == COMPLETED),
        "interrupted": sum(1 for r in runs if r.status == INTERRUPTED),
        "scored_runs": len(scored),
        "score_series": [r.score for r in reversed(scored[:limit])],
        "regression": regression,
    }
