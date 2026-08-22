"""
CYPHEX — Waypoint Trace Recorder

The Verify Gate answers "did this patch really work?". The maintainability
panel (backend/patch/verify_health.py) answers "is the gate itself still
healthy?". This module answers the third question a maintainer asks when
something looks wrong: **"what was the pipeline actually doing, step by
step, and how far did it get?"**

Before this, a scan's step-by-step behaviour existed only as terminal
scrollback. Phase banners printed and were gone; a scan that stalled inside
a phase left no record of WHICH sub-operation it stalled in. The
observability event log (backend/observability/events.py) captured phase
boundaries, but a phase like "DYNAMIC VULNERABILITY SCAN" can run for four
minutes across a crawler, an API sweep, and thirteen attack agents — one
`phase_start` event is not a trace of that.

A trace here is two levels deep, deliberately:

    waypoint   4/9  DYNAMIC VULNERABILITY SCAN        <- the goal
      step     crawler          24 endpoints    ok    <- how it was pursued
      step     api discovery    8 routes        ok
      step     agent 03 SQLi    2 confirmed     ok

Every waypoint carries an explicit **goal** — a plain sentence naming what
this phase is trying to establish. That is what makes the output a trace
rather than a progress bar: a reader who has never seen the codebase can
tell what was being attempted, not just how long it took.

DESIGN CONTRACT — recording is decoupled from rendering.
The recorder is the single source of truth; the live terminal deck
(terminal_ui.render_trace_deck) is one *view* of it, and
backend/observability/health.py is another. A scan running in CI with no
TTY records exactly the same trace as an interactive one — the trace
survives into `/status` instead of being terminal theatre. Nothing in this
module imports a renderer, and nothing here requires a terminal.

FAILURE CONTRACT — same as events.py: recording must never break the scan
it observes. Every public method is total; a bad value degrades to a
best-effort string rather than raising into the pipeline.
"""

import time
from typing import Optional

from backend.observability.events import emit

# Status vocabulary, shared by the recorder, the live deck, and the
# post-hoc /status view so the three can never disagree about what a
# state means.
RUNNING = "running"   # started, not finished — the live state
OK = "ok"             # completed, nothing wrong
WARN = "warn"         # completed, but degraded (a fallback was taken)
FAIL = "fail"         # attempted and failed
SKIP = "skip"         # deliberately not attempted (precondition absent)

TERMINAL_STATUSES = (OK, WARN, FAIL, SKIP)

# Goal lines, keyed by the waypoint number cli_engine.py passes to _step().
# Keyed by number rather than title because the same phase is titled
# differently on the two pipeline paths (the URL-only path calls phase 5
# "AI IMMUNE SYSTEM", the source path calls it "IMMUNE SYSTEM - BUILD
# GENOME"), and a maintainer reading a trace cares about the same goal
# either way. A number with no entry degrades to the phase title itself.
WAYPOINT_GOALS = {
    "1": "Acquire the target's source and identify what it is built with",
    "2": "Find candidate weaknesses in the code without running it",
    "3": "Stand the app up in an isolated sandbox so it can be attacked safely",
    "3b": "Map the surrounding network and find exposed services",
    "4": "Prove which candidates are actually reachable and exploitable",
    "5": "Learn this app's normal behaviour well enough to spot an attack",
    "6": "Attack the hardened genome to measure what it actually blocks",
    "7": "Turn confirmed findings into a report a human can act on",
    "8": "Generate a fix for each confirmed finding and prove it works",
}


def goal_for(num, title: str = "") -> str:
    """The goal sentence for a waypoint number, falling back to its title."""
    key = str(num or "").split("/")[0].strip()
    return WAYPOINT_GOALS.get(key) or (title or "").strip() or "—"


class TraceStep:
    """One sub-operation inside a waypoint."""

    __slots__ = ("label", "detail", "status", "started_at", "ended_at", "evidence")

    def __init__(self, label: str, detail: str = "", evidence: Optional[dict] = None):
        self.label = str(label)
        self.detail = str(detail or "")
        self.status = RUNNING
        self.started_at = time.time()
        self.ended_at = None
        self.evidence = dict(evidence or {})

    @property
    def duration_s(self) -> float:
        return (self.ended_at or time.time()) - self.started_at

    def finish(self, status: str = OK, detail: str = "", evidence: Optional[dict] = None):
        self.status = status if status in TERMINAL_STATUSES else OK
        if detail:
            self.detail = str(detail)
        if evidence:
            self.evidence.update(evidence)
        self.ended_at = time.time()

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "detail": self.detail,
            "status": self.status,
            "duration_s": round(self.duration_s, 2),
            "evidence": self.evidence,
        }


class TraceWaypoint:
    """One pipeline phase, its goal, and the steps taken to pursue it."""

    __slots__ = ("num", "title", "goal", "steps", "started_at", "ended_at", "status", "highlight")

    def __init__(self, num, title: str, highlight: bool = False):
        self.num = str(num)
        self.title = str(title)
        self.goal = goal_for(num, title)
        self.steps = []
        self.started_at = time.time()
        self.ended_at = None
        self.status = RUNNING
        # A highlighted waypoint is one whose internals are worth watching
        # live rather than summarising after the fact (the genome build's
        # per-generation evolution being the motivating case).
        self.highlight = bool(highlight)

    @property
    def duration_s(self) -> float:
        return (self.ended_at or time.time()) - self.started_at

    @property
    def active_step(self) -> Optional[TraceStep]:
        for s in reversed(self.steps):
            if s.status == RUNNING:
                return s
        return None

    def derived_status(self) -> str:
        """A waypoint is as bad as its worst finished step."""
        if any(s.status == FAIL for s in self.steps):
            return FAIL
        if any(s.status == WARN for s in self.steps):
            return WARN
        return self.status if self.status in TERMINAL_STATUSES else OK

    def as_dict(self) -> dict:
        return {
            "num": self.num,
            "title": self.title,
            "goal": self.goal,
            "status": self.derived_status(),
            "duration_s": round(self.duration_s, 2),
            "highlight": self.highlight,
            "steps": [s.as_dict() for s in self.steps],
        }


class TraceRecorder:
    """
    Records the waypoint/step tree for one scan and mirrors every
    transition into the durable event log.

    Held by CyphexEngine for the lifetime of a scan. All methods are
    failure-safe: an exception in tracing must never propagate into the
    pipeline being traced.
    """

    def __init__(self, target_dir: Optional[str] = None, scan_id: Optional[str] = None,
                 max_waypoints: int = 64):
        self.target_dir = target_dir
        self.scan_id = scan_id
        self.waypoints = []
        self.max_waypoints = max_waypoints
        self._listeners = []

    # ── plumbing ────────────────────────────────────────────────────────
    def subscribe(self, fn):
        """Register a callback fired on every trace mutation.

        This is how the live terminal deck stays in sync without the
        recorder knowing a renderer exists. A listener that raises is
        dropped rather than allowed to break the scan.
        """
        self._listeners.append(fn)

    def _notify(self):
        for fn in list(self._listeners):
            try:
                fn(self)
            except Exception:
                try:
                    self._listeners.remove(fn)
                except ValueError:
                    pass

    def _emit(self, event: str, **fields):
        try:
            emit(self.target_dir, event, scan_id=self.scan_id, **fields)
        except Exception:
            pass

    # ── waypoints ───────────────────────────────────────────────────────
    @property
    def current(self) -> Optional[TraceWaypoint]:
        return self.waypoints[-1] if self.waypoints else None

    def begin_waypoint(self, num, title: str, highlight: bool = False) -> Optional[TraceWaypoint]:
        try:
            prev = self.current
            if prev is not None and prev.status == RUNNING:
                self.end_waypoint()
            wp = TraceWaypoint(num, title, highlight=highlight)
            self.waypoints.append(wp)
            # Bound memory on a pathological run; the live deck only ever
            # shows the tail anyway and the durable record is the event log.
            if len(self.waypoints) > self.max_waypoints:
                del self.waypoints[: len(self.waypoints) - self.max_waypoints]
            self._emit("trace_waypoint_start", num=wp.num, title=wp.title,
                       goal=wp.goal, highlight=wp.highlight)
            self._notify()
            return wp
        except Exception:
            return None

    def end_waypoint(self, status: str = OK):
        try:
            wp = self.current
            if wp is None or wp.status != RUNNING:
                return
            for s in wp.steps:
                if s.status == RUNNING:
                    s.finish(OK)
            wp.status = status if status in TERMINAL_STATUSES else OK
            wp.ended_at = time.time()
            self._emit("trace_waypoint_end", num=wp.num, title=wp.title,
                       status=wp.derived_status(), duration_s=round(wp.duration_s, 2),
                       steps=len(wp.steps))
            self._notify()
        except Exception:
            pass

    # ── steps ───────────────────────────────────────────────────────────
    def step(self, label: str, detail: str = "", evidence: Optional[dict] = None) -> Optional[TraceStep]:
        """Open a sub-operation under the current waypoint."""
        try:
            wp = self.current
            if wp is None:
                return None
            st = TraceStep(label, detail, evidence)
            wp.steps.append(st)
            self._emit("trace_step_start", waypoint=wp.num, label=st.label, detail=st.detail)
            self._notify()
            return st
        except Exception:
            return None

    def finish_step(self, st: Optional[TraceStep], status: str = OK,
                    detail: str = "", evidence: Optional[dict] = None):
        try:
            if st is None:
                return
            st.finish(status, detail, evidence)
            wp = self.current
            self._emit("trace_step_end", waypoint=(wp.num if wp else "?"),
                       label=st.label, detail=st.detail, status=st.status,
                       duration_s=round(st.duration_s, 2), **(evidence or {}))
            self._notify()
        except Exception:
            pass

    def note(self, label: str, detail: str = "", status: str = OK,
             evidence: Optional[dict] = None):
        """Record an already-complete sub-operation in one call.

        For work that is finished by the time you can describe it (a count,
        a decision, a fallback that was taken) — the common case.

        If the caller already measured how long the work took and passes it
        as evidence["duration_s"], that value wins. Otherwise the step would
        report ~0.0s simply because open-and-close happened in one call —
        which is a lie about work that genuinely took time (a genome
        generation, an agent probe), and the exact number a maintainer
        reads this trace to find.
        """
        try:
            st = self.step(label, detail, evidence)
            measured = (evidence or {}).get("duration_s")
            if st is not None and isinstance(measured, (int, float)) and measured > 0:
                st.started_at = time.time() - float(measured)
            self.finish_step(st, status, detail, evidence)
        except Exception:
            pass

    # ── views ───────────────────────────────────────────────────────────
    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "waypoints": [w.as_dict() for w in self.waypoints],
        }

    def tail(self, waypoints: int = 1, steps: int = 6):
        """The most recent slice, for a size-bounded live view."""
        wps = self.waypoints[-waypoints:] if waypoints else self.waypoints
        return [(w, w.steps[-steps:] if steps else w.steps) for w in wps]


class NullTrace(TraceRecorder):
    """A recorder that records nothing — used when tracing is disabled.

    Same interface, so call sites never need a `if self.trace:` guard.
    """

    def __init__(self):
        super().__init__(target_dir=None, scan_id=None)

    def _emit(self, event: str, **fields):
        pass
