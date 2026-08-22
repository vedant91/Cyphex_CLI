"""
CYPHEX — Waypoint trace tests.

Guards the two properties the trace exists for:

  1. It is DURABLE. The live deck is a view; the record is the event log.
     A trace recorded with no terminal attached must still be fully
     recoverable by /status afterwards — that is the whole difference
     between traceability and terminal scrollback.

  2. It is HONEST. A waypoint is as bad as its worst step, statuses never
     silently upgrade, and a failure is visible without reading detail
     text.

Plus the failure-safety contract shared with events.py: tracing must never
raise into the pipeline it observes.
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend.observability.trace import (  # noqa: E402
    TraceRecorder, NullTrace, goal_for, WAYPOINT_GOALS,
    OK, WARN, FAIL, SKIP, RUNNING,
)
from backend.observability.health import get_system_health  # noqa: E402
from backend.observability.events import emit  # noqa: E402


class TestGoals:
    def test_every_pipeline_waypoint_has_a_goal(self):
        """A trace without goals is a progress bar. Each numbered phase of
        the pipeline must name what it is trying to establish."""
        for num in ("1", "2", "3", "4", "5", "6", "7", "8"):
            assert WAYPOINT_GOALS.get(num), f"waypoint {num} has no goal"

    def test_goal_lookup_tolerates_the_n_of_m_form(self):
        assert goal_for("5/9") == WAYPOINT_GOALS["5"]
        assert goal_for("3b/9") == WAYPOINT_GOALS["3b"]

    def test_unknown_waypoint_falls_back_to_its_title(self):
        assert goal_for("99", "SOMETHING NEW") == "SOMETHING NEW"

    def test_unknown_waypoint_without_title_never_returns_empty(self):
        assert goal_for("99", "") == "—"


class TestStatusPropagation:
    def test_waypoint_is_as_bad_as_its_worst_step(self):
        tr = TraceRecorder(None, "t")
        tr.begin_waypoint("8/9", "AI PATCH + VERIFY")
        tr.note("a", "", OK)
        tr.note("b", "", FAIL)
        tr.note("c", "", OK)
        assert tr.current.derived_status() == FAIL

    def test_a_warn_degrades_an_otherwise_clean_waypoint(self):
        tr = TraceRecorder(None, "t")
        tr.begin_waypoint("5/9", "GENOME")
        tr.note("gen 0", "", OK)
        tr.note("gen 1", "", WARN)
        assert tr.current.derived_status() == WARN

    def test_fail_outranks_warn(self):
        tr = TraceRecorder(None, "t")
        tr.begin_waypoint("5/9", "GENOME")
        tr.note("a", "", WARN)
        tr.note("b", "", FAIL)
        assert tr.current.derived_status() == FAIL

    def test_ending_a_waypoint_closes_its_running_steps(self):
        """A step left open when the phase ends must not stay RUNNING
        forever — a stuck spinner in a finished trace is a lie."""
        tr = TraceRecorder(None, "t")
        tr.begin_waypoint("4/9", "DYNAMIC SCAN")
        tr.step("crawler", "walking")
        tr.end_waypoint()
        assert all(s.status != RUNNING for s in tr.waypoints[0].steps)

    def test_beginning_a_waypoint_closes_the_previous_one(self):
        tr = TraceRecorder(None, "t")
        tr.begin_waypoint("1/9", "A")
        tr.begin_waypoint("2/9", "B")
        assert tr.waypoints[0].status != RUNNING
        assert tr.waypoints[0].ended_at is not None


class TestDurability:
    def test_trace_survives_into_status_without_a_terminal(self):
        """The end-to-end property: record with no TTY, recover everything
        from the durable event log."""
        with tempfile.TemporaryDirectory() as td:
            emit(td, "scan_start", scan_id="s1")
            tr = TraceRecorder(td, "s1")
            tr.begin_waypoint("5/9", "IMMUNE SYSTEM - BUILD GENOME", highlight=True)
            tr.note("generation 0", "blocked 23/30", WARN)
            tr.note("generation 1", "blocked 20/20", OK)
            tr.end_waypoint()
            emit(td, "scan_end", scan_id="s1")

            trace = get_system_health(td)["last_scan"]["trace"]
            assert len(trace) == 1
            wp = trace[0]
            assert wp["num"] == "5/9"
            assert wp["highlight"] is True
            assert wp["goal"] == WAYPOINT_GOALS["5"]
            assert wp["status"] == WARN, "the warn step must survive the round trip"
            labels = [s["label"] for s in wp["steps"]]
            assert labels == ["generation 0", "generation 1"]

    def test_a_failed_waypoint_is_recoverable_as_failed(self):
        with tempfile.TemporaryDirectory() as td:
            emit(td, "scan_start", scan_id="s1")
            tr = TraceRecorder(td, "s1")
            tr.begin_waypoint("8/9", "AI PATCH + VERIFY")
            tr.note("verify CWE-79", "FAIL · views.js", FAIL)
            tr.end_waypoint()
            emit(td, "scan_end", scan_id="s1")

            trace = get_system_health(td)["last_scan"]["trace"]
            assert trace[0]["status"] == FAIL
            assert any(s["status"] == FAIL for s in trace[0]["steps"])

    def test_no_target_dir_records_in_memory_without_writing(self):
        tr = TraceRecorder(None, "t")
        tr.begin_waypoint("1/9", "A")
        tr.note("x", "", OK)
        tr.end_waypoint()
        assert len(tr.as_dict()["waypoints"]) == 1


class TestFailureSafety:
    def test_step_without_a_waypoint_is_a_noop_not_a_crash(self):
        tr = TraceRecorder(None, "t")
        assert tr.step("orphan") is None
        tr.note("orphan", "", OK)          # must not raise
        tr.finish_step(None, OK)           # must not raise

    def test_a_raising_listener_is_dropped_not_propagated(self):
        """The live deck subscribes to the recorder. A renderer that blows
        up must never take the scan down with it."""
        tr = TraceRecorder(None, "t")

        def boom(_):
            raise RuntimeError("renderer exploded")

        tr.subscribe(boom)
        tr.begin_waypoint("1/9", "A")      # must not raise
        assert boom not in tr._listeners, "a raising listener must be dropped"

    def test_unknown_status_is_coerced_not_trusted(self):
        tr = TraceRecorder(None, "t")
        tr.begin_waypoint("1/9", "A")
        tr.note("x", "", "banana")
        assert tr.current.steps[0].status in (OK, WARN, FAIL, SKIP)

    def test_null_trace_accepts_every_call(self):
        n = NullTrace()
        n.begin_waypoint("1/9", "A")
        n.note("x", "y", OK)
        s = n.step("z")
        n.finish_step(s, OK)
        n.end_waypoint()
        assert n.as_dict()["waypoints"] == [] or True  # never raises

    def test_waypoint_list_is_bounded(self):
        tr = TraceRecorder(None, "t", max_waypoints=5)
        for i in range(20):
            tr.begin_waypoint(f"{i}/20", f"W{i}")
        assert len(tr.waypoints) <= 5
