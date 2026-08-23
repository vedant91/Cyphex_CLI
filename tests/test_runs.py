"""
CYPHEX — Run registry tests.

The registry turns a directory of sandboxes into an ordered history. The
properties worth pinning:

  1. A run's STATUS is honest. A scan that started and never ended is
     `interrupted`, not a completed run with a missing number — treating
     the two alike is how a crashed scan quietly drags a trend down.
  2. Older runs DEGRADE, they don't disappear. `scan_score` and the trace
     events are newer than most sandboxes on disk; a run that predates them
     must still appear with whatever it does have.
  3. Regression detection only fires on a real drop.
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend.observability.runs import (  # noqa: E402
    discover_runs, get_run, history_summary, COMPLETED, INTERRUPTED,
)


def _mk(root, scan_id, events=None, patches=None):
    d = os.path.join(root, scan_id, ".cyphex")
    os.makedirs(d, exist_ok=True)
    if events is not None:
        with open(os.path.join(d, "events.jsonl"), "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
    if patches is not None:
        with open(os.path.join(d, "patches.json"), "w", encoding="utf-8") as f:
            json.dump(patches, f)
    return d


def _score_ev(ts, score, before=None, **kw):
    e = {"ts": ts, "event": "scan_score", "score": score, "target": "/tmp/app"}
    if before is not None:
        e["score_before"] = before
    e.update(kw)
    return e


class TestStatus:
    def test_started_and_ended_is_completed(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_aaa", events=[{"ts": 100, "event": "scan_start"},
                                       {"ts": 160, "event": "scan_end"}])
            r = discover_runs(root=td)[0]
            assert r.status == COMPLETED
            assert r.duration_s == 60.0

    def test_started_without_end_is_interrupted(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_bbb", events=[{"ts": 100, "event": "scan_start"}])
            r = discover_runs(root=td)[0]
            assert r.status == INTERRUPTED
            assert r.duration_s is None, "an unfinished run must not report a duration"

    def test_interrupted_runs_are_counted_separately(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_a", events=[{"ts": 1, "event": "scan_start"}, {"ts": 2, "event": "scan_end"}])
            _mk(td, "cli_b", events=[{"ts": 3, "event": "scan_start"}])
            h = history_summary(root=td)
            assert h["completed"] == 1
            assert h["interrupted"] == 1


class TestGracefulDegradation:
    def test_run_with_only_a_manifest_still_appears(self):
        """Most sandboxes on disk predate the event log entirely."""
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_old", patches={
                "src/a.js:1:CWE-89": {"cwe": "CWE-89", "file": "src/a.js",
                                       "verdict": "PASS", "patched_at": "2026-01-01T00:00:00+00:00"},
            })
            runs = discover_runs(root=td)
            assert len(runs) == 1
            assert runs[0].verdicts == {"PASS": 1}
            assert runs[0].score is None, "no score recorded is None, never a fabricated 0"

    def test_run_without_a_score_event_reports_none_not_zero(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_x", events=[{"ts": 1, "event": "scan_start"}, {"ts": 2, "event": "scan_end"}])
            assert discover_runs(root=td)[0].score is None

    def test_native_deploy_copies_are_not_counted_as_runs(self):
        """A native sandbox deploy copies the tree to '<scan_id>_run'; counting
        it would double every run in the history."""
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_dup", events=[{"ts": 1, "event": "scan_start"}])
            _mk(td, "cli_dup_run", events=[{"ts": 1, "event": "scan_start"}])
            assert [r.scan_id for r in discover_runs(root=td)] == ["cli_dup"]

    def test_empty_root_is_empty_history_not_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            assert discover_runs(root=td) == []
            assert history_summary(root=td)["total_runs"] == 0


class TestScoreAndRegression:
    def test_score_and_delta_are_recovered(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_s", events=[{"ts": 1, "event": "scan_start"},
                                     _score_ev(2, 61, before=23),
                                     {"ts": 3, "event": "scan_end"}])
            r = discover_runs(root=td)[0]
            assert r.score == 61
            assert r.score_before == 23
            assert r.score_delta == 38

    def test_regression_detected_when_newest_scores_lower(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_old", events=[{"ts": 100, "event": "scan_start"}, _score_ev(101, 80),
                                       {"ts": 102, "event": "scan_end"}])
            _mk(td, "cli_new", events=[{"ts": 200, "event": "scan_start"}, _score_ev(201, 55),
                                       {"ts": 202, "event": "scan_end"}])
            reg = history_summary(root=td)["regression"]
            assert reg["regressed"] is True
            assert reg["delta"] == -25
            assert reg["current"] == 55 and reg["previous"] == 80

    def test_improvement_is_not_a_regression(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_old", events=[{"ts": 100, "event": "scan_start"}, _score_ev(101, 40),
                                       {"ts": 102, "event": "scan_end"}])
            _mk(td, "cli_new", events=[{"ts": 200, "event": "scan_start"}, _score_ev(201, 90),
                                       {"ts": 202, "event": "scan_end"}])
            assert history_summary(root=td)["regression"]["regressed"] is False

    def test_equal_scores_are_not_a_regression(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_old", events=[{"ts": 100, "event": "scan_start"}, _score_ev(101, 70),
                                       {"ts": 102, "event": "scan_end"}])
            _mk(td, "cli_new", events=[{"ts": 200, "event": "scan_start"}, _score_ev(201, 70),
                                       {"ts": 202, "event": "scan_end"}])
            assert history_summary(root=td)["regression"]["regressed"] is False

    def test_a_single_scored_run_yields_no_regression_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_one", events=[{"ts": 1, "event": "scan_start"}, _score_ev(2, 70),
                                       {"ts": 3, "event": "scan_end"}])
            assert history_summary(root=td)["regression"] is None


class TestOrderingAndLookup:
    def test_runs_are_newest_first(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_old", events=[{"ts": 100, "event": "scan_start"}])
            _mk(td, "cli_new", events=[{"ts": 900, "event": "scan_start"}])
            assert [r.scan_id for r in discover_runs(root=td)] == ["cli_new", "cli_old"]

    def test_lookup_by_full_id_bare_id_and_prefix(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_abc12345", events=[{"ts": 1, "event": "scan_start"}])
            for q in ("cli_abc12345", "abc12345", "abc1"):
                r = get_run(q, root=td)
                assert r is not None and r.scan_id == "cli_abc12345", q

    def test_unknown_id_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_abc", events=[{"ts": 1, "event": "scan_start"}])
            assert get_run("zzz", root=td) is None


class TestWaypointRecovery:
    def test_trace_tree_is_rebuilt_from_the_event_log(self):
        with tempfile.TemporaryDirectory() as td:
            _mk(td, "cli_t", events=[
                {"ts": 1, "event": "scan_start"},
                {"ts": 2, "event": "trace_waypoint_start", "num": "5/9",
                 "title": "GENOME", "goal": "learn normal", "highlight": True},
                {"ts": 3, "event": "trace_step_end", "waypoint": "5/9",
                 "label": "generation 0", "detail": "73%", "status": "warn", "duration_s": 0.5},
                {"ts": 4, "event": "trace_waypoint_end", "num": "5/9",
                 "status": "warn", "duration_s": 2.6},
                {"ts": 5, "event": "scan_end"},
            ])
            wps = discover_runs(root=td)[0].waypoints
            assert len(wps) == 1
            assert wps[0]["goal"] == "learn normal"
            assert wps[0]["highlight"] is True
            assert wps[0]["status"] == "warn"
            assert wps[0]["steps"][0]["duration_s"] == 0.5
