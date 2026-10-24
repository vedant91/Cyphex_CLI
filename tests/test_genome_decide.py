"""The genome-backed live decision gate (cyphex/daemon.py: decide(), POST /api/decide).
Three tiers (ALLOW/CHALLENGE/BLOCK) from the genome's existing continuous score, with the
critical fail-safe that an untrained target always ALLOWs rather than blocking on nothing."""
import importlib.util
import sys
import types
from unittest.mock import MagicMock

import pytest

for n in ("fastapi", "fastapi.responses", "fastapi.middleware.cors", "uvicorn",
          "numpy", "joblib", "sklearn", "sklearn.ensemble", "sklearn.preprocessing"):
    sys.modules.setdefault(n, MagicMock())

_spec = importlib.util.spec_from_file_location("cyphex_daemon_under_test", "cyphex/daemon.py")
daemon = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("cyphex_daemon_under_test", daemon)
_spec.loader.exec_module(daemon)


class FakeGenome:
    def __init__(self, scores):
        self.scores = scores  # {payload_substring: score}
        self.calls = []

    def score_request(self, endpoint, payload):
        self.calls.append((endpoint, payload))
        for sub, score in self.scores.items():
            if sub in payload:
                return score
        return 0.0


@pytest.fixture(autouse=True)
def _clean_cache(monkeypatch):
    monkeypatch.setattr(daemon, "_genome_cache", {})
    monkeypatch.setattr(daemon, "DECIDE_LOG", [])
    yield


def test_benign_input_allows():
    daemon._genome_cache["http://x"] = FakeGenome({"' OR 1=1--": 0.9})
    r = daemon.decide("http://x", "/search", [{"source": "query.q", "value": "laptop"}])
    assert r["verdict"] == "ALLOW" and r["score"] == 0.0


def test_high_score_blocks():
    daemon._genome_cache["http://x"] = FakeGenome({"' OR 1=1--": 0.9})
    r = daemon.decide("http://x", "/search", [{"source": "query.q", "value": "' OR 1=1--"}])
    assert r["verdict"] == "BLOCK" and r["score"] == 0.9 and r["field"] == "query.q"


def test_mid_score_challenges_not_blocks():
    daemon._genome_cache["http://x"] = FakeGenome({"weird": 0.5})
    r = daemon.decide("http://x", "/search", [{"source": "query.q", "value": "weird"}])
    assert r["verdict"] == "CHALLENGE"


def test_untrained_target_never_blocks():
    """No genome was ever trained for this target - that's an absence of evidence,
    not evidence of an attack. Must always ALLOW, regardless of how malicious the
    payload looks, and must say why."""
    daemon._genome_cache["http://unknown"] = None
    r = daemon.decide("http://unknown", "/search", [{"source": "query.q", "value": "' OR 1=1--; DROP TABLE users;--"}])
    assert r["verdict"] == "ALLOW"
    assert "no trained genome" in r["reason"]


def test_worst_of_multiple_inputs_wins():
    genome = FakeGenome({"bad": 0.9})
    daemon._genome_cache["http://x"] = genome
    r = daemon.decide("http://x", "/search", [
        {"source": "query.a", "value": "fine"},
        {"source": "query.b", "value": "also fine"},
        {"source": "body.c", "value": "bad stuff here"},
    ])
    assert r["verdict"] == "BLOCK" and r["field"] == "body.c"


def test_non_string_and_empty_values_are_skipped_not_crashed():
    genome = FakeGenome({})
    daemon._genome_cache["http://x"] = genome
    r = daemon.decide("http://x", "/search", [
        {"source": "query.a", "value": ""},
        {"source": "query.b", "value": 123},
        {"source": "query.c", "value": None},
    ])
    assert r["verdict"] == "ALLOW"
    assert genome.calls == []  # none of these were ever scored


def test_only_non_allow_verdicts_are_logged():
    daemon._genome_cache["http://x"] = FakeGenome({"bad": 0.9, "meh": 0.5})
    daemon.decide("http://x", "/a", [{"source": "q", "value": "fine"}])
    daemon.decide("http://x", "/b", [{"source": "q", "value": "meh"}])
    daemon.decide("http://x", "/c", [{"source": "q", "value": "bad"}])
    assert len(daemon.DECIDE_LOG) == 2
    assert {e["verdict"] for e in daemon.DECIDE_LOG} == {"CHALLENGE", "BLOCK"}


def test_decide_log_is_capped_at_500(monkeypatch):
    genome = FakeGenome({"bad": 0.9})
    daemon._genome_cache["http://x"] = genome
    for _ in range(550):
        daemon.decide("http://x", "/a", [{"source": "q", "value": "bad"}])
    assert len(daemon.DECIDE_LOG) == 500


def test_load_genome_for_target_caches_the_miss(monkeypatch, tmp_path):
    monkeypatch.setattr(daemon.cyphex_config, "GENOME_STORAGE_DIR", str(tmp_path))
    calls = []
    orig_exists = daemon.os.path.exists
    monkeypatch.setattr(daemon.os.path, "exists", lambda p: (calls.append(p), orig_exists(p))[1])
    g1 = daemon._load_genome_for_target("http://never-scanned")
    g2 = daemon._load_genome_for_target("http://never-scanned")
    assert g1 is None and g2 is None
    assert len(calls) == 1  # second call hit the cache, no second disk check
