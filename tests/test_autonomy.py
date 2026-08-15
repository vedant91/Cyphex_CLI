"""Phase 7 tests for autonomy ladder and degradation honesty mapping."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli_engine import CyphexEngine  # noqa: E402


def test_autonomy_status_fully_verified():
    eng = CyphexEngine()
    eng._patch_run_stats = {
        "verified": 3,
        "unverified": 0,
        "rolled_back": 0,
        "rag_enabled": True,
        "verifier_enabled": True,
    }
    level, reason = eng._autonomy_status()
    assert "L4" in level
    assert "verified" in reason.lower()


def test_autonomy_status_degraded_when_verifier_missing():
    eng = CyphexEngine()
    eng._patch_run_stats = {
        "verified": 0,
        "unverified": 2,
        "rolled_back": 0,
        "rag_enabled": False,
        "verifier_enabled": False,
    }
    level, reason = eng._autonomy_status()
    assert "L1" in level
    assert "unavailable" in reason.lower()
