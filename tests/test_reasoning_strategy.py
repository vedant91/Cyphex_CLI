"""Tests for the Meta-Reasoning strategy engine and self-consistency voting."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.council.reasoning_strategy import (  # noqa: E402
    STRATEGIES,
    active_count,
    select_strategy,
)
from backend.council.patch_council import PatchCouncil  # noqa: E402


def test_registry_active_count_matches_flags():
    assert active_count() == sum(1 for s in STRATEGIES.values() if s.active)
    # Meta-reasoner + the core mechanisms we genuinely run must be active.
    for key in ("standard", "chain_of_thought", "self_consistency", "adversarial", "meta_reasoning"):
        assert STRATEGIES[key].active


def test_router_critical_uses_self_consistency():
    s = select_strategy("CWE-79", "Critical")
    assert s.key == "self_consistency"
    assert s.candidates >= 3


def test_router_hard_cwe_uses_self_consistency_even_when_high():
    # CMDi/SSRF/SQLi justify multi-candidate even at High severity.
    for cwe in ("CWE-78", "CWE-918", "CWE-89"):
        assert select_strategy(cwe, "High").key == "self_consistency"


def test_router_high_uses_chain_of_thought():
    assert select_strategy("CWE-200", "High").key == "chain_of_thought"


def test_router_default_is_standard():
    assert select_strategy("CWE-200", "Low").key == "standard"
    assert select_strategy("", "").key == "standard"


def test_fingerprint_ignores_whitespace():
    a = PatchCouncil._fingerprint_patch("  x = 1\n\n   y = 2  \n")
    b = PatchCouncil._fingerprint_patch("x = 1\ny = 2\n")
    assert a == b


def test_fingerprint_distinguishes_real_changes():
    a = PatchCouncil._fingerprint_patch("x = 1")
    b = PatchCouncil._fingerprint_patch("x = 2")
    assert a != b
