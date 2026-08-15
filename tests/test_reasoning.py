"""Reasoning tests: tier adaptation, grounded reflexion, self-consistency selection.

An earlier version of this file imported these names from `backend.reasoning`,
whose __init__.py is docstring-only and re-exports nothing, so the module failed
at import and every test in it was silently skipped. It also called both async
entry points with signatures they have never had (a `tier=` keyword, generator
callbacks returning dicts, a `.attempts` field on the result).

The real contracts:

    patch_with_reflexion(vuln, context, generate_fn, apply_and_verify_fn,
                         max_rounds=3, strategies=None) -> ReflexionResult
        generate_fn:          async (vuln, context) -> str
        apply_and_verify_fn:  async (vuln, patch)   -> object with .verdict/.evidence

    patch_with_consistency(vuln, context, strategies, generate_fn,
                           apply_and_verify_fn, k=3) -> ConsistencyResult
"""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.reasoning.reflexion import patch_with_reflexion, rounds_for_tier  # noqa: E402
from backend.reasoning.self_consistency import patch_with_consistency, k_for_tier  # noqa: E402


def _verdict(verdict, **evidence):
    """Stand-in for a VerifyResult — only .verdict and .evidence are read."""
    return SimpleNamespace(verdict=verdict, evidence=evidence)


_VULN = SimpleNamespace(name="SQL Injection", cwe="CWE-89")


# ── Tier adaptation ───────────────────────────────────────────────────

def test_tier_adaptation_values():
    assert rounds_for_tier("low") == 1
    assert rounds_for_tier("mid") == 2
    assert rounds_for_tier("high") == 3
    assert k_for_tier("minimal") == 1
    assert k_for_tier("ultra") == 3


def test_tier_adaptation_unknown_tier_falls_back():
    """An unrecognised tier must stay usable rather than collapse to zero work."""
    assert rounds_for_tier("nonsense") == 2
    assert k_for_tier("nonsense") == 2


# ── Grounded reflexion ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reflexion_stops_as_soon_as_a_patch_passes():
    calls = {"n": 0}

    async def gen(_vuln, _context):
        calls["n"] += 1
        return f"candidate_{calls['n']}"

    async def verify(_vuln, patch):
        return _verdict("PASS") if patch == "candidate_2" else _verdict("FAIL", exploit_still_works=True)

    res = await patch_with_reflexion(_VULN, "ctx", gen, verify, max_rounds=3)

    assert res.status == "verified"
    assert res.patch == "candidate_2"
    assert res.rounds == 2
    assert calls["n"] == 2, "must stop generating once a candidate verifies"


@pytest.mark.asyncio
async def test_reflexion_feeds_failure_evidence_into_the_next_round():
    """The 'grounded' part: round N+1's prompt must carry round N's failure."""
    prompts = []

    async def gen(_vuln, context):
        prompts.append(context)
        return f"candidate_{len(prompts)}"

    async def verify(_vuln, _patch):
        return _verdict("FAIL", rescan="Finding CWE-89 still present after patch")

    res = await patch_with_reflexion(_VULN, "ctx", gen, verify, max_rounds=2)

    assert res.status == "unverified"
    assert prompts[0] == "ctx"                 # first round gets bare context
    assert len(prompts[1]) > len(prompts[0])   # second round gets context + feedback
    assert "still present" in prompts[1]


@pytest.mark.asyncio
async def test_reflexion_unverified_when_nothing_passes():
    async def gen(_vuln, _context):
        return "always_broken"

    async def verify(_vuln, _patch):
        return _verdict("FAIL", finding_still_present=True)

    res = await patch_with_reflexion(_VULN, "ctx", gen, verify, max_rounds=3)

    assert res.status == "unverified"
    assert res.rounds == 3
    assert res.verify_evidence.get("finding_still_present") is True


@pytest.mark.asyncio
async def test_reflexion_survives_a_generator_that_raises():
    """A model call blowing up mid-loop must not abort the whole reflexion."""
    calls = {"n": 0}

    async def gen(_vuln, _context):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("model timed out")
        return "recovered"

    async def verify(_vuln, _patch):
        return _verdict("PASS")

    res = await patch_with_reflexion(_VULN, "ctx", gen, verify, max_rounds=3)

    assert res.status == "verified"
    assert res.patch == "recovered"


# ── Self-consistency ──────────────────────────────────────────────────

_STRATEGIES = [
    {"name": "parameterize", "pattern": "?", "description": "placeholders"},
    {"name": "escape", "pattern": "esc", "description": "escaping"},
    {"name": "validate", "pattern": "val", "description": "allow-list"},
]


@pytest.mark.asyncio
async def test_consistency_selects_smallest_passing_candidate():
    patches = {"parameterize": "AAAA", "escape": "AA", "validate": "BBBBBBBB"}

    async def gen(_vuln, context):
        for name, patch in patches.items():
            if f"FIX STRATEGY to use: {name}" in context:
                return patch
        raise AssertionError("strategy name not threaded into the prompt")

    async def verify(_vuln, patch):
        return _verdict("PASS") if patch in {"AAAA", "AA"} else _verdict("FAIL", finding_still_present=True)

    res = await patch_with_consistency(_VULN, "ctx", _STRATEGIES, gen, verify, k=3)

    assert res.status == "verified"
    assert res.patch == "AA", "smallest verified diff wins"
    assert res.strategy_used == "escape"
    assert res.candidates_tried == 3
    assert res.candidates_passed == 2


@pytest.mark.asyncio
async def test_consistency_k_caps_the_number_of_candidates():
    async def gen(_vuln, _context):
        return "patch"

    async def verify(_vuln, _patch):
        return _verdict("FAIL")

    res = await patch_with_consistency(_VULN, "ctx", _STRATEGIES, gen, verify, k=2)
    assert res.candidates_tried == 2


@pytest.mark.asyncio
async def test_consistency_unverified_when_none_pass():
    async def gen(_vuln, _context):
        return "patch"

    async def verify(_vuln, _patch):
        return _verdict("FAIL", finding_still_present=True)

    res = await patch_with_consistency(_VULN, "ctx", _STRATEGIES, gen, verify, k=3)

    assert res.status == "unverified"
    assert res.candidates_passed == 0


@pytest.mark.asyncio
async def test_consistency_blank_patches_are_not_counted():
    """An empty generation is not a candidate — it must not dilute the tally."""
    async def gen(_vuln, context):
        return "" if "parameterize" in context else "real_patch"

    async def verify(_vuln, _patch):
        return _verdict("PASS")

    res = await patch_with_consistency(_VULN, "ctx", _STRATEGIES, gen, verify, k=3)

    assert res.candidates_tried == 2
    assert res.status == "verified"
