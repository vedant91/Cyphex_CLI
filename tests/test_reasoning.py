"""Phase 4 reasoning tests: tier adaptation and verifier-driven selection."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.reasoning import (  # noqa: E402
    rounds_for_tier,
    k_for_tier,
    patch_with_reflexion,
    patch_with_consistency,
)


def test_tier_adaptation_values():
    assert rounds_for_tier("low") == 1
    assert rounds_for_tier("mid") == 2
    assert rounds_for_tier("high") == 3
    assert k_for_tier("minimal") == 1
    assert k_for_tier("ultra") == 3


@pytest.mark.asyncio
async def test_patch_with_reflexion_stops_on_pass():
    calls = {"n": 0}

    async def gen(_feedback, _round):
        calls["n"] += 1
        return {"fixed_code": f"candidate_{calls['n']}"}

    async def verify(candidate):
        if candidate["fixed_code"] == "candidate_2":
            return {"verdict": "PASS", "evidence": {}}
        return {"verdict": "FAIL", "evidence": {"exploit_still_works": True}}

    res = await patch_with_reflexion(gen, verify, tier="high", max_rounds=3)
    assert res.status == "verified"
    assert len(res.attempts) == 2


@pytest.mark.asyncio
async def test_patch_with_consistency_selects_smallest_passing_diff():
    async def gen(k):
        assert k == 3
        return [
            {"fixed_code": "AAAA"},
            {"fixed_code": "AA"},
            {"fixed_code": "BBBBBBBB"},
        ]

    async def verify(candidate):
        if candidate["fixed_code"] in {"AAAA", "AA"}:
            return {"verdict": "PASS", "evidence": {}}
        return {"verdict": "FAIL", "evidence": {"finding_still_present": True}}

    res = await patch_with_consistency(gen, verify, tier="high")
    assert res.status == "verified"
    assert res.selected is not None
    assert res.selected.candidate["fixed_code"] == "AA"
