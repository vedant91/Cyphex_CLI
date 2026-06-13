"""
CYPHEX — Self-Consistency with Verifier as Judge

Generate K candidate patches using distinct fix strategies.
Apply and verify each. Keep the smallest passing diff.

The judge is the VERIFIER (exploit replay / scanner re-scan),
NOT the model ranking its own ideas.

K is tier-adaptive: minimal/low → K=1 (single-shot), high/ultra → K=3.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ConsistencyResult:
    """Result of self-consistency patch generation."""
    patch: str
    status: str             # "verified" | "unverified"
    strategy_used: str
    candidates_tried: int
    candidates_passed: int
    verify_evidence: dict


async def patch_with_consistency(
    vuln,
    context: str,
    strategies: list,
    generate_fn,
    apply_and_verify_fn,
    k: int = 3,
) -> ConsistencyResult:
    """
    Generate K patches with different strategies, keep the one that passes verification.

    Args:
        vuln: The Vuln to fix
        context: Assembled code context
        strategies: List of {name, description, pattern} from security KB
        generate_fn: async fn(vuln, context_with_strategy) -> str
        apply_and_verify_fn: async fn(vuln, fixed_code) -> VerifyResult
        k: Number of candidates (tier-adaptive)

    Returns:
        ConsistencyResult with the best verified patch
    """
    candidates = []

    for i in range(min(k, len(strategies))):
        strategy = strategies[i]
        strategy_prompt = (
            f"\n\nFIX STRATEGY to use: {strategy.get('name', 'default')}\n"
            f"Pattern: {strategy.get('pattern', '')}\n"
            f"Description: {strategy.get('description', '')}"
        )

        try:
            patch = await generate_fn(vuln, context + strategy_prompt)
        except Exception:
            continue

        if not patch or not patch.strip():
            continue

        # Apply and verify
        try:
            verify_result = await apply_and_verify_fn(vuln, patch)
        except Exception as e:
            candidates.append({
                "patch": patch,
                "strategy": strategy.get("name", "unknown"),
                "verified": False,
                "diff_size": len(patch),
                "evidence": {"error": str(e)},
            })
            continue

        candidates.append({
            "patch": patch,
            "strategy": strategy.get("name", "unknown"),
            "verified": verify_result.verdict == "PASS",
            "diff_size": len(patch),
            "evidence": verify_result.evidence,
        })

    # Pick the best: verified + smallest diff
    verified = [c for c in candidates if c["verified"]]
    passed = len(verified)

    if verified:
        winner = min(verified, key=lambda c: c["diff_size"])
        return ConsistencyResult(
            patch=winner["patch"],
            status="verified",
            strategy_used=winner["strategy"],
            candidates_tried=len(candidates),
            candidates_passed=passed,
            verify_evidence=winner["evidence"],
        )

    # None passed — return the first attempt marked unverified
    best = candidates[0] if candidates else {"patch": "", "strategy": "none", "evidence": {}}
    return ConsistencyResult(
        patch=best.get("patch", ""),
        status="unverified",
        strategy_used=best.get("strategy", "none"),
        candidates_tried=len(candidates),
        candidates_passed=0,
        verify_evidence=best.get("evidence", {}),
    )


def k_for_tier(mode: str) -> int:
    """Get K (number of candidates) based on hardware tier."""
    tier_k = {
        "ultra": 3,
        "high": 3,
        "mid": 2,
        "low": 1,
        "minimal": 1,
        "cloud": 3,
    }
    return tier_k.get(mode, 2)
