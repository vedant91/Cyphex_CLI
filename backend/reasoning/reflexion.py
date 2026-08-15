"""
CYPHEX — Grounded Reflexion

Draft → Apply → Verify → Feed REAL failure evidence → Improve.
The critique comes from the VERIFIER, not the model's self-opinion.

Key principle: a 7B model that can't write a correct fix also can't
reliably judge its own fix. Only objective verifier output (exploit replay,
scanner result, build error) is used as feedback.

Terminates on PASS or max_rounds — never on model self-satisfaction.
"""

from typing import Optional
from dataclasses import dataclass


@dataclass
class ReflexionResult:
    """Result of a grounded reflexion loop."""
    patch: str
    status: str           # "verified" | "unverified"
    rounds: int
    strategy_used: str
    verify_evidence: dict  # Last VerifyResult.evidence


async def patch_with_reflexion(
    vuln,
    context: str,
    generate_fn,
    apply_and_verify_fn,
    max_rounds: int = 3,
    strategies: Optional[list] = None,
) -> ReflexionResult:
    """
    Grounded reflexion loop for patch generation.

    Args:
        vuln: The Vuln to fix
        context: Assembled code context (function + imports + KB recipe)
        generate_fn: async fn(vuln, context, feedback=None) -> str (fixed_code)
        apply_and_verify_fn: async fn(vuln, fixed_code) -> VerifyResult
        max_rounds: Maximum reflection rounds (tier-adaptive)
        strategies: List of named fix strategies to try in sequence

    Returns:
        ReflexionResult with the patch and its status
    """
    history = []
    strategy_names = strategies or ["default"]
    best_patch = ""
    best_evidence = {}

    for round_num in range(max_rounds):
        strategy = strategy_names[round_num % len(strategy_names)]

        # Build feedback from prior failures
        feedback = None
        if history:
            last = history[-1]
            feedback = _build_feedback(last["evidence"], last["patch"], round_num)

        # Generate patch (with feedback if available)
        try:
            if feedback:
                patch = await generate_fn(vuln, context + "\n\n" + feedback)
            else:
                patch = await generate_fn(vuln, context)
        except Exception:
            continue

        if not patch or not patch.strip():
            continue

        best_patch = patch

        # Apply and verify
        try:
            verify_result = await apply_and_verify_fn(vuln, patch)
        except Exception as e:
            history.append({
                "patch": patch,
                "evidence": {"error": str(e)},
                "round": round_num,
            })
            continue

        best_evidence = verify_result.evidence

        if verify_result.verdict == "PASS":
            return ReflexionResult(
                patch=patch,
                status="verified",
                rounds=round_num + 1,
                strategy_used=strategy,
                verify_evidence=verify_result.evidence,
            )

        # Record failure for next round's feedback
        history.append({
            "patch": patch,
            "evidence": verify_result.evidence,
            "round": round_num,
        })

    # Exhausted all rounds
    return ReflexionResult(
        patch=best_patch,
        status="unverified",
        rounds=max_rounds,
        strategy_used=strategy_names[-1],
        verify_evidence=best_evidence,
    )


def _build_feedback(evidence: dict, last_patch: str, round_num: int) -> str:
    """
    Build concrete feedback from verifier evidence.
    Never asks "are you sure?" — always provides objective failure details.
    """
    lines = [
        f"=== VERIFICATION FAILED (attempt {round_num + 1}) ===",
        "Your previous patch did NOT fix the vulnerability. Here is the objective evidence:",
    ]

    if evidence.get("rescan"):
        lines.append(f"  SCANNER: {evidence['rescan']}")

    if evidence.get("replay"):
        lines.append(f"  EXPLOIT REPLAY: {evidence['replay']}")

    if evidence.get("build_error"):
        lines.append(f"  BUILD ERROR: {evidence['build_error']}")

    if evidence.get("suppression"):
        lines.append(f"  REJECTED: {evidence['suppression']}")

    if evidence.get("liveness"):
        lines.append(f"  ENDPOINT BROKEN: {evidence['liveness']}")

    if evidence.get("blast_radius"):
        lines.append(f"  TOO MANY CHANGES: {evidence['blast_radius']}")

    lines.append("")
    lines.append("Generate a DIFFERENT fix approach. Do NOT repeat the same strategy.")
    lines.append(f"Previous (failed) code:\n```\n{last_patch[:500]}\n```")

    return "\n".join(lines)


def rounds_for_tier(mode: str) -> int:
    """Get max reflexion rounds based on hardware tier."""
    tier_rounds = {
        "ultra": 3,
        "high": 3,
        "mid": 2,
        "low": 1,
        "minimal": 1,
        "cloud": 3,
    }
    return tier_rounds.get(mode, 2)
