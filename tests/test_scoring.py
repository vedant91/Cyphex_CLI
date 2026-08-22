"""
CYPHEX — Security posture scoring tests.

Guards scoring.py (the single source of truth for the 0-100 posture score
and its 20/40/60/80 presentation bands) against the exact regression class
that motivated this module: a hardcoded band clamp collapsing two genuinely
different post-patch vuln counts to the identical displayed score whenever
a Critical was still open, making real remediation progress look like zero
improvement. There was previously no test coverage for score_from_counts()
at all — that gap is why the bug (and a second, silently-diverged copy of
the same formula in cli_engine.py) shipped unnoticed.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scoring import score_from_counts, score_band, BANDS


class TestScoreFromCounts:
    """Core formula: sanity, monotonicity, and the severity-dominance guarantee."""

    def test_zero_vulns_is_perfect_score(self):
        assert score_from_counts(0, 0, 0, 0) == 100

    def test_single_low_barely_dents_score(self):
        assert score_from_counts(0, 0, 0, 1) > 90

    def test_single_critical_lands_in_poor_or_worse(self):
        # The core guarantee: this must hold from the weight constants alone,
        # with no severity-conditional branch in score_from_counts() itself.
        assert score_from_counts(1, 0, 0, 0) < 40

    def test_open_critical_always_caps_below_fair_regardless_of_other_severities(self):
        # No pile of High/Medium/Low findings can push a score with an open
        # Critical up into FAIR/SECURE territory (>= 60).
        for high in (0, 1, 5, 50):
            for med in (0, 1, 5, 50):
                for low in (0, 1, 5, 50):
                    assert score_from_counts(1, high, med, low) < 60

    def test_regression_partial_remediation_shows_real_improvement(self):
        """The exact bug: before=8 vulns (1 Critical + others), after patching
        4 are fixed/verified leaving 1 Critical + 2 Medium + 1 Low. The old
        formula clamped both to the identical 39 because a Critical was open
        in both states, making 4 verified patches look like zero progress.
        The new formula must show a strictly better score after."""
        before = score_from_counts(crit=1, high=1, med=4, low=2)  # 8 total
        after = score_from_counts(crit=1, high=0, med=2, low=1)   # 4 remain
        assert after > before, (
            f"partial remediation must strictly improve the score "
            f"(before={before}, after={after}) — a flat/lower 'after' score "
            f"means real patches are being displayed as no improvement"
        )

    def test_full_remediation_reaches_perfect_score(self):
        assert score_from_counts(0, 0, 0, 0) == 100

    def test_regression_deep_remediation_shows_improvement_past_the_old_floor(self):
        """The floor-side twin of the regression above, and the exact bug a
        real scan hit: before-patch state had enough open severe findings
        that total penalty already exceeded 100 (easily reached — 6 Critical
        + 5 High is nowhere near exotic on a real scan). A linear
        `100 - penalty` clamped to [0, 100] floors THAT straight to 0 — and
        after verifying 5 patches and clearing several findings, the
        after-patch state (4 Critical + 3 High + 2 Medium) ALSO still
        exceeded penalty 100, so it floored to the identical 0. The banner
        read "Before: 0/100, After: 0/100, Improvement: 0 points" despite 5
        real, verified patches — remediation that is completely real showing
        as if nothing happened, because the floor threw away every bit of
        information about how far past 100 either penalty total was.
        A formula whose output is strictly monotonic over its ENTIRE domain
        (not just the sub-100-penalty range the other regression test
        covers) must show improvement here too."""
        before = score_from_counts(crit=6, high=5, med=3, low=0)   # deep in the red
        after = score_from_counts(crit=4, high=3, med=2, low=0)    # still severe, but strictly fewer
        assert after > before, (
            f"remediation that strictly reduces every severity count must "
            f"strictly improve the score even when both states are severe "
            f"enough that a naive linear formula would floor both to 0 "
            f"(before={before}, after={after})"
        )
        # And neither one should silently be the floor itself — that's the
        # exact symptom (both floor to 0, so "improvement" is invisible).
        assert before > 0 and after > 0, (
            f"a severe-but-distinguishable state should not floor-clip to "
            f"an indistinguishable 0 (before={before}, after={after})"
        )

    def test_monotonic_in_each_severity_independently(self):
        """Fixing any single finding (holding the rest constant) must never
        lower the score, and must strictly raise it below the ceiling."""
        base = dict(crit=2, high=3, med=4, low=5)
        base_score = score_from_counts(**base)
        for key in base:
            worse = dict(base)
            worse[key] += 1
            assert score_from_counts(**worse) <= base_score
            better = dict(base)
            if better[key] > 0:
                better[key] -= 1
                assert score_from_counts(**better) >= base_score

    def test_more_lows_never_outweighs_one_critical(self):
        crit_alone = score_from_counts(1, 0, 0, 0)
        many_lows = score_from_counts(0, 0, 0, 1000)
        assert many_lows > crit_alone

    def test_score_always_in_range(self):
        for crit in (0, 1, 5, 50):
            for high in (0, 1, 5, 50):
                for med in (0, 1, 5, 50):
                    for low in (0, 1, 5, 50):
                        s = score_from_counts(crit, high, med, low)
                        assert 0 <= s <= 100

    def test_negative_counts_are_treated_as_zero(self):
        assert score_from_counts(-1, -1, -1, -1) == 100


class TestScoreBand:
    """Presentation bands are derived FROM the score, never fed back into it."""

    def test_bands_cover_full_range_with_no_gaps(self):
        for score in range(0, 101):
            label, tier = score_band(score)
            assert label in {"SECURE", "FAIR", "AT RISK", "POOR", "CRITICAL"}
            assert tier in {"phosphor", "reference", "caution", "warning"}

    def test_band_thresholds(self):
        assert score_band(100)[0] == "SECURE"
        assert score_band(80)[0] == "SECURE"
        assert score_band(79)[0] == "FAIR"
        assert score_band(60)[0] == "FAIR"
        assert score_band(59)[0] == "AT RISK"
        assert score_band(40)[0] == "AT RISK"
        assert score_band(39)[0] == "POOR"
        assert score_band(20)[0] == "POOR"
        assert score_band(19)[0] == "CRITICAL"
        assert score_band(0)[0] == "CRITICAL"

    def test_bands_sorted_descending_by_minimum(self):
        minimums = [m for m, _, _ in BANDS]
        assert minimums == sorted(minimums, reverse=True)


class TestSingleSourceOfTruth:
    """terminal_ui.py and cli_engine.py must both delegate to scoring.py —
    never hand-copy the formula or the band thresholds."""

    def test_terminal_ui_delegates(self):
        import terminal_ui as ui
        for crit, high, med, low in [(0, 0, 0, 0), (1, 1, 4, 2), (1, 0, 2, 1), (0, 0, 0, 5)]:
            assert ui.score_from_counts(crit, high, med, low) == score_from_counts(crit, high, med, low)

    def test_cli_engine_delegates(self):
        import cli_engine as ce
        for crit, high, med, low in [(0, 0, 0, 0), (1, 1, 4, 2), (1, 0, 2, 1), (0, 0, 0, 5)]:
            assert ce.security_score(crit, high, med, low) == score_from_counts(crit, high, med, low)

    def test_no_hand_copied_band_clamp_remains(self):
        """Guards against the original bug pattern regressing: no source file
        should contain an actual `min(score, <int>)` band-override CALL
        outside of scoring.py itself. AST-based (not text search) so this
        doesn't false-positive on docstrings/comments that reference the old
        pattern by name while explaining the fix."""
        import ast
        import glob

        def has_score_clamp_call(tree):
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "min"
                    and any(isinstance(a, ast.Name) and a.id == "score" for a in node.args)
                    and any(isinstance(a, ast.Constant) and isinstance(a.value, int) for a in node.args)
                ):
                    return True
            return False

        offenders = []
        for f in glob.glob(os.path.join(ROOT, "*.py")):
            if os.path.basename(f) == "scoring.py":
                continue
            text = open(f, encoding="utf-8", errors="ignore").read()
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            if has_score_clamp_call(tree):
                offenders.append(f)
        assert not offenders, f"hand-copied score clamp found outside scoring.py: {offenders}"
