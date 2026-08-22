"""
CYPHEX -- Security posture scoring. The ONLY place in the whole repo that
computes the 0-100 score or the band it falls into. Every caller (rich SOC
UI in terminal_ui.py, plain-text report / ANSI banner fallback in
cli_engine.py) imports from here instead of hand-copying the math -- that
hand-copying is exactly how this file's predecessor logic silently forked
into three different formulas (a log2 one, a clamped variant of it, and an
unrelated linear one in backend/backend/security_posture_score.py) before
this module existed.

Zero third-party dependencies (stdlib `math` only) so it is importable in
every context this repo runs in, including any "no rich / minimal deps"
fallback path -- there is no longer a reason for a caller to keep its own
copy of the formula "just in case this module can't be imported".
"""
import math

# ---------------------------------------------------------------------------
# Severity weight / decay constants.
#
# Each severity's total penalty is a finite geometric series: the k-th open
# finding of severity s costs weight_s * decay_s**(k-1) penalty points --
# front-loaded (the very first finding of a severity already costs the full
# weight_s) with each further finding of that SAME severity costing
# progressively less, shrinking by a factor of decay_s per step. Diminishing
# returns fall out of the curve's shape itself, not from an if/min() clamp.
# Summed over n findings this has the closed form:
#
#     P_s(n) = weight_s * (1 - decay_s**n) / (1 - decay_s)      for n >= 1
#     P_s(0) = 0
#
# Because 0 < decay_s < 1, this partial sum is bounded above by the
# *infinite* series' own limit -- the severity's asymptotic ceiling
# weight_s / (1 - decay_s) -- purely because a convergent geometric series
# can never exceed its own limit. No min()/if-based clamp is needed to keep
# any single severity's damage bounded; boundedness is baked into the shape
# of the curve (0 < decay_s < 1), not applied after the fact.
#
# Algebraic property this curve family has, and the reason the "an open
# Critical can't look SECURE/FAIR" guarantee below needs no if-statement:
# P_s(1) = weight_s * (1-decay_s)/(1-decay_s) = weight_s EXACTLY, for any
# decay in (0,1) -- the first finding of a severity always costs precisely
# that severity's weight constant, independent of how its decay was tuned.
# That decouples "how bad is one finding" (weight_s alone) from "how much
# do repeats still matter" (decay_s alone).
# ---------------------------------------------------------------------------

# --- Critical --------------------------------------------------------------
# weight_s is sized so a single open Critical (n=1) costs exactly this many
# penalty points (P_s(1) == weight_s, see above), landing the score at
# 100-62=38: solidly inside POOR (20-39), comfortably under the AT-RISK/FAIR
# line at 60. This one constant is what makes "an open Critical can't look
# SECURE/FAIR" true purely by arithmetic -- see the proof in
# score_from_counts()'s docstring. Critical outweighs High ~4x (62 vs 16)
# because a Critical is typically a direct, remotely exploitable compromise,
# categorically worse than a hardening gap -- not just "a bit worse".
CRIT_WEIGHT = 62.0
# Fast-ish decay: additional Criticals beyond the first still hurt, but taper
# quickly enough that Critical's own asymptotic ceiling (62/0.75 ~= 82.7)
# doesn't by itself consume nearly the whole 0-100 budget -- leaving real
# room for High/Medium/Low to still move the score once a Critical is
# present, so partial remediation stays visible instead of getting
# floor-clipped away.
CRIT_DECAY = 0.25  # asymptotic ceiling = 62 / (1 - 0.25) ~= 82.7

# --- High --------------------------------------------------------------------
# A single High alone costs 16 points (score 84) -- a real, often-exploitable
# weakness, but far less catastrophic than a Critical by itself.
HIGH_WEIGHT = 16.0
HIGH_DECAY = 0.30  # asymptotic ceiling ~= 22.9 -- well below CRIT_WEIGHT's
                    # own single-finding cost (16 < 62), so no pile of Highs
                    # alone can ever look as bad as one open Critical.

# --- Medium ------------------------------------------------------------------
# A single Medium alone costs 6 points (score 94) -- real, but usually a
# defense-in-depth class of issue rather than directly exploitable.
MED_WEIGHT = 6.0
MED_DECAY = 0.55  # asymptotic ceiling ~= 13.3

# --- Low -----------------------------------------------------------------------
# A single Low alone costs only 2 points (score 98) -- barely registers, as a
# lone low-severity finding should.
LOW_WEIGHT = 2.0
LOW_DECAY = 0.65  # asymptotic ceiling ~= 5.7 -- Low severity mathematically
                   # cannot approach the damage of even a single Critical
                   # (5.7 << 62), no matter how many Lows pile up.

SCORE_MAX = 100  # posture ceiling: 0 findings of any severity -> exactly this
SCORE_MIN = 0    # posture floor: generic numeric-range guard, symmetric with
                  # SCORE_MAX, applied identically regardless of which
                  # severities produced the total (see score_from_counts()).

# ---------------------------------------------------------------------------
# Penalty -> score transform.
#
# The per-severity curves above are individually unclamped and strictly
# monotonic — but summing them and then doing `100 - penalty` clamped to
# [0, 100] reintroduces exactly the kind of information-destroying flatness
# this module's docstring says it exists to eliminate: once total penalty
# reaches 100 (easily hit by, say, 4 Criticals + 3 Highs — nothing exotic),
# EVERY worse combination floor-clips to the identical displayed 0. A scan
# that verifies 5 patches and clears 7 of 16 findings, but still has that
# many severe findings left, showed "0 -> 0, zero improvement" — the exact
# regression class this file exists to prevent, just at the opposite end of
# the range from the original bug (which collapsed a MID-range state; this
# collapsed every FAR-range state onto one point).
#
# SCORE_DECAY_K replaces the linear subtraction with an exponential
# saturation: score = 100 * e^(-penalty / K). This is strictly monotonically
# decreasing in penalty over its ENTIRE domain [0, inf) — two different
# penalty totals can never produce the same score before rounding, no
# matter how severe either one is — while still satisfying score(0) == 100
# exactly and score(penalty) -> 0 (never reaching it) as penalty grows.
# Boundedness again falls out of the curve's own shape (e^x is never
# negative, never exceeds 1 for x<=0), not a clamp bolted onto a linear
# formula. K is picked so a single open Critical alone (penalty==62,
# nothing else open) lands at 38 — the same POOR-band placement the
# original linear design intended — everything else follows from that one
# calibration point.
# ---------------------------------------------------------------------------
SCORE_DECAY_K = 64.0

# ---------------------------------------------------------------------------
# Presentation bands. Purely a function OF the already-computed score --
# these thresholds must never leak back into the scoring formula itself
# (that leak, `if crit: score = min(score, 39)` bolted onto the weighted
# formula, was the original bug: it collapsed genuinely different remaining-
# vuln states to the identical displayed number whenever a Critical was
# still open, hiding real remediation progress).
# ---------------------------------------------------------------------------
BANDS = (
    # (minimum score to qualify, label, severity tier key)
    (80, "SECURE", "phosphor"),
    (60, "FAIR", "reference"),
    (40, "AT RISK", "caution"),
    (20, "POOR", "warning"),
    (0, "CRITICAL", "warning"),
)


def _severity_penalty(weight: float, decay: float, count: int) -> float:
    """Closed-form sum of a k-term geometric series for one severity.

    The n-th open finding of this severity costs weight * decay**(n-1)
    penalty points; summed over `count` findings:

        P(count) = weight * (1 - decay**count) / (1 - decay)

    Strictly increasing in `count` for every finite count (each added term
    is strictly positive when count > 0), and bounded above by
    weight / (1 - decay) as count -> infinity purely because 0 < decay < 1
    -- an asymptote that falls out of the exponential family itself, not an
    externally applied clamp.
    """
    if count <= 0:
        return 0.0
    return weight * (1.0 - decay ** count) / (1.0 - decay)


def score_from_counts(crit: int, high: int, med: int, low: int) -> int:
    """Pure, deterministic 0-100 security posture score from raw vuln counts.

    penalty = P_crit(crit) + P_high(high) + P_med(med) + P_low(low)
    score   = 100 * e^(-penalty / SCORE_DECAY_K), rounded to the nearest int.

    No severity-conditional branch, min(), or band-override appears anywhere
    in this function, and — unlike a linear `100 - penalty` — this transform
    needs no post-hoc range clamp either: e^x is bounded to (0, 1] for every
    x <= 0 by construction, so the output is already inside (0, 100] before
    rounding, for every possible penalty from 0 to infinity. Two DIFFERENT
    penalty totals can never collapse onto the same pre-rounding score, no
    matter how severe either one is — the failure mode a linear-then-clamp
    formula has once penalty crosses 100 (see SCORE_DECAY_K's comment above
    for the regression this replaced: real, verified remediation reading as
    "zero improvement" because both the before- and after-patch states had
    enough open severe findings to floor-clip to the identical 0).

    The guarantee that an open Critical can never look SECURE/FAIR still
    falls out of CRIT_WEIGHT alone, exactly as before: P_crit(1) ==
    CRIT_WEIGHT == 62 exactly (see module docstring), the other three
    severity terms are never negative, and e^(-x/K) is strictly decreasing
    in x, so:

        score(crit>=1, high, med, low) <= 100 * e^(-62/SCORE_DECAY_K) ~= 38

    for every possible high/med/low >= 0 -- a theorem about the transform's
    monotonicity, not a runtime override layered on top of it. The single
    max(SCORE_MIN, min(SCORE_MAX, ...)) below is a defensive numeric-range
    guard for the rounded output (e.g. floating-point edge cases), not a
    clamp the formula relies on to stay in range -- it never references
    which severity produced the total and never references the 20/40/60/80
    presentation bands in BANDS/score_band() below.
    """
    crit = max(0, int(crit))
    high = max(0, int(high))
    med = max(0, int(med))
    low = max(0, int(low))

    penalty = (
        _severity_penalty(CRIT_WEIGHT, CRIT_DECAY, crit)
        + _severity_penalty(HIGH_WEIGHT, HIGH_DECAY, high)
        + _severity_penalty(MED_WEIGHT, MED_DECAY, med)
        + _severity_penalty(LOW_WEIGHT, LOW_DECAY, low)
    )

    raw_score = SCORE_MAX * math.exp(-penalty / SCORE_DECAY_K)
    return max(SCORE_MIN, min(SCORE_MAX, round(raw_score)))


def score_band(score: int):
    """Map an already-computed score to (label, severity_tier_key).

    Single source of truth for the 20/40/60/80 presentation thresholds --
    callers that need a color map that key to their own theme (rich style
    names, ANSI codes, ...); they must not hand-roll these cutoffs.
    """
    for minimum, label, tier in BANDS:
        if score >= minimum:
            return label, tier
    return "CRITICAL", "warning"  # unreachable (BANDS' last row is (0, ...)); defensive only
