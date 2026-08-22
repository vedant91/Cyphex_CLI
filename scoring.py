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

    score = 100 - (P_crit(crit) + P_high(high) + P_med(med) + P_low(low)),
    rounded to the nearest int and range-clamped to [0, 100].

    No severity-conditional branch, min(), or band-override appears anywhere
    in this function. The guarantee that an open Critical can never look
    SECURE/FAIR falls out of CRIT_WEIGHT alone: P_crit(1) == CRIT_WEIGHT ==
    62 exactly (see module docstring), and the other three severity terms
    are never negative (each is a non-negative weight times a value in
    [0,1)), so:

        score(crit>=1, high, med, low) <= 100 - 62 = 38

    for every possible high/med/low >= 0 -- a theorem about the additive
    weighted sum, not a runtime override layered on top of it. The single
    max(SCORE_MIN, min(SCORE_MAX, ...)) below is a generic numeric-range
    guard required by the int-in-[0,100] output contract (identical in
    spirit to clamping any bounded metric to its valid range) -- it never
    references which severity produced the total and never references the
    20/40/60/80 presentation bands in BANDS/score_band() below.

    Known, disclosed limit: because every severity's contribution is
    bounded (the pigeonhole principle any bounded score must obey), enough
    simultaneous high-severity findings (e.g. 2 Criticals + 3 Highs) can
    drive the sum past 100 and floor-clip to 0 same as any other bounded
    metric maxing out. That is a floor at the worst possible end of the
    range (many severe findings all correctly read as "as bad as it gets"),
    not the original bug -- which collapsed a MID-range, genuinely-improved
    state onto an unrelated worse one via an unrelated hardcoded cutoff.
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

    raw_score = SCORE_MAX - penalty
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
