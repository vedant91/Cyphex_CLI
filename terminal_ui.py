"""
CYPHEX Terminal UI — MONO ELECTRIC BLUE
════════════════════════════════════════════════════════════════════════════
A monochromatic system: the entire interface lives in ONE hue's light→dark
ramp (corporate, trustworthy electric blue). Hierarchy and severity are carried
by BRIGHTNESS within the ramp, not by competing hues.

    #7dabff  bright   — high emphasis / active / critical-high findings
    #3b82f6  PRIMARY  — the wordmark, structure, "safe/engaged"
    #2563c6  mid      — medium findings / secondary
    #1a4890  dim      — borders, rails, low findings
    #5f7391  muted    — captions, timestamps, comments
    #c2d0e6  readout  — primary readable prose / numerics

Everything degrades to a single clean static frame when stdout is not a TTY
(CI / pipes) — no escape spam, no alt-screen, no cursor games.

Public render_* names + signatures are preserved for cli_engine.py / cx.py.
"""
import sys, os, math, time, random, asyncio, base64, zlib

from scoring import score_from_counts as _scoring_score_from_counts, score_band as _scoring_band

# Force UTF-8 output whenever the terminal isn't already using it — this
# module prints Unicode unconditionally (box-drawing panels, braille HUD
# frames, severity glyphs) and Rich does NOT swallow the resulting
# UnicodeEncodeError on a non-UTF-8 stdout; it re-raises after annotating the
# message. Gating this to win32 only left every POSIX box with a non-UTF-8
# locale (LANG=C, minimal Docker base images, most CI runners, cron/non-
# interactive shells) with zero protection — the first Unicode render
# crashed the whole scan there, not just on Windows.
try:
    if not (sys.stdout.encoding or "").lower().startswith("utf"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if not (sys.stderr.encoding or "").lower().startswith("utf"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
# Only affects a Python child process THIS process spawns later (it has no
# effect on the current process — PYTHONIOENCODING is read at interpreter
# bootstrap, which has already happened by the time this line runs).
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.columns import Columns
from rich.align import Align
from rich.padding import Padding
from rich.console import Group
from rich.box import Box, ROUNDED, HEAVY, MINIMAL
from rich.theme import Theme
from rich.style import Style
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn

CX_VERSION = "4.4"

# ══════════════════════════════════════════════════════════════════════════
#  MONO ELECTRIC BLUE  (one hue's ramp — hierarchy & severity by brightness)
#  Names kept (PHOS/REF/TGT…) so every renderer recolours by value change.
# ══════════════════════════════════════════════════════════════════════════
VOID      = "#0a0f18"   # near-black navy — background / negative space
PANEL     = "#111b2e"   # raised panel fill (navy)
PHOS      = "#3b82f6"   # PRIMARY blue — wordmark, structure, "safe/engaged"
PHOS_DIM  = "#1a4890"   # dim blue — borders, rails, low emphasis
REF       = "#7dabff"   # bright blue — high emphasis / active / highlights
TGT       = "#7dabff"   # bright blue — commanded target (mono: = accent)
CAUT      = "#2563c6"   # mid blue — caution / medium findings
WARN      = "#7dabff"   # bright blue — critical / high (brightest = most urgent)
WARN_HOT  = "#a9c9ff"   # extra-bright blue — peak emphasis
APEX      = "#d6e6ff"   # near-white blue — rare apex flash
LABEL     = "#5f7391"   # muted blue-grey — captions, timestamps, comments
READOUT   = "#c2d0e6"   # light blue-grey — primary readable prose / numerics

HUD_THEME = Theme({
    "hud.void": VOID, "hud.panel": PANEL,
    "hud.phosphor": PHOS, "hud.phosphor.dim": PHOS_DIM,
    "hud.reference": REF, "hud.target": TGT,
    "hud.caution": CAUT, "hud.warning": WARN, "hud.warning.hot": WARN_HOT,
    "hud.apex": APEX, "hud.label": LABEL, "hud.readout": READOUT,
    # ── legacy aliases so any un-touched renderer keeps rendering ──
    "cy.primary": f"bold {PHOS}", "cy.secondary": f"bold {REF}",
    "cy.success": f"bold {PHOS}", "cy.warning": CAUT,
    "cy.high": WARN, "cy.critical": f"bold {WARN}",
    "cy.muted": LABEL, "cy.border": PHOS_DIM, "cy.dim": f"dim {LABEL}",
    "cy.text": READOUT, "cy.cyan": REF, "cy.purple": TGT,
    "cy.green": PHOS, "cy.red": WARN,
    "brand": f"bold {PHOS}", "accent": REF, "muted": LABEL,
    "ok": f"bold {PHOS}", "warn": CAUT, "err": f"bold {WARN}", "text": READOUT,
})

soc = Console(theme=HUD_THEME, highlight=False)


def _tty(console=None) -> bool:
    return (console or soc).is_terminal


def _cols(console=None) -> int:
    try:
        return (console or soc).size.width
    except Exception:
        return 80


def _ascii_mode(console=None) -> bool:
    """
    True when this terminal can't reliably render the box-drawing/braille/
    geometric glyph vocabulary the rest of this module uses by default.
    Distinct from _tty(): a terminal can be interactive (isatty() True) and
    still unable to render this — legacy Windows cmd.exe with no native VT
    processing is exactly that case. Checked per render call rather than
    cached once, since encoding/redirection can change mid-session (output
    piped partway through, terminal swapped).

    Three signals, any one is enough:
      - Rich's own legacy_windows detection (no VT support found)
      - the stream's encoding isn't UTF-8 (can't paint the glyphs at all)
      - TERM=dumb (plain CI log viewers, some serial consoles)
    """
    c = console or soc
    if getattr(c, "legacy_windows", False):
        return True
    enc = (getattr(c, "encoding", "") or "").lower()
    if enc and not enc.startswith("utf"):
        return True
    if os.environ.get("TERM", "").lower() == "dumb":
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════
#  COLOUR MATH — lerp + easing + score-band thermal colour
# ══════════════════════════════════════════════════════════════════════════
def _h2r(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def lerp(c1, c2, t):
    """Interpolate two hex colours. t in 0..1."""
    t = max(0.0, min(1.0, t))
    a, b = _h2r(c1), _h2r(c2)
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _ease_out(t):
    return 1 - (1 - t) ** 3


_TIER_COLOR = {"warning": WARN, "caution": CAUT, "reference": REF, "phosphor": PHOS}


def score_color(v):
    """Thermal verdict colour — weapons-hot red cools to calm phosphor-green.

    Band cutoffs come from scoring.score_band() (the single source of truth
    for the 20/40/60/80 presentation thresholds) — this only maps that
    band's tier key to this theme's colour constants.
    """
    _, tier = _scoring_band(v)
    return _TIER_COLOR[tier]


def _grad(text, stops):
    """Horizontal multi-stop gradient across a string. Returns a Text."""
    t = Text()
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        pos = i / n * (len(stops) - 1)
        lo = int(pos); hi = min(lo + 1, len(stops) - 1)
        t.append(ch, style=lerp(stops[lo], stops[hi], pos - lo))
    return t


# ══════════════════════════════════════════════════════════════════════════
#  GLYPH KIT
# ══════════════════════════════════════════════════════════════════════════
# Severity pips — geometric, single-width, zero emoji
SEV = {
    "Critical": (WARN,     "▲"),
    "High":     (WARN,     "●"),
    "Medium":   (CAUT,     "◆"),
    "Low":      (LABEL,    "○"),
    "Info":     (LABEL,    "·"),
}
# ASCII counterpart, same keys/colors — swapped in by sev() below whenever
# _ascii_mode() is true, so every caller that reads severity pips through
# sev() gets a safe glyph without needing its own ascii_mode check.
SEV_ASCII = {
    "Critical": (WARN,     "!"),
    "High":     (WARN,     "*"),
    "Medium":   (CAUT,     "+"),
    "Low":      (LABEL,    "o"),
    "Info":     (LABEL,    "."),
}


# BIT (built-in-test) states
BIT_PENDING, BIT_TEST, BIT_GO, BIT_NOGO = "□", "◐", "✓", "✗"
BIT_PENDING_ASCII, BIT_TEST_ASCII, BIT_GO_ASCII, BIT_NOGO_ASCII = "-", "~", "v", "x"


def bit_state():
    """(pending, test, go, nogo) glyph 4-tuple, ASCII-safe.
    e.g. `p, t, g, n = bit_state()`."""
    if _ascii_mode():
        return BIT_PENDING_ASCII, BIT_TEST_ASCII, BIT_GO_ASCII, BIT_NOGO_ASCII
    return BIT_PENDING, BIT_TEST, BIT_GO, BIT_NOGO


# Waypoint / scan phases — geometric glyph + label (no emoji)
STEP_META = {
    1: ("◹", "RECONNAISSANCE"),
    2: ("▦", "STATIC ANALYSIS"),
    3: ("⬢", "SANDBOX DEPLOY"),
    4: ("⇋", "DYNAMIC SCAN"),
    5: ("⟳", "GENOME EVOLUTION"),
    6: ("✦", "ATTACK SIMULATION"),
    7: ("▤", "SECURITY REPORT"),
    8: ("✚", "PATCH & VERIFY"),
}
STEP_META_ASCII = {
    1: ("[R]", "RECONNAISSANCE"),
    2: ("[S]", "STATIC ANALYSIS"),
    3: ("[D]", "SANDBOX DEPLOY"),
    4: ("[X]", "DYNAMIC SCAN"),
    5: ("[G]", "GENOME EVOLUTION"),
    6: ("[A]", "ATTACK SIMULATION"),
    7: ("[P]", "SECURITY REPORT"),
    8: ("[V]", "PATCH & VERIFY"),
}


def step_meta(num):
    """(glyph, title) for a waypoint number, ASCII-safe. Falls back to a
    generic marker + None (caller supplies its own title) for an
    out-of-range waypoint, same as the raw STEP_META.get(n, ...) pattern
    every call site used before."""
    table = STEP_META_ASCII if _ascii_mode() else STEP_META
    fallback_glyph = "[?]" if _ascii_mode() else "◈"
    return table.get(num, (fallback_glyph, None))
_SWEEP_TRAIL = "⣿⣷⣶⣤⣄⡀⠄⠂⠁"          # braille head → tail decay
_RAIN_POOL   = "0369ACEF⠁⠂⠄⡀⢀⠐⠈▓▒░"   # avionics crystallization noise

# CYPHEX wordmark
_LOGO = [
    " ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗",
    "██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝",
    "██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝ ",
    "██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗ ",
    "╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗",
    " ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
]
_LOGO_W = max(len(l) for l in _LOGO)
TAGLINE = "Autonomous cyber-defence · Local-first · Offline-capable"


# ══════════════════════════════════════════════════════════════════════════
#  CANOPY — a custom heavy-corner instrument bezel (nothing is a plain box)
# ══════════════════════════════════════════════════════════════════════════
# 8-line / 4-char-per-line Box spec. Corners glow; dotted edges recede.
CANOPY = Box(
    "┏┅┅┓\n"
    "┋  ┋\n"
    "┡┅┅┩\n"
    "┋  ┋\n"
    "┣╍╍┫\n"
    "┡┅┅┩\n"
    "┋  ┋\n"
    "┗┅┅┛\n"
)

# ASCII-safe counterpart. CANOPY is a custom Box, so it's absent from Rich's
# own LEGACY_WINDOWS_SUBSTITUTIONS table (that table only auto-downgrades
# Rich's own built-in boxes) — Rich correctly detecting a legacy terminal
# does nothing for a Panel/Table using CANOPY unless something here actually
# swaps it. See _box().
CANOPY_ASCII = Box(
    "+--+\n"
    "|  |\n"
    "+--+\n"
    "|  |\n"
    "+--+\n"
    "+--+\n"
    "|  |\n"
    "+--+\n",
    ascii=True,
)


def _box(console=None):
    """CANOPY, or CANOPY_ASCII on a terminal that can't render box-drawing
    glyphs (see _ascii_mode()). Every Panel/Table in this module should
    take its box= from here instead of hardcoding CANOPY directly."""
    return CANOPY_ASCII if _ascii_mode(console) else CANOPY


def _hairline(width, glyph="┅", style=PHOS_DIM):
    return Text(glyph * max(width, 0), style=style)


# ══════════════════════════════════════════════════════════════════════════
#  HUDCanvas — 2×4 sub-pixel Braille engine (the substrate for all motion)
#  DOTS bitmask:  dot1 0x01  dot4 0x08
#                 dot2 0x02  dot5 0x10
#                 dot3 0x04  dot6 0x20
#                 dot7 0x40  dot8 0x80
# ══════════════════════════════════════════════════════════════════════════
_DOT = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]]


class HUDCanvas:
    """A W(cells) × H(cells) canvas addressed at 2×4 sub-pixel resolution.
    One colour per cell (braille cells cannot mix fg colour), last write wins."""

    def __init__(self, cw, ch):
        self.cw, self.ch = cw, ch
        self.px, self.py = cw * 2, ch * 4
        self.cells = [[0] * cw for _ in range(ch)]
        self.color = [[None] * cw for _ in range(ch)]

    def plot(self, x, y, color=None):
        x, y = int(round(x)), int(round(y))
        if not (0 <= x < self.px and 0 <= y < self.py):
            return
        cx, cy = x // 2, y // 4
        self.cells[cy][cx] |= _DOT[y % 4][x % 2]
        if color:
            self.color[cy][cx] = color

    def line(self, x0, y0, x1, y1, color=None):
        x0, y0, x1, y1 = int(x0), int(y0), int(x1), int(y1)
        dx, dy = abs(x1 - x0), abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy
        while True:
            self.plot(x0, y0, color)
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy; x0 += sx
            if e2 < dx:
                err += dx; y0 += sy

    def to_text(self, default=PHOS_DIM):
        t = Text()
        for cy in range(self.ch):
            for cx in range(self.cw):
                v = self.cells[cy][cx]
                if v:
                    t.append(chr(0x2800 + v), style=self.color[cy][cx] or default)
                else:
                    t.append(" ")
            if cy < self.ch - 1:
                t.append("\n")
        return t


def sweep_trail_color(distance, length):
    """boresight_sweep colour law: cyan head → phosphor → dim → void by age."""
    if distance <= 0:
        return REF
    t = min(distance / max(length, 1), 1.0)
    if t < 0.5:
        return lerp(REF, PHOS, t / 0.5)
    return lerp(PHOS, PHOS_DIM, (t - 0.5) / 0.5)


# ══════════════════════════════════════════════════════════════════════════
#  CYPHEX LOCKMARK — the padlock brand glyph, drawn procedurally in Braille
#  (violet body with a lavender top-highlight, magenta shackle, carved keyhole)
# ══════════════════════════════════════════════════════════════════════════
_LAV = "#C9A0FF"   # lavender highlight


def _padlock_canvas(cw=24, ch=16, shackle_open=1.0, lit=PHOS, ring=REF):
    """Draw the CYPHEX padlock. shackle_open in 0..1 raises the shackle above
    the body (1.0 = closed/seated, higher = lifted — used by the boot 'lock')."""
    cv = HUDCanvas(cw, ch)
    W, H = cv.px, cv.py
    cx = W / 2
    bx0, bx1 = int(W * 0.16), int(W * 0.84)
    by0, by1 = int(H * 0.46), int(H * 0.92)
    rad = 5

    def in_body(x, y):
        if not (bx0 <= x <= bx1 and by0 <= y <= by1):
            return False
        for (cxr, cyr) in [(bx0 + rad, by0 + rad), (bx1 - rad, by0 + rad),
                           (bx0 + rad, by1 - rad), (bx1 - rad, by1 - rad)]:
            if (x < bx0 + rad or x > bx1 - rad) and (y < by0 + rad or y > by1 - rad):
                if math.hypot(x - cxr, y - cyr) > rad:
                    return False
        return True

    kh_cx, kh_cy, kh_r = cx, by0 + (by1 - by0) * 0.38, 3.2
    slot_top, slot_bot = kh_cy, by0 + (by1 - by0) * 0.78

    def in_keyhole(x, y):
        if math.hypot(x - kh_cx, y - kh_cy) <= kh_r:
            return True
        if slot_top <= y <= slot_bot:
            halfw = 1.4 + (y - slot_top) / (slot_bot - slot_top) * 2.2
            if abs(x - kh_cx) <= halfw:
                return True
        return False

    for y in range(H):
        for x in range(W):
            if in_body(x, y) and not in_keyhole(x, y):
                t = (y - by0) / (by1 - by0)
                cv.plot(x, y, _LAV if t < 0.18 else lit)

    # shackle — half annulus, lifted by (shackle_open) sub-pixels off the body
    lift = int((shackle_open - 1.0) * 8)
    s_cx = cx
    s_cy = by0 + 2 - lift
    r_out = (bx1 - bx0) * 0.40
    r_in = r_out - 4.5
    ang = 360.0
    while ang < 720.0:
        a = math.radians(ang)
        r = r_in
        while r <= r_out:
            x = s_cx + r * math.cos(a)
            y = s_cy + r * math.sin(a)
            if y <= s_cy:
                cv.plot(x, y, ring)
            r += 0.5
        ang += 0.5
    for leg_x in (s_cx - (r_in + r_out) / 2, s_cx + (r_in + r_out) / 2):
        for y in range(int(s_cy - 1), by0 + 2):
            for dx in (-1, 0, 1):
                cv.plot(leg_x + dx, y, ring)
    return cv


def render_lockmark(console=None, cw=24, ch=16):
    (console or soc).print(Align.center(_padlock_canvas(cw, ch).to_text(default=PHOS_DIM)))


# ══════════════════════════════════════════════════════════════════════════
#  VECTOR WORDMARK — CYPHEX as geometric letter STROKES on the Braille canvas
#  (a new method — not pre-baked block glyphs — laser-etched on at boot)
# ══════════════════════════════════════════════════════════════════════════
_LW, _LH, _LSP, _LYO = 14, 28, 5, 2          # letter box / spacing / y-offset (subpixels)
_WORD = "CYPHEX"
# each glyph = polylines in local coords (x:1..13, y:2..26), y-down
_FONT = {
    'C': [[(13, 2), (4, 2), (1, 6), (1, 22), (4, 26), (13, 26)]],
    'Y': [[(1, 2), (7, 14)], [(13, 2), (7, 14)], [(7, 14), (7, 26)]],
    'P': [[(1, 26), (1, 2), (10, 2), (13, 6), (13, 10), (10, 14), (1, 14)]],
    'H': [[(1, 2), (1, 26)], [(13, 2), (13, 26)], [(1, 14), (13, 14)]],
    'E': [[(13, 2), (1, 2), (1, 26), (13, 26)], [(1, 14), (10, 14)]],
    'X': [[(1, 2), (13, 26)], [(13, 2), (1, 26)]],
}
_LOGO_SUBW = len(_WORD) * _LW + (len(_WORD) - 1) * _LSP     # total subpixel width
_LOGO_CW = _LOGO_SUBW // 2 + 3
_LOGO_CH = (_LH + _LYO * 2) // 4 + 1


def _seg_points(a, b):
    x0, y0, x1, y1 = int(a[0]), int(a[1]), int(b[0]), int(b[1])
    pts = []
    dx, dy = abs(x1 - x0), abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx - dy
    while True:
        pts.append((x0, y0))
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 > -dy:
            err -= dy; x0 += sx
        if e2 < dx:
            err += dx; y0 += sy
    return pts


def _build_logo_points():
    """Ordered (gx,gy) samples along the whole CYPHEX path, reading order."""
    pts = []
    for i, ch_ in enumerate(_WORD):
        ox = i * (_LW + _LSP) + 2
        for poly in _FONT[ch_]:
            for a, b in zip(poly, poly[1:]):
                seg = _seg_points((ox + a[0], _LYO + a[1]), (ox + b[0], _LYO + b[1]))
                pts.extend(seg if not pts else seg[1:])
    return pts


_LOGO_POINTS = _build_logo_points()


def _thick(cv, x, y, color):
    for dx in (-1, 0, 1):
        for dy in (-1, 0, 1):
            cv.plot(x + dx, y + dy, color)


def _vector_logo(frac=1.0, beam=True, body=PHOS):
    """Rasterise the vector wordmark to a fraction `frac` of its arc-length.
    When beam and frac<1, the leading ~edge glows (laser-etch spark)."""
    cv = HUDCanvas(_LOGO_CW, _LOGO_CH)
    head = int(max(0.0, min(1.0, frac)) * len(_LOGO_POINTS))
    for j in range(head):
        gx, gy = _LOGO_POINTS[j]
        if beam and frac < 1.0:
            d = head - j
            if d <= 2:
                col = READOUT                       # white-hot etch spark
            elif d <= 10:
                col = REF                           # magenta cooling
            elif d <= 22:
                col = lerp(body, REF, (22 - d) / 12)
            else:
                col = body
        else:
            col = body
        _thick(cv, gx, gy, col)
    return cv


# ══════════════════════════════════════════════════════════════════════════
#  LED DOT-MATRIX WORDMARK — CYPHEX as a 5×7 scoreboard sign whose dots
#  ignite column-by-column at boot (the active logo).
# ══════════════════════════════════════════════════════════════════════════
_LED_FONT = {
    'C': ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    'Y': ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    'P': ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    'H': ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    'E': ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    'X': ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
}
_LED_WORD = "CYPHEX"
_LED_ROWS = 7
_LED_GAP = 1                      # blank dot-columns between letters
_LED_DOT = "●"


def _build_led_cols():
    cols = []
    for i, ch in enumerate(_LED_WORD):
        g = _LED_FONT[ch]
        for c in range(5):
            cols.append([int(g[r][c]) for r in range(_LED_ROWS)])
        if i < len(_LED_WORD) - 1:
            cols.extend([[0] * _LED_ROWS for _ in range(_LED_GAP)])
    return cols


_LED_COLS = _build_led_cols()
_LED_NC = len(_LED_COLS)
_LED_W = _LED_NC * 2              # rendered character width


def _led_logo(sweep=None, flat=None):
    """CYPHEX as an LED panel. sweep=None → fully lit (settled violet); flat set
    → every lit dot that colour (ignition flash); sweep=int → dots left of the
    sweep column are lit, the head glows white, ahead are dim/unlit."""
    t = Text()
    for r in range(_LED_ROWS):
        for x in range(_LED_NC):
            if _LED_COLS[x][r]:
                if flat is not None:
                    col = flat
                elif sweep is None:
                    col = PHOS
                else:
                    d = sweep - x
                    if d < 0:
                        col = PHOS_DIM                          # unlit LED (dim)
                    elif d == 0:
                        col = READOUT                           # igniting head
                    elif d <= 2:
                        col = lerp(REF, READOUT, (2 - d) / 2)   # hot magenta edge
                    elif d <= 5:
                        col = lerp(PHOS, REF, (5 - d) / 3)      # cooling
                    else:
                        col = PHOS                              # settled violet
                t.append(_LED_DOT, style=col)
            else:
                t.append(" ")
            t.append(" ")
        if r < _LED_ROWS - 1:
            t.append("\n")
    return t


# ══════════════════════════════════════════════════════════════════════════
#  BROKEN-SHACKLE LOCKMARK + CYPHEX LOCKUP  (the brand logo)
#  A padlock whose severed shackle apex is bridged by a { } code-brace —
#  "we find the break and patch it." Solid violet body weight-matches the
#  block wordmark; severed ends are red so "broken" survives mono/colorblind.
# ══════════════════════════════════════════════════════════════════════════
_BROKEN_LOCK = [
    "  ╭─╴{ }╶─╮  ",
    "  │       │  ",
    "▗▄▄▄▄▄▄▄▄▄▄▄▖",
    "▐█████◉█████▌",
    "▐█████╹█████▌",
    "▝▀▀▀▀▀▀▀▀▀▀▀▘",
]
_BLOCK_WORD = [
    "██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗",
    "██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝",
    "██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝ ",
    "██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗ ",
    "╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗",
    " ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
]
_LOCK_W = 13
_LOCKUP_W = _LOCK_W + 3 + max(len(r) for r in _BLOCK_WORD)   # ≈ 64 cols


def _lock_line(row, break_col=WARN, brace=READOUT, key=TGT, body=PHOS):
    t = Text()
    for ch in row:
        if ch == " ":
            t.append(" ")
        elif ch in "╴╶":
            t.append(ch, style=break_col)          # the severed shackle ends
        elif ch in "{}":
            t.append(ch, style=f"bold {brace}")     # the code-brace patch
        elif ch in "◉╹":
            t.append(ch, style=key)                  # keyhole
        else:
            t.append(ch, style=body)                 # violet body / shackle
    return t


def _lockmark_lines(**kw):
    return [_lock_line(r, **kw) for r in _BROKEN_LOCK]


def _lockup(word_style=None):
    """The full brand logo: broken-shackle lock + CYPHEX wordmark, side by side."""
    n = max(len(r) for r in _BLOCK_WORD)
    lock = _lockmark_lines()
    t = Text()
    for i in range(6):
        t.append_text(lock[i])
        t.append("   ")
        if word_style is not None:
            t.append(_BLOCK_WORD[i], style=word_style)
        else:
            for j, ch in enumerate(_BLOCK_WORD[i]):
                if ch == " ":
                    t.append(" ")
                else:
                    t.append(ch, style=lerp(PHOS, REF, j / max(n - 1, 1)))
        if i < 5:
            t.append("\n")
    return t


# ── baked CYPHEX logo image (Option 2) — pre-rendered pixels, no Pillow at runtime ──
_LOGO_W = 74
_LOGO_H = 24
_LOGO_BLOB = (
    'eNrtWGlwVFUW7gSscUNxUGfEchyXWaCmphyXQjExGAaGKCCopISAQPd7t9NZSMIii8ZWpHSITnQEBQYGUCRAQliSEJAQYwFCggmQkB0CZukkvaSTXtLd6X6v'
    'vzm30w/bEMupKeeHwk2dunnnnvvefd/9vnPPa5XqWvsxGoAw6BE+wBfO/dfQGQSvGTOGQKUKg2rGkGtofJdHwf4OL/DY5YHwMBVdP0n+G6+hFMBniJ705mnp'
    'ni6nvVmPUZGZmKoeidGR26DPvODtwWNQkSbxXU1edTiVYGjYdWEqbPn0EKaLwMMTgbHPnMNDE4D5i4DPPlvP48o3bLjuasVIH8zb703EPRdXnahDYqqMUY+3'
    'IHLKcowe04MVq+TaZaXH3o/C8FCN/iD2Kh7388j/CkY7GB7IEXBpdwpQtqJD/mrakRTuP/ZS6ebSdKucmwzQePmeRIzgc/T679df9gwMCcWHX2MAXsr8gJZ/'
    'AEt+/kL/4+o9jP6U5/7wviOMr3cDw3U7NDiTnwjsVMue/ARgWzxWQKUP/1SL7fk68mtkdyFhlaVBvrL277un8t+JNNxQosdQ5Zo/50q+fdtCY/9v+WXgGvT6'
    '8ND1DPZeyrqyBLzIMSKsvLlaYJfgjT8xo+UG4sENJQnGm3NE+Y19uv7xvfGEFcOYb3lzJUdyBClxvxan9go+WwGTWwpF3+aSFAw/rMbIzwXfqbJknP1c7U4I'
    'rCEBN38huA7WpKDmqOBYeFLjGFedhKpS5jhTJtgbK8TeczXx3oLTom0sj68Ue161LkRVHevZCM5TsvNaS4Z7EaouMHMmj2llpn1mnb3KIBprO5ixqZN1NiLF'
    '12TSdsRa4jsf9yY7a926rgonMzzM43tZ80qk+Sr7WEthx+yzN12xf1EYyt9tpwY5+3Xw7+e8EbBmsH2gmPw9hFFeAucWMvi80P1XMMsWsKSYtFtI99qt8Z3d'
    'p/FZKl8B8jXeah5zUONJr0wDvhC9zqI5thGE0dKGhcBxrcd5dL79jq8Ex8wmGi/XelAmOkxfCzZ/C93vjGgz8L2uFLvX9S0Dalj3l8qzL2itO0G+i8wc4HoL'
    'M130pgKEk7WdddYRTtXSgr46E+sUOAbdrP04j7ez1v0eZvhjn65TwkIJfdqWuP7acfD9z1LL64lHvj1a+HcIWE84zM9SQ52lkebuon67Rpq/S4PdxCU/mY/i'
    'V4Zio+Cfx3Aj6bOtKBlSrkbO4L49lPcOMKnogOD7qEDXcxv3HdL0fVm+ACjSuI8Vi27T6WQ/igVHbCAfCs6Xa5Igl4pOE78+Ldqj6hOkvtNCj780znJLldiT'
    'YU6DXCt2lzUI1khu57XWz52pskw45fA5zcxU6Vngk9uYcaORGSNMOlOUNcEaYV5iHsbHXczwm16dudulM3qdrO0iUlxwi9/s6scoe8iVuVal+mS+76+Un9u2'
    'q33Stnlefw6VBHtJe7kM2BPsudaIJ+DjWRSXLcgthOWTfP4Muq+Cd7YGD+4U5L78+EDOj+z3D8yRCCsSPL//gnltR+n+XycBRzS9WQrexwVHHOFEXHI6ywTb'
    'auJTURtx44xga+d8qhK717ZQnmzQ2tFDvLORfaNzwJToIz5Z9gb5VGsmny3RBRBXQWUNFgNmZn5UWUUPMyQj2QFPfAdZexeY4fbBzgvl3bbOcZXmEjZb5rik'
    'rS+7sWV2r7x1jtu3Yz582+cRd6inMR/FyXx885xeiTiCdS+ZTij3uYyTgPuIT54C0lyOxjdOedY+tfepgwx3hWr1sMbz+qlEyF+KHkvJXOevFU4e1zhmn0vk'
    'ODl8p0S7v4I5ndW6vpMVrHs8Hz9HuusgHdaK1pY60bqhnqxRtDT2pMhcd3uCOFW7FnjRJpoOtWuNi4lTS7u05sUGjkXwbLOxtt3+JBu8OhN8CRaXmzVPHExz'
    'Sts4y964dbbPv2mmXd44y4FNZP+Oc2LemA2IuE8NXcQOws4DiguMbZxpk7e9DP87U881Bs7XsPAAR/h7ltNZQnyqJ935d2vktVvmXrp+r+CNLGSSRLncnj/P'
    '8ztVf00fVsRccyuSZalYcDXx80LB6RhzzCI+SaS7zgp170gD++73UpXQ8wHlcYl0d0Dxndd2bfYsgnSJWXYFcTojpUJqE0yvBc/moYE6YBFu4tcWoXkeUr1w'
    'attMvaztANedV2u4aEyovnngGai0j2OtdZtmubEu1ip/HGvBljgvxCc+we03/gH33PoYfnXTn7Do6YPYHNeHj2O7uMlbZktY9Wxl3bc4qcIUHZPeYgsp1x8h'
    'beQKvu4C4l5paiCP53MulQfP5cOiO6mB9FAsuHv2qTHsMp8E57xW0shJwd5XMrd7eFCP4VST/CKAE51z0nLiE7OW8vtxu6Dt2k9VDNddYTA/tUqkR6vOji5d'
    'N8zx5oD+LKxztVXdfq8roQtYQnlc2/7qJdpLj9ZgxFLAy1qyeX4ajFNrXjDVr491YM3zJvmfz3di00seTB6djpG3PIRRd0zEXcP+jLhH1mLTzD7w8Q+fN8ob'
    'KeaNmIr6UJxCtZytxrN5Wjl7ryCdpbrgeAHzrcymWiq0Film7onlScg7Irg2l8zF9QpOJ0RXFPEp76Ro/6wuiB83ZR+IT6wrDXnEp7dC+LTYvRB5l5h5WbAu'
    '+MiS4Mij8y6vQzQeMGqNeUiRDpi1nXEWsU2NNLmAzrqtRqp5AnWBtvk5JNv3S7r2fOg67x9Md5nT2uvXvtCN959rlzOnGbDmBSuWjz+OB0Y8hd/e9gRG3fk3'
    'vBVzDh9ON4NikfmcQV73ogPpE8uuwCkUq5/Md+1/+V2VMbm5/oNpJrw7uVnOmNKMf0w1YFVMPUbfOYl09ygevjsW705pJWsJWMbkb+QPp3MsTwyKk3KWKt8q'
    'gdxNddrA9SgcGVirBvgziD90HwL1Zch+YIAvO6idKwz93Lx8rXy3KPMH1ASh7Z2Yprr3prSDevntmCa8N7kdqZGHce/wMbj/lxF4cEQUVkSfQsazreDjb8dc'
    'kDOnmvDKuKN134fTz7GtnNBw/p1JzfJbExrkNyfUY/UzBsT95V+4m/LTA4TRPbc+Au2YXPw9phV8nEymGHlhRPH5qwEnJY+kR9cWr44x4rXoGl96dI1fP77O'
    'v+Spk/6kJw75F4w9HOiXRp0K+Pn4a9HVvowYE5ZFVRT/FPPR/4YTwpZHV49OH1df//rTDUh/ui5g+ujzeHP8RbKmQK+Pbrw8FoijePKNVn5vuAp+ogvoRT12'
    '3zB9VMNfl0WcnbQsiiyiYtLiiDKy/p5f9/vPTuJxPD50/s+x/QdDajOD'
)
_LOGO_PIXELS = None


def _logo_pixels():
    global _LOGO_PIXELS
    if _LOGO_PIXELS is None:
        _LOGO_PIXELS = zlib.decompress(base64.b64decode(_LOGO_BLOB))
    return _LOGO_PIXELS


def _image_logo():
    """Render the baked logo as colored half-block pixels (▀ = 2 stacked px)."""
    raw = _logo_pixels()
    W, H = _LOGO_W, _LOGO_H

    def px(x, y):
        i = (y * W + x) * 4
        return raw[i], raw[i + 1], raw[i + 2], raw[i + 3]

    t = Text()
    for r in range(0, H - 1, 2):
        for c in range(W):
            tr = px(c, r); br = px(c, r + 1)
            ta = tr[3] > 90; ba = br[3] > 90
            top = "#%02x%02x%02x" % tr[:3]
            bot = "#%02x%02x%02x" % br[:3]
            if not ta and not ba:
                t.append(" ")
            elif ta and ba:
                t.append("▀", style=Style(color=top, bgcolor=bot))
            elif ta:
                t.append("▀", style=top)
            else:
                t.append("▄", style=bot)
        if r < H - 2:
            t.append("\n")
    return t


def _logo_static(console=None, spaced=True):
    """The brand logo: the CYPHEX block wordmark rendered in the Mono Electric
    Blue ramp (left→right PHOS→REF gradient). Collapses to a compact ◼ CYPHEX
    mark only when the terminal is too narrow to fit the full wordmark."""
    c = console or soc
    # NB: the module-level _LOGO_W is reused by the image-blob logo, so measure
    # the ASCII wordmark's own width here rather than trusting that global.
    logo_w = max(len(l) for l in _LOGO)
    # Narrow terminal → compact inline mark (keeps the hero from wrapping).
    if _cols(c) < logo_w + 2:
        word = "C Y P H E X" if spaced else "CYPHEX"
        t = Text()
        t.append("◼ ", style=f"bold {REF}")
        t.append(word, style=f"bold {PHOS}")
        return t
    # Full block wordmark with a horizontal blue gradient.
    span = max(logo_w - 1, 1)
    t = Text()
    for i, line in enumerate(_LOGO):
        for j, ch in enumerate(line):
            if ch == " ":
                t.append(" ")
            else:
                t.append(ch, style=f"bold {lerp(PHOS, REF, j / span)}")
        if i < len(_LOGO) - 1:
            t.append("\n")
    return t


# ══════════════════════════════════════════════════════════════════════════
#  ANNUNCIATOR — reverse-video cockpit lamp tiles
# ══════════════════════════════════════════════════════════════════════════
def annunciator(text, level="phosphor", lit=True):
    """A lamp tile like ▐ MASTER WARNING ▌ (or [ MASTER WARNING ] in
    _ascii_mode). level: phosphor|reference|caution|warning|target."""
    color = {"phosphor": PHOS, "reference": REF, "caution": CAUT,
             "warning": WARN, "target": TGT, "apex": APEX}.get(level, PHOS)
    lwall, rwall = ("[", "]") if _ascii_mode() else ("▐", "▌")
    t = Text()
    if lit:
        t.append(lwall, style=color)
        t.append(f" {text} ", style=f"bold reverse {color}")
        t.append(rwall, style=color)
    else:
        t.append(f"{lwall} {text} {rwall}", style=f"dim {LABEL}")
    return t


def render_annunciator(text, level="phosphor", console=None):
    (console or soc).print(Text("  ") + annunciator(text, level))


# ══════════════════════════════════════════════════════════════════════════
#  BORESIGHT RETICLE — fixed centre targeting cross, state-carrying hub
# ══════════════════════════════════════════════════════════════════════════
def render_boresight(state="idle", console=None):
    hub = {"idle": ("⊕", PHOS), "scanning": ("⌖", REF), "locked": ("◈", TGT)}.get(state, ("⊕", PHOS))
    c = console or soc
    arm = "━━━━━"
    t = Text()
    t.append("        ╹        \n", style=PHOS)
    t.append("  ╺" + arm, style=PHOS)
    t.append(hub[0], style=f"bold {hub[1]}")
    t.append(arm + "╸  \n", style=PHOS)
    t.append("        ╻        ", style=PHOS)
    c.print(Align.center(t))


# ══════════════════════════════════════════════════════════════════════════
#  WORDMARK RENDERING — the shared logo colouring engine
# ══════════════════════════════════════════════════════════════════════════
def _cell_threshold(row, col):
    return (((row * _LOGO_W + col) * 2654435761) % 997) / 997.0


def _wordmark(mode="final", param=0.0, seed=1337, flash=False):
    """
    mode:
      'crystal' param=0..1 : rain freezes into cyan wireframe as param rises
      'beam'    param=col  : one bright SWEEP head redraws cyan→phosphor L→R
      'final'   param=n/a  : settled phosphor wordmark (flash=magenta crossbar)
    """
    rng = random.Random(seed + int(param * 100))
    t = Text()
    for row, raw in enumerate(_LOGO):
        line = raw.ljust(_LOGO_W)
        for col, ch in enumerate(line):
            if ch == " ":
                t.append(" ")
                continue
            if mode == "crystal":
                if _cell_threshold(row, col) <= param:
                    t.append(ch, style=REF)            # frozen cyan wireframe
                else:
                    t.append(rng.choice(_RAIN_POOL), style=PHOS_DIM)
            elif mode == "beam":
                if col < param - 1:
                    t.append(ch, style=lerp(PHOS, PHOS_DIM, row / len(_LOGO) * 0.6))
                elif col <= param:
                    t.append(ch, style=f"bold {REF}")  # the beam head
                else:
                    t.append(ch, style=REF)            # not yet drawn (wireframe)
            else:  # final
                mid = len(_LOGO) // 2
                if flash and row in (mid - 1, mid):
                    t.append(ch, style=f"bold {TGT}")  # ignition carrier pulse
                else:
                    t.append(ch, style=lerp(PHOS, lerp(PHOS, PHOS_DIM, 0.5), row / len(_LOGO)))
        t.append("\n")
    return t


# Backwards-compat shim (older callers referenced _glitch_frame)
BOOT_SEED = 1337
def _glitch_frame(progress=1.0, seed=BOOT_SEED):
    return _wordmark("final") if progress >= 1.0 else _wordmark("crystal", progress, seed)


# ══════════════════════════════════════════════════════════════════════════
#  MASTHEAD — the settled static header (persistent after boot)
# ══════════════════════════════════════════════════════════════════════════
def render_masthead(console=None, hint=True):
    """Claude/Codex-style home screen: LEFT-aligned logo, then a bordered
    workspace box (spanning the window) with a compact command reference and
    the current directory. Not a centered splash."""
    c = console or soc
    c.print()
    # ── Left-aligned brand logo (1-col indent, not centered) ──
    c.print(Padding(_logo_static(c), (0, 0, 0, 1)))
    c.print()
    if not hint:
        return

    # ── Tagline + version ──
    tag = Text()
    tag.append(TAGLINE, style=LABEL)
    tag.append(f"    v{CX_VERSION}", style=PHOS_DIM)

    # ── Compact command reference (two command/description pairs per row) ──
    grid = Table.grid(padding=(0, 3, 0, 0))
    grid.add_column(no_wrap=True, style=f"bold {PHOS}")
    grid.add_column(no_wrap=True, style=READOUT)
    grid.add_column(no_wrap=True, style=f"bold {PHOS}")
    grid.add_column(no_wrap=True, style=READOUT)
    grid.add_row("/scan <target>", "Static + DAST scan", "/watch", "RASP auto-heal daemon")
    grid.add_row("/deep <target>", "+ DeepAgents swarm", "/setup", "Install tools")
    grid.add_row("/full <target>", "DeepAgents + network", "/doctor", "Health check")
    grid.add_row("/net \\[host]", "Network map / audit", "/help", "All commands")

    flags = Text()
    flags.append("flags   ", style=LABEL)
    flags.append("--network  --deepagents  --full  --no-patch", style=PHOS_DIM)

    cwd = Text()
    cwd.append("cwd     ", style=LABEL)
    cwd.append(os.getcwd(), style=REF)

    body = Group(tag, Text(), grid, Text(), flags, cwd)
    c.print(Panel(
        body,
        title=Text("◈ WORKSPACE", style=f"bold {REF}"),
        subtitle=Text("type a path, URL, or plain English to scan it", style=LABEL),
        title_align="left", subtitle_align="left",
        border_style=PHOS_DIM, box=ROUNDED, padding=(1, 2),
    ))
    c.print()


def render_help(console=None):
    """Command deck reference — avionics styled."""
    c = console or soc
    rows = [
        ("/scan", "<path|url>", "Acquire & scan a target (local dir or GitHub repo)"),
        ("/deep", "<path>", "Add the full DeepAgents attack swarm"),
        ("/full", "<path>", "DeepAgents + network sweep (everything)"),
        ("", "flags", "--network  --deepagents  --full  --no-patch  --verbose"),
        ("/net", "[host]", "Network discovery, or audit a specific host"),
        ("/watch", "", "Arm the RASP auto-healing daemon"),
        ("/setup", "", "Install Semgrep, Nuclei; check Ollama & Docker"),
        ("/doctor", "", "Built-In-Test — models, tools & dependencies"),
        ("/benchmark", "[corpus]", "Score the Immune System — precision/recall/F1"),
        ("/verify", "[path]", "Verify Gate maintainability panel — config/status/health"),
        ("", "flags", "--selftest  --ci  --watch [s]  --json <file>"),
        ("/status", "[path]", "System Observability — event log, last scan, errors"),
        ("/models", "", "List available local Ollama models"),
        ("/history", "", "Recent intercepts this session"),
        ("/clear", "", "Repaint the canopy"),
        ("/exit", "/quit", "Power down · canopy dark"),
    ]
    t = Table.grid(padding=(0, 2, 0, 0))
    t.add_column(no_wrap=True, style=f"bold {PHOS}")
    t.add_column(no_wrap=True, style=TGT)
    t.add_column(style=READOUT)
    for cmd, arg, desc in rows:
        t.add_row(cmd, arg, desc)
    c.print(Panel(t, title=Text("◈ COMMAND DECK", style=f"bold {REF}"),
                  subtitle=Text("type a path, URL, or plain English to acquire it", style=LABEL),
                  subtitle_align="left", title_align="left",
                  border_style=PHOS_DIM, box=_box(c), padding=(0, 2)))


# ══════════════════════════════════════════════════════════════════════════
#  BOOT SEQUENCE — crystallize → beam → ignite → align → frame-lock → spin-up
# ══════════════════════════════════════════════════════════════════════════
def _telemetry_line(brg="043", thrt="▲00 ●00", alt="0.0s", defcon="5", gen="⟳v14"):
    t = Text()
    def seg(label, val, vstyle=PHOS):
        t.append("╺╸ ", style=PHOS_DIM)
        t.append(label + " ", style=LABEL)
        t.append(val, style=vstyle)
        t.append("  ", style=PHOS_DIM)
    seg("BRG", brg); seg("THRT", thrt, LABEL); seg("ALT", alt)
    seg("DEF", defcon, PHOS); seg("GEN", gen, REF)
    return t


def _ekg_strip(rhythm="calm", width=16):
    """A resting-sinus braille EKG strip. rhythm: calm|stress|arrhythmia."""
    unit = {"calm": "⣀⡠⠔⠊⠑⠢⢄⣀", "stress": "⣀⡠⢠⡎⢱⡀⠢⢄",
            "arrhythmia": "⣀⡎⢱⡎⢱⡀⠄⣀"}.get(rhythm, "⣀⡠⠔⠊⠑⠢⢄⣀")
    s = (unit * ((width // len(unit)) + 1))[:width]
    color = {"calm": PHOS, "stress": CAUT, "arrhythmia": WARN}.get(rhythm, PHOS)
    return Text(s, style=color)


def render_boot(console=None):
    """CYPHEX logo reveal — the wordmark is LASER-ETCHED onto the glass by a
    travelling beam, ignites, then arms. ~3.0s, alt-screen.
    Non-TTY: nothing (the masthead is the static identity)."""
    c = console or soc
    if not _tty(c):
        return

    def ctr(txt):
        return Align.center(txt, vertical="middle")

    # NOTE: simple placeholder reveal — the full logo animation is the next
    # design step. For now the boot just presents the finished brand logo so
    # boot and masthead are consistent (image logo on truecolor, box otherwise).
    logo = _logo_static(c)
    try:
        with c.screen() as screen:
            # beat 1 — the logo appears + holds
            screen.update(ctr(logo))
            time.sleep(0.85)
            # beat 2 — armed hold
            body = Text()
            body.append_text(logo)
            body.append("\n\n  ")
            body.append_text(annunciator("SYSTEMS ARMED", "phosphor"))
            body.append("   ")
            body.append_text(annunciator("SECURE", "phosphor"))
            body.append("\n\n  ")
            body.append(TAGLINE, style=LABEL)
            screen.update(ctr(body))
            time.sleep(0.7)
        # A brief mascot cameo on the MAIN screen as boot hands off to
        # whatever normally follows (render_masthead). Imported lazily —
        # mascot.py imports these colour constants from this module, so a
        # top-level import here would be circular.
        import mascot as _mascot
        _mascot.success("systems armed")
    except Exception:
        # Never let eye-candy crash a launch
        pass


# ══════════════════════════════════════════════════════════════════════════
#  BUILT-IN TEST — tool / subsystem readiness (staggered GO / NO-GO)
#  Preserves render_tools_live(tools) signature; tools = [(name, ok, hint)]
# ══════════════════════════════════════════════════════════════════════════
def render_tools_live(tools, console=None, stagger=0.10, pulse_hold=0.10):
    c = console or soc

    def cell(name, state):
        pending, test, go, nogo = bit_state()
        if state == "pending":
            return Text.assemble((pending + " ", LABEL), (name, LABEL))
        if state == "test":
            return Text.assemble((test + " ", REF), (name, READOUT))
        if state == "go":
            return Text.assemble((go + " ", PHOS), (name, READOUT))
        return Text.assemble((nogo + " ", WARN), (name, WARN))

    def frame(states):
        grid = Table.grid(padding=(0, 2, 0, 0))
        grid.add_column(no_wrap=True)
        grid.add_column(no_wrap=True, overflow="ellipsis")
        for i, (name, ok, hint) in enumerate(tools):
            note = ""
            if states[i] == "nogo" and hint:
                note = Text("→ " + str(hint), style=LABEL)
            grid.add_row(cell(name, states[i]), note)
        n_go = sum(1 for s in states if s == "go")
        title = Text.assemble(("BUILT-IN TEST ", f"bold {PHOS}"),
                               (f"{n_go}/{len(tools)} GO", LABEL))
        return Panel(grid, title=title, title_align="left",
                     border_style=PHOS_DIM, box=_box(c), padding=(0, 2))

    if not _tty(c):
        c.print(frame(["go" if ok else "nogo" for _, ok, _ in tools]))
        return

    # Lazy import — mascot.py imports this module's colour constants, so a
    # top-level import here would be circular. Bracketed around (not run
    # concurrently with) the Live loop below so the two redraw loops never
    # fight over the same terminal lines. Never let eye-candy crash a launch.
    try:
        import mascot as _mascot
        _mascot.searching("Running built-in test...", flourish=True)
    except Exception:
        _mascot = None

    states = ["pending"] * len(tools)
    any_nogo = False
    with Live(frame(states), console=c, refresh_per_second=14, transient=False) as live:
        for i, (name, ok, hint) in enumerate(tools):
            states[i] = "test"
            live.update(frame(states)); time.sleep(pulse_hold)
            states[i] = "go" if ok else "nogo"
            any_nogo = any_nogo or (not ok)
            live.update(frame(states)); time.sleep(stagger)
    if any_nogo:
        if _mascot:
            try:
                _mascot.error("MASTER CAUTION")
            except Exception:
                pass
        render_annunciator("MASTER CAUTION", "caution", console=c)
    elif _mascot:
        try:
            _mascot.success("all systems go")
        except Exception:
            pass


# Legacy static variant (kept for API completeness)
def render_tools(tools):
    render_tools_live([(n, ok, h) for n, ok, h in tools])


# ══════════════════════════════════════════════════════════════════════════
#  STATUS LINE + REAL-WORK SWEEP PROGRESS
# ══════════════════════════════════════════════════════════════════════════
def render_status(text, style="ok", console=None):
    c = console or soc
    glyph = {"ok": ("✓", PHOS), "warn": ("▲", CAUT), "err": ("✗", WARN),
             "muted": ("╺╸", LABEL), "text": ("▸", REF)}.get(style, ("▸", REF))
    t = Text("  ")
    t.append(glyph[0] + " ", style=glyph[1])
    t.append(text, style=READOUT if style in ("text", "muted") else glyph[1])
    c.print(t)


async def render_progress_task(awaitable, label, console=None, ease_target=92, tick=0.08):
    """Drive a cyan SWEEP progress bar while real work runs concurrently.
    Non-TTY: plain await, no output."""
    c = console or soc
    if not _tty(c):
        return await awaitable

    # Lazy import — mascot.py imports this module's colour constants, so a
    # top-level import here would be circular. A quick announcing beat before
    # the SWEEP bar takes over (never let eye-candy crash real work).
    try:
        import mascot as _mascot
        _mascot.thinking(label, flourish=True)
    except Exception:
        _mascot = None

    with Progress(
        TextColumn("  [bold]{task.fields[lab]}[/bold]", style=REF),
        BarColumn(bar_width=34, style=PHOS_DIM, complete_style=REF, finished_style=PHOS),
        TextColumn("{task.percentage:>3.0f}%", style=LABEL),
        console=c, transient=True,
    ) as progress:
        tid = progress.add_task("", total=100, lab=label)
        work = asyncio.ensure_future(awaitable)
        pct = 0.0
        while not work.done():
            if pct < ease_target:
                pct += (ease_target - pct) * 0.18 + 0.5
                progress.update(tid, completed=min(pct, ease_target))
            await asyncio.sleep(tick)
        progress.update(tid, completed=100)
        try:
            result = work.result()
        except Exception:
            if _mascot:
                try:
                    _mascot.error(label)
                except Exception:
                    pass
            raise

    if _mascot:
        try:
            _mascot.success(label)
        except Exception:
            pass
    return result


# ══════════════════════════════════════════════════════════════════════════
#  HERO / SPLASH — scan header inside the canopy
# ══════════════════════════════════════════════════════════════════════════
def render_hero(scan_id, target="", score=None):
    body = Text()
    body.append_text(_logo_static())
    body.append("\n")
    body.append_text(_telemetry_line())
    body.append("\n\n")
    body.append("  SCAN ID  ", style=LABEL)
    body.append(f"{scan_id}", style=PHOS)
    if target:
        body.append("\n  TARGET   ", style=LABEL)
        body.append(f"{target}", style=READOUT)
    soc.print(Panel(body, border_style=PHOS_DIM, box=_box(), padding=(0, 2)))


# ══════════════════════════════════════════════════════════════════════════
#  WAYPOINT ADVANCE — scan-step transitions as a HUD route
#  Preserves render_step(step_num, total, title, elapsed, mode)
# ══════════════════════════════════════════════════════════════════════════
def _route_rail(active, total):
    t = Text()
    for i in range(1, total + 1):
        if i < active:
            t.append("◉", style=PHOS)
        elif i == active:
            t.append("◇", style=REF)
        else:
            t.append("◌", style=PHOS_DIM)
        if i < total:
            t.append("╌", style=PHOS_DIM)
    return t


def render_step(step_num, total, title, elapsed=0.0, mode="SCAN"):
    import re as _re
    # step_num may carry a sub-step letter (e.g. "3b" for the optional network
    # scan slotted after step 3). Strip it only for the numeric lookups (glyph,
    # rail position) — keep it in the printed label so "3b" reads distinctly
    # from "3" instead of both collapsing to an identical "WAYPOINT 03/09".
    m = _re.match(r"(\d+)([a-zA-Z]*)", str(step_num))
    num_part, suffix = (m.group(1), m.group(2)) if m else (str(step_num), "")
    done = int(num_part or "0")
    total = int(total)
    glyph, _ = step_meta(done)
    display_num = f"{done:02d}{suffix}"

    header = Text()
    header.append(f" {glyph} ", style=f"bold {REF}")
    header.append(f"WAYPOINT {display_num}/{total:02d}", style=f"bold {PHOS}")
    header.append(f"  {title}", style=f"bold {READOUT}")
    header.append(f"   [{mode} t={elapsed:.1f}s]", style=LABEL)
    sub = Text()
    sub.append_text(_route_rail(done, total))

    soc.print()
    soc.print(Panel(header, subtitle=sub, subtitle_align="left",
                    border_style=REF if done else PHOS_DIM, box=_box(), padding=(0, 2)))

    # A single quick SWEEP raster across the incoming bezel (tty only, ≤300ms)
    if _tty():
        w = min(_cols() - 8, 54)
        with Live(console=soc, refresh_per_second=30, transient=True) as live:
            for head in range(0, w + 6, 3):
                bar = Text("  ")
                for x in range(w):
                    d = head - x
                    if 0 <= d <= 8:
                        bar.append("▀", style=sweep_trail_color(d, 8))
                    else:
                        bar.append("▔", style=PHOS_DIM)
                live.update(bar)
                time.sleep(0.01)


def render_waypoint_advance(step_num, total, title, elapsed=0.0, mode="SCAN"):
    render_step(step_num, total, title, elapsed, mode)


# ══════════════════════════════════════════════════════════════════════════
#  PPI RADAR — the reusable "actively hunting" scanning motif
# ══════════════════════════════════════════════════════════════════════════
def render_ppi_radar(sweep_deg=0.0, contacts=None, console=None, static=False):
    """One frame of the braille plan-position-indicator. contacts: list of
    (bearing_deg, range_0_1, 'target'|'benign')."""
    c = console or soc
    cw, ch = 26, 12
    cv = HUDCanvas(cw, ch)
    cx, cy = cv.px / 2, cv.py / 2
    r = min(cx, cy) - 2
    # range rings
    for ang in range(0, 360, 5):
        a = math.radians(ang)
        for rr in (r, r * 0.66, r * 0.33):
            cv.plot(cx + rr * math.cos(a), cy + rr * math.sin(a), PHOS_DIM)
    cv.line(cx - r, cy, cx + r, cy, PHOS_DIM)
    cv.line(cx, cy - r, cx, cy + r, PHOS_DIM)
    # SWEEP arm + decaying tail
    for k in range(5):
        a = math.radians(sweep_deg - k * 7)
        cv.line(cx, cy, cx + r * math.cos(a), cy + r * math.sin(a), sweep_trail_color(k * 2, 10))
    # contacts
    for brg, rng, kind in (contacts or []):
        a = math.radians(brg)
        col = TGT if kind == "target" else PHOS
        bx, by = cx + r * rng * math.cos(a), cy + r * rng * math.sin(a)
        cv.plot(bx, by, col); cv.plot(bx + 1, by, col)

    n = len(contacts or [])
    read = Text()
    read.append(f"  BRG {int(sweep_deg) % 360:03d}°", style=LABEL)
    read.append("  ·  ", style=PHOS_DIM)
    read.append("RNG 0.42", style=LABEL)
    read.append("  ·  ", style=PHOS_DIM)
    read.append(f"CONTACTS {n:02d}", style=TGT if any(k == 'target' for *_, k in (contacts or [])) else PHOS)
    body = Text()
    body.append_text(cv.to_text())
    body.append("\n")
    body.append_text(read)
    c.print(Panel(body, title=Text("PPI · ACTIVE SWEEP", style=f"bold {REF}"),
                  title_align="left", border_style=PHOS_DIM, box=_box(c), padding=(0, 1)))


def render_radar_scan(duration=1.6, contacts=None, console=None):
    """Animate the PPI for `duration` seconds. Non-TTY: one static frame."""
    c = console or soc
    contacts = contacts or [(217, 0.55, "target"), (44, 0.4, "benign"), (120, 0.7, "benign")]
    if not _tty(c):
        render_ppi_radar(217, contacts, console=c)
        return
    steps = max(int(duration / 0.066), 1)
    with Live(console=c, refresh_per_second=15, transient=False) as live:
        for i in range(steps):
            deg = (i * 24) % 360
            cw, ch = 26, 12
            cv = HUDCanvas(cw, ch)
            cx, cy = cv.px / 2, cv.py / 2
            r = min(cx, cy) - 2
            for ang in range(0, 360, 6):
                a = math.radians(ang)
                for rr in (r, r * 0.66, r * 0.33):
                    cv.plot(cx + rr * math.cos(a), cy + rr * math.sin(a), PHOS_DIM)
            cv.line(cx - r, cy, cx + r, cy, PHOS_DIM)
            cv.line(cx, cy - r, cx, cy + r, PHOS_DIM)
            for k in range(6):
                a = math.radians(deg - k * 7)
                cv.line(cx, cy, cx + r * math.cos(a), cy + r * math.sin(a), sweep_trail_color(k * 2, 12))
            for brg, rng, kind in contacts:
                a = math.radians(brg)
                col = TGT if kind == "target" else PHOS
                bx, by = cx + r * rng * math.cos(a), cy + r * rng * math.sin(a)
                cv.plot(bx, by, col); cv.plot(bx + 1, by, col)
            live.update(Panel(cv.to_text(), title=Text("PPI · ACTIVE SWEEP", style=f"bold {REF}"),
                              title_align="left", border_style=PHOS_DIM, box=_box(c), padding=(0, 1)))
            time.sleep(0.066)


# ══════════════════════════════════════════════════════════════════════════
#  COMMAND DECK — the persistent two-line HUD deck for the REPL
# ══════════════════════════════════════════════════════════════════════════
def _defcon_style(level):
    return {5: PHOS, 4: PHOS, 3: CAUT, 2: WARN, 1: WARN}.get(level, PHOS)


def render_command_deck(session=None, console=None):
    """Print the status rail (line 1). The armed caret (line 2) is supplied by
    deck_prompt() as the readline prompt so it never fights the cursor."""
    s = session or {}
    c = console or soc
    defcon = int(s.get("defcon", 5))
    thrt_c = int(s.get("crit", 0)); thrt_h = int(s.get("high", 0))
    wpn = s.get("wpn", "SAFE")
    posture = s.get("posture", "SYS NOMINAL")
    gen = s.get("genome", "⟳v14")
    bpm = int(s.get("bpm", 68))

    wide = _cols(c) >= 96          # room for GENOME + live EKG segments
    rail = Text("  ")
    def sep():
        rail.append(" ╶╌╴ ", style=PHOS_DIM)
    rail.append("╾╴ ", style=PHOS_DIM)
    rail.append(posture, style=PHOS if defcon >= 4 else CAUT)
    sep()
    rail.append("THRT ", style=LABEL)
    rail.append("▲", style=WARN if thrt_c else LABEL)
    rail.append(f"{thrt_c:02d} ", style=WARN if thrt_c else LABEL)
    rail.append("●", style=WARN if thrt_h else LABEL)
    rail.append(f"{thrt_h:02d}", style=WARN if thrt_h else LABEL)
    if wide:
        sep()
        rail.append("GENOME ", style=LABEL)
        rail.append(gen, style=REF)
        sep()
        rail.append_text(_ekg_strip("arrhythmia" if defcon <= 2 else "stress" if defcon == 3 else "calm", 8))
        rail.append(f" {bpm}", style=PHOS if defcon >= 4 else CAUT)
    sep()
    rail.append("DEFCON ", style=LABEL)
    rail.append(f"▊{defcon}", style=f"bold {_defcon_style(defcon)}")
    sep()
    rail.append("WPN ", style=LABEL)
    wpn_style = {"SAFE": LABEL, "ARMED": CAUT, "HOT": f"bold reverse {WARN}"}.get(wpn, LABEL)
    rail.append(f" {wpn} " if wpn == "HOT" else wpn, style=wpn_style)
    c.print(rail)


def _fg(hex):
    r, g, b = _h2r(hex)
    return f"\033[38;2;{r};{g};{b}m"


_ANSI_RST = "\033[0m"


def deck_prompt(session=None):
    """readline-safe armed-caret prompt (line 2). ANSI wrapped in \\001..\\002
    so cursor/column math stays correct on long input. Prefixed with the
    left wall of the input field opened by deck_input_box_top()."""
    s = session or {}
    caret, ccol = {"idle": ("⊕", PHOS), "executing": ("⌖", REF),
                   "locked": ("◈", TGT)}.get(s.get("caret", "idle"), ("⊕", PHOS))

    def rl(seq):
        return "\001" + seq + "\002"

    # _tty() alone only covers the non-interactive case (piped/redirected).
    # This prompt is hand-built raw 24-bit-truecolor ANSI (bypassing Rich's
    # own colorama-backed Windows-compat layer entirely, since it's fed
    # straight to readline/input() rather than printed through a Console)
    # — on an interactive but legacy Windows terminal (isatty() True, no
    # native VT processing), those escapes render as literal garbage
    # instead of a colored caret. _ascii_mode() catches that case too.
    if not _tty() or _ascii_mode():
        return "cx > "
    return (rl(_fg(PHOS_DIM)) + "│ " + rl(_ANSI_RST)
            + rl(_fg(ccol)) + caret + " " + rl(_fg(READOUT)) + "cx "
            + rl(_fg(PHOS)) + "▸ " + rl(_ANSI_RST))


def deck_input_box_top(console=None):
    """Top wall of the boxed input field — printed just above the prompt so
    typing happens visually 'inside' a field, not bare on the rail. Paired
    with deck_input_box_bottom() after the line is submitted; the right
    wall is intentionally not drawn on the input line itself since plain
    readline can't keep a fixed-column border in sync with live typing."""
    c = console or soc
    if not _tty(c):
        return
    width = max(_cols(c), 20)
    l, mid, r = ("+", "-", "+") if _ascii_mode(c) else ("╭", "─", "╮")
    c.print(Text(l + mid * (width - 2) + r, style=PHOS_DIM))


def deck_input_box_bottom(console=None):
    """Bottom wall of the boxed input field — closes it once Enter (or
    Ctrl+C/Ctrl+D) ends the line, so command output renders below the box
    rather than inside it."""
    c = console or soc
    if not _tty(c):
        return
    width = max(_cols(c), 20)
    l, mid, r = ("+", "-", "+") if _ascii_mode(c) else ("╰", "─", "╯")
    c.print(Text(l + mid * (width - 2) + r, style=PHOS_DIM))


# ══════════════════════════════════════════════════════════════════════════
#  AGENT COMMAND CENTER
# ══════════════════════════════════════════════════════════════════════════
def render_agent_header(agent_id, name, objective):
    header = Text()
    header.append("  ▸ ", style=REF)
    header.append(f"[{agent_id}] ", style=f"bold {PHOS}")
    header.append(name, style=f"bold {REF}")
    header.append(f"\n  {objective}", style=LABEL)
    soc.print(Panel(header, border_style=PHOS_DIM, box=_box(), padding=(0, 1)))


def render_agent_result(agent, status, detail=""):
    glyph = {"ok": ("✓", PHOS), "warn": ("▲", CAUT)}.get(status, ("✗", WARN))
    soc.print(Text.assemble(("  " + glyph[0] + " ", glyph[1]),
                            (f"[{agent}] ", LABEL), (detail, READOUT)))


# ══════════════════════════════════════════════════════════════════════════
#  ROUTE / ENDPOINT DISCOVERY
# ══════════════════════════════════════════════════════════════════════════
def render_routes(routes, count=None):
    t = Table(box=_box(), border_style=PHOS_DIM, padding=(0, 1),
              title=Text.assemble(("SOURCE-ROUTE ACQUISITION ", f"bold {PHOS}"),
                                   (f"— {count or len(routes)} routes", LABEL)),
              title_justify="left")
    t.add_column("MTH", style=f"bold {REF}", width=6)
    t.add_column("PATH", style=READOUT, min_width=28)
    t.add_column("SRC", style=LABEL)
    t.add_column("PARAMS", style=TGT)
    for r in routes[:18]:
        params = ", ".join(r.get("params", [])[:3])
        t.add_row(r["method"], r["path"], r.get("source", ""), params or "—")
    soc.print(t)


def render_endpoint_tree(target_url, endpoints, vuln_paths=None):
    vuln_paths = vuln_paths or set()
    tree = Tree(Text(f"◈ {target_url}", style=f"bold {PHOS}"), guide_style=PHOS_DIM)
    groups = {}
    for ep in endpoints:
        path = ep.replace(target_url, "")
        parts = [p for p in path.split("/") if p]
        prefix = f"/{parts[0]}" if parts else "/"
        groups.setdefault(prefix, []).append(path)
    for prefix, paths in sorted(groups.items()):
        branch = tree.add(Text(prefix, style=f"bold {REF}"))
        for p in sorted(paths):
            sub = p.replace(prefix, "", 1).lstrip("/") or "/"
            risk = Text("▲ ", style=WARN) if p in vuln_paths else Text("● ", style=PHOS)
            branch.add(risk + Text(sub, style=READOUT))
    soc.print(Panel(tree, title=Text("ENDPOINT INTELLIGENCE MAP", style=f"bold {PHOS}"),
                    title_align="left", border_style=PHOS_DIM, box=_box(), padding=(0, 1)))


# ══════════════════════════════════════════════════════════════════════════
#  ATTACK GRAPH — DeepAgents exploit-chain sequencing
#  (backend.deepagents.attack_graph.AttackGraph — shared mutable state the
#  swarm writes to in real time; edges are already in discovery order, i.e.
#  the order one confirmed vuln unlocked the next.)
# ══════════════════════════════════════════════════════════════════════════
_CHAIN_PRIORITY = {
    "critical": (WARN,  "▲"),
    "high":     (WARN,  "●"),
    "medium":   (CAUT,  "◆"),
    "low":      (LABEL, "○"),
}


def render_attack_graph(attack_graph):
    """Render the exploit chain as a numbered, priority-ranked sequence —
    source ──action──▶ target — instead of a bare edge count."""
    nodes = getattr(attack_graph, "nodes", {}) or {}
    edges = getattr(attack_graph, "edges", []) or []
    if not nodes and not edges:
        return

    if edges:
        t = Table(box=_box(), border_style=PHOS_DIM, padding=(0, 1),
                  title=Text(f"⇋ ATTACK GRAPH — {len(edges)} chain(s) across {len(nodes)} node(s)",
                             style=f"bold {REF}"),
                  title_justify="left")
        t.add_column("#", style=LABEL, width=3)
        t.add_column("PRI", width=4, justify="center")
        t.add_column("EXPLOIT CHAIN (discovery order)", min_width=40, overflow="fold")
        for i, e in enumerate(edges, 1):
            col, pip = _CHAIN_PRIORITY.get(e.priority, (LABEL, "·"))
            chain = Text()
            chain.append(e.source or "?", style=READOUT)
            chain.append(f"  ──{(e.action or '').replace('_', ' ')}──▶  ", style=TGT)
            chain.append(e.target or "?", style=f"bold {REF}")
            t.add_row(str(i), Text(pip, style=col), chain)
        soc.print(t)
    else:
        soc.print(Text(f"  ⇋ {len(nodes)} node(s) touched — no chained exploitation discovered",
                       style=LABEL))

    creds = getattr(attack_graph, "confirmed_creds", []) or []
    tokens = getattr(attack_graph, "confirmed_tokens", []) or []
    priv = getattr(attack_graph, "privilege_level", "none") or "none"
    priv_color = WARN if priv == "admin" else CAUT if priv == "user" else PHOS
    line = Text("  PRIVILEGE ", style=LABEL)
    line.append(f"{priv.upper()}", style=f"bold {priv_color}")
    line.append("   │   ", style=PHOS_DIM)
    line.append("CREDS HARVESTED ", style=LABEL)
    line.append(f"{len(creds)}", style=WARN if creds else PHOS)
    line.append("   │   ", style=PHOS_DIM)
    line.append("TOKENS HARVESTED ", style=LABEL)
    line.append(f"{len(tokens)}", style=WARN if tokens else PHOS)
    soc.print(line)


# ══════════════════════════════════════════════════════════════════════════
#  KNOWLEDGE GRAPH — PageIndex-style Knowledge Tree, CWE-centered view
#  (backend.rag.knowledge_tree.KnowledgeTreeBuilder — code_tree + knowledge_tree
#  + cwe_index. The cwe_index IS the graph: each CWE hub links code sinks found
#  in THIS repo to the security-knowledge sections and fix strategies for it.)
# ══════════════════════════════════════════════════════════════════════════
def render_knowledge_graph(tree, cwe_index=None, max_hubs=10):
    """Render the CWE index as a hub-and-spoke graph: CWE ─▶ code location(s),
    CWE ─▶ knowledge-base section(s), CWE ─▶ fix strategy. This is the actual
    graph structure the patch prompt queries at CWE + file + line lookup time."""
    if not tree:
        return
    cwe_index = cwe_index or tree.get("_cwe_index") or {}
    children = tree.get("children", []) or []
    code_tree = next((c for c in children if c.get("type") == "code_tree"), {}) or {}
    knowledge_tree = next((c for c in children if c.get("type") == "knowledge_tree"), {}) or {}

    routes = [n for n in code_tree.get("children", []) if n.get("type") == "route"]
    sinks = [n for n in code_tree.get("children", []) if n.get("type") == "sink"]
    docs = knowledge_tree.get("children", []) or []

    head = Text()
    head.append("  ROUTES ", style=LABEL); head.append(f"{len(routes)}   ", style=READOUT)
    head.append("SINKS ", style=LABEL); head.append(f"{len(sinks)}   ", style=READOUT)
    head.append("KB DOCS ", style=LABEL); head.append(f"{len(docs)}   ", style=READOUT)
    head.append("│  ", style=PHOS_DIM)
    head.append("CWE HUBS ", style=LABEL); head.append(f"{len(cwe_index)}", style=f"bold {PHOS}")
    soc.print(Panel(head, title=Text("◈ KNOWLEDGE GRAPH — CWE ⟷ code ⟷ security KB", style=f"bold {PHOS}"),
                    title_align="left", border_style=PHOS_DIM, box=_box(), padding=(0, 1)))

    if not cwe_index:
        return

    # Rank hubs by how connected they are (edges = code + knowledge + fix nodes)
    # so the densest, most-actionable CWEs surface first — never a silent cap,
    # the footer names how many were left out.
    ranked = sorted(
        cwe_index.items(),
        key=lambda kv: len(kv[1].get("code_nodes", [])) + len(kv[1].get("knowledge_nodes", [])),
        reverse=True,
    )
    tree_view = Tree(Text("Cyphex Knowledge Tree", style=f"bold {PHOS}"), guide_style=PHOS_DIM)
    for cwe, idx in ranked[:max_hubs]:
        c_nodes = idx.get("code_nodes", [])
        k_nodes = idx.get("knowledge_nodes", [])
        strategies = idx.get("fix_strategies", [])
        hub = tree_view.add(Text(f"⊙ {cwe}", style=f"bold {REF}"))
        for cn in c_nodes[:4]:
            loc = f"{cn.get('file', '?')}:{cn.get('line', 0)}"
            hub.add(Text(f"◈ code      ──▶  {loc}", style=READOUT))
        for kn in k_nodes[:3]:
            hub.add(Text(f"◈ knowledge ──▶  {kn.get('title', '')[:52]}", style=CAUT))
        if strategies:
            names = ", ".join(s.get("name", "fix") for s in strategies[:3])
            hub.add(Text(f"◈ fix       ──▶  {names}", style=PHOS))
    if len(ranked) > max_hubs:
        tree_view.add(Text(f"… and {len(ranked) - max_hubs} more CWE hub(s)", style=LABEL))
    soc.print(Panel(tree_view, border_style=PHOS_DIM, box=_box(), padding=(0, 1)))


# ══════════════════════════════════════════════════════════════════════════
#  VULNERABILITY COMMAND CENTER
# ══════════════════════════════════════════════════════════════════════════
def _tally(vulns):
    crit = sum(1 for v in vulns if v.severity == "Critical")
    high = sum(1 for v in vulns if v.severity == "High")
    med  = sum(1 for v in vulns if v.severity == "Medium")
    low  = sum(1 for v in vulns if v.severity in ("Low", "Info"))
    return crit, high, med, low


def score_from_counts(crit, high, med, low):
    """Single source of truth for the 0-100 posture score.

    Thin re-export of scoring.score_from_counts() — the real implementation,
    constants, and the algebraic proof that an open Critical can't score
    SECURE/FAIR live in scoring.py, importable with zero third-party deps so
    every caller (report panel, before/after panel, final banner, and the
    ANSI no-rich fallback in cli_engine.py) can share this exact function
    instead of hand-copying the formula. That hand-copying is how the
    before/after panel and the banner drifted apart previously: a severity
    band cap (`if crit: score = min(score, 39)`) got bolted onto this
    function only, so two different post-patch vuln counts that both still
    had one open Critical collapsed to the identical displayed score,
    hiding real remediation progress. scoring.score_from_counts() replaces
    that clamp with weight constants that guarantee the same "no Critical
    can look SECURE/FAIR" property by construction, with no min()/if-based
    override and no plateau.
    """
    return _scoring_score_from_counts(crit, high, med, low)


# Back-compat alias for existing internal callers.
_score_from_counts = score_from_counts


def render_vulns(vulns, duration=0):
    crit, high, med, low = _tally(vulns)
    total = len(vulns)
    score = _score_from_counts(crit, high, med, low)
    color = score_color(score)

    head = Text()
    head.append("  THREAT BOARD   ", style=LABEL)
    head.append("▲ ", style=WARN); head.append(f"CRIT {crit:02d}   ", style=WARN)
    head.append("● ", style=WARN); head.append(f"HIGH {high:02d}   ", style=WARN if high else LABEL)
    head.append("◆ ", style=CAUT); head.append(f"MED {med:02d}   ", style=CAUT if med else LABEL)
    head.append("○ ", style=LABEL); head.append(f"LOW {low:02d}   ", style=LABEL)
    head.append("│  ", style=PHOS_DIM); head.append(f"TOTAL {total:02d}", style=READOUT)
    soc.print(Panel(head, border_style=color, box=_box(), padding=(0, 1),
                    title=Text("◈ TARGET ASSESSMENT", style=f"bold {color}"), title_align="left"))

    if not vulns:
        return score
    t = Table(box=_box(), border_style=PHOS_DIM, padding=(0, 1),
              title=Text(f"CONFIRMED CONTACTS ({total})", style=f"bold {PHOS}"),
              title_justify="left")
    t.add_column("#", style=LABEL, width=3)
    t.add_column("SEV", width=10)
    t.add_column("VULNERABILITY", min_width=28, style=READOUT)
    t.add_column("CWE", style=TGT, width=10)
    t.add_column("BEARING", style=LABEL)
    for i, v in enumerate(vulns, 1):
        st, pip = _sev_style(v.severity)
        t.add_row(str(i), Text(f"{pip} {v.severity}", style=st),
                  getattr(v, "title", None) or v.vuln_type, v.cwe or "—", v.endpoint or "")
    soc.print(t)
    return score


# ══════════════════════════════════════════════════════════════════════════
#  AI SECURITY COUNCIL  (+ TARGET LOCK on a confirmed critical)
# ══════════════════════════════════════════════════════════════════════════
def render_council_vote(finding, votes, critical=False):
    cards = []
    for model, approved, reason in votes:
        verdict = Text("◈ ACQUIRED", style=f"bold {TGT}") if approved else Text("○ CLEAR", style=PHOS)
        short = (reason or "")[:58]
        card = Panel(Text(short, style=LABEL),
                     title=Text(model, style=f"bold {REF}"), subtitle=verdict,
                     border_style=PHOS_DIM, box=_box(), width=26, padding=(0, 1))
        cards.append(card)
    confirmed = sum(1 for _, a, _ in votes if a)
    total = len(votes)
    soc.print(Columns(cards, padding=(0, 1)))
    bar_w = 20
    filled = int(confirmed / total * bar_w) if total else 0
    color = TGT if confirmed > total // 2 else PHOS
    bar = Text("  CONSENSUS ", style=LABEL)
    bar.append(f"{confirmed}/{total}  ", style=f"bold {color}")
    bar.append("█" * filled, style=color)
    bar.append("░" * (bar_w - filled), style=PHOS_DIM)
    bar.append(f"  {confirmed/total*100:.0f}%" if total else "", style=LABEL)
    soc.print(bar)

    if critical and confirmed > total // 2:
        render_target_lock(getattr(finding, "endpoint", "src"),
                           getattr(finding, "cwe", "CWE-???"),
                           getattr(finding, "vuln_type", "CRITICAL"))


def render_target_lock(bearing, cwe, kind, console=None):
    """THE novelty hook — a council-confirmed critical acquired like a bogey.
    Four TD brackets converge and snap shut. Non-TTY: the closed-lock frame."""
    c = console or soc
    solution = Text()
    solution.append(" ◆ TGT LOCK ", style=f"bold reverse {TGT}")
    solution.append("  BRG ", style=LABEL); solution.append(str(bearing), style=READOUT)
    solution.append("  ·  ", style=PHOS_DIM); solution.append(str(cwe), style=TGT)
    solution.append("  ·  ", style=PHOS_DIM)
    solution.append("SOL: PATCH ARMED", style=f"bold {PHOS}")

    if not _tty(c):
        c.print(Text("  ") + Text("◆", style=TGT) + solution)
        return

    stages = [("⌜", "⌝", "⌞", "⌟"), ("⌈", "⌉", "⌊", "⌋"), ("◆", "◆", "◆", "◆")]
    with Live(console=c, refresh_per_second=20, transient=True) as live:
        for tl, tr, bl, br in stages:
            frame = Text("\n  ")
            frame.append(f"{tl}      {tr}\n  ", style=f"bold {TGT}")
            frame.append("   ⌖   \n  ", style=f"bold {TGT}")
            frame.append(f"{bl}      {br}", style=f"bold {TGT}")
            live.update(Align.center(frame))
            time.sleep(0.08)
    c.print(Text("  ") + Text("◆ ", style=TGT) + solution)


def slam_defcon(level=1, console=None):
    """Whole-canopy escalation — hazard stripes wipe the frame on a critical.
    Non-TTY: one slammed static line."""
    c = console or soc
    if not _tty(c):
        c.print(Text("  ") + annunciator(f"DEFCON {level} · MASTER WARNING", "warning"))
        return
    w = min(_cols(c) - 4, 60)
    with Live(console=c, refresh_per_second=30, transient=True) as live:
        for head in range(0, w + 4, 4):
            stripes = Text("  ")
            for x in range(w):
                stripes.append("╱" if x <= head else " ",
                               style=WARN_HOT if x == head else WARN)
            live.update(stripes)
            time.sleep(0.02)
    c.print(Text("  ") + annunciator(f"DEFCON {level}", "warning")
            + Text("  ") + annunciator("MASTER WARNING", "warning"))


# ══════════════════════════════════════════════════════════════════════════
#  BEHAVIORAL GENOME
# ══════════════════════════════════════════════════════════════════════════
def render_genome(gen_count, block_history, endpoints=0, converged=False):
    content = Text()
    content.append("  GENERATION ", style=LABEL)
    content.append(f"{gen_count}", style=f"bold {PHOS}")
    content.append("    STATUS ", style=LABEL)
    if converged:
        content.append("CONVERGED ✓", style=f"bold {PHOS}")
    else:
        content.append("EVOLVING ⟳", style=CAUT)
    content.append("    ENDPOINTS ", style=LABEL)
    content.append(f"{endpoints}\n\n", style=READOUT)
    if block_history:
        first, last = block_history[0], block_history[-1]
        content.append("  BLOCK RATE ", style=LABEL)
        content.append(f"{first:.0f}%", style=CAUT)
        content.append(" → ", style=PHOS_DIM)
        content.append(f"{last:.0f}%\n  ", style=f"bold {PHOS}")
        for val in block_history:
            if val >= 95:   ch, col = "█", PHOS
            elif val >= 80: ch, col = "▆", REF
            elif val >= 60: ch, col = "▄", CAUT
            else:           ch, col = "▂", WARN
            content.append(ch, style=col)
    soc.print(Panel(content, title=Text("⟳ BEHAVIORAL GENOME", style=f"bold {PHOS}"),
                    title_align="left", border_style=PHOS_DIM, box=_box(), padding=(0, 1)))


# ══════════════════════════════════════════════════════════════════════════
#  ATTACK SIMULATION ARENA
# ══════════════════════════════════════════════════════════════════════════
def render_attacks(attacks_data, blocked=0, total_mal=0, fp=0):
    t = Table(box=_box(), border_style=PHOS_DIM, padding=(0, 1),
              title=Text("✦ ATTACK SIMULATION ARENA", style=f"bold {REF}"),
              title_justify="left")
    t.add_column("ATTACK", style=READOUT, min_width=16)
    t.add_column("PAYLOAD", max_width=24, style=LABEL)
    t.add_column("TYPE", justify="center", width=8)
    t.add_column("BEFORE", justify="center", width=9)
    t.add_column("AFTER", justify="center", width=9)
    t.add_column("SCORE", justify="right", width=6)
    type_colors = {"sqli": WARN, "xss": WARN, "cmdi": CAUT, "lfi": TGT,
                   "ssrf": REF, "benign": PHOS}
    for row in attacks_data:
        name, payload, ptype, before, after, sv = row
        tc = type_colors.get(ptype, LABEL)
        t.add_row(name, payload[:22], Text(ptype, style=tc), before, after, f"{sv:.3f}")
    soc.print(t)
    rate = (blocked / total_mal * 100) if total_mal else 0
    color = PHOS if rate >= 80 else CAUT if rate >= 50 else WARN
    line = Text("  DEFENSE RATE ", style=LABEL)
    line.append(f"{blocked}/{total_mal} ({rate:.0f}%)", style=f"bold {color}")
    line.append("   │   ", style=PHOS_DIM)
    line.append(f"FALSE POSITIVES {fp}", style=WARN if fp else PHOS)
    soc.print(line)


# ══════════════════════════════════════════════════════════════════════════
#  PATCH OPERATIONS CENTER
# ══════════════════════════════════════════════════════════════════════════
def render_patch_pipeline(generated, reviewed, approved, applied, verified):
    stages = [("GENERATED", generated), ("REVIEWED", reviewed), ("APPROVED", approved),
              ("APPLIED", applied), ("VERIFIED", verified)]
    cards = []
    for name, count in stages:
        col = PHOS if count > 0 else LABEL
        cards.append(Panel(Text.assemble((name + "\n", col), (str(count), f"bold {col}")),
                           border_style=PHOS_DIM, box=_box(), width=15))
    soc.print(Panel(Columns(cards), title=Text("✚ PATCH PIPELINE", style=f"bold {PHOS}"),
                    title_align="left", border_style=PHOS_DIM, box=_box(), padding=(0, 1)))


def render_patch_table(patches):
    t = Table(box=_box(), border_style=PHOS_DIM, padding=(0, 1),
              title=Text("PATCH RESULTS", style=f"bold {PHOS}"), title_justify="left")
    t.add_column("#", width=3, style=LABEL)
    t.add_column("VULNERABILITY", min_width=24, style=READOUT)
    t.add_column("CWE", width=9, style=TGT)
    t.add_column("METHOD", width=10)
    t.add_column("STATUS", width=10, justify="center")
    for i, (name, cwe, f, method, status) in enumerate(patches, 1):
        m_color = REF if method == "TEMPLATE" else TGT
        s_color = PHOS if status == "APPLIED" else WARN
        t.add_row(str(i), name, cwe, Text(method, style=m_color), Text(status, style=s_color))
    soc.print(t)


# ══════════════════════════════════════════════════════════════════════════
#  IMMUNE-SYSTEM BENCHMARK — detection metrics as a range-card readout
#  Consumes the report dict from cyphex_benchmark.run_benchmark().
# ══════════════════════════════════════════════════════════════════════════
def _rate_bar(rate, width=16):
    """A width-cell bar coloured by detection rate (rate in 0..1)."""
    filled = int(round(width * rate))
    col = score_color(rate * 100)
    t = Text()
    t.append("█" * filled, style=col)
    t.append("─" * (width - filled), style=PHOS_DIM)
    return t


def _sparkline(rates, width_per_point=4):
    """Inline trend line: one colored block per value (0-100), score-tiered."""
    t = Text()
    for i, r in enumerate(rates):
        if i:
            t.append(" ", style=LABEL)
        t.append(f"{r:>3.0f}", style=f"bold {score_color(r)}")
    return t


def render_benchmark(report, console=None):
    c = console or soc
    conf = report["confusion"]
    passed = report["gates"]["passed"]
    v_col = PHOS if passed else WARN
    v_lamp = "phosphor" if passed else "warning"

    body = Text()
    # ── header line ──
    body.append("  ", style=LABEL)
    body.append(report.get("corpus", "corpus"), style=f"bold {READOUT}")
    body.append("\n  ", style=LABEL)
    body.append(report.get("detector", "detector"), style=PHOS)
    ml = "ML+heuristic" if report.get("sklearn_active") else "heuristic-only"
    body.append(f"   ·  τ={report['threshold']}  ·  {ml}  ·  ", style=LABEL)
    body.append(f"{report['total']} samples", style=READOUT)
    body.append(f" ({report['attacks']} atk / {report['benign']} benign)  ·  ", style=LABEL)
    body.append(f"{report['per_sample_ms']} ms/sample", style=REF)
    body.append("\n\n")

    # ── confusion matrix ──
    body.append("                 BLOCKED    ALLOWED\n", style=LABEL)
    body.append("    ATTACK   ", style=f"bold {WARN}")
    body.append(f"  {conf['tp']:>5}    ", style=f"bold {PHOS}")
    body.append(f"  {conf['fn']:>5}", style=WARN if conf["fn"] else LABEL)
    body.append(f"    recall {report['recall']*100:5.1f}%\n", style=LABEL)
    body.append("    BENIGN   ", style=f"bold {REF}")
    body.append(f"  {conf['fp']:>5}    ", style=WARN if conf["fp"] else LABEL)
    body.append(f"  {conf['tn']:>5}", style=f"bold {PHOS}")
    body.append(f"    FPR    {report['fpr']*100:5.1f}%\n\n", style=LABEL)

    # ── metric tapes ──
    for name, key in (("PRECISION", "precision"), ("RECALL", "recall"),
                      ("F1 SCORE", "f1"), ("ACCURACY", "accuracy")):
        val = report[key] * 100
        body.append(f"  {name:<10} ", style=LABEL)
        body.append_text(_score_tape(val, width=32))
        body.append(f"  {val:5.1f}%\n", style=f"bold {score_color(val)}")
    body.append("\n")

    # ── per-class detection ──
    body.append("  PER-CLASS DETECTION\n", style=f"bold {PHOS}")
    for row in report["per_class"]:
        body.append(f"    {row['class']:<15}", style=READOUT)
        body.append(f"{row['detected']:>2}/{row['total']:<2}  ", style=LABEL)
        body.append_text(_rate_bar(row["rate"]))
        body.append(f"  {row['rate']*100:5.1f}%\n", style=score_color(row["rate"] * 100))

    # ── residual misses / false positives ──
    if report["misses"]:
        body.append("\n  RESIDUAL MISSES (attack allowed)\n", style=f"bold {WARN}")
        for m in report["misses"][:6]:
            body.append(f"    [{m['label']}] ", style=WARN)
            body.append(f"{m['payload'][:52]}", style=READOUT)
            body.append(f"  ({m['score']:.2f})\n", style=LABEL)
    if report["false_positives"]:
        body.append("\n  FALSE POSITIVES (benign blocked)\n", style=f"bold {CAUT}")
        for fp in report["false_positives"][:6]:
            body.append(f"    {fp['payload'][:56]}", style=READOUT)
            body.append(f"  ({fp['score']:.2f})\n", style=LABEL)

    # ── verdict ──
    body.append("\n  ")
    verdict = "GATE PASS" if passed else "GATE REVIEW"
    body.append_text(annunciator(verdict, v_lamp))
    body.append(f"   recall ≥ {report['gates']['min_recall']*100:.0f}%   "
                f"FPR ≤ {report['gates']['max_fpr']*100:.0f}%", style=LABEL)

    c.print(Panel(body, title=Text("◈ IMMUNE SYSTEM BENCHMARK", style=f"bold {v_col}"),
                  title_align="left", border_style=v_col, box=_box(c), padding=(0, 2)))


# ══════════════════════════════════════════════════════════════════════════
#  VERIFY GATE — maintainer health panel for backend/patch/verifier.py
#  Consumes the report dict from backend.patch.verify_health.get_verify_health().
#  Shows config (what it checks + what tooling that needs), status (how it has
#  performed durably, across every scan), and next steps — the three things a
#  maintainer needs to trust or fix the single most load-bearing guarantee in
#  the codebase: a patch only counts as "fixed" if it was actually proven.
# ══════════════════════════════════════════════════════════════════════════
def render_verify_health(report, console=None):
    c = console or soc
    verdicts = report["verdicts"]
    total = report["total_patches"]
    rate = report["durability_rate"]
    healthy = rate >= 70 and total > 0
    v_col = PHOS if healthy else (WARN if total else LABEL)
    v_lamp = "phosphor" if healthy else ("warning" if total else "reference")

    body = Text()

    # ── configuration ──
    body.append("  CONFIGURATION\n", style=f"bold {PHOS}")
    caps = report["config"]["blast_radius_caps"]
    body.append("    blast-radius cap   ", style=LABEL)
    body.append("  ".join(f"{sev} {n}" for sev, n in caps.items()), style=READOUT)
    body.append("\n    suppression guards ", style=LABEL)
    body.append(f"{report['config']['suppression_patterns_tracked']} patterns tracked "
                 "(nosemgrep, eslint-disable, # noqa, @ts-ignore, ...)", style=READOUT)
    body.append("\n\n    toolchain readiness — what each check depends on to run at all\n", style=LABEL)
    for name, info in report["config"]["toolchain"].items():
        lamp = PHOS if info["ok"] else WARN
        mark = "✓" if info["ok"] else "✗"
        body.append(f"      {mark} ", style=f"bold {lamp}")
        body.append(f"{name:<15}", style=READOUT)
        body.append(f"{info['version'][:40]:<42}", style=LABEL)
        body.append(f"gates: {info['gates']}\n", style=LABEL)

    if report.get("selftest"):
        body.append("\n    live self-test — actually drove each check, not just presence\n", style=LABEL)
        for name, info in report["selftest"].items():
            if info["ok"] is None:
                lamp, mark = LABEL, "·"
            else:
                lamp, mark = (PHOS, "✓") if info["ok"] else (WARN, "✗")
            body.append(f"      {mark} ", style=f"bold {lamp}")
            body.append(f"{name:<15}", style=READOUT)
            body.append(f"{info['detail'][:52]:<54}", style=LABEL)
            body.append(f"{info['duration_ms']}ms\n", style=LABEL)

    # ── status / health ──
    body.append("\n  STATUS\n", style=f"bold {PHOS}")
    body.append(f"    {report['manifests_found']} scan manifest(s)  ·  ", style=LABEL)
    body.append(f"{total} patch attempt(s) recorded\n", style=READOUT)
    if total:
        body.append("    ")
        body.append_text(_rate_bar(rate / 100, width=32))
        body.append(f"  {rate:5.1f}% durable-verified\n\n", style=f"bold {score_color(rate)}")

        body.append("    PASS ", style=f"bold {PHOS}")
        body.append(f"{verdicts.get('PASS', 0):>4}   ", style=READOUT)
        body.append("FAIL ", style=f"bold {WARN}")
        body.append(f"{verdicts.get('FAIL', 0):>4}   ", style=READOUT)
        body.append("UNVERIFIABLE ", style=f"bold {CAUT}")
        body.append(f"{verdicts.get('UNVERIFIABLE', 0):>4}\n", style=READOUT)

        reasons = report["reason_tally"]
        if reasons:
            body.append("\n    why (evidence key → count)\n", style=LABEL)
            for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:8]:
                body.append(f"      {reason:<22}{n}\n", style=READOUT)

        if report.get("cwe_breakdown"):
            body.append("\n    by CWE\n", style=LABEL)
            for row in report["cwe_breakdown"]:
                body.append(f"      {row['cwe']:<10}", style=TGT)
                body.append_text(_rate_bar(row["durability_rate"] / 100, width=16))
                body.append(f"  {row['durability_rate']:5.1f}%  ", style=f"bold {score_color(row['durability_rate'])}")
                body.append(f"(PASS {row['pass']} / FAIL {row['fail']} / UNVERIFIABLE {row['unverifiable']})\n",
                             style=LABEL)

        if report.get("trend") and len(report["trend"]) > 1:
            body.append("\n    trend — durability rate, oldest → newest scan\n", style=LABEL)
            body.append("      ")
            body.append_text(_sparkline([r["durability_rate"] for r in report["trend"]]))
            body.append("\n")

        if report["recent"]:
            body.append("\n    recent verifications\n", style=LABEL)
            for e in report["recent"][:6]:
                vd = e.get("verdict", "?")
                vcol = PHOS if vd == "PASS" else (WARN if vd == "FAIL" else CAUT)
                body.append(f"      {vd:<13}", style=f"bold {vcol}")
                body.append(f"{e.get('cwe', '?'):<9}", style=TGT)
                body.append(f"{e.get('file', '?')}:{e.get('line', '?')}\n", style=LABEL)
    else:
        body.append("    no patch history yet — run a scan with patching enabled\n", style=LABEL)

    # ── next steps ──
    body.append("\n  NEXT STEPS\n", style=f"bold {PHOS}")
    for step in report["next_steps"]:
        body.append("    → ", style=CAUT)
        body.append(f"{step}\n", style=READOUT)

    # ── verdict lamp ──
    body.append("\n  ")
    verdict_label = "GATE HEALTHY" if healthy else ("GATE DEGRADED" if total else "GATE UNUSED")
    body.append_text(annunciator(verdict_label, v_lamp))

    c.print(Panel(body, title=Text("⛨ VERIFY GATE — MAINTAINABILITY PANEL", style=f"bold {v_col}"),
                  title_align="left", border_style=v_col, box=_box(c), padding=(0, 2)))


# ══════════════════════════════════════════════════════════════════════════
#  SYSTEM OBSERVABILITY — unifies the event log (backend.observability) with
#  the Verify Gate report into one "is the pipeline healthy right now, and
#  what happened on the last scan" dashboard. Consumes the report dict from
#  backend.observability.health.get_system_health().
# ══════════════════════════════════════════════════════════════════════════
def render_observability(report, console=None):
    c = console or soc
    last = report.get("last_scan")
    errors = report.get("recent_errors") or []
    has_history = report["event_logs_found"] > 0
    healthy = has_history and last and last["completed"] and not errors
    v_col = PHOS if healthy else (WARN if (has_history and (not last or not last["completed"] or errors)) else LABEL)
    v_lamp = "phosphor" if healthy else ("warning" if has_history else "reference")

    body = Text()

    # ── event log ──
    body.append("  EVENT LOG\n", style=f"bold {PHOS}")
    body.append(f"    {report['event_logs_found']} scan(s) instrumented  ·  ", style=LABEL)
    body.append(f"{report['events_recorded']} event(s) recorded\n", style=READOUT)

    # ── last scan ──
    body.append("\n  LAST SCAN\n", style=f"bold {PHOS}")
    if last:
        body.append("    scan_id  ", style=LABEL)
        body.append(f"{last['scan_id']}\n", style=READOUT)
        state_col = PHOS if last["completed"] else WARN
        state = "COMPLETED" if last["completed"] else ("STARTED — no scan_end seen" if last["started"] else "UNKNOWN")
        body.append("    status   ", style=LABEL)
        body.append(f"{state}", style=f"bold {state_col}")
        if last["duration_s"] is not None:
            body.append(f"   ({last['duration_s']:.1f}s)", style=LABEL)
        body.append("\n")

        if last["phase_timings"]:
            body.append("\n    phase timings\n", style=LABEL)
            for p in last["phase_timings"]:
                body.append(f"      {str(p['title'])[:38]:<40}", style=READOUT)
                body.append(f"{p['duration_s']:>6.1f}s\n", style=LABEL)

        ag = last["agents"]
        ag_total = ag["succeeded"] + ag["timed_out"] + ag["errored"]
        if ag_total:
            body.append("\n    DeepAgents swarm   ", style=LABEL)
            body.append(f"{ag['succeeded']} ok", style=f"bold {PHOS}")
            body.append("  ·  ", style=LABEL)
            body.append(f"{ag['timed_out']} timed out", style=f"bold {CAUT}" if ag["timed_out"] else LABEL)
            body.append("  ·  ", style=LABEL)
            body.append(f"{ag['errored']} errored\n", style=f"bold {WARN}" if ag["errored"] else LABEL)

        cg = last["cognee"]
        if cg["recall_total"] or cg["persist_total"]:
            body.append("    cognee memory      ", style=LABEL)
            body.append(f"recall {cg['recall_ok']}/{cg['recall_total']}", style=READOUT)
            body.append("  ·  ", style=LABEL)
            body.append(f"persist {cg['persist_ok']}/{cg['persist_total']}\n", style=READOUT)

        if last["patch_verdicts"]:
            body.append("    patch verdicts     ", style=LABEL)
            body.append("  ".join(f"{k} {v}" for k, v in last["patch_verdicts"].items()), style=READOUT)
            body.append("\n")
    else:
        body.append("    no scan has been instrumented yet\n", style=LABEL)

    # ── recent errors ──
    if errors:
        body.append("\n  RECENT ERRORS\n", style=f"bold {WARN}")
        for e in errors[:6]:
            body.append(f"      {e.get('event', '?'):<24}", style=f"bold {WARN}")
            detail = e.get("error") or e.get("reason") or e.get("agent") or ""
            body.append(f"{str(detail)[:50]}\n", style=LABEL)

    # ── verify gate summary (embedded, one line) ──
    vg = report.get("verify_gate") or {}
    if vg.get("total_patches"):
        body.append("\n  VERIFY GATE   ", style=f"bold {PHOS}")
        body.append(f"{vg['durability_rate']:.1f}% durable-verified across {vg['total_patches']} patch attempt(s) "
                     "— see /verify for the full panel\n", style=READOUT)

    # ── next steps ──
    body.append("\n  NEXT STEPS\n", style=f"bold {PHOS}")
    for step in report["next_steps"]:
        body.append("    → ", style=CAUT)
        body.append(f"{step}\n", style=READOUT)

    # ── verdict lamp ──
    body.append("\n  ")
    verdict_label = "SYSTEM NOMINAL" if healthy else ("SYSTEM DEGRADED" if has_history else "NO TELEMETRY YET")
    body.append_text(annunciator(verdict_label, v_lamp))

    c.print(Panel(body, title=Text("◈ SYSTEM OBSERVABILITY", style=f"bold {v_col}"),
                  title_align="left", border_style=v_col, box=_box(c), padding=(0, 2)))


# ══════════════════════════════════════════════════════════════════════════
#  SCORE REVEAL — the cinematic finale (targeting solution + thermal cooldown)
#  Preserves render_final_banner(...) signature
# ══════════════════════════════════════════════════════════════════════════
def _score_tape(value, width=40):
    filled = int(width * value / 100)
    color = score_color(value)
    t = Text()
    for i in range(width):
        if i < filled:
            t.append("█", style=color)
        elif i == filled:
            t.append("◄", style=f"bold {color}")
        else:
            t.append("─", style=PHOS_DIM)
    return t


def _verdict(score):
    """Label + colour + tier for a score. Bands come from scoring.score_band()
    (the single source of truth for the 20/40/60/80 cutoffs) — this only
    attaches this theme's colour constant to the returned tier key."""
    label, tier = _scoring_band(score)
    return label, _TIER_COLOR[tier], tier


def render_score_reveal(score, crit, high, med, low, elapsed, scan_id,
                        patches_applied=0, patches_total=0, endpoints=0,
                        killed=None, unpatchable=0, console=None):
    c = console or soc
    label, color, lamp = _verdict(score)
    total = crit + high + med + low

    def board(shown, cool_val):
        cc = score_color(cool_val)
        body = Text()
        body.append("\n  COMPUTING SOLUTION\n\n" if shown < score else "\n  TARGETING SOLUTION LOCKED\n\n",
                    style=REF if shown < score else PHOS)
        body.append("  ⌈ ", style=f"bold {cc}")
        body.append(f"{shown:3d}", style=f"bold {cc}")
        body.append(" / 100 ⌉   ", style=cc)
        body.append(label if shown >= score else "····", style=f"bold {cc}")
        body.append("\n\n  ")
        body.append_text(_score_tape(cool_val))
        return body

    if not _tty(c):
        c.print(Panel(Align.center(board(score, score)),
                      title=Text("◈ INTERCEPT COMPLETE", style=f"bold {color}"),
                      border_style=color, box=_box(c), padding=(0, 2)))
    else:
        # dim / compute → odometer roll-up with thermal cool-down
        ticks = 26
        with Live(console=c, refresh_per_second=30, transient=True) as live:
            for i in range(ticks + 1):
                p = _ease_out(i / ticks)
                shown = int(score * p)
                live.update(Panel(Align.center(board(shown, shown)),
                                  title=Text("◈ COMPUTING INTERCEPT", style=f"bold {REF}"),
                                  border_style=score_color(shown), box=_box(c), padding=(0, 2)))
                time.sleep(0.03)
            # LOCK — one-time xenon apex flash
            flash = Text("\n  ")
            flash.append(f"⌈ {score:3d} / 100 ⌉", style=f"bold {APEX}")
            flash.append(f"   {label}\n\n  ", style=f"bold {APEX}")
            flash.append_text(_score_tape(score))
            live.update(Panel(Align.center(flash), title=Text("◈ SOLUTION LOCKED", style=f"bold {APEX}"),
                              border_style=APEX, box=_box(c), padding=(0, 2)))
            time.sleep(0.12)
        c.print(Panel(Align.center(board(score, score)),
                      title=Text("◈ INTERCEPT COMPLETE", style=f"bold {color}"),
                      border_style=color, box=_box(c), padding=(0, 2)))

    # verdict annunciator
    render_annunciator(label, lamp, console=c)

    # KILL BOARD
    t = Table(box=_box(c), border_style=PHOS_DIM, show_header=False, padding=(0, 2))
    t.add_column(style=LABEL, width=14)
    t.add_column(style=READOUT)
    # crit/high/med/low are the findings STILL OPEN after remediation. Printing
    # them under a "KILLS" label claimed the scan had killed them — the exact
    # opposite. Kills are the verified-remediated tally, reported separately.
    kc, kh, km, kl = killed or (0, 0, 0, 0)
    t.add_row("KILLS", Text.assemble(("▲", PHOS if kc else LABEL), (f"{kc:02d} ", PHOS if kc else LABEL),
              ("●", PHOS if kh else LABEL), (f"{kh:02d} ", PHOS if kh else LABEL),
              ("◆", PHOS if km else LABEL), (f"{km:02d} ", PHOS if km else LABEL),
              ("○", PHOS if kl else LABEL), (f"{kl:02d}", PHOS if kl else LABEL)))
    t.add_row("REMAINING", Text.assemble(("▲", WARN), (f"{crit:02d} ", WARN if crit else LABEL), ("●", WARN),
              (f"{high:02d} ", WARN if high else LABEL), ("◆", CAUT), (f"{med:02d} ", CAUT if med else LABEL),
              ("○", LABEL), (f"{low:02d}", LABEL)))
    _patches = Text.assemble((f"{patches_applied}", PHOS), (f"/{patches_total} APPLIED", LABEL))
    if unpatchable:
        # Runtime-only findings never reach the patch loop; leaving them out of
        # the denominator made "2/3 APPLIED" look like full coverage of 7 vulns.
        _patches.append(f"  ·  {unpatchable} NO SOURCE", style=CAUT)
    t.add_row("PATCHES", _patches)
    t.add_row("ENDPOINTS", Text(str(endpoints), style=READOUT))
    t.add_row("INTERCEPT", Text(f"{elapsed:.1f}s", style=REF))
    t.add_row("SCAN ID", Text(scan_id, style=PHOS))
    t.add_row("PIPELINE", Text("RAG · Council · Reasoning · Genome", style=TGT))
    c.print(t)
    c.print(Text("\n  cyphex", style=f"bold {PHOS}")
            + Text(f"  ·  Glass-Cockpit Cyber-Defense Interceptor  v{CX_VERSION}\n", style=LABEL))


def render_final_banner(score, crit, high, med, low, elapsed, scan_id,
                        patches_applied=0, patches_total=0, endpoints=0,
                        killed=None, unpatchable=0):
    render_score_reveal(score, crit, high, med, low, elapsed, scan_id,
                        patches_applied, patches_total, endpoints,
                        killed=killed, unpatchable=unpatchable)


# gradient bar kept for any legacy internal caller
def _gradient_bar(value, max_val, width=30):
    ratio = min(value / max_val, 1.0) if max_val else 0
    filled = int(ratio * width)
    color = score_color(int(ratio * 100))
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("─" * (width - filled), style=PHOS_DIM)
    return bar


def _sev_style(sev):
    """(color, glyph) for a severity name — ASCII-safe. The one place both
    SEV read sites in this module should go through, so a legacy Windows /
    dumb-terminal / non-UTF-8 stream never sees the geometric pips."""
    table = SEV_ASCII if _ascii_mode() else SEV
    return table.get(sev, table["Low"])
