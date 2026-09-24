"""
CYPHEX palette — BLOOD SIGNAL
════════════════════════════════════════════════════════════════════════════
The single source of truth for every colour the CLI paints. Dependency-free on
purpose: terminal_ui (Rich), cx.py's plain-ANSI fallback, deck_input's raw-mode
editor and mascot's no-Rich fallback all import it, so the values can never
drift between them again. They used to be hand-copied into five files with
"keep in sync by hand" comments, and they did drift.

Colour is assigned by PURPOSE, not by decoration. Blood red owns the brand and
the structure; every other hue is a signal and means exactly one thing, so a
block's colour tells you what kind of block it is before you read it:

    structure   blood     wordmark, panel titles, the frame itself
                clot      borders, rails, dividers (recessive, but visible)
    signal      ice       active / running / command names / section headers
                lilac     identifiers: CWE ids, scan ids, waypoint numbers
    severity    arterial  Critical findings, errors, FAIL, target lock
                ember     High findings, AT RISK
                amber     Medium findings, warnings, unmeasured / unknown
                slate     Low findings
    outcome     verified  PASS, healthy, secure, patched
    text        bone      readable prose and numerics
                ash       captions, timestamps, comments

The previous theme ran everything through one desaturated rose ramp, so a
passing gate and a failing one rendered in the same colour and severity rows
were separated by brightness steps too small to scan. Distinct hues fix that.

Contrast on VOID (WCAG ratio): blood 3.6 (bold / large use only), clot 2.2
(borders), arterial 5.5, every other text colour >= 5.8.

The legacy names (PHOS, REF, TGT...) are kept so ~700 renderer call sites
recolour by value change alone.
"""

VOID     = "#0b0708"   # background / negative space
PANEL    = "#1a1012"   # raised panel fill

# structure — the brand
PHOS     = "#d0142c"   # blood — wordmark, titles, structure
PHOS_DIM = "#8c1a2b"   # clot — borders, rails, dividers
WARN_HOT = "#ff6b7d"   # hot blood — brand-gradient peak, peak emphasis
APEX     = "#fff0f1"   # near-white flash — score lock, rare apex moments

# signal
REF      = "#5ec8e5"   # ice — active / running / commands / section headers
TGT      = "#b9a3ff"   # lilac — identifiers (CWE, scan id, waypoint number)

# severity (hue, not brightness, carries rank so rows scan at a glance)
WARN     = "#ff2e4c"   # arterial — Critical, errors, FAIL, target lock
HIGH     = "#ff7a3d"   # ember — High, AT RISK
CAUT     = "#f2b33d"   # amber — Medium, warnings, unknown / unmeasured
LOW      = "#7f9bc0"   # slate — Low

# outcome
OK       = "#3ddc97"   # verified — PASS, healthy, secure, patched

# mascot
CHASSIS  = "#3a3436"   # the buddy's dark-grey body (its ear), as in the sprite art

# text
READOUT  = "#e9e4df"   # bone — readable prose / numerics
LABEL    = "#8f8985"   # ash — captions, timestamps, comments


def rgb(hex_colour: str) -> tuple:
    h = hex_colour.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def fg(hex_colour: str) -> str:
    """24-bit truecolor foreground SGR for a palette hex."""
    return "\033[38;2;%d;%d;%dm" % rgb(hex_colour)


def bg(hex_colour: str) -> str:
    """24-bit truecolor background SGR for a palette hex."""
    return "\033[48;2;%d;%d;%dm" % rgb(hex_colour)


class ANSI:
    """Plain-escape colours for the non-Rich print paths (setup, daemon,
    GitHub hook, onboarder, legacy agents). The conventional names map to a
    ROLE, not to the literal colour: RED is the error/critical signal, GREEN
    is verified success. CYAN/CY stay the brand colour because every banner
    that uses them was written when cyan *was* the brand."""
    RED = R = fg(WARN)          # error / critical
    GREEN = G = fg(OK)          # success / verified
    YELLOW = Y = fg(CAUT)       # warning / medium
    BLUE = B = fg(LOW)          # info / low
    MAGENTA = M = fg(REF)       # active / high emphasis
    CYAN = CY = fg(PHOS)        # brand — banners, wordmark
    WHITE = W = fg(READOUT)     # prose
    GRAY = fg(LABEL)            # captions / timestamps
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = RST = "\033[0m"
