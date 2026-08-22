#!/usr/bin/env python3
"""
CYPHEX — Interactive CLI (cx)
Claude/Codex-style REPL with slash commands.

Usage:
    python3 cx.py              → drops into interactive session
    python3 cx.py scan         → quick full scan (prompts for path)
    python3 cx.py <target>     → auto-detect target and scan
"""
import asyncio
import os
import sys
import shutil
import subprocess
try:
    import readline
except ImportError:
    # readline is POSIX-only (GNU readline/libedit binding) — absent from
    # Windows CPython entirely. pyreadline3 is the Windows-compatible shim
    # (see pyproject.toml's win32-only dependency); if neither is available,
    # tab-completion/history are simply disabled rather than crashing the
    # whole interactive workspace at import time.
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None
import glob
import time
import textwrap

# ── UTF-8 everywhere ──────────────────────────────────────────────────────────
os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ── Load .env ─────────────────────────────────────────────────────────────────
def _load_env():
    env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env):
        with open(env, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))
_load_env()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend", "backend"))


# ── Rich boot UI (optional — falls back to plain ANSI banner if unavailable) ──
try:
    import terminal_ui as ui
    BOOT_UI = True
except ImportError:
    BOOT_UI = False

CX_VERSION = ui.CX_VERSION if BOOT_UI else "4.3"

# ── Boxed live input editor (optional — falls back to readline/input()) ──────
# deck_input owns the line editing itself (termios raw mode + hand-rolled key
# decoding) so ALL FOUR walls of the input field stay up WHILE the user types.
# Plain readline can only ever keep three up: it redraws the input line and
# clears to end-of-line on every edit, wiping anything painted at a fixed right
# column — see terminal_ui.deck_input_box_top()'s docstring for the long form.
#
# Guarded like readline and terminal_ui above, but on Exception rather than
# ImportError alone: a module that is present-but-broken (a bad edit, a partial
# install, a platform that trips its module-level probing) must degrade to
# today's readline behaviour, not take the whole interactive workspace down at
# import time. deck_input.supported() then makes the per-turn call.
try:
    import deck_input
    RAW_INPUT = True
except Exception:
    deck_input = None
    RAW_INPUT = False

# ── Terminal mascot (optional — _spinner() below just stays a plain line if
#    unavailable; no-ops itself on non-tty/NO_COLOR either way) ──────────────
try:
    import mascot
    MASCOT_UI = True
except ImportError:
    MASCOT_UI = False


def _boot_animation():
    """No-op. The workspace opens straight to the LEFT-aligned welcome box
    (Claude/Codex style) — no centered boot splash. Kept as a hook so a future
    opt-in animation can be re-enabled without touching the REPL."""
    return


def _show_header():
    """Repaint the persistent masthead — BORESIGHT canopy or ANSI fallback."""
    _clear()
    if BOOT_UI:
        try:
            ui.render_masthead()
            return
        except Exception:
            pass
    print(BANNER)


def _deck():
    """Print the persistent command-deck status rail (static snapshot per turn)."""
    if BOOT_UI:
        try:
            ui.render_command_deck(_session)
        except Exception:
            pass


def _repl_prompt():
    """readline-safe armed caret (BORESIGHT) or the plain fallback prompt."""
    if BOOT_UI:
        try:
            return ui.deck_prompt(_session)
        except Exception:
            pass
    return f"{C.CYAN}cx{C.RST}{C.GREY}>{C.RST} "


def _raw_input_live() -> bool:
    """True when deck_input's raw-mode editor will drive THIS turn's prompt.

    Asked ONCE per REPL turn and then threaded through every wall call below.
    That single decision is what keeps the box honest: the editor paints the
    whole three-row field itself (top wall, text row + right wall, bottom
    wall), so if each call site asked deck_input independently and the answers
    ever disagreed mid-turn — a console swapped, NO_COLOR set by a command,
    stdout no longer a tty — scrollback would keep a doubled top rule or an
    orphaned bottom rule forever. Either the editor draws all the walls or
    _input_box_top/_input_box_bottom do. Never a mix.
    """
    if not RAW_INPUT:
        return False
    try:
        return bool(deck_input.supported())
    except Exception:
        return False


def _input_box_top(raw: bool = False):
    """Open the bordered input field above the prompt (no-op in the plain
    ANSI fallback, or if rendering fails — never blocks the REPL).

    Also a no-op when the raw-mode editor is driving (raw=True): read_line()
    paints its own top wall, so a rule from here would simply be a second,
    duplicate one stacked above the field.
    """
    if raw:
        return
    if BOOT_UI:
        try:
            ui.deck_input_box_top()
        except Exception:
            pass


def _input_box_bottom(raw: bool = False):
    """Close the bordered input field after a line is submitted.

    No-op when the raw-mode editor is driving (raw=True): by the time
    read_line() returns, the editor has already painted the bottom wall and
    parked the cursor on the line below it — on Enter, on Ctrl+C and on
    Ctrl+D alike, since that happens in its teardown `finally` arm. Printing
    a rule here would strand a stray wall under a box that is already closed.
    """
    if raw:
        return
    if BOOT_UI:
        try:
            ui.deck_input_box_bottom()
        except Exception:
            pass


def _read_command(raw: bool = False) -> str:
    """Read one command line from the user.

    raw=True  → deck_input's raw-mode editor: a complete box while typing,
                with tab completion served by the same _completer readline
                uses, and Up/Down over this session's input history.
    raw=False → today's behaviour, byte for byte: input(_repl_prompt()).

    Both paths raise KeyboardInterrupt on Ctrl+C and EOFError on Ctrl+D at an
    empty line, and both return the line unstripped (the REPL strips), so the
    caller's existing arms need no special-casing.
    """
    if raw:
        try:
            return deck_input.read_line(_session, completer=_completer,
                                        history=_input_history)
        except (KeyboardInterrupt, EOFError):
            raise                     # the REPL's own arms own these
        except Exception:
            # The editor broke *after* opening its field. Its teardown has
            # already restored the tty and closed the box, so open a fresh
            # readline field for this one turn rather than leaving a bare
            # prompt hanging under a closed box — and close it on every exit
            # path here, because the REPL will skip its own bottom wall for
            # this turn (raw is nominally still True).
            _input_box_top(raw=False)
            try:
                return input(_repl_prompt())
            finally:
                _input_box_bottom(raw=False)
    return input(_repl_prompt())


def _goodbye():
    if BOOT_UI:
        try:
            ui.soc.print(f"\n  [{ui.REF}]◈[/] [{ui.PHOS}]CYPHEX offline · canopy dark.[/]\n")
            return
        except Exception:
            pass
    print(f"\n  {C.CYAN}Goodbye.{C.RST}\n")


def _print_help():
    if BOOT_UI:
        try:
            ui.render_help()
            return
        except Exception:
            pass
    print(QUICK_HELP)


# ── Colours ── plain-ANSI fallback palette · MONO SIGNAL RED brand ───────────
# Only used when terminal_ui / rich is unavailable. Mirrors terminal_ui.py's
# single-hue red ramp so the degraded banner stays on-brand. RED/YEL keep their
# names as the alert channel, but their VALUES now sit inside the red ramp —
# a literal red error mark on a red theme reads as body text, so severity is
# carried by brightness here exactly as it is in terminal_ui.py.
#
# The alert marks take the TOP two rungs (APEX for ✗, WARN_HOT for ⚠) plus
# bold, so the channel is strictly brighter than everything it has to be
# distinguished from. Placing them mid-ramp does not work: at CAUT the warning
# mark lands at the same luminance as the muted caption grey (0.172 vs 0.168),
# and at REF the error mark is byte-identical to NEON, so a failure renders
# exactly like a command name. Severity ordering here is now strictly
# monotonic — captions < body < emphasis < warning < error.
#
# These are raw 24-bit truecolor escapes with no Rich/colorama translation —
# this class exists specifically for the case where rich itself failed to
# import, so it can't lean on Console's own Windows-compat layer the way the
# normal path does. On legacy Windows without native VT processing they'd
# render as literal escape garbage; colorama enables VT mode where it can
# and strips them where it can't, degrading to plain uncolored text instead.
try:
    import colorama
    colorama.init(autoreset=False)
except ImportError:
    pass


C_BOLD = "\033[1m"


def _tc(hex_):
    r, g, b = (int(hex_[i:i + 2], 16) for i in (1, 3, 5))
    return f"\033[38;2;{r};{g};{b}m"

class C:
    CYAN   = _tc("#D95E62")   # PRIMARY red — wordmark / accents / active
    NEON   = _tc("#E18E91")   # bright red — command names / high emphasis
    # Alert channel. Both marks are BOLD, which the rest of the palette is
    # not, because this path has none of the structure Rich gives the normal
    # one — no panels, no rules, no styled headings. A bare ⚠ or ✗ sits in a
    # line of plain terminal text and has to carry its own emphasis, so weight
    # does the work hue can't in a single-hue theme.
    #
    # Bold on the error mark also mirrors terminal_ui's "err": bold WARN. Colour
    # alone cannot separate it there either: WARN and REF are the same value, so
    # without the weight an error renders identically to ordinary high-emphasis
    # text (which is exactly what this fallback did before).
    RED    = C_BOLD + _tc("#F4E4E1")  # APEX — error mark, peak of the ramp
    YEL    = C_BOLD + _tc("#EABCB8")  # WARN_HOT — warning mark, one rung below
    BLUE   = _tc("#D95E62")   # PRIMARY red
    GREY   = _tc("#8E7174")   # muted red-grey — captions / timestamps
    MAG    = _tc("#E18E91")   # bright red (legacy alias)
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RST    = "\033[0m"
    ITALIC = "\033[3m"
    UL     = "\033[4m"


# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
 ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝
██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝ 
██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗ 
╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗
 ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{C.RST}
{C.GREY}  Autonomous Cyber Defence · AI-Powered · Offline-First{C.RST}
{C.DIM}  Type {C.CYAN}/help{C.DIM} to see all commands · {C.CYAN}Tab{C.DIM} for autocomplete{C.RST}
"""

QUICK_HELP = f"""
{C.CYAN}{C.BOLD}Available Commands{C.RST}
{C.DIM}─────────────────────────────────────────────────────────────{C.RST}

  {C.NEON}/scan <target>{C.RST}     Scan a path or GitHub URL  (Static + DAST)
  {C.NEON}/deep <target>{C.RST}     Add the full DeepAgents attack swarm
  {C.NEON}/full <target>{C.RST}     DeepAgents + network sweep (everything)
     {C.GREY}flags:{C.RST} {C.DIM}--network  --deepagents  --full  --no-patch  --verbose{C.RST}
     {C.GREY}e.g.  {C.RST}{C.DIM}/scan ./vibemart --network --deepagents{C.RST}
     {C.GREY}      {C.RST}{C.DIM}--verbose shows full pipeline detail; default is concise phase summaries{C.RST}
  {C.NEON}/net [host]{C.RST}        Network discovery, or audit a specific host
  {C.NEON}/watch{C.RST}             Start the RASP auto-healing daemon
  {C.NEON}/setup{C.RST}             Install Semgrep, Nuclei; check Ollama & Docker
  {C.NEON}/doctor{C.RST}            Check all models, tools, and dependencies
  {C.NEON}/benchmark{C.RST}         Score the Immune System (precision/recall/F1)
  {C.NEON}/verify [path]{C.RST}     Verify Gate maintainability panel (config/status/health)
     {C.GREY}flags:{C.RST} {C.DIM}--selftest  --ci  --watch [secs]  --json out.json{C.RST}
  {C.NEON}/status [path]{C.RST}     System Observability — event log, last scan, agent/cognee health
     {C.GREY}flags:{C.RST} {C.DIM}--watch [secs]  --json out.json{C.RST}
  {C.NEON}/models{C.RST}            List available local Ollama models
  {C.NEON}/history{C.RST}           Show recent scans this session
  {C.NEON}/clear{C.RST}             Repaint the workspace
  {C.NEON}/exit{C.RST}  {C.NEON}/quit{C.RST}      Exit CYPHEX

{C.DIM}─────────────────────────────────────────────────────────────
  Tip: type a path, URL, or plain English — "scan my repo <link>",
       "run a full scan on ./app" — and press Enter{C.RST}
"""


# ── Readline autocomplete ──────────────────────────────────────────────────────
COMMANDS = [
    "/scan", "/deep", "/deepagents", "/full", "/net", "/netmap", "/netwatch",
    "/netaudit", "/watch", "/setup", "/benchmark", "/bench", "/verify", "/status", "/doctor",
    "/models", "/version", "/history", "/clear", "/exit", "/quit", "/help",
]

def _completer(text, state):
    options = [c for c in COMMANDS if c.startswith(text)]
    # Also complete file paths
    if text.startswith("/") and not any(text.startswith(c) for c in COMMANDS):
        options = glob.glob(text + "*")
    elif not text.startswith("/"):
        options += glob.glob(text + "*")
    if state < len(options):
        return options[state]
    return None

if readline:
    readline.set_completer(_completer)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n")


# ── Session state ─────────────────────────────────────────────────────────────
_session = {
    "last_path": None,
    "last_target": None,
    "history": [],
}

# Command lines typed at the REPL prompt, for the raw-mode editor's Up/Down.
# Deliberately NOT _session["history"], which holds scan-record dicts —
# deck_input.read_line() wants a plain list[str] and refuses to append to
# anything else. In memory for the life of the process only, exactly like
# readline's own history on the fallback path: nothing is written to disk.
_input_history: list[str] = []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clear():
    # Never clear when piped/redirected — it would spam escape codes into logs.
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")

def _spinner(msg: str):
    """Print a status line, with a brief animated mascot flourish alongside
    it — the mascot is fully stopped and erased again before this returns,
    so it never races the subprocess that _run_cyphex() spawns right after."""
    print(f"\n  {C.CYAN}◆{C.RST} {msg}")
    if MASCOT_UI:
        try:
            mascot.thinking(msg, flourish=True)
        except Exception:
            pass

def _ok(msg: str):
    print(f"  {C.NEON}✓{C.RST} {msg}")

def _warn(msg: str):
    print(f"  {C.YEL}⚠{C.RST} {msg}")

def _err(msg: str):
    print(f"  {C.RED}✗{C.RST} {msg}")

def _dim(msg: str):
    print(f"  {C.GREY}{msg}{C.RST}")

def _prompt_path(prompt_text: str = "Target path or URL") -> str:
    """Prompt the user for a path with tab completion."""
    try:
        val = input(f"  {C.CYAN}❯{C.RST} {C.BOLD}{prompt_text}:{C.RST} ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return ""
    return val

def _run_cyphex(args: list[str]):
    """Delegate to the existing cyphex_cli.py with the given args."""
    script = os.path.join(os.path.dirname(__file__), "cyphex_cli.py")
    cmd = [sys.executable, script] + args
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n  {C.YEL}[Scan interrupted]{C.RST}")

def _record_history(cmd: str, target: str):
    _session["history"].append({
        "time": time.strftime("%H:%M"),
        "cmd": cmd,
        "target": target,
    })


# ── Command handlers ───────────────────────────────────────────────────────────

def _cmd_scan(arg: str, deep: bool = False, network: bool = False):
    """Run a scan. Inline flags (any order, after the target):
         --network / -n        add the network security sweep
         --deep / --deepagents add the full DeepAgents attack swarm
         --full / --all        both of the above
         --no-patch            scan only, skip auto-patching
         --verbose             show full pipeline detail (per-payload DAST
                                narration, per-file SAST hits, patch-loop
                                internals) instead of concise phase summaries
    So `/scan ./app --network --deepagents` == the long cyphex_cli invocation.
    """
    import shlex
    no_patch = False
    verbose = False
    positional = []
    try:
        tokens = shlex.split(arg) if arg else []
    except ValueError:
        tokens = arg.split() if arg else []
    for t in tokens:
        tl = t.lower()
        if tl in ("--deep", "--deepagents", "--use-deepagents"):
            deep = True
        elif tl in ("--network", "--net", "-n"):
            network = True
        elif tl in ("--full", "--all"):
            deep = network = True
        elif tl in ("--no-patch", "--nopatch", "--scan-only"):
            no_patch = True
        elif tl in ("--verbose", "-v"):
            verbose = True
        elif t.startswith("-"):
            _dim(f"(ignoring unknown flag {t})")
        else:
            positional.append(t)
    target = " ".join(positional).strip()

    if not target:
        # Was anything scanned before? Offer it as default.
        default = _session.get("last_path") or _session.get("last_target")
        hint = f" [{C.GREY}{default}{C.RST}]" if default else ""
        target = _prompt_path(f"Path or GitHub URL{hint}")
        if not target:
            if default:
                target = default
            else:
                _err("No target specified.")
                return

    target = target.strip()

    # Build args
    scan_args = ["scan"]
    if target.startswith("http") and "github.com" in target:
        scan_args += ["--repo", target]
        _spinner(f"Cloning and scanning {C.CYAN}{target}{C.RST}")
    else:
        # Expand path
        expanded = os.path.expanduser(target)
        if not os.path.exists(expanded):
            _err(f"Path not found: {expanded}")
            return
        scan_args += ["--path", expanded]
        _spinner(f"Scanning {C.CYAN}{expanded}{C.RST}")

    if deep or network:
        scan_args += ["--network"]
    if deep:
        scan_args += ["--use-deepagents"]
    if no_patch:
        scan_args += ["--no-patch"]
    if verbose:
        scan_args += ["--verbose"]

    scan_args += ["--non-interactive"]

    bits = ["DeepAgents" if deep else "Static + DAST"]
    if network:
        bits.append("Network")
    if no_patch:
        bits.append("scan-only")
    if verbose:
        bits.append("verbose")
    _dim(f"Mode: {' + '.join(bits)}")
    print()

    _session["last_path"] = target
    _record_history("/deep" if deep else "/scan", target)
    _run_cyphex(scan_args)


def _cmd_net(arg: str):
    """Run a network scan / audit."""
    if arg:
        # Specific host — run netaudit
        _spinner(f"Running network audit on {C.CYAN}{arg}{C.RST}")
        _run_cyphex(["netaudit", "--host", arg, "--oracle"])
        _record_history("/net", arg)
    else:
        # Auto-detect subnet
        _spinner("Running network discovery on local subnet...")
        _run_cyphex(["netmap"])
        _record_history("/net", "local subnet")


def _cmd_doctor():
    _spinner("Running system health check...")
    _run_cyphex(["doctor"])


def _cmd_watch():
    _spinner("Starting RASP auto-healing daemon (Ctrl+C to stop)...")
    _run_cyphex(["watch"])


def _cmd_setup():
    """One-time setup — install/verify Semgrep, Nuclei, Ollama, Docker."""
    _spinner("Running one-time setup — installing optional security tools...")
    print()
    try:
        from cyphex.cli import _setup_tools
        _setup_tools()
    except Exception:
        # Fall back to a subprocess so setup still works if the package layout
        # differs (e.g. run straight from the repo without an editable install).
        try:
            subprocess.run([sys.executable, "-c",
                            "from cyphex.cli import _setup_tools; _setup_tools()"],
                           cwd=os.path.dirname(os.path.abspath(__file__)))
        except Exception as e:
            _err(f"Setup failed: {e}")
            _dim("Install manually: pip install semgrep · brew install nuclei · https://ollama.ai")


def _cmd_version():
    """Show the CYPHEX masthead + version."""
    _show_header()


def _cmd_benchmark(arg: str):
    """Benchmark the Immune System detector against a labelled corpus.

    Usage:  /benchmark [corpus.json|.csv] [--threshold 0.5] [--json out.json]
    Bundled corpus runs fully offline. Writes benchmark_report.json — the
    'measurable result' artifact for the submission.
    """
    import shlex
    data = threshold = json_out = None
    threshold = 0.5
    toks = shlex.split(arg) if arg else []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("--data", "-d") and i + 1 < len(toks):
            data = toks[i + 1]; i += 2
        elif t in ("--threshold", "-t") and i + 1 < len(toks):
            try: threshold = float(toks[i + 1])
            except ValueError: _warn(f"bad threshold '{toks[i+1]}', using 0.5")
            i += 2
        elif t in ("--json", "-o") and i + 1 < len(toks):
            json_out = toks[i + 1]; i += 2
        elif not t.startswith("-") and data is None:
            data = t; i += 1
        else:
            i += 1

    _spinner("Evaluating Immune System against labelled corpus...")
    try:
        import cyphex_benchmark as bench
        report, _ = bench.run_benchmark(data, threshold=threshold)
    except Exception as e:
        _err(f"Benchmark failed: {e}")
        return

    rendered = False
    if BOOT_UI:
        try:
            ui.render_benchmark(report); rendered = True
        except Exception:
            rendered = False
    if not rendered:
        try:
            import cyphex_benchmark as bench
            bench._print_plain(report)
        except Exception:
            pass

    out = json_out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_report.json")
    try:
        import json as _json
        with open(out, "w") as f:
            _json.dump(report, f, indent=2)
        _dim(f"Report written → {out}")
    except Exception:
        pass


def _render_verify_report(report):
    rendered = False
    if BOOT_UI:
        try:
            ui.render_verify_health(report); rendered = True
        except Exception:
            rendered = False
    if not rendered:
        from backend.patch.verify_health import print_plain
        print_plain(report)


def _cmd_verify(arg: str):
    """Verify Gate maintainability panel — config, status, and next steps.

    Usage:  /verify [path] [--json out.json] [--selftest] [--ci] [--watch [secs]]
    No path: sweeps every scan manifest CYPHEX has ever written
    (backend/sandboxes/*/.cyphex/patches.json). A path checks just that
    one directory's .cyphex/patches.json.

      --selftest   also live-drive each check (not just probe presence) —
                   proves the build/rescan/replay checks actually work
      --ci         print a machine-checkable PASS/DEGRADED/UNUSABLE verdict
                   and return a process exit code (0/1/2) for CI gating
      --watch [s]  keep re-reading and re-rendering every `s` seconds
                   (default 5) until Ctrl+C — requires an interactive TTY

    Returns the CI exit code (int) when --ci is passed, else None — callers
    that need process exit semantics (main()'s bare-CLI dispatch) check for
    an int return and sys.exit() on it themselves; the REPL ignores it.
    """
    import shlex
    path = json_out = None
    selftest = ci = watch = False
    watch_interval = 5.0
    toks = shlex.split(arg) if arg else []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("--json", "-o") and i + 1 < len(toks):
            json_out = toks[i + 1]; i += 2
        elif t == "--selftest":
            selftest = True; i += 1
        elif t == "--ci":
            ci = True; i += 1
        elif t == "--watch":
            watch = True
            if i + 1 < len(toks) and not toks[i + 1].startswith("-"):
                try:
                    watch_interval = max(1.0, float(toks[i + 1]))
                    i += 1
                except ValueError:
                    pass
            i += 1
        elif not t.startswith("-") and path is None:
            path = t; i += 1
        else:
            i += 1

    from backend.patch.verify_health import get_verify_health, compute_gate_exit_code

    if watch:
        if not sys.stdout.isatty():
            _warn("--watch needs an interactive terminal; showing a single snapshot instead.")
            watch = False
        else:
            try:
                while True:
                    _clear()
                    report = get_verify_health(path, include_selftest=selftest)
                    _render_verify_report(report)
                    _dim(f"Watching — refreshing every {watch_interval:g}s (Ctrl+C to stop)")
                    time.sleep(watch_interval)
            except KeyboardInterrupt:
                print()
                return None

    _spinner("Reading Verify Gate history..." + (" (live self-test...)" if selftest else ""))
    try:
        report = get_verify_health(path, include_selftest=selftest)
    except Exception as e:
        _err(f"Verify Gate panel failed: {e}")
        return 2 if ci else None

    _render_verify_report(report)

    if json_out:
        try:
            import json as _json
            with open(json_out, "w") as f:
                _json.dump(report, f, indent=2, default=str)
            _dim(f"Report written → {json_out}")
        except Exception:
            pass

    if ci:
        code = compute_gate_exit_code(report)
        label = {0: "PASS — gate healthy", 1: "DEGRADED", 2: "UNUSABLE"}[code]
        color = C.NEON if code == 0 else (C.YEL if code == 1 else C.RED)
        print(f"\n  {color}{C.BOLD}[CI] Verify Gate: {label} (exit {code}){C.RST}")
        return code
    return None


def _cmd_status(arg: str):
    """System Observability dashboard — event log, last scan, agent/cognee health, errors.

    Usage:  /status [path] [--json out.json] [--watch [secs]]
    No path: sweeps every scan CYPHEX has instrumented
    (backend/sandboxes/*/.cyphex/events.jsonl). A path checks just that one
    sandbox's event log.
    """
    import shlex
    path = json_out = None
    watch = False
    watch_interval = 5.0
    toks = shlex.split(arg) if arg else []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("--json", "-o") and i + 1 < len(toks):
            json_out = toks[i + 1]; i += 2
        elif t == "--watch":
            watch = True
            if i + 1 < len(toks) and not toks[i + 1].startswith("-"):
                try:
                    watch_interval = max(1.0, float(toks[i + 1]))
                    i += 1
                except ValueError:
                    pass
            i += 1
        elif not t.startswith("-") and path is None:
            path = t; i += 1
        else:
            i += 1

    def _render(report):
        rendered = False
        if BOOT_UI:
            try:
                ui.render_observability(report); rendered = True
            except Exception:
                rendered = False
        if not rendered:
            print(f"\n  CYPHEX System Observability")
            print(f"  {report['event_logs_found']} scan(s) instrumented, "
                  f"{report['events_recorded']} event(s) recorded")
            last = report.get("last_scan")
            if last:
                print(f"  last scan: {last['scan_id']}  completed={last['completed']}  "
                      f"duration={last['duration_s']}s")
            for step in report["next_steps"]:
                print(f"    -> {step}")
            print()

    from backend.observability.health import get_system_health

    if watch:
        if not sys.stdout.isatty():
            _warn("--watch needs an interactive terminal; showing a single snapshot instead.")
            watch = False
        else:
            try:
                while True:
                    _clear()
                    _render(get_system_health(path))
                    _dim(f"Watching — refreshing every {watch_interval:g}s (Ctrl+C to stop)")
                    time.sleep(watch_interval)
            except KeyboardInterrupt:
                print()
                return

    _spinner("Reading system observability...")
    try:
        report = get_system_health(path)
    except Exception as e:
        _err(f"Observability dashboard failed: {e}")
        return

    _render(report)

    if json_out:
        try:
            import json as _json
            with open(json_out, "w") as f:
                _json.dump(report, f, indent=2, default=str)
            _dim(f"Report written → {json_out}")
        except Exception:
            pass


def _cmd_models():
    """List available Ollama models."""
    print()
    try:
        import httpx
        r = httpx.get("http://localhost:11434/api/tags", timeout=5)
        models = r.json().get("models", [])
        if not models:
            _warn("No models found. Run: ollama pull llama3.1:8b")
            return
        print(f"  {C.CYAN}{C.BOLD}Available local models:{C.RST}")
        print(f"  {C.GREY}{'─' * 50}{C.RST}")
        for m in models:
            name  = m.get("name", "?")
            size  = m.get("size", 0)
            size_gb = f"{size / 1e9:.1f} GB" if size else ""
            print(f"  {C.NEON}●{C.RST} {C.BOLD}{name:<30}{C.RST}  {C.GREY}{size_gb}{C.RST}")
    except Exception as e:
        _err(f"Cannot reach Ollama: {e}")
        _dim("Start Ollama with: ollama serve")


def _cmd_history():
    if not _session["history"]:
        _dim("No scans in this session yet.")
        return
    print(f"\n  {C.CYAN}{C.BOLD}Scan history this session:{C.RST}")
    print(f"  {C.GREY}{'─' * 50}{C.RST}")
    for item in _session["history"][-10:]:
        print(f"  {C.GREY}{item['time']}{C.RST}  {C.NEON}{item['cmd']:<8}{C.RST}  {item['target']}")


def _auto_scan(raw: str):
    """
    User typed something that isn't a slash command.
    If it looks like a path or URL, scan it directly. Otherwise hand it to
    the natural-language router (nl_router.py, backed by local Ollama) —
    "run my repo <link>" becomes "/scan <link> --full" — so the workspace
    reads plain English the same way it always read slash commands.
    """
    raw = raw.strip()
    if not raw:
        return
    is_url  = raw.startswith("http")
    is_path = os.path.exists(os.path.expanduser(raw)) or raw.startswith("./") or raw.startswith("~/")
    if is_url or is_path:
        _cmd_scan(raw)
        return

    routed = _nl_route(raw)
    if routed:
        _dim(f"→ {routed}")
        _handle(routed)
        return

    _err(f"Unknown command or path not found: {C.BOLD}{raw}{C.RST}")
    _dim("Type /help to see available commands, or plain English like \"scan my repo <link>\".")


def _nl_route(raw: str) -> str | None:
    """Ask the local Ollama router (nl_router.py) to translate free text
    into a slash command. Fails silently (returns None) if Ollama isn't
    installed, isn't running, or refuses — the REPL then just falls back
    to the plain "unknown command" message, same as before this existed."""
    try:
        import nl_router
    except ImportError:
        return None
    _dim("interpreting…")
    return nl_router.translate(raw)


# ── Main REPL ─────────────────────────────────────────────────────────────────

def _handle(line: str):
    """Parse and dispatch one input line."""
    line = line.strip()
    if not line:
        return

    parts = line.split(None, 1)
    cmd   = parts[0].lower()
    arg   = parts[1] if len(parts) > 1 else ""

    match cmd:
        case "/help" | "help":
            _print_help()

        case "/scan":
            _cmd_scan(arg)

        case "/deep" | "/deepagents":
            _cmd_scan(arg, deep=True)

        case "/full":
            _cmd_scan(arg, deep=True, network=True)

        case "/net" | "/netmap":
            _cmd_net(arg)

        case "/netwatch":
            _spinner("Starting network anomaly monitor (Ctrl+C to stop)...")
            _run_cyphex(["netwatch"])

        case "/netaudit":
            host = arg or _prompt_path("Host IP to audit")
            if host:
                _run_cyphex(["netaudit", "--host", host, "--oracle"])

        case "/watch":
            _cmd_watch()

        case "/setup":
            _cmd_setup()

        case "/doctor":
            _cmd_doctor()

        case "/version":
            _cmd_version()

        case "/models":
            _cmd_models()

        case "/benchmark" | "/bench":
            _cmd_benchmark(arg)

        case "/verify":
            _cmd_verify(arg)

        case "/status":
            _cmd_status(arg)

        case "/history":
            _cmd_history()

        case "/clear" | "clear":
            _show_header()

        case "/exit" | "/quit" | "exit" | "quit":
            _goodbye()
            sys.exit(0)

        case _:
            _auto_scan(line)


def run_workspace():
    """Public entry point — drop straight into the interactive CYPHEX workspace.
    Called by the `cyphex` console-script (cyphex.cli) when no subcommand is
    given, so `cyphex` alone opens the workspace like `claude` / `codex`."""
    _repl()


def _repl():
    """Drop into the interactive REPL — BORESIGHT command deck."""
    _boot_animation()
    _show_header()

    while True:
        # Persistent deck: repaint the status rail before each prompt so posture
        # is always honest. Static snapshot per turn — the animated deck only
        # runs inside rich.Live during operations, never against readline.
        _deck()
        # ONE decision per turn, threaded through all four calls below: either
        # deck_input's editor paints the whole box (walls up while typing), or
        # _input_box_top/_input_box_bottom do (walls up after Enter). The
        # submitted field looks the same either way; only the live one differs.
        raw = _raw_input_live()
        _input_box_top(raw)
        try:
            line = _read_command(raw).strip()
        except KeyboardInterrupt:
            # Ctrl+C → new line, don't quit
            _input_box_bottom(raw)
            print()
            continue
        except EOFError:
            # Ctrl+D → quit
            _input_box_bottom(raw)
            _goodbye()
            break

        _input_box_bottom(raw)
        _handle(line)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    # If called with args, handle them directly then drop into REPL or exit
    if len(sys.argv) > 1:
        raw_arg = " ".join(sys.argv[1:])
        first   = sys.argv[1].lower()

        # cx --version / -v / version
        if first in ("--version", "-v", "version", "/version"):
            _boot_animation()
            _show_header()
            return

        # cx scan [path]        → /scan  (cli_engine paints its own hero)
        if first in ("scan", "/scan"):
            _clear()
            _cmd_scan(" ".join(sys.argv[2:]))
            return

        # cx deep [path]        → /deep
        if first in ("deep", "/deep"):
            _clear()
            _cmd_scan(" ".join(sys.argv[2:]), deep=True)
            return

        # cx net [host]
        if first in ("net", "/net", "netmap", "/netmap"):
            _show_header()
            _cmd_net(" ".join(sys.argv[2:]))
            return

        # cx doctor
        if first in ("doctor", "/doctor"):
            _show_header()
            _cmd_doctor()
            return

        # cx models
        if first in ("models", "/models"):
            _show_header()
            _cmd_models()
            return

        # cx benchmark [corpus] [--threshold x]
        if first in ("benchmark", "/benchmark", "bench", "/bench"):
            _show_header()
            _cmd_benchmark(" ".join(sys.argv[2:]))
            return

        # cx verify [path] [--json out.json] [--selftest] [--ci] [--watch [s]]
        if first in ("verify", "/verify"):
            _show_header()
            code = _cmd_verify(" ".join(sys.argv[2:]))
            if code is not None:
                sys.exit(code)
            return

        # cx status [path] [--json out.json] [--watch [s]]
        if first in ("status", "/status"):
            _show_header()
            _cmd_status(" ".join(sys.argv[2:]))
            return

        # cx <path/url> → auto-scan
        _clear()
        _cmd_scan(raw_arg)
        return

    # No args → interactive REPL
    _repl()


if __name__ == "__main__":
    main()
