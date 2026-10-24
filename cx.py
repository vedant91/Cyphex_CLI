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
import getpass
import os
import sys
import shlex
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

# Pinned footer (rail + input box + buddy), Claude-Code style. Only used when
# the raw-mode editor drives input; any other terminal keeps the inline box.
try:
    import footer_dock
except ImportError:
    footer_dock = None


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


def _dock_rail():
    if not BOOT_UI:
        return ""
    try:
        width = shutil.get_terminal_size().columns
        if footer_dock is not None:
            width -= footer_dock.GUTTER      # the buddy's antenna shares the row
        return ui.rail_ansi(_session, width)
    except Exception:
        return ""


def _dock_live(raw: bool) -> bool:
    """Pin the footer for this turn? Needs the raw editor (it is what paints
    the box at fixed rows) and a terminal footer_dock accepts. Released again
    if a turn ever runs without it, so a stale region can't outlive the box."""
    if footer_dock is None:
        return False
    try:
        if raw and footer_dock.reserve(_dock_rail()):
            return True
        footer_dock.release()
    except Exception:
        pass
    return False


def _echo_command(line: str):
    """The box is pinned, so the submitted line would vanish from history on
    the next turn — echo it into the transcript the way Claude Code does."""
    if not line:
        return
    if BOOT_UI:
        try:
            caret, ccol = ui.deck_caret(_session)
            ui.soc.print(f"[{ccol}]{caret}[/] [{ui.LABEL}]cx ▸[/] [{ui.READOUT}]{line}[/]",
                         markup=True, highlight=False)
            return
        except Exception:
            pass
    print(f"{C.GREY}> {line}{C.RST}")


def _read_command(raw: bool = False, anchor=None) -> str:
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
                                        history=_input_history, anchor=anchor,
                                        suggest=_suggest if anchor else None)
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


# ── Colours ── plain-ANSI fallback palette ──────────────────────────────────
# Only used when terminal_ui / rich is unavailable. Values come from
# ui_palette.py (dependency-free), the same roles terminal_ui uses, so the
# degraded banner cannot drift from the Rich one. The alert marks are also
# BOLD: this path has no panels or styled headings, so a bare ⚠ or ✗ in a
# line of plain text has to carry its own weight.
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


import ui_palette as _P

C_BOLD = "\033[1m"


_tc = _P.fg

class C:
    CYAN   = _tc(_P.PHOS)             # blood — wordmark / structure
    NEON   = _tc(_P.REF)              # ice — command names / active
    RED    = C_BOLD + _tc(_P.WARN)    # arterial — error mark
    YEL    = C_BOLD + _tc(_P.CAUT)    # amber — warning mark
    OK     = _tc(_P.OK)               # verified — success
    GREY   = _tc(_P.LABEL)            # ash — captions / timestamps
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
  {C.NEON}/verify <scan_id>{C.RST}  Open ONE recorded run — score, verdicts, full waypoint trace
  {C.NEON}/status [path]{C.RST}     System Observability — event log, last scan, agent/cognee health
     {C.GREY}flags:{C.RST} {C.DIM}--watch [secs]  --json out.json{C.RST}
  {C.NEON}/runs [N]{C.RST}          Recorded runs, newest first — status, score, verified
     {C.GREY}flags:{C.RST} {C.DIM}--json out.json{C.RST}
  {C.NEON}/models{C.RST}            List available local Ollama models
  {C.NEON}/history{C.RST}           Show recent scans this session
  {C.NEON}/clear{C.RST}             Repaint the workspace
  {C.NEON}/exit{C.RST}  {C.NEON}/quit{C.RST}      Exit CYPHEX

{C.DIM}─────────────────────────────────────────────────────────────
  Traceability: every scan records a goal + sub-steps per waypoint. The
  buddy beside the trace is a state indicator — its animation is bound to
  what the pipeline is doing. Replay any past run with /verify <scan_id>.
─────────────────────────────────────────────────────────────
  Tip: type a path, URL, or plain English — "scan my repo <link>",
       "run a full scan on ./app" — and press Enter{C.RST}
"""


# ── Readline autocomplete ──────────────────────────────────────────────────────
COMMANDS = [
    "/scan", "/deep", "/deepagents", "/full", "/net", "/netmap", "/netwatch",
    "/netaudit", "/watch", "/setup", "/benchmark", "/bench", "/verify", "/status", "/runs", "/doctor",
    "/models", "/llm", "/webhook", "/sheet", "/github", "/version", "/history", "/clear", "/exit", "/quit", "/help",
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

# ── "/" and "@" popup menus — the deck_input read_line(suggest=...) provider ──
# "/" at the start of the line lists commands (from terminal_ui.COMMAND_DECK,
# the same table /help renders); "@" anywhere, or the argument of a command
# that takes a path, lists files under the working directory.
_PATH_CMDS = {"/scan", "/deep", "/deepagents", "/full", "/verify", "/status",
              "/benchmark", "/bench"}
#: Never indexed for "@": VCS/tooling/dependency trees and scan sandboxes —
#: thousands of files nobody means to pick, and slow to walk.
_INDEX_SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__",
               ".mypy_cache", ".pytest_cache", "dist", "build", ".cyphex",
               ".claude", ".graphify", "graphify-out", "sandboxes", ".next"}
_INDEX_MAX = 5000          # entries; a bigger tree is still reachable by typing a dir/
_INDEX_BUDGET_S = 0.3      # wall-clock cap on one walk, so the popup never stalls
_INDEX_TTL_S = 30.0        # re-walk after this, so new files show up
_MENU_LIMIT = 50           # matches handed to the popup (it scrolls within them)
_index_cache = {"cwd": None, "at": 0.0, "items": []}


def _file_index():
    """Relative paths under cwd, breadth-first (shallow entries first, so the
    cap and the time budget cut the deep tail, not the top level); dirs end
    with "/"."""
    cwd = os.getcwd()
    now = time.monotonic()
    c = _index_cache
    if c["cwd"] == cwd and now - c["at"] < _INDEX_TTL_S:
        return c["items"]
    items, queue, deadline = [], [""], now + _INDEX_BUDGET_S
    while queue and len(items) < _INDEX_MAX and time.monotonic() < deadline:
        rel = queue.pop(0)
        try:
            entries = sorted(os.scandir(os.path.join(cwd, rel) if rel else cwd),
                             key=lambda e: e.name.lower())
        except OSError:
            continue
        for e in entries:
            if e.name.startswith("."):
                continue
            try:
                is_dir = e.is_dir()
            except OSError:
                continue
            if is_dir:
                if e.name in _INDEX_SKIP:
                    continue
                items.append(rel + e.name + "/")
                queue.append(rel + e.name + "/")
            else:
                items.append(rel + e.name)
    c.update(cwd=cwd, at=now, items=items)
    return items


def _subsequence(q, s):
    it = iter(s)
    return all(ch in it for ch in q)


def _path_items(q, at):
    """File suggestions for a partial path `q`. A path-like q ("src/", "./x",
    "~/Doc") lists that directory; a bare word fuzzy-searches the index."""
    Sug = deck_input.Suggestion
    if q == "" or "/" in q or q.startswith(("~", ".")):
        typed_dir = q[:len(q) - len(os.path.basename(q))]
        base = os.path.basename(q).lower()
        target = os.path.expanduser(typed_dir) or "."
        found = []
        try:
            for e in os.scandir(target):
                if e.name.startswith(".") and not base.startswith("."):
                    continue
                if not e.name.lower().startswith(base):
                    continue
                try:
                    is_dir = e.is_dir()
                except OSError:
                    continue
                if is_dir and e.name in _INDEX_SKIP and base != e.name.lower():
                    continue                  # still reachable by typing it in full
                found.append(typed_dir + e.name + ("/" if is_dir else ""))
                if len(found) >= 500:
                    break
        except OSError:
            return []
        paths = sorted(found, key=lambda p: (not p.endswith("/"), p.lower()))
    else:
        ql = q.lower()
        ranked = []
        for p in _file_index():
            name = os.path.basename(p.rstrip("/")).lower()
            pl = p.lower()
            if name.startswith(ql):
                rank = 0
            elif ql in name:
                rank = 1
            elif ql in pl:
                rank = 2
            elif _subsequence(ql, pl):
                rank = 3
            else:
                continue
            ranked.append((rank, len(p), p))
        paths = [p for _, _, p in sorted(ranked)]
    out = []
    for p in paths[:_MENU_LIMIT]:
        is_dir = p.endswith("/")
        final = shlex.quote(p) if any(ch.isspace() for ch in p) else p
        out.append(Sug(p, "directory" if is_dir else "file", final + " ",
                       False, (("@" if at else "") + p) if is_dir else None))
    return out


def _command_items(q):
    Sug = deck_input.Suggestion
    rows = getattr(ui, "COMMAND_DECK", None) if BOOT_UI else None
    if not rows:
        rows = [(c, "", "") for c in COMMANDS]
    ql = q.lower()
    ranked = []
    for i, (cmd, arg, desc) in enumerate(rows):
        if not cmd:
            continue                          # a "flags" note row, not a command
        if cmd.startswith(ql):
            rank = 0
        elif ql[1:] and ql[1:] in cmd:
            rank = 1
        elif len(ql) > 3 and ql[1:] in desc.lower():
            rank = 2                          # 3+ letters: fewer accidental hits
        else:
            continue
        alias = arg.startswith("/")            # e.g. /exit's "/quit"
        takes_arg = bool(arg) and not alias
        required = arg.startswith("<")
        label = cmd if not takes_arg else f"{cmd} {arg}"
        # A required argument inserts "cmd " and keeps editing (the file popup
        # opens for path commands); anything else runs on Enter.
        ranked.append((rank, i, Sug(label, desc + (f"  (also {arg})" if alias else ""),
                                    cmd + (" " if required else ""), not required,
                                    cmd + " " if takes_arg else None)))
    return [it for _, _, it in sorted(ranked, key=lambda r: (r[0], r[1]))]


def _suggest(text, pos):
    """deck_input suggest= provider: (start, end, [Suggestion]) or None."""
    before = text[:pos]
    if before.startswith("/") and not any(ch.isspace() for ch in before):
        end = len(text.split(None, 1)[0]) if text.strip() else pos
        return 0, max(end, pos), _command_items(before)
    start = max(before.rfind(" "), before.rfind("\t")) + 1
    nxt = text.find(" ", pos)
    end = len(text) if nxt < 0 else nxt
    token = text[start:pos]
    if token.startswith("@"):
        return start, end, _path_items(token[1:], at=True)
    first = before.split(None, 1)[0] if before.strip() else ""
    if (first.lower() in _PATH_CMDS and before[:start].strip() == first
            and not token.startswith("-")):
        return start, end, _path_items(token, at=False)
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
    if footer_dock is not None:
        # Static here; a scan child adopts the footer and animates it itself
        # (two processes animating the same rows would interleave paints).
        what = next((a for a in args if not a.startswith("-")), "")
        try:
            footer_dock.start_task(f"running {os.path.basename(what) or what}".strip(),
                                   state="working", animate=False)
        except Exception:
            pass
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

    # A positional that names a recorded run opens that run instead of being
    # treated as a target directory. Checked before the path interpretation
    # because a scan id (cli_5f055704, or just 5f055704) is never also a
    # directory the user meant to scope to — and drilling into one run is
    # the whole point of the run-history table listing them.
    if path and not os.path.isdir(os.path.expanduser(path)):
        try:
            from backend.observability.runs import get_run
            run = get_run(path)
        except Exception:
            run = None
        if run is not None:
            rendered = False
            if BOOT_UI:
                try:
                    ui.render_run_detail(run); rendered = True
                except Exception:
                    rendered = False
            if not rendered:
                d = run.as_dict()
                print(f"\n  RUN {d['scan_id']}  ({d['status']})")
                print(f"    target   {d.get('target') or '—'}")
                print(f"    duration {d.get('duration_s') or '—'}s")
                print(f"    score    {d.get('score') if d.get('score') is not None else '—'}")
                print(f"    verdicts {d.get('verdicts') or '—'}")
                for wp in d.get("waypoints", []):
                    print(f"    [{wp.get('status', '?')}] {wp.get('num')} {wp.get('title')}")
            if json_out:
                try:
                    import json as _json
                    with open(json_out, "w") as f:
                        _json.dump(run.as_dict(), f, indent=2, default=str)
                    _dim(f"Run written → {json_out}")
                except Exception:
                    pass
            return None
        _warn(f"No recorded run matches '{path}' — showing the full panel instead.")
        path = None

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
        color = C.OK if code == 0 else (C.YEL if code == 1 else C.RED)
        print(f"\n  {color}{C.BOLD}[CI] Verify Gate: {label} (exit {code}){C.RST}")
        return code
    return None


def _cmd_runs(arg: str):
    """Recorded scan runs, newest first.

    Usage:  /runs [N] [--json out.json]

    The history table the Verify Gate panel summarises. Each row is one
    recorded scan; pass a scan id to `/verify <id>` to open it in full.
    """
    import shlex
    limit, json_out = 12, None
    toks = shlex.split(arg) if arg else []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("--json", "-o") and i + 1 < len(toks):
            json_out = toks[i + 1]; i += 2
        elif t.isdigit():
            limit = max(1, int(t)); i += 1
        else:
            i += 1

    _spinner("Reading run history...")
    try:
        from backend.observability.runs import history_summary
        hist = history_summary(limit=limit)
    except Exception as e:
        _err(f"Run history failed: {e}")
        return

    runs = hist.get("runs") or []
    if not runs:
        _warn("No recorded runs yet — run a scan first.")
        return

    print()
    print(f"  {C.BOLD}{hist['total_runs']} run(s) recorded{C.RST}  "
          f"{C.GREY}·{C.RST} {C.NEON}{hist['completed']} completed{C.RST}  "
          f"{C.GREY}·{C.RST} {C.YEL}{hist['interrupted']} interrupted{C.RST}")
    reg = hist.get("regression")
    if reg:
        arrow = "v" if reg["regressed"] else ("^" if reg["delta"] > 0 else "=")
        col = C.RED if reg["regressed"] else (C.NEON if reg["delta"] > 0 else C.GREY)
        print(f"  latest vs previous: {col}{arrow} {reg['previous']} -> {reg['current']} "
              f"({reg['delta']:+d}){C.RST}")
    print(f"  {C.GREY}{'-' * 66}{C.RST}")
    print(f"  {C.GREY}{'scan':<12}{'took':<9}{'status':<14}{'score':<8}{'verified':<10}{C.RST}")
    for r in runs:
        sid = str(r.get("scan_id", "?")).replace("cli_", "")
        dur = r.get("duration_s")
        took = f"{dur:.0f}s" if isinstance(dur, (int, float)) else "-"
        st = r.get("status", "unknown")
        scol = C.NEON if st == "completed" else C.YEL
        score = r.get("score")
        vd = r.get("verdicts") or {}
        ver = f"{vd.get('PASS', 0)}/{sum(vd.values())}" if vd else "-"
        print(f"  {C.CYAN}{sid:<12}{C.RST}{C.GREY}{took:<9}{C.RST}"
              f"{scol}{st:<14}{C.RST}{str(score if score is not None else '-'):<8}{ver:<10}")
    print()
    _dim(f"Open one in full:  /verify {str(runs[0].get('scan_id','')).replace('cli_','')}")

    if json_out:
        try:
            import json as _json
            with open(json_out, "w") as f:
                _json.dump(hist, f, indent=2, default=str)
            _dim(f"History written -> {json_out}")
        except Exception:
            pass


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


def _notify():
    # Loaded by path: backend/backend/cyphex.py (on sys.path above) shadows the cyphex/ package here.
    import importlib.util
    if "cyphex_notify" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "cyphex_notify", os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyphex", "notify.py"))
        sys.modules["cyphex_notify"] = mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return sys.modules["cyphex_notify"]


def _sheets():
    # Loaded by path, same reason as _notify(): sys.path shadowing in this process.
    import importlib.util
    if "cyphex_sheets" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "cyphex_sheets", os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyphex", "sheets.py"))
        sys.modules["cyphex_sheets"] = mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return sys.modules["cyphex_sheets"]


def _cmd_sheet(arg: str):
    """Connect a Google Sheet (via a tiny Apps Script web app) so every
    attack attempt — endpoint, payload, outcome, why — appends live while a
    scan runs, same connection model as /webhook."""
    sh = _sheets()
    arg = arg.strip()

    if arg.lower() == "setup":
        secret = sh.start_setup()
        print(f"\n  {C.CYAN}{C.BOLD}Connect a Google Sheet{C.RST}")
        _dim("1. Open your sheet -> Extensions -> Apps Script.")
        _dim("2. Delete the placeholder code and paste this in its place:")
        print(f"\n{sh.setup_script(secret)}")
        _dim("3. Deploy -> New deployment -> type 'Web app' -> execute as Me, access Anyone.")
        _dim("4. Copy the web app URL (ends in /exec) and run:  /sheet <that url>")
        return

    if arg.lower().startswith("remove"):
        which = arg[6:].strip() or "all"
        n = sh.disconnect(which)
        _ok(f"Disconnected {n} sheet(s).") if n else _warn("Nothing to remove. Use /sheet to see the numbers.")
        return

    if not arg:
        conns = sh.saved()
        print(f"\n  {C.CYAN}{C.BOLD}Sheet connections{C.RST}")
        for i, c in enumerate(conns, 1):
            print(f"  {C.NEON}●{C.RST} {i}. {sh.label(c['url'])}  {C.GREY}connected{C.RST}")
        if not conns:
            _dim("Nothing connected yet. Run /sheet setup first, then /sheet <web-app-url>.")
        _dim("Remove:  /sheet remove [n|all]")
        return

    secret = sh.pending_secret()
    if not secret:
        _err("No secret on file — run /sheet setup first, then paste the URL it gives you.")
        return
    _spinner("Checking the sheet accepts rows…")
    res = sh.connect(arg, secret)
    if res["ok"]:
        sh.clear_pending()
        _ok(f"Connected to {res['label']}")
        _dim("Every tested endpoint, payload and outcome will now append there while a scan runs.")
    else:
        _err(res["error"])


def _cmd_webhook(arg: str):
    """Connect a Google Chat / Slack / Teams webhook so every scan reports to that space."""
    notify = _notify()
    arg = arg.strip()
    if arg.lower().startswith("remove"):
        which = arg[6:].strip() or "all"
        n = notify.disconnect(which)
        _ok(f"Disconnected {n} webhook(s).") if n else _warn("Nothing to remove. Use /webhook to see the numbers.")
        return
    if not arg:
        saved = notify.saved_urls()
        print(f"\n  {C.CYAN}{C.BOLD}Webhook connections{C.RST}")
        for i, u in enumerate(saved, 1):
            print(f"  {C.NEON}●{C.RST} {i}. {notify.label(u)}  {C.GREY}connected{C.RST}")
        if not saved:
            _dim("Nothing connected yet. Every scan notification goes to the spaces listed here.")
        _dim("Connect:  /webhook <link>   (or paste the link on its own)   ·   Remove:  /webhook remove [n|all]")
        return
    _spinner("Saying hello to your chat space…")
    res = notify.connect(arg)
    if res["ok"]:
        _ok(f"Connected to {res['label']}")
        _dim("Cyphex Buddy just said hello there. Scan updates, reports and PR approvals will now go to this space.")
    else:
        _err(res["error"])


def _verify_github_token(token: str) -> str:
    """The authenticated login name if `token` works against GitHub's API,
    else "". Best-effort — a network hiccup here must never block saving
    the token the user explicitly chose to enter."""
    try:
        import httpx
        r = httpx.get("https://api.github.com/user",
                      headers={"Authorization": f"Bearer {token}"}, timeout=8)
        if r.status_code == 200:
            return r.json().get("login", "") or ""
    except Exception:
        pass
    return ""


def _cmd_github(arg: str):
    """Check or connect GitHub auth. Needed for org-wide microservice
    discovery: point /deep at one repo and CYPHEX finds its sibling
    services elsewhere in the same GitHub org, automatically.

    Two independent ways in, pick whichever you actually have:
      /github login          — via the gh CLI (gh auth login)
      /github token [<pat>]  — paste a personal access token directly,
                                no gh required
      /github clear          — remove a token saved with /github token
    """
    from backend.services.github_discovery import (
        clear_saved_token, load_saved_token, resolve_github_token, save_token,
    )

    parts = arg.strip().split(None, 1)
    sub = parts[0].lower() if parts else ""
    rest = parts[1] if len(parts) > 1 else ""

    if sub == "login":
        if not shutil.which("gh"):
            _err("gh CLI not found.")
            _dim("Install it: https://cli.github.com — or use /github token instead.")
            return
        _spinner("Launching gh auth login — follow the prompts (browser or device code)…")
        try:
            subprocess.run(["gh", "auth", "login"])  # interactive: inherits this terminal
        except Exception as e:
            _err(f"gh auth login failed: {e}")
            return
        if resolve_github_token():
            _ok("Connected. /deep <repo-url> will now find its org siblings automatically.")
        else:
            _warn("Still no token found — run `gh auth status` to check what went wrong.")
        return

    if sub == "token":
        token = rest.strip()
        if not token:
            try:
                token = getpass.getpass("  Paste your GitHub token (hidden, not saved to shell history): ").strip()
            except Exception:
                _err("Couldn't read hidden input here — pass it inline instead: /github token <token>")
                return
        if not token:
            _warn("No token entered — nothing saved.")
            return
        _spinner("Checking the token against GitHub…")
        who = _verify_github_token(token)
        save_token(token)
        if who:
            _ok(f"Saved. Authenticated as {who}.")
        else:
            _warn("Saved, but GitHub didn't accept it just now — double-check it's valid and not expired.")
        _dim("/deep <repo-url> will now use it for org-wide sibling discovery.")
        return

    if sub == "clear":
        if clear_saved_token():
            _ok("Removed the saved token.")
        else:
            _dim("No token was saved with /github token — nothing to remove.")
        return

    print(f"\n  {C.CYAN}{C.BOLD}GitHub connection{C.RST}")
    if os.environ.get("GITHUB_TOKEN"):
        _ok("Using the GITHUB_TOKEN environment variable.")
    elif load_saved_token():
        _ok("Using a token saved via /github token.")
    elif resolve_github_token():
        _ok("Using gh CLI auth (gh auth login).")
    else:
        _warn("No GitHub token found.")
        _dim("Two ways in — pick whichever you have:")
        _dim("  /github login          — via the GitHub CLI (gh auth login)")
        _dim("  /github token <token>  — paste a personal access token, no gh required")
    _dim("")
    _dim("What this is for: point /deep at one microservice's repo and CYPHEX finds its")
    _dim("sibling services elsewhere in the same GitHub org, clones them, and scans the")
    _dim("whole group together. No token -> that repo is scanned alone, as normal.")


def _llm_provider():
    # Loaded by path (stdlib-only module), same reason as _notify(): sys.path shadowing in this process.
    import importlib.util
    if "cyphex_llm_provider" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "cyphex_llm_provider", os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend", "llm_provider.py"))
        sys.modules["cyphex_llm_provider"] = mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return sys.modules["cyphex_llm_provider"]


def _cmd_llm(arg: str):
    """Use your own OpenAI-compatible LLM (a hosted API or a self-hosted SLM) instead of local Ollama."""
    prov = _llm_provider()
    parts = arg.split()
    sub = parts[0].lower() if parts else ""

    if sub in ("local", "off", "clear", "remove"):
        _ok("Back to local Ollama.") if prov.clear() else _warn("No saved hosted LLM to remove.")
        if os.environ.get("CYPHEX_LLM_BASE_URL"):
            _warn("CYPHEX_LLM_* environment variables are still set and override this.")
        return

    cfg = prov.load()
    if not parts or sub == "status":
        print(f"\n  {C.CYAN}{C.BOLD}LLM provider{C.RST}")
        if prov.active():
            src = "environment" if os.environ.get("CYPHEX_LLM_BASE_URL") else "saved by /llm"
            print(f"  {C.NEON}●{C.RST} Hosted: {prov.label(cfg)}  {C.GREY}key {prov.mask(cfg.get('api_key', ''))} · {src}{C.RST}")
            if len(prov.all_models(cfg)) > 1:
                print(f"  {C.GREY}  council review also uses: {', '.join(prov.all_models(cfg)[1:])}{C.RST}")
        else:
            print(f"  {C.NEON}●{C.RST} Local Ollama {C.GREY}(default){C.RST}")
        _dim("Use your own:  /llm set   (or  /llm <base-url> <api-key> [model])   ·   Test:  /llm test   ·   Back to local:  /llm local")
        return

    if sub == "test":
        if not prov.active():
            return _warn("No hosted LLM configured. Use /llm set")
        res = prov.check(cfg["base_url"], cfg.get("api_key", ""), cfg["model"])
        _ok(f"Working: {prov.label(cfg)} replied '{res['reply']}'") if res["ok"] else _err(res["error"])
        return

    if sub == "set":
        parts = parts[1:]
    interactive = not parts
    try:
        import getpass
        url = parts[0] if parts else input("  Base URL (e.g. https://api.openai.com/v1): ").strip()
        key = parts[1] if len(parts) > 1 else getpass.getpass("  API key (hidden; Enter if the server needs none): ").strip()
        model = parts[2] if len(parts) > 2 else ""
    except (EOFError, KeyboardInterrupt):
        return _warn("Cancelled.")
    _spinner("Testing the connection…")
    res = prov.check(url, key, model)
    if not res["ok"]:
        return _err(res["error"])
    extra = []
    if interactive:
        try:
            if not model and len(res["models"]) > 1:
                print(f"  {C.GREY}Models: {', '.join(res['models'][:12])}{' …' if len(res['models']) > 12 else ''}{C.RST}")
                pick = input(f"  Model [Enter = {res['model']}]: ").strip()
                if pick and pick != res["model"]:
                    res = prov.check(url, key, pick)
                    if not res["ok"]:
                        return _err(res["error"])
            second = input("  Extra model for council review (optional, Enter to skip): ").strip()
            extra = [second] if second and second != res["model"] else []
        except (EOFError, KeyboardInterrupt):
            return _warn("Cancelled.")
    cfg = {"base_url": res["base_url"], "api_key": key, "model": res["model"], "extra_models": extra}
    prov.save(cfg)
    _ok(f"Connected: {prov.label(cfg)}  (key {prov.mask(key)})")
    _warn(f"Scans will now send code snippets and findings to {prov.label(cfg).split(' via ')[-1]}. "
          f"Use /llm local to go back to Ollama.")


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

        case "/llm":
            _cmd_llm(arg)

        case "/webhook" | "/webhooks":
            _cmd_webhook(arg)

        case "/sheet" | "/sheets":
            _cmd_sheet(arg)

        case "/github":
            _cmd_github(arg)

        case "/benchmark" | "/bench":
            _cmd_benchmark(arg)

        case "/verify":
            _cmd_verify(arg)

        case "/status":
            _cmd_status(arg)

        case "/runs":
            _cmd_runs(arg)

        case "/history":
            _cmd_history()

        case "/clear" | "clear":
            _show_header()

        case "/exit" | "/quit" | "exit" | "quit":
            _goodbye()
            sys.exit(0)

        case _:
            # A pasted chat-webhook link is a connection request, never a scan target.
            _cmd_webhook(line) if _notify().looks_like_webhook(line) else _auto_scan(line)


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
        # ONE decision per turn, threaded through all four calls below: either
        # deck_input's editor paints the whole box (walls up while typing), or
        # _input_box_top/_input_box_bottom do (walls up after Enter). The
        # submitted field looks the same either way; only the live one differs.
        raw = _raw_input_live()
        docked = _dock_live(raw)
        anchor = None
        if docked:
            # Pinned footer: rail + buddy + box live below the scroll region,
            # so output scrolls above them instead of carrying them away.
            try:
                anchor = footer_dock.begin_input(_dock_rail())
            except Exception:
                anchor = None
            if anchor is None:          # footer failed: this turn goes inline
                docked = False
                try:
                    footer_dock.release()
                except Exception:
                    pass
        if not docked:
            # Persistent deck: repaint the status rail before each prompt so
            # posture is always honest. Static snapshot per turn.
            _deck()
            _input_box_top(raw)
        try:
            line = _read_command(raw, anchor).strip()
        except KeyboardInterrupt:
            # Ctrl+C → new line, don't quit
            if docked:
                footer_dock.end_input()
            else:
                _input_box_bottom(raw)
                print()
            continue
        except EOFError:
            # Ctrl+D → quit
            if docked:
                footer_dock.end_input()
                footer_dock.release()
            else:
                _input_box_bottom(raw)
            _goodbye()
            break

        if docked:
            footer_dock.end_input()
            _echo_command(line)
        else:
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
