"""
CYPHEX Mascot Companion Window — opt-in macOS fallback
════════════════════════════════════════════════════════════════════════════
Product requirement this file implements, verbatim:

    "if cannot do on integrated terminal make a new terminal with our configs"

mascot.py's animated companion (see mascot.py) normally redraws itself
in place inside the CLI's OWN controlling terminal. Some environments can't
render that well (a dumb/non-ANSI terminal, a pane too small, a host that
mangles cursor-redraw escapes, etc.). For exactly that situation — and
ONLY when a caller has explicitly decided the integrated render is not an
option — this module can spawn a SEPARATE, dedicated terminal window on
macOS whose sole job is to host the mascot animation, driven by a small
polling loop script (mascot_companion_loop.py, next to this file).

THIS IS OPT-IN, NEVER AUTOMATIC
--------------------------------------------------------------------------
open_companion_window() is a plain, inert function. Importing this module
does nothing, and nothing anywhere else in the CYPHEX codebase calls it
automatically — that wiring is deliberately NOT part of this change. It is
meant to be invoked explicitly by a future opt-in code path, e.g.:

    # a future CLI flag, chosen by the user:
    if args.mascot_window:
        import mascot_companion
        mascot_companion.open_companion_window()

    # or an explicit call from mascot.py itself, only after mascot.py has
    # already decided (on its own, elsewhere) that the integrated terminal
    # can't render the animation well:
    import mascot_companion
    mascot_companion.open_companion_window()

Do not add either of those call sites as part of this change — this file
only builds the capability.

HOW IT WORKS
--------------------------------------------------------------------------
1. Detection order (see _detect_target): prefer iTerm2 if
   /Applications/iTerm.app exists (best quality — iTerm2 supports the
   inline-image protocol a future pixel-art backend can use). Otherwise
   fall back to macOS's built-in Terminal.app. Off macOS, or if neither
   AppleScript call can succeed (headless/no GUI session, osascript
   missing, the Apple Event errors for any reason), open_companion_window()
   returns False. It NEVER raises and NEVER hangs — every subprocess call
   carries a timeout (see `timeout` kwarg, default 5s).

2. The spawned window runs mascot_companion_loop.py (same directory as
   this file) via `python <that path>`, using the same interpreter that is
   currently running this process (sys.executable) unless overridden with
   `python_exe=`, `cd`-ed into this repo first so the loop script's own
   imports resolve the same way they would from an integrated run.

3. dry_run=True (see the __main__ self-test below) builds the exact shell
   command and AppleScript that WOULD be run and prints them instead of
   calling osascript — this is how the capability is verified in sandboxes
   / CI with no GUI session attached, without ever popping a real window.
"""

import os
import shlex
import shutil
import subprocess
import sys

# ── constants ────────────────────────────────────────────────────────────
ITERM_APP_PATH = "/Applications/iTerm.app"
LOOP_SCRIPT_NAME = "mascot_companion_loop.py"
WINDOW_TITLE = "CYPHEX Mascot"
DEFAULT_TIMEOUT = 5.0  # seconds — see requirement 4: never let a hung
                        # osascript/AppleScript dialog block the caller.


# ── AppleScript string escaping ─────────────────────────────────────────
def _as_literal(s):
    """Escape `s` for safe embedding inside a double-quoted AppleScript
    string literal (backslashes and double quotes only — AppleScript has
    no other special characters inside a plain string)."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


# ── shell command the companion window will run ────────────────────────
def _build_shell_command(python_exe=None, state_file=None):
    """Build the (already shell-escaped) command string that runs the
    standalone loop script in the new window: `cd <repo> && <python>
    <loop_script.py> [--state-file <path>]`. The leading `cd` matches
    "our configs" — the loop script (and any future asset-loading it does,
    e.g. reading assets/mascot/*.png) runs with this repo as its working
    directory, same as an integrated run would."""
    py = python_exe or sys.executable or "python3"
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    loop_script = os.path.join(repo_dir, LOOP_SCRIPT_NAME)
    parts = [py, loop_script]
    if state_file:
        parts += ["--state-file", state_file]
    cmd = " ".join(shlex.quote(p) for p in parts)
    return f"cd {shlex.quote(repo_dir)} && {cmd}"


# ── AppleScript builders ────────────────────────────────────────────────
def _iterm_applescript(command, title=WINDOW_TITLE, iterm_profile=None):
    """Modern iTerm2 AppleScript API: `create window with default profile
    command "..."` (or `with profile "<name>" command "..."` when a
    specific iTerm2 profile name is given — the hook a future "CYPHEX"
    dynamic profile, matching terminal_ui.py's HUD_THEME colours, can be
    passed through via the `iterm_profile` kwarg once one ships)."""
    cmd_lit = _as_literal(command)
    title_lit = _as_literal(title)
    if iterm_profile:
        profile_clause = f'profile "{_as_literal(iterm_profile)}"'
    else:
        profile_clause = "default profile"
    return (
        'tell application "iTerm"\n'
        f'    set newWindow to (create window with {profile_clause} command "{cmd_lit}")\n'
        "    tell current session of newWindow\n"
        f'        set name to "{title_lit}"\n'
        "    end tell\n"
        "end tell"
    )


def _terminal_applescript(command, title=WINDOW_TITLE):
    """Fallback via macOS's built-in Terminal.app: `do script "..."`,
    then name the new tab so the companion window is easy to spot."""
    cmd_lit = _as_literal(command)
    title_lit = _as_literal(title)
    return (
        'tell application "Terminal"\n'
        "    activate\n"
        f'    set newTab to do script "{cmd_lit}"\n'
        f'    set custom title of newTab to "{title_lit}"\n'
        "end tell"
    )


# ── detection ────────────────────────────────────────────────────────────
def _detect_target(prefer=None):
    """Return "iterm", "terminal", or None (nothing usable).

    `prefer` ("iterm" | "terminal"), when given, is returned as-is without
    checking the filesystem or platform at all — it exists purely so
    dry_run=True can demonstrate both branches deterministically from
    this sandbox (which has no /Applications and no GUI session), per
    requirement 5. Real (non-forced) detection only ever runs on macOS."""
    if prefer in ("iterm", "terminal"):
        return prefer
    if sys.platform != "darwin":
        return None
    if os.path.isdir(ITERM_APP_PATH):
        return "iterm"
    return "terminal"  # Terminal.app ships with every macOS install


# ── public entrypoint ───────────────────────────────────────────────────
def open_companion_window(
    *,
    prefer=None,
    dry_run=False,
    timeout=DEFAULT_TIMEOUT,
    python_exe=None,
    state_file=None,
    iterm_profile=None,
):
    """Spawn a separate, dedicated macOS terminal window to host the CYPHEX
    mascot animation. OPT-IN ONLY — see the module docstring above; nothing
    in this codebase calls this automatically, and this function must only
    ever run in response to an explicit user action.

    Returns True if a window was successfully spawned (or, under
    dry_run=True, if a target terminal app was resolved and the command
    that *would* run was printed), False if not possible or declined.
    Never raises and never hangs: every subprocess call is wrapped in
    try/except and bounded by `timeout` seconds.

    Kwargs:
        prefer       "iterm" | "terminal" | None (default). Forces which
                     branch to use, skipping the normal
                     /Applications/iTerm.app detection — intended for
                     testing (see the dry-run self-test below), not
                     normal callers.
        dry_run      If True, build the exact shell command and AppleScript
                     that would be run and print them instead of invoking
                     osascript. No window is opened, no subprocess with
                     side effects runs. Default False.
        timeout      Seconds to wait for the osascript subprocess before
                     giving up and returning False. Default 5.0 — keeps a
                     hung AppleScript dialog from ever blocking the caller.
        python_exe   Interpreter to run mascot_companion_loop.py with in
                     the new window. Defaults to sys.executable (the same
                     interpreter running the calling process), falling
                     back to "python3" if that's unavailable.
        state_file   Path to the mascot state file the loop script should
                     poll. Defaults (inside the loop script) to
                     ~/.cyphex/mascot_state when omitted here.
        iterm_profile
                     Optional iTerm2 profile NAME to launch with instead
                     of iTerm's "default profile" — the extension point
                     for "our configs" (a future CYPHEX-branded iTerm2
                     dynamic profile). Ignored on the Terminal.app branch.
    """
    target = _detect_target(prefer)
    if target is None:
        return False

    command = _build_shell_command(python_exe=python_exe, state_file=state_file)
    if target == "iterm":
        script = _iterm_applescript(command, iterm_profile=iterm_profile)
    else:
        script = _terminal_applescript(command)

    if dry_run:
        print(f"[mascot_companion] DRY RUN — target={target!r} (no window opened)")
        print(f"[mascot_companion] shell command:\n    {command}")
        print("[mascot_companion] osascript -e:")
        for line in script.splitlines():
            print(f"    {line}")
        return True

    if not shutil.which("osascript"):
        return False

    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode == 0
    except Exception:
        # subprocess.TimeoutExpired, FileNotFoundError, permission errors,
        # no GUI/window-server session, etc. — always fail closed, never
        # raise out of this function.
        return False


if __name__ == "__main__":
    # Dry-run self-test — verifiable with no GUI session attached (this
    # sandbox has none). Forces both branches via `prefer` so both are
    # demonstrated regardless of what's actually installed here.
    print("=== mascot_companion.py self-test (dry_run=True — no windows opened) ===\n")

    print("--- branch: iTerm2 (prefer='iterm') ---")
    ok_iterm = open_companion_window(prefer="iterm", dry_run=True)
    print(f"[mascot_companion] open_companion_window(...) -> {ok_iterm}\n")

    print("--- branch: Terminal.app (prefer='terminal') ---")
    ok_terminal = open_companion_window(prefer="terminal", dry_run=True)
    print(f"[mascot_companion] open_companion_window(...) -> {ok_terminal}\n")

    assert ok_iterm is True and ok_terminal is True, "dry-run self-test failed"
    print("=== self-test OK ===")
