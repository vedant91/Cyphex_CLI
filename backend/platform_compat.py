"""
CYPHEX — Cross-Platform Compatibility Helpers

The portability audit (see the cross-platform hardening plan) found the same
few Windows/POSIX gotchas re-solved inconsistently at several call sites
across the codebase — most of a class of bug existing not because the fix is
hard, but because it got applied once and never centralized. This module is
that single place.

Scope grows with the phased rollout (PR2 ships the two helpers PR2's own
fixes need; later phases add UTF-8 I/O, ASCII-glyph fallback, and color-init
helpers as those land) rather than speculatively building the whole surface
up front — a helper with no caller yet is itself a maintenance liability.
"""

import os
import shutil
from typing import Optional


def resolve_binary_cmd(name: str) -> str:
    """
    Resolve a binary name to something subprocess.run(..., shell=False) can
    actually launch on this platform.

    Many dev-tool CLIs installed via npm (tsc, eslint, and anything else
    that ships as an npm global bin) are `.cmd`/`.ps1` shims on Windows, not
    native `.exe` files — Win32 CreateProcess (what non-shell `subprocess`
    uses) cannot launch those given only the bare name, even when
    shutil.which() has already confirmed the shim is on PATH. Falling back
    to the explicit "<name>.cmd" spelling is the pattern this codebase
    already uses successfully for npm (cli_engine.py, onboarder.py,
    sandbox_manager.py); centralized here so every other .cmd-shimmed tool
    (tsc included) gets the same fix instead of re-discovering the same bug
    at a new call site.

    Always returns a non-empty string — callers should still guard with
    their own try/except FileNotFoundError, since "resolved" doesn't
    guarantee "actually runnable" (PATH can change between the which() call
    and the subprocess call, however rarely).
    """
    resolved = shutil.which(name)
    if resolved:
        return resolved
    return f"{name}.cmd" if os.name == "nt" else name


def resolve_shell(preferred: str = "bash") -> Optional[str]:
    """
    Resolve a POSIX shell for subprocess's `executable=` kwarg (or asyncio's
    create_subprocess_shell). Returns None — meaning "let the platform
    default apply" (/bin/sh on POSIX) — when `preferred` isn't found,
    rather than a hardcoded absolute path that doesn't exist everywhere:
    minimal/Alpine (musl) containers commonly ship only /bin/sh, and
    CYPHEX's own sandbox agents run arbitrary target apps inside exactly
    that kind of minimal container.

    Bash-specific syntax (arrays, `[[ ]]`, process substitution, ...) is not
    portable to the /bin/sh fallback — callers relying on bashisms should
    treat a None return as "bash is unavailable", not silently swap shells.
    """
    return shutil.which(preferred)
