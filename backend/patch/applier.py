"""
CYPHEX — Range-Accurate Patch Applier

Replaces the destructive blank-all-lines approach with precision patching:
  - Replaces only the vulnerable line range, preserving surrounding code
  - Always creates a backup before modifying
  - Validates syntax after apply (py_compile for Python, node --check for JS)
  - Supports rollback on failure

Kills bug R2: "Blind line-range overwrite destroys error handlers, closing braces, valid logic"
"""

import os
import subprocess
import shutil
import tempfile
from dataclasses import dataclass
from typing import Optional


@dataclass
class ApplyResult:
    """Result of a patch application attempt."""
    success: bool
    file_path: str
    backup_content: str       # Original file content for rollback
    error: Optional[str] = None
    parse_valid: Optional[bool] = None  # True if syntax check passed


def _check_path_containment(file_path: str, source_dir: Optional[str]) -> Optional[str]:
    """
    Defense-in-depth path-safety guard for writes, independent of resolver.py's
    own containment check (an attacker shouldn't be able to escalate to
    arbitrary-file-write just because some other code path skipped/mis-used
    the resolver).

    Returns an error message if file_path is unsafe to write to, else None.
    """
    if os.path.islink(file_path):
        return f"Refusing to write through a symlink: {file_path}"

    if source_dir:
        real_source = os.path.realpath(source_dir)
        real_target = os.path.realpath(file_path)
        if real_target != real_source and not real_target.startswith(real_source + os.sep):
            return f"Refusing to write outside source directory ({source_dir!r}): {file_path}"

    return None


def _atomic_write(file_path: str, content: str) -> None:
    """
    Write `content` to file_path atomically: write to a temp file in the same
    directory, then os.replace() it over the target. This is atomic on both
    POSIX and Windows, so a crash/kill mid-write can never leave the file
    truncated or partially written (unlike `open(path, "w")`, which truncates
    immediately).
    """
    directory = os.path.dirname(file_path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".cyphex.tmp.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(content)
        os.replace(tmp_path, file_path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def apply_patch(
    file_path: str,
    start_line: int,
    end_line: int,
    fixed_code: str,
    source_dir: Optional[str] = None,
) -> ApplyResult:
    """
    Apply a patch to a specific line range in a file.

    Args:
        file_path: Absolute path to the file to patch
        start_line: Start of vulnerable range (1-indexed, inclusive)
        end_line: End of vulnerable range (1-indexed, inclusive)
        fixed_code: The replacement code from the LLM/template
        source_dir: Optional root directory the file must stay contained in
            (second containment guard, independent of resolver.py)

    Returns:
        ApplyResult with backup for rollback
    """
    if not os.path.isfile(file_path):
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content="",
            error=f"File not found: {file_path}",
        )

    unsafe = _check_path_containment(file_path, source_dir)
    if unsafe:
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content="",
            error=unsafe,
        )

    # Read original. errors="surrogateescape" round-trips ANY byte sequence
    # (even invalid UTF-8) losslessly, unlike errors="ignore" which silently
    # drops non-UTF-8 bytes from the entire file on every read/write.
    try:
        backup_content = open(file_path, "r", encoding="utf-8", errors="surrogateescape").read()
    except Exception as e:
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content="",
            error=f"Cannot read file: {e}",
        )

    lines = backup_content.split("\n")
    line_count = len(lines)

    # Strictly validate the line range BEFORE splicing anything. An inverted
    # or out-of-bounds range must never be allowed to silently corrupt the
    # file (duplicate/delete large chunks) — fail closed instead.
    if (
        not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or start_line < 1
        or end_line < start_line
        or end_line > line_count + 1
    ):
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content=backup_content,
            error=(
                f"Invalid line range [{start_line}, {end_line}] for file with "
                f"{line_count} lines (require 1 <= start_line <= end_line <= {line_count + 1})"
            ),
        )

    # Convert to 0-indexed slice bounds (end_line is inclusive 1-indexed, so
    # it maps directly to the exclusive 0-indexed slice-end).
    start_idx = start_line - 1
    end_idx = end_line

    # Split fixed code into lines, preserving structure
    fixed_lines = fixed_code.split("\n")

    # Remove trailing empty line if the fixed code ends with \n
    if fixed_lines and fixed_lines[-1] == "":
        fixed_lines = fixed_lines[:-1]

    # Replace the line range with the fixed code
    new_lines = lines[:start_idx] + fixed_lines + lines[end_idx:]

    # Second containment guard, right before we open the file for writing —
    # do not rely solely on the check performed above (or on the resolver):
    # re-validate immediately before the write to close any TOCTOU window
    # (e.g. file_path being swapped for a symlink between the earlier check
    # and now).
    unsafe = _check_path_containment(file_path, source_dir)
    if unsafe:
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content=backup_content,
            error=unsafe,
        )

    # Write the patched file atomically
    try:
        new_content = "\n".join(new_lines)
        _atomic_write(file_path, new_content)
    except Exception as e:
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content=backup_content,
            error=f"Cannot write file: {e}",
        )

    # Syntax validation
    parse_ok = _validate_syntax(file_path)

    if parse_ok is False:
        # Auto-rollback on syntax error
        rollback(file_path, backup_content, source_dir=source_dir)
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content=backup_content,
            error="Patch produced invalid syntax — auto-rolled back",
            parse_valid=False,
        )

    return ApplyResult(
        success=True,
        file_path=file_path,
        backup_content=backup_content,
        parse_valid=parse_ok,
    )


def rollback(file_path: str, backup_content: str, source_dir: Optional[str] = None) -> bool:
    """Restore a file to its pre-patch state (atomic write, same guards as apply_patch)."""
    unsafe = _check_path_containment(file_path, source_dir)
    if unsafe:
        return False
    try:
        _atomic_write(file_path, backup_content)
        return True
    except Exception:
        return False


def _validate_syntax(file_path: str) -> Optional[bool]:
    """
    Check if the patched file has valid syntax.
    Returns True (valid), False (invalid), or None (can't check).
    """
    ext = os.path.splitext(file_path)[1].lower()

    # Python files
    if ext == ".py":
        try:
            import py_compile
            py_compile.compile(file_path, doraise=True)
            return True
        except py_compile.PyCompileError:
            return False
        except Exception:
            return None

    # JavaScript/TypeScript files
    if ext in (".js", ".mjs", ".cjs"):
        if shutil.which("node"):
            try:
                result = subprocess.run(
                    ["node", "--check", file_path],
                    capture_output=True, text=True, timeout=10
                )
                return result.returncode == 0
            except Exception:
                return None

    if ext in (".ts", ".tsx"):
        if shutil.which("tsc"):
            try:
                result = subprocess.run(
                    ["tsc", "--noEmit", file_path],
                    capture_output=True, text=True, timeout=15
                )
                return result.returncode == 0
            except Exception:
                return None

    # Can't validate this file type
    return None
