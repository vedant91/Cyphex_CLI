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


def apply_patch(
    file_path: str,
    start_line: int,
    end_line: int,
    fixed_code: str,
) -> ApplyResult:
    """
    Apply a patch to a specific line range in a file.

    Args:
        file_path: Absolute path to the file to patch
        start_line: Start of vulnerable range (1-indexed, inclusive)
        end_line: End of vulnerable range (1-indexed, inclusive)
        fixed_code: The replacement code from the LLM/template

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

    # Read original
    try:
        backup_content = open(file_path, "r", encoding="utf-8", errors="ignore").read()
    except Exception as e:
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content="",
            error=f"Cannot read file: {e}",
        )

    lines = backup_content.split("\n")

    # Validate line range (convert to 0-indexed)
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)

    if start_idx >= len(lines):
        return ApplyResult(
            success=False,
            file_path=file_path,
            backup_content=backup_content,
            error=f"Start line {start_line} exceeds file length ({len(lines)} lines)",
        )

    # Split fixed code into lines, preserving structure
    fixed_lines = fixed_code.split("\n")

    # Remove trailing empty line if the fixed code ends with \n
    if fixed_lines and fixed_lines[-1] == "":
        fixed_lines = fixed_lines[:-1]

    # Replace the line range with the fixed code
    new_lines = lines[:start_idx] + fixed_lines + lines[end_idx:]

    # Write the patched file
    try:
        new_content = "\n".join(new_lines)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
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
        rollback(file_path, backup_content)
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


def rollback(file_path: str, backup_content: str) -> bool:
    """Restore a file to its pre-patch state."""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(backup_content)
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
