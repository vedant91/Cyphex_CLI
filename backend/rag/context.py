"""Context extraction utilities for patch generation prompts."""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple

_WINDOW = 15
_MAX_FUNCTION_LINES = 200


def detect_language(file_path: str) -> str:
    ext = os.path.splitext(file_path or "")[1].lower()
    if ext in {".py"}:
        return "python"
    if ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return "javascript"
    return "text"


def extract_imports(content: str, lang: str) -> str:
    lines = content.splitlines()
    out = []
    for ln in lines[:160]:
        s = ln.strip()
        if not s:
            continue
        if lang == "python":
            if s.startswith("import ") or s.startswith("from "):
                out.append(ln)
        elif lang == "javascript":
            if s.startswith("import ") or "require(" in s:
                out.append(ln)
        if len(out) >= 20:
            break
    return "\n".join(out)


def _window(lines: list[str], line_number: int) -> str:
    idx = max(0, (line_number or 1) - 1)
    start = max(0, idx - _WINDOW)
    end = min(len(lines), idx + _WINDOW + 1)
    return "\n".join(lines[start:end])


def _quote_balanced(text: str) -> bool:
    singles = re.findall(r"(?<!\\)'", text)
    doubles = re.findall(r'(?<!\\)"', text)
    backticks = re.findall(r"(?<!\\)`", text)
    return len(singles) % 2 == 0 and len(doubles) % 2 == 0 and len(backticks) % 2 == 0


def _brace_balance(text: str) -> int:
    in_single = False
    in_double = False
    in_backtick = False
    escaped = False
    bal = 0

    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue

        if ch == "'" and not in_double and not in_backtick:
            in_single = not in_single
            continue
        if ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
            continue
        if ch == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            continue

        if in_single or in_double or in_backtick:
            continue

        if ch == "{":
            bal += 1
        elif ch == "}":
            bal -= 1

    return bal


def _extract_python_function(lines: list[str], line_number: int) -> Optional[str]:
    idx = max(0, line_number - 1)
    if idx >= len(lines):
        idx = len(lines) - 1
    if idx < 0:
        return None

    start = None
    base_indent = None
    for i in range(idx, -1, -1):
        raw = lines[i]
        stripped = raw.lstrip(" ")
        if stripped.startswith("def ") or stripped.startswith("async def "):
            start = i
            base_indent = len(raw) - len(stripped)
            break
    if start is None or base_indent is None:
        return None

    end = len(lines)
    for j in range(start + 1, len(lines)):
        raw = lines[j]
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= base_indent and not raw.lstrip().startswith("#"):
            end = j
            break

    snippet = "\n".join(lines[start:end])
    if snippet.count("\n") + 1 > _MAX_FUNCTION_LINES:
        return None
    return snippet


def _js_anchor(lines: list[str], idx: int) -> Optional[int]:
    patterns = [
        re.compile(r"\b(app|router)\.(get|post|put|patch|delete|all)\s*\("),
        re.compile(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\("),
        re.compile(r"\b(const|let|var)\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\([^)]*\)\s*=>"),
    ]
    for i in range(idx, -1, -1):
        line = lines[i]
        if any(p.search(line) for p in patterns):
            return i
    return None


def _extract_js_function(lines: list[str], line_number: int) -> Optional[str]:
    idx = max(0, line_number - 1)
    if idx >= len(lines):
        idx = len(lines) - 1
    if idx < 0:
        return None

    start = _js_anchor(lines, idx)
    if start is None:
        return None

    block = []
    seen_open = False
    balance = 0
    for i in range(start, min(len(lines), start + _MAX_FUNCTION_LINES)):
        ln = lines[i]
        block.append(ln)
        delta = _brace_balance(ln)
        if "{" in ln:
            seen_open = True
        balance += delta
        if seen_open and balance == 0:
            break

    text = "\n".join(block)
    if not text.strip():
        return None
    if text.count("\n") + 1 > _MAX_FUNCTION_LINES:
        return None
    if _brace_balance(text) != 0:
        return None
    if not _quote_balanced(text):
        return None
    return text


def extract_function(content: str, line_number: int, lang: str) -> Tuple[str, str]:
    """Return (snippet, extraction_quality), quality in {function, window}."""
    lines = content.splitlines()
    if not lines:
        return "", "window"

    snippet = None
    if lang == "python":
        snippet = _extract_python_function(lines, line_number)
    elif lang == "javascript":
        snippet = _extract_js_function(lines, line_number)

    if snippet:
        return snippet, "function"
    return _window(lines, line_number), "window"
