"""
CYPHEX — Code Context Extractor

Extracts the enclosing function + imports for a given line number.
Provides the model with precise, high-signal context instead of 5 blind lines.

Two extraction strategies:
  - JavaScript/TypeScript: brace-walk to find enclosing function/route handler
  - Python: indentation-based walk to enclosing def/async def

Falls back to ±15-line window if extraction fails or produces unbalanced output.
Returns (snippet, quality) where quality ∈ {"function", "window"}.
"""

import re
from typing import Tuple, Optional


def extract_function(content: str, line: int, lang: str = "js") -> Tuple[str, str]:
    """
    Extract the enclosing function containing the given line.

    Args:
        content: Full file content
        line: 1-indexed line number of the vulnerability
        lang: Language hint ("js", "ts", "py", "php")

    Returns:
        (snippet, quality) where quality is "function" or "window"
    """
    lines = content.split("\n")
    idx = line - 1  # Convert to 0-indexed

    if idx < 0 or idx >= len(lines):
        return _window_fallback(lines, idx), "window"

    if lang in ("py", "python"):
        result = _extract_python_function(lines, idx)
    else:
        result = _extract_js_function(lines, idx)

    if result:
        snippet = "\n".join(result)
        # Sanity check: not too large, and brace-balanced for JS
        if len(result) > 200:
            return _window_fallback(lines, idx), "window"
        if lang not in ("py", "python") and not _is_brace_balanced(snippet):
            return _window_fallback(lines, idx), "window"
        return snippet, "function"

    return _window_fallback(lines, idx), "window"


def extract_imports(content: str, lang: str = "js") -> str:
    """
    Extract import/require statements from the top of a file.

    Args:
        content: Full file content
        lang: Language hint

    Returns:
        String containing all import lines
    """
    lines = content.split("\n")
    imports = []

    for line in lines[:80]:  # Only scan first 80 lines
        stripped = line.strip()
        if lang in ("py", "python"):
            if stripped.startswith(("import ", "from ")):
                imports.append(line)
        else:
            if re.match(r'\s*(import |from ["\']|const \w+ = require|var \w+ = require|let \w+ = require)', stripped):
                imports.append(line)

    return "\n".join(imports)


def detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext_map = {
        ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js",
        ".ts": "ts", ".tsx": "ts",
        ".py": "py",
        ".php": "php",
        ".rb": "rb",
        ".go": "go",
        ".java": "java",
    }
    import os
    ext = os.path.splitext(file_path)[1].lower()
    return ext_map.get(ext, "js")


# ═══════════════════════════════════════════════════════════════
# JavaScript / TypeScript Function Extraction
# ═══════════════════════════════════════════════════════════════

# Patterns that start a function/handler boundary
JS_FUNCTION_START = re.compile(
    r'^\s*(?:'
    r'(?:router|app|server)\s*\.\s*(?:get|post|put|delete|patch|all|use)\s*\('  # Express routes
    r'|(?:async\s+)?function\s+\w+'                                              # function declarations
    r'|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\('                           # arrow functions
    r'|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?function'                     # function expressions
    r'|(?:async\s+)?\w+\s*\([^)]*\)\s*\{'                                       # method definitions
    r'|module\.exports\s*='                                                       # module exports
    r'|exports\.\w+\s*='                                                          # named exports
    r')',
    re.IGNORECASE
)


def _extract_js_function(lines: list, target_idx: int) -> Optional[list]:
    """Walk backwards from target line to find enclosing function, then forward to close."""
    # Walk backwards to find function start
    start = target_idx
    brace_depth = 0

    while start > 0:
        line = lines[start]
        brace_depth += line.count("}") - line.count("{")

        if brace_depth > 0 or JS_FUNCTION_START.match(line):
            break
        start -= 1

    # Walk forward to find matching closing brace
    end = target_idx
    brace_depth = 0

    for i in range(start, len(lines)):
        brace_depth += lines[i].count("{") - lines[i].count("}")
        end = i
        if brace_depth <= 0 and i > start:
            break

    if end - start < 2:
        return None

    return lines[start:end + 1]


# ═══════════════════════════════════════════════════════════════
# Python Function Extraction
# ═══════════════════════════════════════════════════════════════

def _extract_python_function(lines: list, target_idx: int) -> Optional[list]:
    """Walk backwards to enclosing def/async def, forward by indentation."""
    # Walk backwards to find def
    start = target_idx
    while start > 0:
        stripped = lines[start].lstrip()
        if stripped.startswith(("def ", "async def ")):
            break
        start -= 1

    if start == 0 and not lines[0].lstrip().startswith(("def ", "async def ")):
        return None

    # Get the indentation of the def line
    def_indent = len(lines[start]) - len(lines[start].lstrip())

    # Walk forward: everything at deeper indentation belongs to this function
    end = start + 1
    while end < len(lines):
        line = lines[end]
        # Skip blank lines
        if not line.strip():
            end += 1
            continue
        # If indentation returns to def level or less, stop
        line_indent = len(line) - len(line.lstrip())
        if line_indent <= def_indent and line.strip():
            break
        end += 1

    if end - start < 2:
        return None

    return lines[start:end]


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _window_fallback(lines: list, target_idx: int) -> str:
    """±15-line window fallback."""
    start = max(0, target_idx - 15)
    end = min(len(lines), target_idx + 16)
    return "\n".join(lines[start:end])


def _is_brace_balanced(text: str) -> bool:
    """Check if braces are roughly balanced (ignoring strings for speed)."""
    opens = text.count("{")
    closes = text.count("}")
    return abs(opens - closes) <= 1  # Allow ±1 for partial functions
