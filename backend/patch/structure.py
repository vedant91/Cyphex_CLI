"""
CYPHEX — Structural Integrity Check

Catches the patch-quality bug class node --check / py_compile CANNOT see:
a patch that stays syntactically valid but deletes the enclosing route
handler / function / class that gave its body a scope. The remaining
statements parse fine — no unmatched brace, no compile error — but any
reference to a parameter that only existed inside the deleted wrapper
(req, res, self, ...) is now a runtime ReferenceError, and the route is no
longer registered at all.

This is a purely textual, language-agnostic-ish check: it does not
understand control flow, only "did every route/handler/function/class
declaration that existed in the original range survive, by name/path, in
the replacement?". A patch is free to rewrite the BODY of a handler however
it likes; it must not make the handler's own declaration disappear.
"""

import re
from typing import Optional


# Express / Koa / Fastify / generic `<router|app>.<verb>('/path', ...)` route
# registrations. Captures (verb, path).
_JS_ROUTE_RE = re.compile(
    r"""\b(?:router|app)\s*\.\s*(get|post|put|delete|patch|options|head|all|use)\s*"""
    r"""\(\s*(['"`])([^'"`]*)\2""",
    re.IGNORECASE,
)

# `function name(...)` declarations (named functions only — anonymous
# callbacks aren't identifiable by name, so they're out of scope here).
_JS_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(")

# Python `def name(...)` — module or method level, any indent.
_PY_DEF_RE = re.compile(r"^[ \t]*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)

# Python `class Name` declarations.
_PY_CLASS_RE = re.compile(r"^[ \t]*class\s+([A-Za-z_]\w*)\b", re.MULTILINE)

# Flask / FastAPI style `@app.route('/path')` / `@router.get('/path')` decorators.
_PY_ROUTE_DECORATOR_RE = re.compile(
    r"""@[\w.]+\.(route|get|post|put|delete|patch)\s*\(\s*(['"])([^'"]*)\2""",
    re.IGNORECASE,
)


def check_structure_preserved(original: str, patched: str) -> Optional[str]:
    """
    Compare a vulnerable code range to its proposed replacement.

    Returns None if every declaration the original range introduced is
    still present in the replacement, or a human-readable reason string
    describing what got dropped otherwise.

    Only checks for REMOVAL — a patch is free to add new routes/functions
    (e.g. splitting a handler), that's never flagged.
    """
    if not original or not patched:
        return None

    # ── Express/Koa/Fastify route registrations: verb + path must survive ──
    orig_routes = {(m.group(1).lower(), m.group(3)) for m in _JS_ROUTE_RE.finditer(original)}
    if orig_routes:
        patched_routes = {(m.group(1).lower(), m.group(3)) for m in _JS_ROUTE_RE.finditer(patched)}
        missing = orig_routes - patched_routes
        if missing:
            verb, path = sorted(missing)[0]
            return (
                f"route handler '{verb.upper()} {path or '/'}' was removed — its body "
                f"is left unwrapped, so req/res/next fall out of scope and the route "
                f"is no longer registered"
            )

    # ── Named JS function declarations ──
    orig_fns = set(_JS_FUNCTION_RE.findall(original))
    if orig_fns:
        missing = orig_fns - set(_JS_FUNCTION_RE.findall(patched))
        if missing:
            return f"function declaration(s) removed: {', '.join(sorted(missing))}"

    # ── Python def/class ──
    orig_defs = set(_PY_DEF_RE.findall(original))
    if orig_defs:
        missing = orig_defs - set(_PY_DEF_RE.findall(patched))
        if missing:
            return f"function definition(s) removed: {', '.join(sorted(missing))}"

    orig_classes = set(_PY_CLASS_RE.findall(original))
    if orig_classes:
        missing = orig_classes - set(_PY_CLASS_RE.findall(patched))
        if missing:
            return f"class definition(s) removed: {', '.join(sorted(missing))}"

    # ── Flask/FastAPI decorator routes ──
    orig_deco = {(m.group(1).lower(), m.group(3)) for m in _PY_ROUTE_DECORATOR_RE.finditer(original)}
    if orig_deco:
        patched_deco = {(m.group(1).lower(), m.group(3)) for m in _PY_ROUTE_DECORATOR_RE.finditer(patched)}
        missing = orig_deco - patched_deco
        if missing:
            verb, path = sorted(missing)[0]
            return f"route decorator '@...{verb}(\"{path}\")' was removed"

    return None
