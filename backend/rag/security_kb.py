"""
CYPHEX — Security Knowledge Base Loader

Loads security_kb.json and provides CWE → fix strategy lookups.
Used to give the patch model proven fix patterns instead of inventing from scratch.
"""

import os
import json
from typing import Optional


_KB_CACHE = None


def _load_kb() -> dict:
    """Load the security KB from the JSON file (cached)."""
    global _KB_CACHE
    if _KB_CACHE is not None:
        return _KB_CACHE

    kb_path = os.path.join(os.path.dirname(__file__), "security_kb.json")
    try:
        with open(kb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            _KB_CACHE = data.get("entries", {})
    except Exception:
        _KB_CACHE = {}

    return _KB_CACHE


def get_fix_recipe(cwe: str) -> Optional[dict]:
    """
    Get the fix recipe for a CWE.

    Returns dict with: name, description, fix_strategies, anti_patterns
    or None if CWE not in KB.
    """
    kb = _load_kb()
    return kb.get(cwe)


def get_fix_strategies(cwe: str, framework: str = "") -> list:
    """
    Get applicable fix strategies for a CWE, optionally filtered by framework.

    Returns list of {name, description, pattern, applies_to}.
    """
    recipe = get_fix_recipe(cwe)
    if not recipe:
        return []

    strategies = recipe.get("fix_strategies", [])

    if not framework:
        return strategies

    # Filter by framework
    applicable = []
    for s in strategies:
        applies = s.get("applies_to", ["*"])
        if "*" in applies or framework.lower() in [a.lower() for a in applies]:
            applicable.append(s)

    return applicable if applicable else strategies


def get_anti_patterns(cwe: str) -> list:
    """Get known anti-patterns for a CWE."""
    recipe = get_fix_recipe(cwe)
    if not recipe:
        return []
    return recipe.get("anti_patterns", [])


def format_for_prompt(cwe: str, framework: str = "") -> str:
    """
    Format the KB recipe as a string suitable for inclusion in a prompt.
    """
    recipe = get_fix_recipe(cwe)
    if not recipe:
        return ""

    strategies = get_fix_strategies(cwe, framework)
    anti_patterns = get_anti_patterns(cwe)

    parts = [f"CWE: {cwe} — {recipe.get('name', 'Unknown')}"]
    parts.append(f"Description: {recipe.get('description', '')}")

    if strategies:
        parts.append("\nPROVEN FIX STRATEGIES:")
        for i, s in enumerate(strategies, 1):
            parts.append(f"  {i}. {s['name']}: {s.get('description', '')}")
            parts.append(f"     Example: {s.get('pattern', '')}")

    if anti_patterns:
        parts.append(f"\nKNOWN ANTI-PATTERNS (avoid these): {', '.join(anti_patterns)}")

    return "\n".join(parts)


def detect_framework(deps: dict) -> str:
    """Detect the web framework from dependency info."""
    node_deps = deps.get("node_deps", [])
    python_deps = deps.get("python_deps", [])

    frameworks = {
        "express": "express",
        "fastify": "fastify",
        "koa": "koa",
        "next": "next",
        "react": "react",
        "vue": "vue",
        "angular": "angular",
        "flask": "flask",
        "django": "django",
        "fastapi": "fastapi",
    }

    for dep in node_deps + python_deps:
        dep_lower = dep.lower()
        for key, name in frameworks.items():
            if key in dep_lower:
                return name

    return ""


class SecurityKB:
    """
    Thin wrapper around the raw KB dict providing method-call access.
    Used by cli_engine.py's RAG context enrichment block so the rest of
    the codebase doesn't need to know the internal dict shape.
    """

    def primary_strategy(self, cwe: str):
        """
        Return the first fix strategy for a CWE, or None.
        The returned object has a .pattern attribute.
        """
        strategies = get_fix_strategies(cwe)
        if not strategies:
            return None
        from types import SimpleNamespace
        s = strategies[0]
        return SimpleNamespace(
            pattern=s.get("pattern", s.get("description", "")),
            name=s.get("name", ""),
            description=s.get("description", ""),
        )

    def anti_patterns(self, cwe: str) -> list:
        """Return list of anti-pattern strings for a CWE."""
        return get_anti_patterns(cwe)


def load_security_kb() -> SecurityKB:
    """
    Return a SecurityKB instance backed by the loaded JSON file.
    Safe to call multiple times — the underlying KB dict is cached.
    """
    return SecurityKB()
