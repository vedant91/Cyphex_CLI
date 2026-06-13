"""
CYPHEX — Deterministic Template Transforms

100%-deterministic fixes for high-frequency CWEs.
Zero model dependency — regex-based code transforms that are always correct.

Each transform is STILL verified before acceptance (a regex can be wrong).
If verification fails, the finding falls through to model-based reasoning.

Kills R6: "Rule-based fallback emits comments-as-code"
"""

import re
from typing import Optional, Callable


# ═══════════════════════════════════════════════════════════════
# Transform Functions (defined first so the registry can reference them)
# ═══════════════════════════════════════════════════════════════

def _fix_sqli_template_literal(code: str) -> str:
    """Replace template literal SQL with parameterized queries."""

    def replacer(match):
        full = match.group(0)
        # Extract the template literal content
        tpl_match = re.search(r'`([^`]*)`', full)
        if not tpl_match:
            return full

        template = tpl_match.group(1)

        # Find all ${...} interpolations
        vars_found = re.findall(r'\$\{([^}]+)\}', template)
        if not vars_found:
            return full

        # Replace each ${var} with ?
        parameterized = re.sub(r'\$\{[^}]+\}', '?', template)

        # Build the replacement
        vars_list = ", ".join(vars_found)
        return full.replace(f'`{template}`', f'"{parameterized}", [{vars_list}]')

    pattern = r'(?:db|connection|pool)\.query\s*\(\s*`[^`]*\$\{[^`]*`'
    result = re.sub(pattern, replacer, code, flags=re.DOTALL)
    return result


def _fix_sqli_concatenation(code: str) -> str:
    """Replace string concatenation SQL with parameterized queries."""
    pattern = r'(["\'])(SELECT\s[^"\']*?)\1\s*\+\s*(\w+(?:\.\w+)*)'
    match = re.search(pattern, code, re.I)
    if match:
        quote = match.group(1)
        query_part = match.group(2)
        var = match.group(3)
        replacement = f'{quote}{query_part}?{quote}, [{var}]'
        return code[:match.start()] + replacement + code[match.end():]
    return code


def _fix_hardcoded_secret(code: str) -> str:
    """Replace hardcoded secrets with environment variable references."""

    def replacer(match):
        full = match.group(0)
        key_match = re.match(r'(\w+)\s*[:=]\s*["\']', full)
        if not key_match:
            return full
        key = key_match.group(1).upper()
        return re.sub(r'["\'][^"\']+["\']', f'process.env.{key}', full)

    pattern = r'(?:password|secret|api_?key|token|MYSQL_ROOT_PASSWORD)\s*[:=]\s*["\'][^"\']{4,}["\']'
    return re.sub(pattern, replacer, code, flags=re.I)


def _fix_wildcard_cors(code: str) -> str:
    """Replace wildcard CORS with a placeholder origin list."""
    code = re.sub(
        r"cors\s*\(\s*\{\s*origin\s*:\s*['\"]?\*['\"]?",
        "cors({ origin: [process.env.ALLOWED_ORIGIN || 'https://localhost:3000']",
        code
    )
    code = re.sub(
        r"['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]?\*['\"]?",
        "'Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || 'https://localhost:3000'",
        code
    )
    return code


# ═══════════════════════════════════════════════════════════════
# Transform Registry
# ═══════════════════════════════════════════════════════════════

TRANSFORMS: dict[str, dict[str, dict]] = {
    "CWE-89": {
        "generic": {
            "detect": r'(?:db\.query|connection\.query|pool\.query)\s*\(\s*`[^`]*\$\{',
            "transform": _fix_sqli_template_literal,
        },
        "mysql": {
            "detect": r'(?:db\.query|connection\.query|pool\.query)\s*\(\s*["\'][^"\']*\+',
            "transform": _fix_sqli_concatenation,
        },
    },
    "CWE-798": {
        "generic": {
            "detect": r'(?:password|secret|api_?key|token)\s*[:=]\s*["\'][^"\']{4,}["\']',
            "transform": _fix_hardcoded_secret,
        },
    },
    "CWE-942": {
        "generic": {
            "detect": r'(?:cors|Access-Control-Allow-Origin)\s*[:(]\s*["\']?\*["\']?',
            "transform": _fix_wildcard_cors,
        },
    },
}


# ═══════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════

def apply_template(cwe: str, code: str, framework: str = "") -> Optional[str]:
    """
    Try to apply a deterministic template fix for the given CWE.

    Returns the fixed code, or None if no template applies.
    Never returns comments-as-code — either a real transform or None.
    """
    transform = TRANSFORMS.get(cwe)
    if not transform:
        return None

    # Try framework-specific first, then generic
    for key in [framework, "generic"]:
        if not key:
            continue
        entry = transform.get(key)
        if entry and re.search(entry["detect"], code, re.I | re.DOTALL):
            try:
                result = entry["transform"](code)
                if result and result != code:
                    return result
            except Exception:
                continue

    return None
