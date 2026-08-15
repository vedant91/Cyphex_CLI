"""
CYPHEX — Deterministic Template Transforms

100%-deterministic fixes for high-frequency CWEs.
Zero model dependency — regex-based code transforms that are always correct.

Each transform is STILL verified before acceptance (a regex can be wrong).
If verification fails, the finding falls through to model-based reasoning.

Kills R6: "Rule-based fallback emits comments-as-code"
"""

import json
import re
from typing import Optional, Callable


# Shell metacharacters that make a command string ambiguous to safely split
# into a "binary + argv" form via regex alone (compound commands, pipes,
# redirection, command substitution). When present, the CMDi transforms
# below bail out (leave the code unchanged) rather than guess — the finding
# then falls through to model-based reasoning instead of an incorrect fix.
_SHELL_METACHARACTERS = ("&&", "||", ";", "|", "`", "$(", ">", "<")


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
    """
    Replace string-concatenation SQL with a parameterized query.

    Captures the FULL concatenation chain (every "literal" + var + "literal"
    + var ... term), not just the first '+'. The previous version only
    replaced the first `"SELECT ..." + var` pair and left everything after it
    untouched — e.g. `"SELECT * FROM t WHERE id=" + id + " AND active=1"`
    became `"SELECT * FROM t WHERE id=?", [id] + " AND active=1"`, a dangling
    `+` that is neither valid nor safe. Now every literal chunk is stitched
    into one parameterized string and every variable becomes a bind param,
    in order.
    """
    call_pattern = re.compile(
        r'((?:db|connection|pool)\.query\s*\(\s*)'
        r'(["\'][^"\']*["\'](?:\s*\+\s*(?:["\'][^"\']*["\']|\w+(?:\.\w+)*))+)',
        re.I,
    )

    def replacer(match):
        prefix = match.group(1)
        expr = match.group(2)
        terms = [t.strip() for t in re.split(r'\+', expr)]

        parts = []
        params = []
        for term in terms:
            if term[:1] in ('"', "'"):
                parts.append(term[1:-1])
            else:
                parts.append('?')
                params.append(term)

        if not params:
            return match.group(0)

        query_text = "".join(parts)
        quote = '"' if '"' not in query_text else "'"
        return f'{prefix}{quote}{query_text}{quote}, [{", ".join(params)}]'

    return call_pattern.sub(replacer, code)


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


def _fix_cmdi_execsync(code: str) -> str:
    """
    Replace execSync/exec calls whose command is a template literal
    containing interpolated variables with a REAL fix: execFileSync/execFile
    invoked with an argument array. execFile* never spawns a shell, so shell
    metacharacters in the interpolated values cannot be used for command
    injection at all — there's no shell there to interpret them.

    The previous version of this transform fabricated an unrelated
    file-extension allowlist (['json', 'csv', 'xml', 'text', 'pdf']) for
    every variable regardless of what it actually was, and substituted a
    fake "Operation completed" string instead of running anything — neither
    validates nor fixes the actual vulnerability.

    Handles patterns like:
      execSync(`ping ${host}`)
      const out = execSync(`ls ${dir}`).toString();
      exec(`ls ${dir}`, callback)

    Preserves the original left-to-right order of literal words and
    interpolated variables when building the argv array (a variable is not
    always the trailing argument — e.g. `cmd /c ${arg} --verbose` — and
    argv order matters for correctness). Bails out (leaves code unchanged)
    if the template contains shell metacharacters (&&, |, ;, backticks,
    command substitution, redirection) or if it can't identify a literal
    binary name to run, so the finding falls through to model-based
    reasoning instead of emitting a guessed, possibly-incorrect fix (this
    transform never fabricates comments-as-code).
    """
    # NOTE: `rest` deliberately excludes '(' as well as ')' — a trailing
    # callback that itself contains parens (e.g. `(err, out) => {...}`) can't
    # be located correctly by a simple regex (which paren closes the outer
    # call?), so excluding '(' makes the whole pattern simply fail to match
    # in that case, causing this transform to bail out (return code
    # unchanged) instead of miscomputing the match boundary and corrupting
    # the file.
    pattern = re.compile(
        r'(?P<assign>const\s+\w+\s*=\s*)?'
        r'(?P<prefix>child_process\.)?(?P<fn>execSync|exec)\s*\(\s*'
        r'`(?P<tpl>[^`]*)`'
        r'(?P<rest>(?:\s*,\s*[^()]*)?)\)'
        r'(?P<tostr>\s*\.toString\(\))?\s*;?'
    )

    match = pattern.search(code)
    if not match:
        return code

    template = match.group("tpl")
    if any(meta in template for meta in _SHELL_METACHARACTERS):
        return code  # compound/ambiguous shell command — don't guess

    # Split on ${...} interpolations: tokens alternates static, var, static,
    # var, ..., static. Walk it left-to-right so word/variable ORDER is
    # preserved in the resulting argv array.
    tokens = re.split(r'\$\{([^}]+)\}', template)

    binary = None
    argv_items = []
    has_var = False
    for i, tok in enumerate(tokens):
        if i % 2 == 1:
            var = tok.strip()
            if binary is None:
                return code  # command can't start with a variable
            argv_items.append(var)
            has_var = True
        else:
            for word in tok.split():
                if binary is None:
                    binary = word
                else:
                    argv_items.append(json.dumps(word))

    if not has_var or binary is None:
        return code

    argv = ", ".join(argv_items)

    assign = match.group("assign") or ""
    # Preserve the `child_process.` prefix if the original call used it, so
    # the rewrite never needs an import/destructure the file doesn't already
    # have — `child_process` (the module object) exposes execFile*/execFile
    # exactly like it exposes exec*/exec.
    prefix = match.group("prefix") or ""
    if match.group("fn") == "execSync":
        call_expr = f'{prefix}execFileSync({json.dumps(binary)}, [{argv}])'
        if match.group("tostr"):
            call_expr += ".toString()"
    else:
        rest = (match.group("rest") or "").strip()
        callback = rest[1:].strip() if rest.startswith(",") else ""
        callback_part = f", {callback}" if callback else ""
        call_expr = f'{prefix}execFile({json.dumps(binary)}, [{argv}]{callback_part})'

    new_code = f'{assign}{call_expr};'
    return code[:match.start()] + new_code + code[match.end():]


def _fix_cmdi_exec_concat(code: str) -> str:
    """
    Replace execSync/exec calls whose command is built via string
    concatenation with a REAL fix: execFileSync/execFile invoked with an
    argument array, so shell metacharacters in the concatenated values can
    never reach a shell.

    Captures the FULL concatenation chain (not just the first '+'), so a
    command like `"cmd /c " + userInput + " --verbose"` is handled
    completely instead of leaving a dangling fragment behind.

    Handles patterns like:
      exec("ping " + host, callback)
      execSync("cmd /c " + userInput)

    Bails out (returns code unchanged) if the literal portion of the chain
    contains shell metacharacters — too ambiguous to safely split — so the
    finding falls through to model-based reasoning instead of a guess.
    """
    # See _fix_cmdi_execsync for why `rest` excludes '(' — it makes the whole
    # pattern fail to match (safe bail-out) rather than mis-locate the outer
    # call's closing paren when the trailing callback itself contains parens.
    call_re = re.compile(
        r'(?P<assign>const\s+\w+\s*=\s*)?'
        r'(?P<prefix>child_process\.)?(?P<fn>execSync|exec)\s*\(\s*'
        r'(?P<expr>["\'][^"\']*["\'](?:\s*\+\s*(?:["\'][^"\']*["\']|\w+(?:\.\w+)*))+)'
        r'(?P<rest>(?:\s*,\s*[^()]*)?)\)'
        r'(?P<tostr>\s*\.toString\(\))?\s*;?'
    )

    match = call_re.search(code)
    if not match:
        return code

    terms = [t.strip() for t in re.split(r'\+', match.group("expr"))]

    # Shell-metacharacter check runs over the concatenated literal text only
    # (variables' runtime values are opaque to us and irrelevant here — the
    # whole point of execFile* is that they can never reach a shell).
    literal_text_for_check = "".join(t[1:-1] for t in terms if t[:1] in ("'", '"'))
    if any(meta in literal_text_for_check for meta in _SHELL_METACHARACTERS):
        return code  # compound shell command — too ambiguous to safely split

    # Walk the terms in order so word/variable ORDER is preserved in the
    # resulting argv array — a variable isn't always the trailing argument
    # (e.g. `"cmd /c " + arg + " --verbose"`), and argv order matters.
    binary = None
    argv_items = []
    has_var = False
    for term in terms:
        if term[:1] in ("'", '"'):
            for word in term[1:-1].split():
                if binary is None:
                    binary = word
                else:
                    argv_items.append(json.dumps(word))
        else:
            if binary is None:
                return code  # command can't start with a variable
            argv_items.append(term)
            has_var = True

    if not has_var or binary is None:
        return code

    argv = ", ".join(argv_items)

    assign = match.group("assign") or ""
    prefix = match.group("prefix") or ""
    if match.group("fn") == "execSync":
        call_expr = f'{prefix}execFileSync({json.dumps(binary)}, [{argv}])'
        if match.group("tostr"):
            call_expr += ".toString()"
    else:
        rest = (match.group("rest") or "").strip()
        callback = rest[1:].strip() if rest.startswith(",") else ""
        callback_part = f", {callback}" if callback else ""
        call_expr = f'{prefix}execFile({json.dumps(binary)}, [{argv}]{callback_part})'

    new_code = f'{assign}{call_expr};'
    return code[:match.start()] + new_code + code[match.end():]


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
            # NOTE: must require the closing quote before the '+' — the old
            # pattern (["\'][^"\']*\+) could never match ANY real
            # concatenation ("..." + var), because '+' always comes AFTER the
            # closing quote, never inside the quoted content, so this
            # transform was silent dead code. Fixed to require ["\']\s*\+.
            "detect": r'(?:db\.query|connection\.query|pool\.query)\s*\(\s*["\'][^"\']*["\']\s*\+',
            "transform": _fix_sqli_concatenation,
        },
    },
    "CWE-78": {
        "execsync_tpl": {
            "detect": r'(?:execSync|exec)\s*\(\s*`[^`]*\$\{',
            "transform": _fix_cmdi_execsync,
        },
        "exec_concat": {
            "detect": r'(?:execSync|exec)\s*\(\s*["\'][^"\']*["\']\s*\+',
            "transform": _fix_cmdi_exec_concat,
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
            # Mirrors the two forms _fix_wildcard_cors actually rewrites. The
            # previous pattern — `(?:cors|Access-Control-Allow-Origin)\s*[:(]\s*["\']?\*`
            # — accepted a set of inputs disjoint from the transform's: it matched
            # `cors: "*"` and raw `Access-Control-Allow-Origin: *`, neither of
            # which the transform touches, while rejecting `cors({ origin: "*" })`
            # and `"Access-Control-Allow-Origin", "*"`, which it does. Detect and
            # transform could therefore never fire on the same input, so this
            # template returned None for every possible input.
            "detect": (
                r'cors\s*\(\s*\{\s*origin\s*:\s*["\']?\*'
                r'|["\']Access-Control-Allow-Origin["\']\s*,\s*["\']?\*'
            ),
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

    # Priority order: framework-specific → generic → all other variants
    priority_keys = []
    if framework:
        priority_keys.append(framework)
    priority_keys.append("generic")
    # Add all remaining keys (for CWE-78's "execsync_tpl", "exec_concat", etc.)
    for key in transform:
        if key not in priority_keys:
            priority_keys.append(key)

    for key in priority_keys:
        entry = transform.get(key)
        if entry and re.search(entry["detect"], code, re.I | re.DOTALL):
            try:
                result = entry["transform"](code)
                if result and result != code:
                    return result
            except Exception:
                continue

    return None
