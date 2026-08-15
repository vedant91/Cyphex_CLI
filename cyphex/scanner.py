"""
CYPHEX — Static Analysis Engine

Multi-language static scanner with Semgrep integration.
Falls back to built-in regex patterns when Semgrep is unavailable.

Supports 20+ languages across 4 priority tiers:
  P0: JavaScript, TypeScript, Python
  P1: Java, Go, PHP, Ruby
  P2: C, C++, Rust, C#
  P3: Swift, Kotlin, Terraform, Dockerfile, YAML
"""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StaticFinding:
    """A vulnerability found by static analysis."""
    rule_id: str
    name: str
    severity: str           # Critical | High | Medium | Low | Info
    cwe: str                # e.g. "CWE-89"
    file_path: str
    line_number: int
    code_snippet: str
    message: str
    fix_hint: str = ""
    source: str = "builtin"  # "semgrep" | "builtin"


# ══════════════════════════════════════════════════════════════
#  SEMGREP INTEGRATION (primary, when available)
# ══════════════════════════════════════════════════════════════

def semgrep_available() -> bool:
    """Check if Semgrep CLI is installed."""
    if os.name == "nt":
        try:
            res = subprocess.run(["wsl", "semgrep", "--version"], capture_output=True, text=True, timeout=5)
            return res.returncode == 0
        except Exception:
            return False
    return shutil.which("semgrep") is not None


def run_semgrep(source_dir: str, config: str = "auto") -> list[StaticFinding]:
    """
    Run Semgrep scan and return normalized findings.
    Uses 'auto' config (5000+ rules across 30+ languages).
    """
    try:
        # --metrics=off keeps this a local-first tool (no telemetry phone-home).
        cmd = ["semgrep", "--config", config, "--json", "--quiet", "--timeout", "120", "--metrics=off"]
        if os.name == "nt":
            wsl_path = subprocess.run(["wsl", "wslpath", "-a", source_dir], capture_output=True, text=True).stdout.strip()
            cmd = ["wsl", "semgrep", "--config", config, "--json", "--quiet", "--timeout", "120", "--metrics=off", wsl_path]
        else:
            cmd.append(source_dir)

        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=300
        )
        # Semgrep can exit 2 on partial/rule-fetch errors while STILL emitting valid
        # results on stdout — parse whatever JSON is present rather than dropping
        # every finding on any non-0/1 exit.
        if not (result.stdout or "").strip():
            return []

        data = json.loads(result.stdout)
        findings = []
        for r in data.get("results", []):
            severity_map = {
                "ERROR": "High", "WARNING": "Medium", "INFO": "Low"
            }
            # Extract CWE from metadata
            metadata = r.get("extra", {}).get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe = cwe_list[0] if cwe_list else "CWE-unknown"
            if isinstance(cwe, str) and "CWE-" not in cwe:
                cwe = f"CWE-{cwe}"

            findings.append(StaticFinding(
                rule_id=r.get("check_id", "unknown"),
                name=r.get("check_id", "").split(".")[-1].replace("-", " ").title(),
                severity=severity_map.get(
                    r.get("extra", {}).get("severity", "WARNING"), "Medium"
                ),
                cwe=cwe,
                file_path=r.get("path", ""),
                line_number=r.get("start", {}).get("line", 0),
                code_snippet=r.get("extra", {}).get("lines", ""),
                message=r.get("extra", {}).get("message", ""),
                fix_hint=metadata.get("fix", ""),
                source="semgrep",
            ))
        return findings
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []


# ══════════════════════════════════════════════════════════════
#  BUILT-IN REGEX SCANNER (fallback)
# ══════════════════════════════════════════════════════════════

# Language definitions: extensions → patterns
LANGUAGE_PATTERNS: dict[str, dict] = {
    # ── P0: Web Core ──
    "javascript": {
        "extensions": [".js", ".jsx", ".mjs", ".cjs"],
        "rules": [
            {
                "id": "js-sqli-template",
                "name": "SQL Injection (Template Literal)",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|[a-zA-Z0-9_]+)',
                "fix_hint": "Use parameterized queries with ? placeholders",
            },
            {
                "id": "js-sqli-concat",
                "name": "SQL Injection (String Concatenation)",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:SELECT|INSERT|UPDATE|DELETE).*\$\{',
                "fix_hint": "Use parameterized queries with ? placeholders",
            },
            {
                "id": "js-xss-innerhtml",
                "name": "XSS via innerHTML",
                "cwe": "CWE-79",
                "severity": "High",
                "pattern": r'\.innerHTML\s*=\s*(?![\'"]\s*$)',
                "fix_hint": "Use .textContent or sanitize with DOMPurify",
            },
            {
                "id": "js-xss-send",
                "name": "Reflected XSS (res.send)",
                "cwe": "CWE-79",
                "severity": "High",
                "pattern": r'res\.send\s*\(\s*`[^`]*\$\{',
                "fix_hint": "Escape user input before sending HTML responses",
            },
            {
                "id": "js-eval",
                "name": "Dangerous eval() Usage",
                "cwe": "CWE-95",
                "severity": "Critical",
                "pattern": r'\beval\s*\(\s*(?:req\.|request\.|params\.|query\.)',
                "fix_hint": "Never eval user input. Use JSON.parse() for data.",
            },
            {
                "id": "js-cmdi-exec",
                "name": "Command Injection (child_process)",
                "cwe": "CWE-78",
                "severity": "Critical",
                "pattern": r'(?:exec|execSync|spawn)\s*\(\s*`[^`]*\$\{',
                "fix_hint": "Use execFile with argument arrays, never shell strings",
            },
            {
                "id": "js-hardcoded-secret",
                "name": "Hardcoded Secret/API Key",
                "cwe": "CWE-798",
                "severity": "High",
                "pattern": r'(?:api[_-]?key|secret|password|token|auth)\s*[:=]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']',
                "fix_hint": "Move secrets to environment variables",
            },
            {
                "id": "js-path-traversal",
                "name": "Path Traversal",
                "cwe": "CWE-22",
                "severity": "High",
                "pattern": r'(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|params\.|query\.)',
                "fix_hint": "Validate and sanitize file paths, use path.resolve + allowlist",
            },
            {
                "id": "js-nosql-injection",
                "name": "NoSQL Injection",
                "cwe": "CWE-943",
                "severity": "Critical",
                "pattern": r'\.(?:find|findOne|updateOne|deleteOne)\s*\(\s*(?:req\.body|req\.query|req\.params)',
                "fix_hint": "Validate and sanitize MongoDB query objects",
            },
        ],
    },
    "typescript": {
        "extensions": [".ts", ".tsx"],
        "rules": "javascript",  # Inherit JS rules
    },
    # ── P0: Python ──
    "python": {
        "extensions": [".py"],
        "rules": [
            {
                "id": "py-sqli-fstring",
                "name": "SQL Injection (f-string)",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:execute|executemany|raw)\s*\(\s*f["\']',
                "fix_hint": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s', (id,))",
            },
            {
                "id": "py-sqli-format",
                "name": "SQL Injection (format/concat)",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:execute|executemany)\s*\([^)]*\.format\s*\(',
                "fix_hint": "Use parameterized queries with %s placeholders",
            },
            {
                "id": "py-cmdi",
                "name": "Command Injection (os/subprocess)",
                "cwe": "CWE-78",
                "severity": "Critical",
                "pattern": r'(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen))\s*\([^)]*(?:request\.|input\(|sys\.argv)',
                "fix_hint": "Use subprocess with shell=False and argument lists",
            },
            {
                "id": "py-eval",
                "name": "Dangerous eval/exec",
                "cwe": "CWE-95",
                "severity": "Critical",
                "pattern": r'\b(?:eval|exec)\s*\(\s*(?:request\.|input\(|sys\.argv)',
                "fix_hint": "Never eval user input. Use ast.literal_eval for data.",
            },
            {
                "id": "py-hardcoded-secret",
                "name": "Hardcoded Secret",
                "cwe": "CWE-798",
                "severity": "High",
                "pattern": r'(?:SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']',
                "fix_hint": "Use os.getenv() or a secrets manager",
            },
            {
                "id": "py-ssrf",
                "name": "SSRF (Server-Side Request Forgery)",
                "cwe": "CWE-918",
                "severity": "High",
                "pattern": r'requests\.(?:get|post|put|delete)\s*\(\s*(?:request\.|url\s*=)',
                "fix_hint": "Validate and allowlist target URLs",
            },
            {
                "id": "py-deserialize",
                "name": "Insecure Deserialization (pickle)",
                "cwe": "CWE-502",
                "severity": "Critical",
                "pattern": r'pickle\.(?:loads?|Unpickler)\s*\(',
                "fix_hint": "Never unpickle untrusted data. Use JSON instead.",
            },
        ],
    },
    # ── P1: Enterprise ──
    "java": {
        "extensions": [".java"],
        "rules": [
            {
                "id": "java-sqli",
                "name": "SQL Injection (String concat)",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:executeQuery|executeUpdate|prepareStatement)\s*\([^)]*\+\s*(?:request|param|input)',
                "fix_hint": "Use PreparedStatement with ? placeholders",
            },
            {
                "id": "java-xss",
                "name": "XSS (Unescaped output)",
                "cwe": "CWE-79",
                "severity": "High",
                "pattern": r'(?:getWriter|getOutputStream)\s*\(\s*\).*(?:request\.getParameter|getAttribute)',
                "fix_hint": "Use OWASP Encoder.forHtml() before output",
            },
            {
                "id": "java-cmdi",
                "name": "Command Injection",
                "cwe": "CWE-78",
                "severity": "Critical",
                "pattern": r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*(?:request|param|input)',
                "fix_hint": "Use ProcessBuilder with explicit argument arrays",
            },
            {
                "id": "java-deserialize",
                "name": "Insecure Deserialization",
                "cwe": "CWE-502",
                "severity": "Critical",
                "pattern": r'(?:ObjectInputStream|readObject)\s*\(',
                "fix_hint": "Implement ObjectInputFilter or use JSON/protobuf",
            },
        ],
    },
    "go": {
        "extensions": [".go"],
        "rules": [
            {
                "id": "go-sqli",
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:db\.Query|db\.Exec|db\.QueryRow)\s*\([^)]*(?:fmt\.Sprintf|"\s*\+)',
                "fix_hint": "Use db.Query(query, args...) with $1 placeholders",
            },
            {
                "id": "go-cmdi",
                "name": "Command Injection",
                "cwe": "CWE-78",
                "severity": "Critical",
                "pattern": r'exec\.Command\s*\(\s*(?:r\.Form|r\.URL|os\.Args)',
                "fix_hint": "Validate command arguments, use allowlists",
            },
        ],
    },
    "php": {
        "extensions": [".php"],
        "rules": [
            {
                "id": "php-sqli",
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
                "fix_hint": "Use PDO prepared statements",
            },
            {
                "id": "php-cmdi",
                "name": "Command Injection",
                "cwe": "CWE-78",
                "severity": "Critical",
                "pattern": r'(?:exec|system|passthru|shell_exec|popen)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
                "fix_hint": "Use escapeshellarg() and escapeshellcmd()",
            },
            {
                "id": "php-xss",
                "name": "XSS (Reflected)",
                "cwe": "CWE-79",
                "severity": "High",
                "pattern": r'echo\s+\$_(?:GET|POST|REQUEST)',
                "fix_hint": "Use htmlspecialchars() with ENT_QUOTES",
            },
            {
                "id": "php-file-include",
                "name": "Local File Inclusion",
                "cwe": "CWE-98",
                "severity": "Critical",
                "pattern": r'(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)',
                "fix_hint": "Use an allowlist of valid include paths",
            },
        ],
    },
    "ruby": {
        "extensions": [".rb", ".erb"],
        "rules": [
            {
                "id": "rb-sqli",
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'\.where\s*\(\s*"[^"]*#\{',
                "fix_hint": "Use .where('col = ?', value) with placeholders",
            },
            {
                "id": "rb-cmdi",
                "name": "Command Injection",
                "cwe": "CWE-78",
                "severity": "Critical",
                "pattern": r'(?:system|exec|`)\s*(?:\(?\s*"[^"]*#\{|params)',
                "fix_hint": "Use Open3.capture3 with separate arguments",
            },
        ],
    },
    # ── P2: Systems ──
    "c_cpp": {
        "extensions": [".c", ".cpp", ".cc", ".h", ".hpp"],
        "rules": [
            {
                "id": "c-buffer-overflow",
                "name": "Buffer Overflow Risk",
                "cwe": "CWE-120",
                "severity": "Critical",
                "pattern": r'\b(?:strcpy|strcat|sprintf|gets)\s*\(',
                "fix_hint": "Use strncpy, strncat, snprintf, fgets with size limits",
            },
            {
                "id": "c-format-string",
                "name": "Format String Vulnerability",
                "cwe": "CWE-134",
                "severity": "Critical",
                "pattern": r'printf\s*\(\s*(?!")[a-zA-Z_]',
                "fix_hint": "Always use format string: printf(\"%s\", user_input)",
            },
        ],
    },
    "csharp": {
        "extensions": [".cs"],
        "rules": [
            {
                "id": "cs-sqli",
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:SqlCommand|ExecuteReader|ExecuteNonQuery)\s*\([^)]*(?:\+\s*|"\s*\+\s*)(?:Request|input)',
                "fix_hint": "Use SqlParameter with parameterized queries",
            },
        ],
    },
    "rust": {
        "extensions": [".rs"],
        "rules": [
            {
                "id": "rs-unsafe",
                "name": "Unsafe Block Usage",
                "cwe": "CWE-119",
                "severity": "Medium",
                "pattern": r'\bunsafe\s*\{',
                "fix_hint": "Minimize unsafe blocks; document safety invariants",
            },
            {
                "id": "rs-sqli",
                "name": "SQL Injection (format!)",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:execute|query)\s*\(\s*&?format!\s*\(',
                "fix_hint": "Use query parameters: sqlx::query(\"SELECT * WHERE id=$1\").bind(id)",
            },
        ],
    },
    # ── P3: Mobile ──
    "swift": {
        "extensions": [".swift"],
        "rules": [
            {
                "id": "swift-hardcoded",
                "name": "Hardcoded Secret",
                "cwe": "CWE-798",
                "severity": "High",
                "pattern": r'(?:apiKey|secret|password|token)\s*[:=]\s*"[A-Za-z0-9+/=_\-]{16,}"',
                "fix_hint": "Use Keychain or environment configuration",
            },
        ],
    },
    "kotlin": {
        "extensions": [".kt", ".kts"],
        "rules": [
            {
                "id": "kt-sqli",
                "name": "SQL Injection",
                "cwe": "CWE-89",
                "severity": "Critical",
                "pattern": r'(?:rawQuery|execSQL)\s*\(\s*"[^"]*\$',
                "fix_hint": "Use query() with selectionArgs parameter",
            },
        ],
    },
    # ── P3: Infrastructure ──
    "dockerfile": {
        "extensions": ["Dockerfile", ".dockerfile"],
        "rules": [
            {
                "id": "docker-root",
                "name": "Container Running as Root",
                "cwe": "CWE-250",
                "severity": "Medium",
                "pattern": r'^(?!.*USER\s+\S).*(?:CMD|ENTRYPOINT)',
                "fix_hint": "Add USER directive before CMD/ENTRYPOINT",
            },
            {
                "id": "docker-latest",
                "name": "Using :latest Tag",
                "cwe": "CWE-1104",
                "severity": "Low",
                "pattern": r'FROM\s+\S+:latest',
                "fix_hint": "Pin to a specific version tag for reproducibility",
            },
        ],
    },
    "yaml": {
        "extensions": [".yml", ".yaml"],
        "rules": [
            {
                "id": "yaml-secret",
                "name": "Hardcoded Secret in Config",
                "cwe": "CWE-798",
                "severity": "High",
                "pattern": r'(?:password|secret|api_key|token)\s*:\s*["\']?[A-Za-z0-9+/=_\-]{16,}',
                "fix_hint": "Use environment variable references or secrets manager",
            },
        ],
    },
    # ── P3: Database / SQL files ──
    "sql": {
        "extensions": [".sql", ".sqlite", ".db"],
        "rules": [
            {
                "id": "sql-grant-all",
                "name": "Excessive DB Privileges (GRANT ALL)",
                "cwe": "CWE-250",
                "severity": "High",
                "pattern": r'GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+\*\.\*',
                "fix_hint": "Grant minimum required privileges per table",
            },
            {
                "id": "sql-no-password",
                "name": "User Created Without Password",
                "cwe": "CWE-521",
                "severity": "Critical",
                "pattern": r"CREATE\s+USER\s+['\"][^'\"]+['\"]\s*;",
                "fix_hint": "Always set a strong password: IDENTIFIED BY 'password'",
            },
            {
                "id": "sql-root-remote",
                "name": "Root Remote Access Enabled",
                "cwe": "CWE-284",
                "severity": "Critical",
                "pattern": r"GRANT\s+.*ON\s+.*TO\s+['\"]root['\"]@['\"]%['\"]",
                "fix_hint": "Restrict root to localhost: 'root'@'localhost'",
            },
            {
                "id": "sql-hardcoded-password",
                "name": "Hardcoded Password in SQL",
                "cwe": "CWE-798",
                "severity": "High",
                "pattern": r"(?:IDENTIFIED\s+BY|PASSWORD\s*=)\s*['\"][^'\"]{4,}['\"]",
                "fix_hint": "Use environment variables for database passwords",
            },
            {
                "id": "sql-plaintext-insert",
                "name": "Plaintext Password in INSERT",
                "cwe": "CWE-256",
                "severity": "High",
                "pattern": r"INSERT\s+INTO\s+\w*users?\w*.*(?:password|passwd|pwd)\s*.*VALUES\s*\(.*['\"][^'\"]{4,}['\"]",
                "fix_hint": "Hash passwords with bcrypt before storing",
            },
            {
                "id": "sql-drop-cascade",
                "name": "Dangerous DROP CASCADE",
                "cwe": "CWE-1188",
                "severity": "Medium",
                "pattern": r"DROP\s+(?:TABLE|DATABASE|SCHEMA)\s+.*CASCADE",
                "fix_hint": "Use DROP ... RESTRICT to prevent cascading deletes",
            },
        ],
    },
    # ── P3: Environment / Config files ──
    "env": {
        "extensions": [".env", ".env.local", ".env.development", ".env.production"],
        "rules": [
            {
                "id": "env-secret-exposed",
                "name": "Secret Exposed in .env File",
                "cwe": "CWE-312",
                "severity": "High",
                "pattern": r'(?:SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*\S{8,}',
                "fix_hint": "Never commit .env files. Add to .gitignore",
            },
            {
                "id": "env-debug-enabled",
                "name": "Debug Mode Enabled in Production",
                "cwe": "CWE-489",
                "severity": "Medium",
                "pattern": r'(?:DEBUG|NODE_ENV)\s*=\s*(?:true|development)',
                "fix_hint": "Set DEBUG=false and NODE_ENV=production in production",
            },
        ],
    },
}

# Resolve inheritance (e.g., TypeScript inherits JS rules)
for lang, data in LANGUAGE_PATTERNS.items():
    if isinstance(data.get("rules"), str):
        parent = data["rules"]
        data["rules"] = LANGUAGE_PATTERNS[parent]["rules"]


def _get_language_for_file(file_path: str) -> Optional[str]:
    """Detect language from file extension."""
    basename = os.path.basename(file_path)
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    for lang, data in LANGUAGE_PATTERNS.items():
        for lang_ext in data["extensions"]:
            if lang_ext.startswith(".") and ext == lang_ext:
                return lang
            if not lang_ext.startswith(".") and basename == lang_ext:
                return lang
    return None


def run_builtin_scan(source_dir: str) -> list[StaticFinding]:
    """
    Run the built-in regex scanner across all supported files.
    Falls back to this when Semgrep is not installed.
    """
    findings = []
    skip_dirs = {
        "node_modules", ".git", "__pycache__", "venv", ".venv",
        "dist", "build", ".next", "target", "vendor", "Pods",
    }

    for root, dirs, files in os.walk(source_dir):
        # Skip irrelevant directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for fname in files:
            fpath = os.path.join(root, fname)
            lang = _get_language_for_file(fpath)
            if not lang:
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            rules = LANGUAGE_PATTERNS[lang]["rules"]
            for line_num, line in enumerate(lines, start=1):
                for rule in rules:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        # ── False-positive suppression for parameterized queries ──
                        # If this is a SQLi rule, check whether the call already
                        # passes a params array (e.g., db.query(sql, [val]) or
                        # query(sql, params)).  Those are SAFE — skip them.
                        if rule["cwe"] == "CWE-89":
                            # Build a multi-line context window (current + next 2 lines)
                            context_window = line
                            for offset in range(1, 3):
                                if line_num - 1 + offset < len(lines):
                                    context_window += " " + lines[line_num - 1 + offset]
                            # Patterns that prove parameterised usage:
                            #   query(sql, [val1, val2])   query(sql, [email])
                            #   query(sql, params)         query(sql, values)
                            #   query(`...`, [val])        execute(sql, [val])
                            param_patterns = [
                                r'(?:query|execute|raw)\s*\([^,]+,\s*\[',        # second arg is array literal [...]
                                r'(?:query|execute|raw)\s*\([^,]+,\s*(?:params|values|args|bindings)\b',  # named params
                            ]
                            is_parameterised = any(
                                re.search(pp, context_window, re.IGNORECASE)
                                for pp in param_patterns
                            )
                            if is_parameterised:
                                continue  # Safe — already parameterised, skip finding

                        rel_path = os.path.relpath(fpath, source_dir)
                        findings.append(StaticFinding(
                            rule_id=rule["id"],
                            name=rule["name"],
                            severity=rule["severity"],
                            cwe=rule["cwe"],
                            file_path=rel_path,
                            line_number=line_num,
                            code_snippet=line.strip()[:120],
                            message=f"{rule['name']} detected in {lang}",
                            fix_hint=rule.get("fix_hint", ""),
                            source="builtin",
                        ))

    # Deduplicate (same rule + same file + same line)
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def run_static_analysis(source_dir: str) -> list[StaticFinding]:
    """
    Run static analysis on source code.
    Runs BOTH Semgrep (when available) AND the built-in 20-language scanner and
    returns the UNION (deduped) — the two were previously mutually exclusive, so
    turning Semgrep on silently shrank coverage to just one ruleset.
    """
    findings: list[StaticFinding] = []
    if semgrep_available():
        findings = run_semgrep(source_dir)

    builtin = run_builtin_scan(source_dir)
    seen = {(f.file_path, f.line_number, f.rule_id) for f in findings}
    for b in builtin:
        key = (b.file_path, b.line_number, b.rule_id)
        if key not in seen:
            seen.add(key)
            findings.append(b)
    return findings


def scan_single_file(file_path: str, source_dir: Optional[str] = None) -> list[StaticFinding]:
    """
    Scan exactly one file (used by the patch verifier for scoped re-scans).

    Uses Semgrep on the single file when available, otherwise the built-in
    regex rules. `file_path` may be absolute or relative; findings carry their
    `file_path` relative to `source_dir` when provided so they compare equal to
    the original scan's findings.
    """
    if not os.path.exists(file_path):
        return []

    findings: list[StaticFinding] = []
    if semgrep_available():
        findings = run_semgrep(file_path)

    if not findings:
        lang = _get_language_for_file(file_path)
        if lang:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                return []
            rules = LANGUAGE_PATTERNS[lang]["rules"]
            for line_num, line in enumerate(lines, start=1):
                for rule in rules:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append(StaticFinding(
                            rule_id=rule["id"],
                            name=rule["name"],
                            severity=rule["severity"],
                            cwe=rule["cwe"],
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip()[:120],
                            message=f"{rule['name']} detected in {lang}",
                            fix_hint=rule.get("fix_hint", ""),
                            source="builtin",
                        ))

    # Normalize file_path relative to source_dir for stable comparisons.
    if source_dir:
        for f in findings:
            try:
                if os.path.isabs(f.file_path):
                    f.file_path = os.path.relpath(f.file_path, source_dir)
            except ValueError:
                pass

    # Dedup (same rule + line)
    seen = set()
    unique = []
    for f in findings:
        k = (f.rule_id, f.line_number)
        if k not in seen:
            seen.add(k)
            unique.append(f)
    return unique
