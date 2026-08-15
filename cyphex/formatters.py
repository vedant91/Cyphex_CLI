"""
CYPHEX — Output Formatters

Converts scan results into different output formats:
  - table:    Rich terminal table (default)
  - json:     Machine-readable JSON
  - sarif:    SARIF v2.1.0 (GitHub/IDE integration)
  - markdown: Human-readable report
"""

import json
import re
from datetime import datetime, timezone
from typing import Any

# Matches ANSI/VT escape sequences (e.g. "\x1b[31m") so scanned-repo content
# can't inject terminal control codes into rendered reports.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
# Any other C0 control character except newline (\n) and tab (\t).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Markdown characters that could break out of the surrounding structure
# (emphasis, code spans, links) if left unescaped.
_MD_SPECIAL_RE = re.compile(r"([`*_\[\]])")


def _sanitize_for_markdown(value: Any) -> str:
    """Neutralize attacker-controlled scan content (evidence, descriptions,
    fix hints, code snippets) before embedding it in a generated Markdown
    report: strip ANSI/control characters, then escape Markdown metacharacters.
    """
    if value is None:
        return ""
    text = str(value)
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    text = _MD_SPECIAL_RE.sub(r"\\\1", text)
    return text


def to_json(scan_result: dict) -> str:
    """Format scan result as pretty JSON."""
    return json.dumps(scan_result, indent=2, default=str)


def to_sarif(scan_result: dict) -> str:
    """
    Format scan result as SARIF v2.1.0.
    Compatible with GitHub Code Scanning, VS Code SARIF Viewer, etc.
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CYPHEX",
                    "version": scan_result.get("version", "0.1.0"),
                    "informationUri": "https://github.com/Punya23/Cyphex_CLI",
                    "rules": [],
                }
            },
            "results": [],
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": scan_result.get("timestamp", datetime.now(timezone.utc).isoformat()),
            }],
        }]
    }

    rules_seen = set()
    run = sarif["runs"][0]

    for vuln in scan_result.get("vulnerabilities", []):
        rule_id = vuln.get("cwe", "CWE-unknown")

        # Add rule definition if not yet seen
        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": vuln.get("name", "Unknown"),
                "shortDescription": {"text": vuln.get("name", "Unknown vulnerability")},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(vuln.get("severity", "Medium"))
                },
            })

        # Add result
        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(vuln.get("severity", "Medium")),
            "message": {"text": vuln.get("description", vuln.get("name", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": vuln.get("endpoint", vuln.get("file_path", "unknown")),
                    },
                    "region": {
                        "startLine": vuln.get("line_number", 1),
                    }
                }
            }],
        }
        run["results"].append(result)

    return json.dumps(sarif, indent=2)


def to_markdown(scan_result: dict) -> str:
    """Format scan result as a Markdown report."""
    lines = []
    summary = scan_result.get("summary", {})
    score = scan_result.get("score", 0)

    lines.append("# CYPHEX Security Assessment Report\n")
    lines.append(f"**Scan ID:** `{scan_result.get('scan_id', 'N/A')}`  ")
    lines.append(f"**Target:** `{scan_result.get('target', 'N/A')}`  ")
    lines.append(f"**Timestamp:** {scan_result.get('timestamp', 'N/A')}  ")
    lines.append(f"**Duration:** {summary.get('duration_seconds', 0)}s  ")
    lines.append(f"**Score:** **{score}/100**\n")

    lines.append("## Summary\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| 🔴 Critical | {summary.get('critical', 0)} |")
    lines.append(f"| 🟠 High | {summary.get('high', 0)} |")
    lines.append(f"| 🟡 Medium | {summary.get('medium', 0)} |")
    lines.append(f"| 🔵 Low | {summary.get('low', 0)} |")
    lines.append(f"| **Total** | **{summary.get('total_vulns', 0)}** |\n")

    vulns = scan_result.get("vulnerabilities", [])
    if vulns:
        lines.append("## Vulnerabilities\n")
        for i, v in enumerate(vulns, 1):
            sev = v.get("severity", "Unknown")
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(sev, "⚪")
            # These fields (name, cwe, endpoint, description, evidence,
            # fix_hint, code snippets) can contain attacker-influenced content
            # pulled straight from the scanned repo — sanitize before
            # embedding them in the generated Markdown report.
            name = _sanitize_for_markdown(v.get("name", "Unknown"))
            cwe = _sanitize_for_markdown(v.get("cwe", ""))
            endpoint = _sanitize_for_markdown(v.get("endpoint", "N/A"))
            lines.append(f"### {i}. {icon} {name} ({cwe})\n")
            lines.append(f"- **Severity:** {sev}")
            lines.append(f"- **Endpoint:** `{endpoint}`")
            if v.get("description"):
                lines.append(f"- **Description:** {_sanitize_for_markdown(v['description'])}")
            if v.get("evidence"):
                lines.append(f"- **Evidence:** `{_sanitize_for_markdown(v['evidence'])}`")
            if v.get("fix_hint"):
                lines.append(f"- **Fix:** {_sanitize_for_markdown(v['fix_hint'])}")
            if v.get("code_snippet"):
                lines.append(f"- **Code:**\n\n```\n{_sanitize_for_markdown(v['code_snippet'])}\n```")
            lines.append("")
    else:
        lines.append("## ✅ No Vulnerabilities Found\n")

    lines.append("---\n*Generated by [CYPHEX](https://github.com/Punya23/Cyphex_CLI)*\n")
    return "\n".join(lines)


def _severity_to_sarif_level(severity: str) -> str:
    """Map CYPHEX severity to SARIF level."""
    return {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Info": "note",
    }.get(severity, "warning")


def format_output(scan_result: dict, fmt: str = "json") -> str:
    """Format scan result in the specified format."""
    formatters = {
        "json": to_json,
        "sarif": to_sarif,
        "markdown": to_markdown,
    }
    formatter = formatters.get(fmt, to_json)
    return formatter(scan_result)
