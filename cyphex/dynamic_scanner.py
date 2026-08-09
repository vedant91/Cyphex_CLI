"""
CYPHEX — Dynamic Analysis Engine

Integrates industry-standard DAST tools for production-grade dynamic scanning.
Priority:
  1. Nuclei (lightweight, 8000+ templates, single binary)
  2. OWASP ZAP (comprehensive, requires Java — optional heavyweight)
  3. Built-in agents (current custom agents — always available fallback)

Usage:
    Nuclei: Install from https://github.com/projectdiscovery/nuclei
    ZAP:    Install from https://www.zaproxy.org/ (optional)
"""

import asyncio
import json
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DynamicFinding:
    """A vulnerability found by dynamic analysis."""
    name: str
    severity: str           # Critical | High | Medium | Low | Info
    cwe: str
    url: str
    method: str = "GET"
    evidence: str = ""
    description: str = ""
    template_id: str = ""   # Nuclei template or ZAP plugin ID
    source: str = "builtin"  # "nuclei" | "zap" | "builtin"
    fix_hint: str = ""
    curl_command: str = ""   # Reproducible PoC


# ══════════════════════════════════════════════════════════════
#  NUCLEI INTEGRATION (primary — lightweight)
# ══════════════════════════════════════════════════════════════

def nuclei_available() -> bool:
    """Check if Nuclei CLI is installed."""
    return shutil.which("nuclei") is not None


async def run_nuclei(
    target_url: str,
    severity: str = "critical,high,medium",
    templates: Optional[list[str]] = None,
    rate_limit: int = 50,
    timeout: int = 300,
) -> list[DynamicFinding]:
    """
    Run Nuclei scan against a target URL.
    Handles Windows by writing to a temp file instead of /dev/stdout.
    """
    is_windows = platform.system() == "Windows"
    out_path = None

    print(f"  → [DAST] Nuclei scanning {target_url}")
    print(f"  → [DAST] Severity: {severity} | Rate: {rate_limit} req/s")
    print(f"  → [DAST] Templates: cve,sqli,xss,rce,lfi,ssrf,redirect,exposure")

    cmd = [
        "nuclei",
        "-u", target_url,
        "-severity", severity,
        "-silent",
        "-duc",                          # Disable update check
        "-rate-limit", str(rate_limit),
        "-timeout", "10",               # Per-request timeout
        "-retries", "1",
        "-no-color",
    ]

    # Use web-specific templates by default
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    else:
        cmd.extend(["-tags", "cve,sqli,xss,rce,lfi,ssrf,redirect,exposure"])

    # Windows: /dev/stdout doesn't exist — write to temp file
    if is_windows:
        out_path = tempfile.mktemp(suffix=".jsonl")
        cmd.extend(["-o", out_path, "-json"])
    else:
        cmd.extend(["-json-export", "/dev/stdout"])

    try:
        proc = await asyncio.to_thread(
            subprocess.run, cmd,
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL
        )

        # Read output from temp file (Windows) or stdout (Linux/Mac)
        raw = ""
        if is_windows and out_path and os.path.exists(out_path):
            try:
                with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                    raw = f.read().strip()
            finally:
                os.remove(out_path)
        else:
            raw = proc.stdout.strip()

        if not raw:
            print(f"  → [DAST] Nuclei: No findings (target may be missing templates)")
            return []

        findings = []
        # Parse JSONL (one JSON object per line)
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                if isinstance(r, dict):
                    findings.append(_nuclei_to_finding(r))
            except json.JSONDecodeError:
                continue

        # Also try to parse as a single JSON array (fallback)
        if not findings:
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    for r in data:
                        if isinstance(r, dict):
                            findings.append(_nuclei_to_finding(r))
                elif isinstance(data, dict):
                    findings.append(_nuclei_to_finding(data))
            except json.JSONDecodeError:
                pass

        print(f"  → [DAST] Nuclei: {len(findings)} finding(s) confirmed")
        return findings

    except subprocess.TimeoutExpired:
        print(f"  → [DAST] Nuclei: Timed out after {timeout}s")
        if out_path and os.path.exists(out_path):
            os.remove(out_path)
        return []
    except FileNotFoundError:
        print(f"  → [DAST] Nuclei: Binary not found (run: cyphex setup)")
        return []


def _nuclei_to_finding(result: dict) -> DynamicFinding:
    """Convert a Nuclei JSON result to DynamicFinding."""
    info = result.get("info", {})
    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    # Extract CWE from classification
    classification = info.get("classification", {})
    cwe_list = classification.get("cwe-id", [])
    cwe = cwe_list[0] if cwe_list else "CWE-unknown"
    if isinstance(cwe, str) and not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"

    return DynamicFinding(
        name=info.get("name", result.get("template-id", "Unknown")),
        severity=severity_map.get(
            info.get("severity", "medium").lower(), "Medium"
        ),
        cwe=cwe,
        url=result.get("matched-at", result.get("host", "")),
        method=result.get("type", "http").upper(),
        evidence=result.get("extracted-results", result.get("matcher-name", "")),
        description=info.get("description", ""),
        template_id=result.get("template-id", ""),
        source="nuclei",
        curl_command=result.get("curl-command", ""),
    )


# ══════════════════════════════════════════════════════════════
#  OWASP ZAP INTEGRATION (optional — comprehensive)
# ══════════════════════════════════════════════════════════════

def zap_available() -> bool:
    """Check if OWASP ZAP is installed and its API is reachable."""
    # Check for zap CLI
    if shutil.which("zap-cli") or shutil.which("zap.sh") or shutil.which("zap-baseline.py"):
        return True
    # Check for Docker ZAP image
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}",
             "--filter", "reference=ghcr.io/zaproxy/zaproxy*"],
            capture_output=True, text=True, timeout=5
        )
        return "zaproxy" in result.stdout
    except Exception:
        return False


async def run_zap_baseline(
    target_url: str,
    timeout: int = 600,
) -> list[DynamicFinding]:
    """
    Run ZAP baseline scan (passive + spider, no active attack).
    Uses the Docker image for portability.

    For active scanning, use run_zap_full() instead.
    """
    # Prefer Docker ZAP (most portable)
    if _zap_docker_available():
        return await _run_zap_docker(target_url, scan_type="baseline", timeout=timeout)

    # Fall back to local ZAP
    zap_cli = shutil.which("zap-baseline.py") or shutil.which("zap-cli")
    if not zap_cli:
        return []

    try:
        result = await asyncio.to_thread(
            subprocess.run,
            [zap_cli, "-t", target_url, "-J", "zap_report.json", "-I"],
            capture_output=True, text=True, timeout=timeout
        )

        # Parse JSON report
        report_path = "zap_report.json"
        if os.path.exists(report_path):
            with open(report_path) as f:
                data = json.load(f)
            os.remove(report_path)
            return _parse_zap_report(data)

    except Exception:
        pass

    return []


async def run_zap_full(
    target_url: str,
    timeout: int = 1200,
) -> list[DynamicFinding]:
    """
    Run ZAP full active scan (spider + passive + active attack).
    WARNING: This actively attacks the target. Only use against sandboxed apps.
    """
    if _zap_docker_available():
        return await _run_zap_docker(target_url, scan_type="full-scan", timeout=timeout)
    return []


def _zap_docker_available() -> bool:
    """Check if ZAP Docker image is available."""
    try:
        result = subprocess.run(
            ["docker", "images", "-q", "ghcr.io/zaproxy/zaproxy:stable"],
            capture_output=True, text=True, timeout=5
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


async def _run_zap_docker(
    target_url: str,
    scan_type: str = "baseline",
    timeout: int = 600,
) -> list[DynamicFinding]:
    """Run ZAP scan via Docker."""
    report_name = f"zap_report_{os.getpid()}.json"

    # Map scan type to ZAP script
    script = {
        "baseline": "zap-baseline.py",
        "full-scan": "zap-full-scan.py",
        "api-scan": "zap-api-scan.py",
    }.get(scan_type, "zap-baseline.py")

    cmd = [
        "docker", "run", "--rm",
        "--network", "host",  # Access localhost targets
        "-v", f"{os.getcwd()}:/zap/wrk:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        script,
        "-t", target_url,
        "-J", report_name,
        "-I",  # Don't fail on warnings
    ]

    try:
        await asyncio.to_thread(
            subprocess.run, cmd,
            capture_output=True, text=True, timeout=timeout
        )

        report_path = os.path.join(os.getcwd(), report_name)
        if os.path.exists(report_path):
            with open(report_path) as f:
                data = json.load(f)
            os.remove(report_path)
            return _parse_zap_report(data)

    except Exception:
        pass

    return []


def _parse_zap_report(data: dict) -> list[DynamicFinding]:
    """Parse ZAP JSON report into DynamicFindings."""
    findings = []
    zap_severity_map = {
        "0": "Info",
        "1": "Low",
        "2": "Medium",
        "3": "High",
    }

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            severity = zap_severity_map.get(
                str(alert.get("riskcode", "2")), "Medium"
            )

            # Extract CWE
            cwe_id = alert.get("cweid", "")
            cwe = f"CWE-{cwe_id}" if cwe_id and cwe_id != "-1" else "CWE-unknown"

            # Get first instance for evidence
            instances = alert.get("instances", [])
            first_instance = instances[0] if instances else {}

            findings.append(DynamicFinding(
                name=alert.get("name", "Unknown"),
                severity=severity,
                cwe=cwe,
                url=first_instance.get("uri", site.get("@name", "")),
                method=first_instance.get("method", "GET"),
                evidence=first_instance.get("evidence", ""),
                description=alert.get("desc", ""),
                template_id=f"zap-{alert.get('pluginid', 'unknown')}",
                source="zap",
                fix_hint=alert.get("solution", ""),
            ))

    return findings


# ══════════════════════════════════════════════════════════════
#  UNIFIED DYNAMIC SCAN RUNNER
# ══════════════════════════════════════════════════════════════

async def run_dynamic_analysis(
    target_url: str,
    use_active_scan: bool = False,
) -> tuple[list[DynamicFinding], str]:
    """
    Run dynamic analysis using the best available tool.
    Returns: (findings, tool_used)

    Priority: Nuclei → ZAP → built-in agents (handled by caller)
    """
    # 1. Try Nuclei (lightweight, fast)
    if nuclei_available():
        findings = await run_nuclei(target_url)
        if findings:
            return findings, "nuclei"

    # 2. Try ZAP (comprehensive, heavyweight)
    if zap_available():
        if use_active_scan:
            findings = await run_zap_full(target_url)
        else:
            findings = await run_zap_baseline(target_url)
        if findings:
            return findings, "zap"

    # 3. Fallback: return empty (caller uses built-in agents)
    return [], "builtin"
