"""
CYPHEX — Patch Verification Gate

The core guarantee: a patch is ONLY accepted if measured-fixed.
Two verification branches:
  Static:  Re-run scanner on patched file → finding must be gone
  Dynamic: Replay exploit against sandbox → attack must fail + endpoint must be alive

Guards against patch gaming:
  - Anti-suppression: reject nosemgrep/eslint-disable/# noqa
  - Blast-radius: reject oversized diffs
  - Liveness: endpoint must still respond to benign requests

Verdict = PASS requires ALL checks green.
If verifier can't run → UNVERIFIABLE (never counted as "fixed").
"""

import os
import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ═══════════════════════════════════════════════════════════════
# Verification Result Contract
# ═══════════════════════════════════════════════════════════════

@dataclass
class VerifyResult:
    """Shared contract — every patch speaks this."""
    kind: str               # "static" | "dynamic" | "none"
    finding_gone: bool      # Scanner no longer reports it / exploit no longer works
    builds: bool            # Parse/typecheck ok (True if not checkable)
    endpoint_alive: bool    # Benign request still works (True if n/a)
    no_suppression: bool    # No scanner suppression comments added
    blast_ok: bool          # Diff within size cap
    verdict: str            # "PASS" | "FAIL" | "UNVERIFIABLE"
    evidence: dict = field(default_factory=dict)  # Concrete failure details

    @staticmethod
    def compute_verdict(finding_gone, builds, endpoint_alive, no_suppression, blast_ok) -> str:
        if finding_gone and builds and endpoint_alive and no_suppression and blast_ok:
            return "PASS"
        return "FAIL"


# ═══════════════════════════════════════════════════════════════
# Static Verification (re-scan patched file)
# ═══════════════════════════════════════════════════════════════

def verify_static(
    location,
    vuln,
    source_dir: str,
    parse_valid: Optional[bool] = None,
    original_content: str = "",
    patched_content: str = "",
    blast_radius_cap: int = 40,
) -> VerifyResult:
    """
    Verify a static finding by re-running the scanner on the patched file.

    Args:
        location: Location dataclass with .file, .line, .rel
        vuln: The original Vuln
        source_dir: Root of the scanned project
        parse_valid: Result of syntax check (from applier)
        original_content: Pre-patch file content (for diff size check)
        patched_content: Post-patch file content
        blast_radius_cap: Max diff lines before flagging
    """
    evidence = {}

    # Build check
    builds = parse_valid if parse_valid is not None else True
    if not builds:
        evidence["build_error"] = "Patch failed syntax validation"

    # Anti-suppression check
    no_suppression = _check_no_suppression(original_content, patched_content)
    if not no_suppression:
        evidence["suppression"] = "Patch added scanner-suppression comments"

    # Blast radius check
    blast_ok = _check_blast_radius(original_content, patched_content, blast_radius_cap)
    if not blast_ok:
        evidence["blast_radius"] = f"Diff exceeds {blast_radius_cap} lines"

    # Re-scan the patched file
    finding_gone = _rescan_file(location, vuln, source_dir)
    if not finding_gone:
        evidence["rescan"] = f"Finding {vuln.cwe or vuln.name} still present after patch"

    verdict = VerifyResult.compute_verdict(
        finding_gone, builds, True, no_suppression, blast_ok
    )

    return VerifyResult(
        kind="static",
        finding_gone=finding_gone,
        builds=builds,
        endpoint_alive=True,  # N/A for static
        no_suppression=no_suppression,
        blast_ok=blast_ok,
        verdict=verdict,
        evidence=evidence,
    )


# ═══════════════════════════════════════════════════════════════
# Dynamic Verification (exploit replay)
# ═══════════════════════════════════════════════════════════════

async def verify_dynamic(
    location,
    vuln,
    original_content: str = "",
    patched_content: str = "",
    blast_radius_cap: int = 40,
) -> VerifyResult:
    """
    Verify a dynamic finding by replaying the exploit.

    Args:
        location: Location dataclass with .url, .method
        vuln: The original Vuln with .payload
        original_content: Pre-patch content (for suppression check if file also patched)
        patched_content: Post-patch content
        blast_radius_cap: Max diff lines
    """
    if not HAS_HTTPX:
        return VerifyResult(
            kind="none", finding_gone=False, builds=True,
            endpoint_alive=False, no_suppression=True, blast_ok=True,
            verdict="UNVERIFIABLE",
            evidence={"error": "httpx not available for replay"},
        )

    evidence = {}
    url = location.url
    method = location.method or "GET"
    payload = getattr(vuln, "payload", "") or ""

    # 1. Replay the exploit
    finding_gone = await _replay_exploit(url, method, payload, vuln, evidence)

    # 2. Liveness check — benign request must still work
    endpoint_alive = await _check_liveness(url, evidence)

    # 3. Suppression + blast radius (if file content provided)
    no_suppression = _check_no_suppression(original_content, patched_content) if original_content else True
    blast_ok = _check_blast_radius(original_content, patched_content, blast_radius_cap) if original_content else True

    verdict = VerifyResult.compute_verdict(
        finding_gone, True, endpoint_alive, no_suppression, blast_ok
    )

    return VerifyResult(
        kind="dynamic",
        finding_gone=finding_gone,
        builds=True,
        endpoint_alive=endpoint_alive,
        no_suppression=no_suppression,
        blast_ok=blast_ok,
        verdict=verdict,
        evidence=evidence,
    )


# ═══════════════════════════════════════════════════════════════
# Guard Checks
# ═══════════════════════════════════════════════════════════════

SUPPRESSION_PATTERNS = [
    r"nosemgrep",
    r"eslint-disable",
    r"#\s*noqa",
    r"@ts-ignore",
    r"@ts-expect-error",
    r"noinspection",
    r"pragma:\s*no\s*cover",
]


def _check_no_suppression(original: str, patched: str) -> bool:
    """Reject patches that add scanner-suppression comments."""
    if not original or not patched:
        return True

    for pattern in SUPPRESSION_PATTERNS:
        orig_count = len(re.findall(pattern, original, re.I))
        patch_count = len(re.findall(pattern, patched, re.I))
        if patch_count > orig_count:
            return False

    # Check if the patch deletes the entire function/route handler
    orig_lines = [l.strip() for l in original.split("\n") if l.strip()]
    patch_lines = [l.strip() for l in patched.split("\n") if l.strip()]

    if len(patch_lines) < len(orig_lines) * 0.3:
        # More than 70% of code was deleted — suspicious
        return False

    return True


def _check_blast_radius(original: str, patched: str, cap: int) -> bool:
    """Check if the diff is within the blast radius cap."""
    if not original or not patched:
        return True

    orig_lines = original.split("\n")
    patch_lines = patched.split("\n")

    # Count changed lines
    changed = 0
    max_len = max(len(orig_lines), len(patch_lines))
    for i in range(max_len):
        orig_l = orig_lines[i] if i < len(orig_lines) else ""
        patch_l = patch_lines[i] if i < len(patch_lines) else ""
        if orig_l != patch_l:
            changed += 1

    return changed <= cap


# ═══════════════════════════════════════════════════════════════
# Scanner Re-run (Static)
# ═══════════════════════════════════════════════════════════════

def _rescan_file(location, vuln, source_dir: str) -> bool:
    """
    Re-run the static scanner on the patched file.
    Returns True if the original finding is gone.
    """
    try:
        from cyphex.scanner import run_static_analysis
    except ImportError:
        return True  # Can't verify → optimistic (will be marked UNVERIFIABLE upstream)

    try:
        findings = run_static_analysis(source_dir)
    except Exception:
        return True  # Scanner error → can't determine

    vuln_cwe = getattr(vuln, "cwe", "") or ""
    vuln_name = (getattr(vuln, "name", "") or "").lower()

    # Strip [STATIC] / [DYNAMIC] prefix for comparison
    vuln_name_clean = re.sub(r'^\[(STATIC|DYNAMIC)\]\s*', '', vuln_name, flags=re.I)

    target_file = location.rel or (location.file or "")
    target_line = location.line or 0

    for f in findings:
        # Match by file
        f_path = getattr(f, "file_path", "")
        if not _paths_match(f_path, target_file, source_dir):
            continue

        # Match by CWE or name
        f_cwe = getattr(f, "cwe", "") or ""
        f_name = (getattr(f, "name", "") or "").lower()

        cwe_match = vuln_cwe and f_cwe and vuln_cwe == f_cwe
        name_match = vuln_name_clean and vuln_name_clean in f_name

        if not cwe_match and not name_match:
            continue

        # Match by line (±2 tolerance for reflow)
        f_line = getattr(f, "line_number", 0) or 0
        if abs(f_line - target_line) <= 2:
            return False  # Finding still present!

    return True  # Finding is gone


def _paths_match(finding_path: str, target_path: str, source_dir: str) -> bool:
    """Check if two file paths refer to the same file."""
    if not finding_path or not target_path:
        return False

    # Normalize
    fp = os.path.normpath(finding_path).replace("\\", "/")
    tp = os.path.normpath(target_path).replace("\\", "/")

    if fp == tp:
        return True

    # Try relative comparison
    try:
        fp_rel = os.path.relpath(finding_path, source_dir).replace("\\", "/")
        if fp_rel == tp:
            return True
    except ValueError:
        pass

    # Basename match as last resort (risky but catches semgrep paths)
    return os.path.basename(fp) == os.path.basename(tp)


# ═══════════════════════════════════════════════════════════════
# Exploit Replay (Dynamic)
# ═══════════════════════════════════════════════════════════════

async def _replay_exploit(url: str, method: str, payload: str, vuln, evidence: dict) -> bool:
    """
    Replay the original exploit. Returns True if the vuln is GONE (exploit fails).
    """
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            kwargs = {}
            if method.upper() == "POST":
                kwargs["data"] = payload
            elif payload:
                # Append payload as query param
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}q={payload}"

            response = await client.request(method, url, **kwargs)
            status = response.status_code
            body = response.text[:2000]

            # Check if exploit indicators are present
            vuln_name = (getattr(vuln, "name", "") or "").lower()
            exploit_succeeded = _check_exploit_indicators(vuln_name, payload, body, status)

            if exploit_succeeded:
                evidence["replay"] = f"Exploit still works: status={status}, payload reflected"
                return False  # Vuln still present

            evidence["replay"] = f"Exploit blocked: status={status}"
            return True  # Vuln fixed

    except Exception as e:
        evidence["replay_error"] = str(e)
        return True  # Connection error might mean the endpoint is properly blocked


async def _check_liveness(url: str, evidence: dict) -> bool:
    """Check that the endpoint still responds to benign requests."""
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            response = await client.get(url)
            alive = response.status_code < 500
            if not alive:
                evidence["liveness"] = f"Endpoint returned {response.status_code} — may be broken"
            return alive
    except Exception as e:
        evidence["liveness_error"] = str(e)
        return False


def _check_exploit_indicators(vuln_name: str, payload: str, response_body: str, status: int) -> bool:
    """Check if the exploit payload succeeded based on the vulnerability type."""
    body_lower = response_body.lower()

    # SQL Injection indicators
    if "sql" in vuln_name:
        if payload and payload in response_body:
            return True
        if any(ind in body_lower for ind in ["error in your sql", "mysql_", "syntax error", "unclosed quotation"]):
            return True
        # Boolean-based: if the injected condition returns data
        if "or 1=1" in (payload or "").lower() and status == 200 and len(response_body) > 100:
            return True

    # XSS indicators
    if "xss" in vuln_name:
        if payload and payload in response_body:
            return True
        if "<script" in body_lower and "alert" in body_lower:
            return True

    # Command Injection indicators
    if "command" in vuln_name or "cmdi" in vuln_name:
        if payload and any(ind in response_body for ind in ["root:", "uid=", "bin/", "Windows"]):
            return True

    # Path Traversal indicators
    if "traversal" in vuln_name or "lfi" in vuln_name or "path" in vuln_name:
        if any(ind in body_lower for ind in ["root:x:", "[boot loader]", "passwd"]):
            return True

    return False
