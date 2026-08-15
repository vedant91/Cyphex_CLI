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
import difflib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

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
    finding_gone: Optional[bool]  # True=confirmed gone, False=still present, None=couldn't verify
    builds: Optional[bool]  # True=parses, False=syntax error, None=couldn't check this file type
    endpoint_alive: bool    # Benign request still works (True if n/a)
    no_suppression: bool    # No scanner suppression comments added
    blast_ok: bool          # Diff within size cap
    verdict: str            # "PASS" | "FAIL" | "UNVERIFIABLE"
    evidence: dict = field(default_factory=dict)  # Concrete failure details

    @staticmethod
    def compute_verdict(finding_gone, builds, endpoint_alive, no_suppression, blast_ok) -> str:
        """
        finding_gone and builds are tri-state (True / False / None). None means
        "this check could not be run" and must NEVER be silently treated as a
        pass — that's exactly how a scanner error or an unsupported language
        used to produce a false PASS.

        endpoint_alive / no_suppression / blast_ok are plain booleans (already
        True when not applicable) — an observed False there is a real,
        measured failure, not an "couldn't check" state.
        """
        tri_state_checks = (finding_gone, builds)

        # Any check that actually ran and failed → FAIL, no ambiguity.
        if any(c is False for c in tri_state_checks):
            return "FAIL"
        if not (endpoint_alive and no_suppression and blast_ok):
            return "FAIL"

        # Nothing failed, but at least one check couldn't be run at all →
        # UNVERIFIABLE. Never claim PASS for something that wasn't measured.
        if any(c is None for c in tri_state_checks):
            return "UNVERIFIABLE"

        return "PASS"


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

    # Build check — parse_valid is tri-state (True/False/None). None means the
    # applier couldn't check syntax for this file type (e.g. not Python/JS/TS)
    # — that must contribute to UNVERIFIABLE, not silently pass as "builds=True".
    builds = parse_valid
    if builds is False:
        evidence["build_error"] = "Patch failed syntax validation"
    elif builds is None:
        evidence["build_unverifiable"] = "Could not validate syntax for this file type"

    # Anti-suppression check
    no_suppression = _check_no_suppression(original_content, patched_content)
    if not no_suppression:
        evidence["suppression"] = "Patch added scanner-suppression comments"

    # Blast radius check
    blast_ok = _check_blast_radius(original_content, patched_content, blast_radius_cap)
    if not blast_ok:
        evidence["blast_radius"] = f"Diff exceeds {blast_radius_cap} lines"

    # Re-scan the patched file. finding_gone is tri-state: True (confirmed
    # gone), False (still present), or None (scanner unavailable/errored —
    # never treated as "fixed").
    finding_gone = _rescan_file(location, vuln, source_dir)
    if finding_gone is False:
        evidence["rescan"] = f"Finding {vuln.cwe or vuln.name} still present after patch"
    elif finding_gone is None:
        evidence["rescan_unverifiable"] = "Static scanner unavailable — could not confirm the finding is gone"

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
            kind="none", finding_gone=None, builds=True,
            endpoint_alive=False, no_suppression=True, blast_ok=True,
            verdict="UNVERIFIABLE",
            evidence={"error": "httpx not available for replay"},
        )

    evidence = {}
    url = location.url
    method = location.method or "GET"
    payload = getattr(vuln, "payload", "") or ""

    # 1. Replay the exploit. finding_gone is tri-state: True (exploit
    # confirmed blocked), False (still exploitable), or None (replay was
    # inconclusive — e.g. timeout/connection error — never treated as fixed).
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
    """
    Check if the diff is within the blast radius cap.

    Uses difflib.SequenceMatcher to compute a REAL line diff rather than a
    positional (index-by-index) comparison. A positional comparison massively
    over-counts: inserting or deleting a single line shifts every subsequent
    line, so the naive approach would count the entire rest of the file as
    "changed" even though only one line actually changed.
    """
    if not original or not patched:
        return True

    orig_lines = original.split("\n")
    patch_lines = patched.split("\n")

    matcher = difflib.SequenceMatcher(a=orig_lines, b=patch_lines, autojunk=False)
    changed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        # For a replace/insert/delete hunk, count the larger side (lines
        # removed vs. lines added) as the number of "changed lines".
        changed += max(i2 - i1, j2 - j1)

    return changed <= cap


# ═══════════════════════════════════════════════════════════════
# Scanner Re-run (Static)
# ═══════════════════════════════════════════════════════════════

def _rescan_file(location, vuln, source_dir: str) -> Optional[bool]:
    """
    Re-run the static scanner on the patched file.

    Returns True if the original finding is confirmed gone, False if it's
    confirmed still present, or None if the scanner could not be run at all
    (missing dependency / scanner crash). None must be treated by the caller
    as UNVERIFIABLE — it is NOT evidence the fix worked, so it must never be
    coerced into a "PASS".
    """
    try:
        from cyphex.scanner import run_static_analysis
    except ImportError:
        return None  # Can't verify — caller must mark UNVERIFIABLE, never PASS

    try:
        # flag_comments=False: the scanner normally treats a match inside a
        # comment as a false positive, but here that would let a patch which
        # merely comments the vulnerable line out register as "finding gone".
        # Verification sees commented matches; ordinary scans do not.
        findings = run_static_analysis(source_dir, flag_comments=False)
    except Exception:
        return None  # Scanner error — can't determine, never PASS

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
    """
    Check if two file paths refer to the same file, via exact or
    relative-path comparison only.

    Deliberately does NOT fall back to a basename-only match (e.g.
    "orders.js" == "orders.js" regardless of directory): two files can share
    a basename in different directories, and matching on basename alone
    could make _rescan_file compare the wrong file's scanner findings
    against this location — silently reporting a finding as "gone" (or
    "still present") based on an unrelated file. Mirrors the same
    basename-collision fix applied to resolver.py's file resolution.
    """
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

    return False


# ═══════════════════════════════════════════════════════════════
# Exploit Replay (Dynamic)
# ═══════════════════════════════════════════════════════════════

def _tls_verify_for(url: str) -> bool:
    """
    Only disable TLS certificate verification when the target is a loopback
    address (i.e. the local sandbox CYPHEX itself spun up) — never for an
    arbitrary remote host, where skipping verification would allow a
    man-in-the-middle to fake a "vuln fixed" response.
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return True
    return host not in ("localhost", "127.0.0.1", "::1")


async def _replay_exploit(url: str, method: str, payload: str, vuln, evidence: dict) -> Optional[bool]:
    """
    Replay the original exploit.

    Returns True if the vuln is confirmed GONE (exploit blocked), False if
    it's confirmed still exploitable, or None if the replay was inconclusive
    (e.g. connection error/timeout) — an inconclusive result must NEVER be
    treated as "fixed"; the caller marks it UNVERIFIABLE instead.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=_tls_verify_for(url)) as client:
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
        evidence["replay_unverifiable"] = (
            "Exploit replay could not be completed (network/timeout error) — "
            "treated as inconclusive, NOT as fixed"
        )
        return None  # Inconclusive — never report "fixed" on an exception


async def _check_liveness(url: str, evidence: dict) -> bool:
    """Check that the endpoint still responds to benign requests."""
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=_tls_verify_for(url)) as client:
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
