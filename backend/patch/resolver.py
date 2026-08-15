"""
CYPHEX — Location Resolver

Parses Vuln.endpoint into a structured Location.
Single source of truth for "where is this vulnerability?"

Two forms:
  Static:  "relative/path/file.js:42" → Location(kind="file", file=abs_path, line=42)
  Dynamic: "http://localhost:PORT/login" → Location(kind="url", url=..., method="GET")
"""

import os
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Location:
    """Resolved vulnerability location."""
    kind: str               # "file" | "url"
    file: Optional[str]     # Absolute path to source file (static only)
    rel: Optional[str]      # Repo-relative path (for display + manifest)
    line: Optional[int]     # Line number in file (static only)
    url: Optional[str]      # Live URL (dynamic only)
    method: str = "GET"     # HTTP method (dynamic only)


def resolve(vuln, source_dir: str) -> Optional[Location]:
    """
    Parse a Vuln's endpoint field into a structured Location.

    Args:
        vuln: A Vuln dataclass with .endpoint, .name, .evidence fields
        source_dir: Absolute path to the scanned source directory

    Returns:
        Location or None if the endpoint is unparseable
    """
    endpoint = (vuln.endpoint or "").strip()
    if not endpoint:
        return None

    # ── Dynamic finding: endpoint is a URL ──
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        method = _extract_method(vuln)
        return Location(
            kind="url",
            file=None,
            rel=None,
            line=None,
            url=endpoint,
            method=method,
        )

    # ── Static finding: endpoint is "path/to/file.ext:linenum" ──
    if ":" in endpoint:
        parts = endpoint.rsplit(":", 1)
        file_part = parts[0].strip()
        line_part = parts[1].strip().split()[0] if len(parts) > 1 else ""

        # Line must be a valid integer
        try:
            line_num = int(line_part)
        except (ValueError, IndexError):
            return None

        # Resolve to absolute path
        abs_path = _resolve_file_path(file_part, source_dir)
        if abs_path is None:
            return None

        # Compute repo-relative path
        try:
            rel_path = os.path.relpath(abs_path, source_dir)
        except ValueError:
            rel_path = file_part

        return Location(
            kind="file",
            file=abs_path,
            rel=rel_path,
            line=line_num,
            url=None,
        )

    return None


def _contain(candidate: str, source_dir: str) -> Optional[str]:
    """
    Security guard: only allow a candidate path that resolves (after following
    any symlinks) to somewhere inside source_dir. Returns the realpath if safe,
    else None.

    Rejects:
      - Any path whose realpath escapes source_dir (path traversal / absolute
        path injection via a crafted vuln.endpoint).
      - Symlinks — a symlink inside source_dir can point anywhere on disk, so
        allowing it would defeat the containment check above.
    """
    if not os.path.isfile(candidate):
        return None
    if os.path.islink(candidate):
        return None

    real_source = os.path.realpath(source_dir)
    real_candidate = os.path.realpath(candidate)

    if real_candidate == real_source or real_candidate.startswith(real_source + os.sep):
        return real_candidate
    return None


def _resolve_file_path(file_ref: str, source_dir: str) -> Optional[str]:
    """
    Resolve a file reference to an absolute path.
    Handles both relative and absolute paths, and semgrep-style paths.

    Every candidate is passed through _contain() so a maliciously crafted
    vuln.endpoint (e.g. "/etc/passwd" or "../../../../etc/passwd:1") can never
    resolve to a file outside source_dir — this is what applier.py relies on
    (along with its own second guard) before it ever opens a file for writing.
    """
    # Already absolute and exists
    if os.path.isabs(file_ref) and os.path.isfile(file_ref):
        contained = _contain(file_ref, source_dir)
        if contained:
            return os.path.normpath(contained)
        return None

    # Relative to source_dir
    candidate = os.path.normpath(os.path.join(source_dir, file_ref))
    contained = _contain(candidate, source_dir)
    if contained:
        return contained

    # Try stripping leading slashes or common prefixes
    stripped = file_ref.lstrip("/\\")
    candidate = os.path.normpath(os.path.join(source_dir, stripped))
    contained = _contain(candidate, source_dir)
    if contained:
        return contained

    # Try just the filename in common subdirectories. Only succeeds if EXACTLY
    # ONE file across the whole search matches the basename — two files with
    # the same name in different directories must never silently collide
    # (that could patch the wrong file).
    basename = os.path.basename(file_ref)
    matches = []
    for subdir in ["", "routes", "src", "api", "app", "lib", "server"]:
        candidate = os.path.join(source_dir, subdir, basename)
        contained = _contain(candidate, source_dir)
        if contained and contained not in matches:
            matches.append(contained)

    if len(matches) == 1:
        return matches[0]

    return None


def _extract_method(vuln) -> str:
    """Extract HTTP method from vuln evidence or curl_command."""
    evidence = getattr(vuln, "evidence", "") or ""

    # Look for method in evidence
    method_match = re.search(r'-X\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)', evidence, re.I)
    if method_match:
        return method_match.group(1).upper()

    # Check if payload suggests POST
    if getattr(vuln, "payload", ""):
        name = (getattr(vuln, "name", "") or "").lower()
        if any(kw in name for kw in ["sql injection", "xss", "command injection", "login"]):
            return "POST"

    return "GET"


def is_patchable(location: Optional[Location]) -> bool:
    """A finding is patchable if it has a source file + line number."""
    return (
        location is not None
        and location.kind == "file"
        and location.file is not None
        and location.line is not None
        and os.path.isfile(location.file)
    )
