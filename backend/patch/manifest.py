"""
CYPHEX — Patch Manifest

Tracks what has been patched, with what verdict, for durability measurement.
Stored in .cyphex/patches.json in the source directory.

Kills R4: "After score is assumed, not measured"
Kills R5: "File-level resolution marks all vulns in a file as fixed"
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Optional


class PatchManifest:
    """Read/write .cyphex/patches.json for patch durability tracking."""

    def __init__(self, source_dir: str):
        self.dir = os.path.join(source_dir, ".cyphex")
        self.path = os.path.join(self.dir, "patches.json")
        self.entries: dict = {}
        self._load()

    def _load(self):
        if os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.entries = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.entries = {}

    def save(self):
        os.makedirs(self.dir, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, indent=2, ensure_ascii=False)

    def record(
        self,
        rel_path: str,
        line: int,
        cwe: str,
        vuln_type: str,
        verdict: str,
        original_hash: str,
        patched_hash: str,
        exploit_payload: str = "",
        evidence: Optional[dict] = None,
    ):
        """Record a patch attempt with its verification verdict."""
        key = f"{rel_path}:{line}:{cwe}"
        self.entries[key] = {
            "vuln_type": vuln_type,
            "cwe": cwe,
            "file": rel_path,
            "line": line,
            "patched_at": datetime.now(timezone.utc).isoformat(),
            "original_hash": original_hash,
            "patched_hash": patched_hash,
            "verdict": verdict,            # "PASS" | "FAIL" | "UNVERIFIABLE"
            "verified": verdict == "PASS",
            "exploit_payload": exploit_payload[:200],
            "evidence": evidence or {},
        }
        self.save()

    def is_already_patched(self, rel_path: str, line: int, cwe: str) -> bool:
        """Check if this location was already patched (and verified)."""
        key = f"{rel_path}:{line}:{cwe}"
        entry = self.entries.get(key)
        if entry and entry.get("verified"):
            return True
        return False

    def get_verified_count(self) -> int:
        """Count patches that actually passed verification."""
        return sum(1 for e in self.entries.values() if e.get("verified"))

    def get_unverified_count(self) -> int:
        """Count patches applied but not verified."""
        return sum(1 for e in self.entries.values() if not e.get("verified"))

    def get_durability_stats(self) -> dict:
        """Compute patch durability statistics."""
        total = len(self.entries)
        verified = self.get_verified_count()
        unverified = self.get_unverified_count()
        return {
            "total_patches": total,
            "verified": verified,
            "unverified": unverified,
            "durability_rate": (verified / total * 100) if total > 0 else 0,
        }

    @staticmethod
    def content_hash(content: str) -> str:
        """Compute a hash of file content for change detection."""
        return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()[:16]
