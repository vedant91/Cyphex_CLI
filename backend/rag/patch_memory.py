"""
CYPHEX — Patch Memory

Two stores:
  1. Exact cache: (semantic_hash(function), cwe) → verified_diff
     Reapplied verbatim, then RE-VERIFIED (never trusted blind).
  2. Pattern library: (cwe, framework) → strategy name
     Feeds RAG to prefer strategies that worked before.

Only verified patches are stored. Per-project by default.
"""

import os
import re
import json
import hashlib
from datetime import datetime, timezone
from typing import Optional


class PatchMemory:
    """Verified-fix cache for patch reuse."""

    def __init__(self, project_dir: str):
        self.dir = os.path.join(project_dir, ".cyphex")
        self.path = os.path.join(self.dir, "patch_memory.json")
        self.memory: dict = {}
        self._load()

    def _load(self):
        if os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.memory = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.memory = {}

    def _save(self):
        os.makedirs(self.dir, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.memory, f, indent=2, ensure_ascii=False)

    def recall(self, cwe: str, function_code: str) -> Optional[dict]:
        """
        Check if we have a verified fix for this (cwe, function_code) combo.
        Returns {patch, strategy, stored_at} or None.
        """
        sem_hash = self.semantic_hash(function_code)
        key = f"{cwe}:{sem_hash}"
        entry = self.memory.get(key)
        if entry:
            entry["reuse_count"] = entry.get("reuse_count", 0) + 1
            self._save()
            return entry
        return None

    def store(self, cwe: str, function_code: str, patch: str,
              strategy: str = "", verified: bool = True):
        """Store a verified patch for future reuse."""
        if not verified:
            return  # Only remember verified patches

        sem_hash = self.semantic_hash(function_code)
        key = f"{cwe}:{sem_hash}"
        self.memory[key] = {
            "patch": patch,
            "strategy": strategy,
            "cwe": cwe,
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "reuse_count": 0,
            "function_hash": sem_hash,
        }
        self._save()

    def invalidate(self, cwe: str, function_code: str) -> bool:
        """
        Purge a poisoned entry: a patch that was stored as "verified" but
        later turned out to break the target (e.g. the structural-integrity
        check catches it on reuse, after it already slipped past an earlier
        scan's gate). Without this, a bad fix stored once is replayed
        verbatim on every future scan forever — recall() only re-verifies
        the REUSED patch, it never corrects the cache. Returns True if an
        entry was actually removed.
        """
        sem_hash = self.semantic_hash(function_code)
        key = f"{cwe}:{sem_hash}"
        if key in self.memory:
            del self.memory[key]
            self._save()
            return True
        return False

    def get_preferred_strategy(self, cwe: str) -> Optional[str]:
        """Get the strategy that has worked most for this CWE."""
        strategies = {}
        for key, entry in self.memory.items():
            if entry.get("cwe") == cwe and entry.get("strategy"):
                s = entry["strategy"]
                strategies[s] = strategies.get(s, 0) + entry.get("reuse_count", 0) + 1

        if strategies:
            return max(strategies, key=strategies.get)
        return None

    @staticmethod
    def semantic_hash(code: str) -> str:
        """
        Hash of code with comments and whitespace stripped.
        Reformatting/renames don't bust the cache.
        """
        # Strip comments
        cleaned = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
        cleaned = re.sub(r'#.*?$', '', cleaned, flags=re.MULTILINE)
        # Strip whitespace
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:16]
