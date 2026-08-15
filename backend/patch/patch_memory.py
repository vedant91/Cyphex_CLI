"""Verified patch memory: exact semantic cache + pattern library."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strip_comments(text: str) -> str:
    if not text:
        return ""
    t = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    t = re.sub(r"//.*", "", t)
    t = re.sub(r"#.*", "", t)
    return t


def semantic_hash(function_text: str) -> str:
    base = _strip_comments(function_text or "")
    base = re.sub(r"\s+", "", base)
    return hashlib.sha256(base.encode("utf-8", "ignore")).hexdigest()


class PatchMemory:
    def __init__(self, project_root: str):
        self.root = project_root
        self.dir = os.path.join(project_root, ".cyphex")
        self.exact_path = os.path.join(self.dir, "exact_cache.json")
        self.pattern_path = os.path.join(self.dir, "pattern_library.json")
        self._exact: dict[str, dict] = {}
        self._patterns: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        for path, target in ((self.exact_path, "exact"), (self.pattern_path, "patterns")):
            try:
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if target == "exact":
                        self._exact = data.get("entries", {})
                    else:
                        self._patterns = data.get("entries", {})
            except (OSError, ValueError, KeyError):
                if target == "exact":
                    self._exact = {}
                else:
                    self._patterns = {}

    def save(self) -> None:
        os.makedirs(self.dir, exist_ok=True)
        with open(self.exact_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "updated_at": _now(), "entries": self._exact}, f, indent=2)
        with open(self.pattern_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "updated_at": _now(), "entries": self._patterns}, f, indent=2)

    @staticmethod
    def exact_key(function_text: str, cwe: str) -> str:
        return f"{semantic_hash(function_text)}:{(cwe or 'CWE-unknown').upper()}"

    def store_verified(self, function_text: str, cwe: str, fixed_code: str, evidence: Optional[dict] = None) -> None:
        k = self.exact_key(function_text, cwe)
        self._exact[k] = {
            "cwe": (cwe or "CWE-unknown").upper(),
            "semantic_hash": semantic_hash(function_text),
            "fixed_code": fixed_code,
            "verified": True,
            "stored_at": _now(),
            "evidence": evidence or {},
        }

    def recall_exact(self, function_text: str, cwe: str) -> Optional[dict]:
        return self._exact.get(self.exact_key(function_text, cwe))

    def add_pattern(self, cwe: str, framework: str, strategy: str) -> None:
        key = f"{(cwe or 'CWE-unknown').upper()}::{(framework or 'generic').lower()}"
        self._patterns[key] = {
            "cwe": (cwe or "CWE-unknown").upper(),
            "framework": (framework or "generic").lower(),
            "strategy": strategy,
            "updated_at": _now(),
        }

    def get_pattern(self, cwe: str, framework: str) -> Optional[dict]:
        key = f"{(cwe or 'CWE-unknown').upper()}::{(framework or 'generic').lower()}"
        return self._patterns.get(key)
