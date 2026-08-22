"""
Tests for PatchManifest legacy-schema loading + auto-migration and the
backend.patch.migrate_manifests sweep.

Regression target: a pre-v1 CYPHEX build wrote patches.json as a
{"version", "updated_at", "patches": [...]} wrapper. PatchManifest._load()
used to json.load() that straight into self.entries, so is_already_patched()'s
self.entries.get("file:line:cwe") lookup always missed and every location in
those sandboxes re-patched from scratch on re-scan.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.patch.manifest import PatchManifest  # noqa: E402
from backend.patch import migrate_manifests  # noqa: E402


LEGACY_ENTRY = {
    "key": "app.js:30:CWE-798",
    "vuln_type": "Hardcoded Secrets",
    "cwe": "CWE-798",
    "rel_path": "app.js",
    "line": 30,
    "verdict": "PASS",
    "verified": True,
    "original_hash": "a" * 64,
    "patched_hash": "b" * 64,
    "evidence": {"changed_lines": 5},
}


def _write(source_dir, obj):
    d = os.path.join(source_dir, ".cyphex")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "patches.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return path


# ── legacy load + cache lookup ────────────────────────────────────────

def test_legacy_wrapper_is_readable_by_cache_lookup():
    src = tempfile.mkdtemp()
    _write(src, {"version": 1, "updated_at": "2026-06-14T05:53:31Z", "patches": [LEGACY_ENTRY]})

    m = PatchManifest(src)
    assert len(m.entries) == 1
    assert m.is_already_patched("app.js", 30, "CWE-798") is True
    # a location that was never patched still misses
    assert m.is_already_patched("app.js", 99, "CWE-89") is False


def test_legacy_load_auto_migrates_file_to_flat_schema():
    src = tempfile.mkdtemp()
    path = _write(src, {"version": 1, "patches": [LEGACY_ENTRY]})

    PatchManifest(src)  # _load() should rewrite the file in place

    raw = json.load(open(path, encoding="utf-8"))
    assert "patches" not in raw                     # wrapper is gone
    assert "app.js:30:CWE-798" in raw               # flat composite key present
    assert raw["app.js:30:CWE-798"]["verified"] is True
    # the map key is not duplicated back inside the entry body
    assert "key" not in raw["app.js:30:CWE-798"]


def test_legacy_entry_without_key_rebuilds_composite_key():
    src = tempfile.mkdtemp()
    entry = dict(LEGACY_ENTRY)
    entry.pop("key")  # an even older record with no precomputed key
    _write(src, {"version": 1, "patches": [entry]})

    m = PatchManifest(src)
    assert m.is_already_patched("app.js", 30, "CWE-798") is True


# ── current schema is untouched ───────────────────────────────────────

def test_flat_schema_loads_unchanged_and_is_not_flagged_migrated():
    src = tempfile.mkdtemp()
    flat = {"app.js:30:CWE-798": {k: v for k, v in LEGACY_ENTRY.items() if k != "key"}}
    _write(src, flat)

    entries, migrated = PatchManifest._normalize(flat)
    assert migrated is False
    assert entries == flat

    m = PatchManifest(src)
    assert m.is_already_patched("app.js", 30, "CWE-798") is True


def test_garbage_toplevel_does_not_crash():
    src = tempfile.mkdtemp()
    _write(src, ["not", "a", "dict"])
    m = PatchManifest(src)
    assert m.entries == {}


def test_empty_legacy_wrapper_becomes_empty_flat_map():
    src = tempfile.mkdtemp()
    path = _write(src, {"version": 1, "patches": []})
    PatchManifest(src)
    assert json.load(open(path, encoding="utf-8")) == {}


# ── migrate_manifests sweep ───────────────────────────────────────────

def test_migrate_root_converts_only_legacy_files():
    root = tempfile.mkdtemp()
    legacy_dir = os.path.join(root, "cli_legacy")
    flat_dir = os.path.join(root, "cli_flat")
    _write(legacy_dir, {"version": 1, "patches": [LEGACY_ENTRY]})
    flat = {"x.js:1:CWE-79": {"verified": True, "cwe": "CWE-79", "file": "x.js", "line": 1}}
    _write(flat_dir, flat)

    summary = migrate_manifests.migrate_root(root, dry_run=False)
    assert summary["scanned"] == 2
    assert summary["skipped_flat"] == 1
    assert len(summary["migrated"]) == 1
    assert not summary["errors"]

    # legacy file is now flat and cache-visible
    m = PatchManifest(legacy_dir)
    assert m.is_already_patched("app.js", 30, "CWE-798") is True
    # flat file untouched
    assert json.load(open(os.path.join(flat_dir, ".cyphex", "patches.json"), encoding="utf-8")) == flat


def test_migrate_root_dry_run_writes_nothing():
    root = tempfile.mkdtemp()
    legacy_dir = os.path.join(root, "cli_legacy")
    path = _write(legacy_dir, {"version": 1, "patches": [LEGACY_ENTRY]})

    summary = migrate_manifests.migrate_root(root, dry_run=True)
    assert len(summary["migrated"]) == 1
    # file still in the legacy wrapper shape
    raw = json.load(open(path, encoding="utf-8"))
    assert isinstance(raw.get("patches"), list)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
