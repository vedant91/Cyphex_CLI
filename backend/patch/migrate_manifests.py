"""
CYPHEX — one-time patch-manifest schema migration.

Sweeps every backend/sandboxes/*/.cyphex/patches.json and rewrites any that
are still in the pre-v1 wrapper schema ({"version", "updated_at",
"patches": [...]}) into the flat "file:line:cwe" -> entry map PatchManifest
uses now. PatchManifest already self-heals a legacy file the next time its
sandbox is scanned (see PatchManifest._load), but a target that is never
re-scanned would keep its history invisible to is_already_patched() forever.
This converts all of them up front.

Idempotent: files already in the flat schema are left untouched. Read-only or
unreadable files are reported and skipped, never crashed on.

Usage:
    python -m backend.patch.migrate_manifests [--dry-run] [--root DIR]
"""

import argparse
import glob
import json
import os

from backend.patch.manifest import PatchManifest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_ROOT = os.path.join(_REPO_ROOT, "backend", "sandboxes")


def _is_legacy(raw) -> bool:
    return isinstance(raw, dict) and isinstance(raw.get("patches"), list)


def migrate_root(root: str, dry_run: bool = False) -> dict:
    """Migrate every legacy manifest under `root`. Returns a summary dict."""
    paths = sorted(glob.glob(os.path.join(root, "*", ".cyphex", "patches.json")))
    summary = {"scanned": len(paths), "migrated": [], "skipped_flat": 0, "errors": []}

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            summary["errors"].append((path, f"unreadable: {e}"))
            continue

        if not _is_legacy(raw):
            summary["skipped_flat"] += 1
            continue

        flat, _ = PatchManifest._normalize(raw)
        if dry_run:
            summary["migrated"].append((path, len(flat)))
            continue

        # Reuse PatchManifest.save() for the same atomic temp-file+os.replace
        # write the live path uses — never a partial manifest on disk.
        source_dir = os.path.dirname(os.path.dirname(path))  # strip /.cyphex/patches.json
        try:
            m = PatchManifest(source_dir)  # _load already migrated in-memory + saved
            summary["migrated"].append((path, len(m.entries)))
        except Exception as e:
            summary["errors"].append((path, f"write failed: {e}"))

    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Migrate pre-v1 CYPHEX patch manifests to the flat schema.")
    ap.add_argument("--root", default=_DEFAULT_ROOT, help="sandboxes root (default: backend/sandboxes)")
    ap.add_argument("--dry-run", action="store_true", help="report what would change without writing")
    args = ap.parse_args()

    s = migrate_root(args.root, dry_run=args.dry_run)
    verb = "would migrate" if args.dry_run else "migrated"
    print(f"scanned {s['scanned']} manifest(s); {s['skipped_flat']} already flat; "
          f"{verb} {len(s['migrated'])}")
    for path, n in s["migrated"]:
        print(f"  {verb}: {path} ({n} record(s))")
    for path, err in s["errors"]:
        print(f"  ERROR {path}: {err}")
    return 1 if s["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
