"""Portable genome bundles — export/import a trained genome between machines.

A genome lives as 4 sibling files in GENOME_STORAGE_DIR: genome_<hash>.pkl, .json,
.pkl.hmac, and the per-installation .genome_hmac.key that signs it. Moving just the
.pkl without the key breaks BehavioralGenome.load() silently and unhelpfully: it
generates a NEW random key, the old signature no longer matches, and load() refuses
with "HMAC mismatch". That's the #1 landmine for shipping a scanned genome anywhere
(a laptop -> a production host). export()/import_genome() make it one file, one
command, on both ends — built for the self-hosted model, where the same team
controls both the scan and the deployment, so shipping the signing key inside the
bundle is the same trust boundary either way, not a new exposure.
"""
import hashlib
import hmac
import json
import os
import zipfile
from datetime import datetime, timezone

from immune.behavioral_genome import _get_or_create_hmac_key, _sign_file


def target_hash(target_url: str) -> str:
    return hashlib.md5(target_url.encode()).hexdigest()[:12]


def export_genome(target_url: str, storage_dir: str, out_path: str) -> str:
    """Bundle a trained genome's 4 files for `target_url` into one portable
    .cxgenome (zip) at out_path. Raises FileNotFoundError if nothing was ever
    trained for this target — `cyphex scan` must run before this does."""
    h = target_hash(target_url)
    genome_path = os.path.join(storage_dir, f"genome_{h}")
    pkl, meta, sig = genome_path + ".pkl", genome_path + ".json", genome_path + ".pkl.hmac"
    key_path = os.path.join(storage_dir, ".genome_hmac.key")
    for p in (pkl, meta, sig, key_path):
        if not os.path.exists(p):
            raise FileNotFoundError(
                f"Missing {p} — nothing trained for this target yet, run `cyphex scan` first")

    manifest = {
        "target_url": target_url,
        "target_hash": h,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "format_version": 1,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        z.write(pkl, "genome.pkl")
        z.write(meta, "genome.json")
        z.write(sig, "genome.pkl.hmac")
        z.write(key_path, "hmac.key")
    return out_path


def import_genome(bundle_path: str, storage_dir: str) -> dict:
    """Unpack a .cxgenome bundle into storage_dir. VERIFIES the bundle's own
    signature against the key it shipped with first (catches transfer corruption
    or tampering — not a trust decision about the exporting machine, just "is this
    genuinely what export_genome() produced"), then RE-SIGNS the .pkl with the
    TARGET install's own key (created if this is a fresh storage_dir, reused if
    other genomes already live here) so it loads correctly alongside them — the
    target's .genome_hmac.key is never overwritten by an imported bundle.

    Returns the manifest dict. Raises ValueError if the bundle's own signature
    doesn't check out.
    """
    os.makedirs(storage_dir, exist_ok=True)
    with zipfile.ZipFile(bundle_path, "r") as z:
        manifest = json.loads(z.read("manifest.json"))
        pkl_bytes = z.read("genome.pkl")
        meta_bytes = z.read("genome.json")
        shipped_sig = z.read("genome.pkl.hmac").decode().strip()
        shipped_key = z.read("hmac.key")

    digest = hmac.new(shipped_key, pkl_bytes, digestmod=hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, shipped_sig):
        raise ValueError(
            f"Bundle signature mismatch — {bundle_path} may be corrupted or tampered "
            f"with; refusing to import")

    h = manifest.get("target_hash") or target_hash(manifest["target_url"])
    genome_path = os.path.join(storage_dir, f"genome_{h}")
    with open(genome_path + ".pkl", "wb") as f:
        f.write(pkl_bytes)
    with open(genome_path + ".json", "wb") as f:
        f.write(meta_bytes)

    local_key = _get_or_create_hmac_key(storage_dir)
    local_sig = _sign_file(genome_path + ".pkl", local_key)
    with open(genome_path + ".pkl.hmac", "w") as f:
        f.write(local_sig)
    try:
        os.chmod(genome_path + ".pkl.hmac", 0o600)
    except OSError:
        pass

    return manifest
