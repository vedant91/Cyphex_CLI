"""Portable genome bundles (backend/backend/immune/genome_bundle.py): export the 4 files
a trained genome lives as into one file, import it elsewhere. The .pkl is treated as an
opaque byte blob throughout — these tests use fake bytes instead of a real sklearn pickle,
which exercises the exact same code path (export/import never deserialize the pickle)."""
import hashlib
import os

import pytest

from immune.behavioral_genome import _get_or_create_hmac_key, _sign_file
from immune.genome_bundle import export_genome, import_genome, target_hash

TARGET = "http://localhost:54145"


def _make_source_genome(storage_dir, target=TARGET, pkl_bytes=b"FAKE_GENOME_BYTES"):
    h = target_hash(target)
    genome_path = os.path.join(storage_dir, f"genome_{h}")
    with open(genome_path + ".pkl", "wb") as f:
        f.write(pkl_bytes)
    with open(genome_path + ".json", "w") as f:
        f.write('{"endpoints": 5}')
    key = _get_or_create_hmac_key(storage_dir)
    sig = _sign_file(genome_path + ".pkl", key)
    with open(genome_path + ".pkl.hmac", "w") as f:
        f.write(sig)
    return genome_path, h


def test_export_fails_cleanly_when_nothing_was_ever_trained(tmp_path):
    with pytest.raises(FileNotFoundError):
        export_genome(TARGET, str(tmp_path), str(tmp_path / "out.cxgenome"))


def test_export_then_import_round_trips_the_pkl_bytes_losslessly(tmp_path):
    src, prod = tmp_path / "src", tmp_path / "prod"
    src.mkdir(); prod.mkdir()
    genome_path, h = _make_source_genome(str(src), pkl_bytes=b"exact bytes 12345")

    bundle = export_genome(TARGET, str(src), str(tmp_path / "app.cxgenome"))
    manifest = import_genome(bundle, str(prod))

    assert manifest["target_url"] == TARGET and manifest["target_hash"] == h
    imported_pkl = os.path.join(str(prod), f"genome_{h}.pkl")
    assert open(imported_pkl, "rb").read() == b"exact bytes 12345"


def test_imported_genome_verifies_with_the_targets_own_key_not_the_shipped_one(tmp_path):
    src, prod = tmp_path / "src", tmp_path / "prod"
    src.mkdir(); prod.mkdir()
    _make_source_genome(str(src))
    bundle = export_genome(TARGET, str(src), str(tmp_path / "app.cxgenome"))
    import_genome(bundle, str(prod))

    h = target_hash(TARGET)
    prod_key = _get_or_create_hmac_key(str(prod))
    src_key = _get_or_create_hmac_key(str(src))
    assert prod_key != src_key  # different installs, different keys — by construction

    pkl_path = os.path.join(str(prod), f"genome_{h}.pkl")
    shipped_sig = open(os.path.join(str(prod), f"genome_{h}.pkl.hmac")).read().strip()
    assert _sign_file(pkl_path, prod_key) == shipped_sig  # re-signed with prod's key
    assert _sign_file(pkl_path, src_key) != shipped_sig    # NOT the source's key


def test_importing_does_not_disturb_an_unrelated_genome_already_in_the_same_storage_dir(tmp_path):
    """The real-world case a per-storage-dir shared key creates: a production host running
    multiple target apps off one daemon, importing genomes from different scanning machines
    (different source keys) at different times. Importing B must not break A."""
    src, prod = tmp_path / "src", tmp_path / "prod"
    src.mkdir(); prod.mkdir()

    other_pkl = os.path.join(str(prod), "genome_other999.pkl")
    with open(other_pkl, "wb") as f:
        f.write(b"unrelated pre-existing genome")
    prod_key_before = _get_or_create_hmac_key(str(prod))
    other_sig = _sign_file(other_pkl, prod_key_before)
    with open(other_pkl + ".hmac", "w") as f:
        f.write(other_sig)

    _make_source_genome(str(src))
    bundle = export_genome(TARGET, str(src), str(tmp_path / "app.cxgenome"))
    import_genome(bundle, str(prod))

    assert _get_or_create_hmac_key(str(prod)) == prod_key_before  # key never overwritten
    assert _sign_file(other_pkl, prod_key_before) == other_sig    # other genome still verifies


def test_tampered_bundle_is_rejected_not_silently_imported(tmp_path):
    import zipfile
    src = tmp_path / "src"; src.mkdir()
    _make_source_genome(str(src))
    bundle_path = str(tmp_path / "app.cxgenome")
    export_genome(TARGET, str(src), bundle_path)

    with zipfile.ZipFile(bundle_path) as z:
        data = {n: z.read(n) for n in z.namelist()}
    data["genome.pkl"] += b"TAMPERED"
    tampered = str(tmp_path / "tampered.cxgenome")
    with zipfile.ZipFile(tampered, "w") as z:
        for n, d in data.items():
            z.writestr(n, d)

    with pytest.raises(ValueError, match="signature mismatch"):
        import_genome(tampered, str(tmp_path / "prod2"))


def test_target_hash_matches_cli_engines_own_convention():
    """Must match cli_engine.py's hashlib.md5(target_url.encode()).hexdigest()[:12]
    exactly, or export/import would look for the wrong genome_<hash> files entirely."""
    expected = hashlib.md5(TARGET.encode()).hexdigest()[:12]
    assert target_hash(TARGET) == expected
