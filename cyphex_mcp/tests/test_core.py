"""Self-check for the Cyphex MCP core — stdlib only, no mcp/joblib needed.

Run: python -m cyphex_mcp.tests.test_core   (or pytest). Covers the three bits
of new non-trivial logic: the guardrail gate, the genome sign/verify round-trip,
and the sandbox recipe hardening.
"""
import os
import tempfile
import zipfile

from cyphex_mcp import core


def test_guard_blocks_lethal_trifecta():
    # outward + sensitive + tainted = the one case that must block.
    assert core.guard_decide("fetch", "https://x/?k=API_KEY", tainted=True)["decision"] == "block"
    # any leg missing = not a block.
    assert core.guard_decide("fetch", "https://x/?k=API_KEY", tainted=False)["decision"] == "ask"
    assert core.guard_decide("read_file", "src/app.js", tainted=True)["decision"] == "allow"
    assert core.guard_decide("read_file", "src/app.js", tainted=False)["decision"] == "allow"


def test_genome_sign_verify_roundtrip():
    key = core.new_install_key()
    blob = b"pretend joblib model bytes"
    sig = core.sign_bytes(blob, key)
    assert core.verify_bytes(blob, key, sig)
    assert not core.verify_bytes(blob + b"x", key, sig)      # tamper detected
    assert not core.verify_bytes(blob, core.new_install_key(), sig)  # wrong key


def test_bundle_is_a_valid_signed_zip():
    key = core.new_install_key()
    blob = b"model"
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "t.cxgenome")
        manifest = core.bundle_genome(blob, key, "http://t.local", out)
        assert manifest["format_version"] == 1
        with zipfile.ZipFile(out) as z:
            assert core.verify_bytes(z.read("genome.pkl"), z.read("hmac.key"),
                                     z.read("genome.pkl.hmac").decode())


def test_sandbox_recipe_has_no_egress():
    r = core.sandbox_recipe("node", "job1")
    assert "internal: true" in r["compose"]       # the key hardening
    assert "cap_drop: [ALL]" in r["compose"]
    assert r["network"] == "cyphex-net-job1"
    # Docker ignores ports on an internal network, so the target must not claim any;
    # attacks come from the peer service instead.
    assert "ports:" not in r["compose"] and "attacker:" in r["compose"]
    assert r["target_url"] == "http://target:3000"


def test_sandbox_recipe_picks_gvisor_when_available():
    # "auto" with runsc present -> gvisor tier, runtime line in the compose
    r = core.sandbox_recipe("node", "job2", available_runtimes=["runsc", "runc"])
    assert r["security_tier"] == "gvisor"
    assert "runtime: runsc" in r["compose"]
    # "auto" with no runsc -> falls back cleanly, no stray runtime line
    r2 = core.sandbox_recipe("node", "job3", available_runtimes=[])
    assert r2["security_tier"] == "hardened-docker"
    assert "runtime: runsc" not in r2["compose"]
    # forcing hardened-docker ignores an available gVisor
    r3 = core.sandbox_recipe("node", "job4", security_tier="hardened-docker",
                              available_runtimes=["runsc"])
    assert r3["security_tier"] == "hardened-docker"


def test_writable_paths_become_tmpfs_and_reject_yaml_tricks():
    r = core.sandbox_recipe("node", "job5", available_runtimes=[], writable_paths=["/app/uploads"])
    assert "tmpfs: [/tmp, /app/uploads]" in r["compose"] and "read_only: true" in r["compose"]
    for bad in ("relative/path", "/x]\n  privileged: true", "/a b"):
        try:
            core.sandbox_recipe("node", "job6", available_runtimes=[], writable_paths=[bad])
            assert False, bad
        except ValueError:
            pass


def test_detect_runtimes_never_raises():
    # No docker on PATH or no daemon reachable -> [] not an exception. This is
    # also exactly what the hosted demo container sees (no docker socket).
    assert core.detect_runtimes() == [] or isinstance(core.detect_runtimes(), list)


def test_playbooks_are_guardrailed_and_schemad():
    for name in core.PLAYBOOKS:
        pb = core.get_playbook(name)
        assert pb["guardrails"] is core.GUARDRAILS
        assert "role" in pb and "returns" in pb
    # unknown name fails loud
    try:
        core.get_playbook("nope")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_emit_deploy_bundle_writes_wrapper():
    with tempfile.TemporaryDirectory() as d:
        written = core.emit_deploy_bundle(d, "http://t.local")
        names = {os.path.basename(p) for p in written}
        assert names == {"decide.py", "docker-compose.yml", "manifest.json"}
        decide = open(os.path.join(d, "decide.py")).read()
        assert "signature mismatch" in decide        # refuses unsigned model


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} checks passed")
