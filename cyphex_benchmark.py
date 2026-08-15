#!/usr/bin/env python3
"""
CYPHEX — Immune System Benchmark Harness  (`cx benchmark`)
═══════════════════════════════════════════════════════════════════════════

Runs the REAL BehavioralGenome anomaly detector over a labelled corpus of
attack + benign payloads and reports the metrics a security jury actually
asks for:

    precision · recall · F1 · accuracy · false-positive rate
    per-attack-class detection rate · confusion matrix

Why this exists
---------------
CYPHEX's headline claim is "the Immune System stops attacks (incl. zero-days)
without blocking real users." A single ALLOW/BLOCK demo table is an anecdote;
this harness turns it into a *reproducible number* — exactly what the
HACK4HUMANITY rubric rewards ("a measurable result: detects X of Y").

Ethics / offline
----------------
The bundled corpus is fully synthetic and self-authored — no live traffic, no
PII — so it runs in any isolated sandbox with no network. Point --data at an
external labelled dataset (CSV or JSON) to validate against approved research
data (e.g. CSE-CIC-IDS2018 web-attack payloads):

    python3 cyphex_benchmark.py                       # bundled corpus
    python3 cyphex_benchmark.py --data mydata.csv     # payload,label[,attack]
    python3 cyphex_benchmark.py --threshold 0.4 --json report.json

Exit code is non-zero if recall or FPR fall outside the pass gates, so the
harness doubles as a CI regression check on detector quality.
"""
import argparse
import csv
import json
import os
import sys
import time

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CORPUS = os.path.join(BENCH_DIR, "benchmarks", "immune_corpus.json")

# Default decision boundary — matches the ALLOW/BLOCK cut used in live scans.
DEFAULT_THRESHOLD = 0.5
# CI pass gates (tunable). A regression that drops recall or spikes FPR fails.
GATE_MIN_RECALL = 0.80
GATE_MAX_FPR = 0.10


def _ensure_backend_on_path():
    """Make `immune.behavioral_genome` importable regardless of CWD."""
    p = os.path.join(BENCH_DIR, "backend", "backend")
    if p not in sys.path:
        sys.path.insert(0, p)


def load_corpus(path=None):
    """Load a labelled corpus from JSON or CSV.

    JSON: {"endpoint": "...", "samples": [{"payload","label","attack"}, ...]}
    CSV : header row with columns `payload`,`label`[,`attack`]. When `attack`
          is absent it is inferred as (label.lower() != "benign").
    Returns (meta: dict, samples: list[dict]).
    """
    path = path or DEFAULT_CORPUS
    if not os.path.exists(path):
        raise FileNotFoundError(f"Corpus not found: {path}")

    if path.lower().endswith(".csv"):
        samples = []
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                payload = row.get("payload") or row.get("text") or row.get("input")
                if payload is None:
                    continue
                label = (row.get("label") or row.get("class") or "").strip() or "unknown"
                if "attack" in row and str(row["attack"]).strip() != "":
                    attack = str(row["attack"]).strip().lower() in ("1", "true", "yes", "attack", "malicious")
                else:
                    attack = label.lower() not in ("benign", "normal", "clean", "0", "")
                samples.append({"payload": payload, "label": label, "attack": attack})
        meta = {"name": os.path.basename(path), "endpoint": "/search"}
        return meta, samples

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    samples = []
    for s in data.get("samples", []):
        label = str(s.get("label", "unknown"))
        attack = bool(s.get("attack", label.lower() not in ("benign", "normal", "clean")))
        samples.append({"payload": s["payload"], "label": label, "attack": attack})
    meta = {
        "name": data.get("name", os.path.basename(path)),
        "endpoint": data.get("endpoint", "/search"),
        "description": data.get("description", ""),
    }
    return meta, samples


def run_benchmark(path=None, threshold=DEFAULT_THRESHOLD, endpoint=None, genome=None):
    """Score every sample with the real BehavioralGenome and compute metrics."""
    _ensure_backend_on_path()
    from immune.behavioral_genome import BehavioralGenome, HAS_SKLEARN

    meta, samples = load_corpus(path)
    endpoint = endpoint or meta.get("endpoint", "/search")
    genome = genome or BehavioralGenome()

    t0 = time.perf_counter()
    scored = []
    for s in samples:
        score = float(genome.score_request(endpoint, s["payload"]))
        scored.append({
            "payload": s["payload"],
            "label": s["label"],
            "attack": s["attack"],
            "score": score,
            "blocked": score >= threshold,
        })
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    report = compute_metrics(scored, threshold)
    report.update({
        "corpus": meta.get("name", "corpus"),
        "endpoint": endpoint,
        "elapsed_ms": round(elapsed_ms, 1),
        "per_sample_ms": round(elapsed_ms / max(len(scored), 1), 3),
        "sklearn_active": bool(HAS_SKLEARN),
        "detector": "BehavioralGenome (heuristic + IsolationForest)",
    })
    return report, scored


def compute_metrics(scored, threshold):
    """Confusion matrix + precision/recall/F1/FPR + per-class detection."""
    tp = fp = tn = fn = 0
    per_class = {}          # class -> [detected, total]
    misses = []             # attacks that slipped through
    false_positives = []    # benign that got blocked

    for r in scored:
        blocked = r["blocked"]
        if r["attack"]:
            per_class.setdefault(r["label"], [0, 0])
            per_class[r["label"]][1] += 1
            if blocked:
                tp += 1
                per_class[r["label"]][0] += 1
            else:
                fn += 1
                misses.append({"payload": r["payload"], "label": r["label"], "score": r["score"]})
        else:
            if blocked:
                fp += 1
                false_positives.append({"payload": r["payload"], "score": r["score"]})
            else:
                tn += 1

    n = len(scored)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    per_class_rows = sorted(
        ({"class": k, "detected": v[0], "total": v[1],
          "rate": (v[0] / v[1] if v[1] else 0.0)} for k, v in per_class.items()),
        key=lambda x: (-x["rate"], x["class"]),
    )

    passed = recall >= GATE_MIN_RECALL and fpr <= GATE_MAX_FPR

    return {
        "threshold": threshold,
        "total": n,
        "attacks": tp + fn,
        "benign": tn + fp,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fpr": round(fpr, 4),
        "per_class": per_class_rows,
        "misses": misses,
        "false_positives": false_positives,
        "gates": {"min_recall": GATE_MIN_RECALL, "max_fpr": GATE_MAX_FPR, "passed": passed},
    }


def _print_plain(report):
    """Dependency-free fallback report (used when terminal_ui is unavailable)."""
    c = report["confusion"]
    print(f"\n  CYPHEX Immune System Benchmark — {report['corpus']}")
    print(f"  detector: {report['detector']}  |  threshold: {report['threshold']}  "
          f"|  ML: {'on' if report['sklearn_active'] else 'off (heuristic only)'}")
    print(f"  samples: {report['total']}  ({report['attacks']} attack / {report['benign']} benign)"
          f"  |  {report['per_sample_ms']} ms/sample\n")
    print(f"                 blocked   allowed")
    print(f"    attack   |    {c['tp']:>4}      {c['fn']:>4}   (recall {report['recall']*100:.1f}%)")
    print(f"    benign   |    {c['fp']:>4}      {c['tn']:>4}   (FPR    {report['fpr']*100:.1f}%)\n")
    print(f"    precision {report['precision']*100:.1f}%   recall {report['recall']*100:.1f}%   "
          f"F1 {report['f1']*100:.1f}%   accuracy {report['accuracy']*100:.1f}%\n")
    print("  Per-attack-class detection:")
    for row in report["per_class"]:
        bar = "#" * int(row["rate"] * 20)
        print(f"    {row['class']:<16} {row['detected']:>2}/{row['total']:<2}  {row['rate']*100:5.1f}%  {bar}")
    if report["misses"]:
        print("\n  Missed (attack allowed):")
        for m in report["misses"]:
            print(f"    [{m['label']}] {m['payload'][:60]}  (score {m['score']:.2f})")
    if report["false_positives"]:
        print("\n  False positives (benign blocked):")
        for fp in report["false_positives"]:
            print(f"    {fp['payload'][:60]}  (score {fp['score']:.2f})")
    verdict = "PASS" if report["gates"]["passed"] else "REVIEW"
    print(f"\n  Gate: recall>={GATE_MIN_RECALL*100:.0f}%  FPR<={GATE_MAX_FPR*100:.0f}%  ->  {verdict}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="CYPHEX Immune System benchmark")
    ap.add_argument("--data", default=None, help="labelled corpus (JSON or CSV); default = bundled")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="block decision boundary 0..1")
    ap.add_argument("--endpoint", default=None, help="endpoint key to score against")
    ap.add_argument("--json", dest="json_out", default=None, help="write machine-readable report to this path")
    ap.add_argument("--plain", action="store_true", help="force plain text (skip the HUD render)")
    args = ap.parse_args(argv)

    report, scored = run_benchmark(args.data, threshold=args.threshold, endpoint=args.endpoint)

    rendered = False
    if not args.plain:
        try:
            import terminal_ui as ui
            ui.render_benchmark(report)
            rendered = True
        except Exception:
            rendered = False
    if not rendered:
        _print_plain(report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"  report written -> {args.json_out}")

    return 0 if report["gates"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
