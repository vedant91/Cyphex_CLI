# `benchmarks/`

## `immune_corpus.json`

The labelled corpus behind the immune system's published numbers, and behind the
CI regression gate.

| | |
|---|---|
| Name | CYPHEX Immune System — Web-Attack Payload Benchmark v1 |
| Samples | **76** — 46 attack, 30 benign |
| Endpoint | `/search` |
| Licence | Self-authored synthetic data, CC0 |
| Provenance | Fully synthetic. No live traffic, no PII, safe to run offline in any sandbox |

### Class distribution

| Label | n | | Label | n |
|---|---|---|---|---|
| `benign` | 30 | | `ssti` | 4 |
| `sqli` | 10 | | `nosqli` | 3 |
| `xss` | 8 | | `xxe` | 2 |
| `cmdi` | 7 | | `ldapi` | 1 |
| `path_traversal` | 5 | | `crlf` | 1 |
| `ssrf` | 5 | | | |

The 30 benign samples deliberately include **hard** cases — apostrophe names,
SQL keywords used in ordinary prose, relative paths, code snippets — because
those are exactly what breaks a naive regex WAF. They are the reason the
false-positive rate is a meaningful number rather than a formality.

### Schema

```json
{
  "name": "...", "description": "...", "endpoint": "/search", "license": "...",
  "samples": [
    { "payload": "' OR '1'='1' --", "label": "sqli", "attack": true },
    { "payload": "blue running shoes", "label": "benign", "attack": false }
  ]
}
```

`label` is the attack class (or `benign`); `attack` is the ground-truth boolean
the metrics are computed against.

---

## Running it

```bash
cyphex benchmark                                   # or: python3 cyphex_benchmark.py
cyphex benchmark --threshold 0.6 --json out.json
cyphex benchmark --data cic-ids2018.csv            # any labelled CSV
```

`--data` accepts a CSV with `payload,label[,attack]` columns, so an external
corpus can be swapped in without touching the harness.

**Exit code is the CI gate:** non-zero if recall drops below **80%** or the
false-positive rate climbs above **10%**.

> The `cyphex` / `cx` launchers report the gate verdict either way. Only the
> `cyphex benchmark` and `python3 cyphex_benchmark.py` forms set a process exit
> code; the workspace's `/benchmark` does not, because the REPL should not exit.

## Current measured result

**91.3% recall · 97.7% precision · 94.4% F1 · 3.3% FPR · ~0.04 ms/sample.**

Output includes the confusion matrix, per-class detection rates, and every miss
and false positive by name. Current misses: `admin'--`, `" OR ""="`,
`| whoami`, and a Windows-style traversal path.

**Read the number honestly.** *n* = 76 is small. These figures are
**directional, not certified**, and the co-evolution block rates quoted
elsewhere are in-distribution — they are not a generalization claim. Any summary
of this project that drops that caveat is misrepresenting it.

## Extending the corpus

Add samples to the `samples` array with the same three keys. Two rules:

1. **Synthetic only.** No captured live traffic, no PII. The CC0 claim and the
   "safe to run offline" claim both depend on this.
2. **Add hard benign cases too.** A corpus that only grows on the attack side
   inflates recall while quietly hiding false-positive regressions.

Bump `name` when the composition changes materially, so an old measurement is
never mistaken for a new one.
