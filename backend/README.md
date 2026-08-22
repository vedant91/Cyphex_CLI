# `backend/` — engine internals

Everything the scan pipeline is made of. This directory is **not** pip-installed;
`pyproject.toml` exposes only the `cyphex*` package plus a list of root-level
`py-modules`. `backend/` is imported by path, which is why `cyphex/cli.py` puts
both the project root and `backend/backend/` on `sys.path` at import time.

Start at [`../README.md`](../README.md) for what CYPHEX does, and
[`../AGENTS.md`](../AGENTS.md) for the invariants a change here must not break.

> **Historical note.** An earlier version of this file described a
> "5-stage orchestration pipeline" driven by `backend/scan_orchestrator.py` and
> the Cerebras API. Both are gone. The pipeline lives in
> [`../cli_engine.py`](../cli_engine.py) and inference is local-only by default
> (Ollama on `127.0.0.1:11434`). If you find a doc still describing the old
> shape, it is stale.

---

## Map

| Package | Owns |
|---|---|
| `deepagents/` | The 13 Oracle-guided attack agents, the shared attack graph, and the attack-surface index |
| `council/` | Multi-model debate, model→role selection, reasoning-strategy routing, route tracing |
| `rag/` | Vectorless code index, PageIndex-style Knowledge Tree, security KB, optional cognee cross-project memory |
| `reasoning/` | Reflexion, self-consistency, session memory, reasoning-tree capture |
| `patch/` | The remediation pipeline **and the Verify Gate** |
| `observability/` | Append-only JSONL event log, health aggregation, trace |
| `network/` | Host discovery, network genome, topology, vulnerability mapping |
| `config/` | DAST constants |
| `backend/immune/` | Behavioural genome + adversarial co-evolution controller |
| `backend/agents/` | The classic (non-Deep) agent suite, still used on the Nuclei/ZAP path |
| `backend/models/` | Shared dataclasses — `Scan`, `AgentResult`, `Genome` |
| `platform_compat.py` | Cross-platform binary and shell resolution |
| `sandboxes/` · `workdir/` | Generated at runtime, gitignored |

The doubled path (`backend/backend/`) is historical. It is load-bearing —
`cyphex/cli.py` adds it to `sys.path` explicitly — so do not flatten it casually.

---

## `patch/` — the part that matters most

The honesty guarantee lives here. Read these three files in order:

| File | Role |
|---|---|
| `resolver.py` | Turn a finding into a concrete target: file, line range, enclosing function |
| `applier.py` | Splice the patch in. Refuses symlinks, validates line ranges, writes atomically |
| **`verifier.py`** | **The Verify Gate.** The five checks and the tri-state verdict algebra |

Supporting cast: `templates.py` (deterministic regex transforms for CWE-89, 78,
798, 942 — no model, no variance), `patch_memory.py` (semantic-hash cache of
previously *verified* fixes), `context.py` and `structure.py` (what the model is
shown), `manifest.py` + `migrate_manifests.py` (the per-scan `patches.json` that
`verify_health.py` later aggregates), `regression.py`, and
**`verify_health.py`** (the maintainability report behind `cyphex verify`).

### The invariant you must not break

`finding_gone` and `builds` are **tri-state**: `True` / `False` / `None`.
`None` means *unmeasured* and must **never** be coerced into a `PASS`. A check
that ran and failed outranks one that never ran. Everything CYPHEX claims about
itself rests on this. `tests/test_verifier.py` is mutation-checked — each
invariant was deliberately broken to confirm the suite catches it.

Changing what counts as a verified fix means changing `verifier.py` **and**
`tests/test_verifier.py` together.

---

## `deepagents/` — the attack swarm

`base_deep_agent.py` implements the loop every agent runs: **baseline → plan →
probe → decide → mutate → chain**. `oracle_attack.py` is the local-LLM brain
(`plan()` / `decide()` / `mutate()`). The 13 subclasses each specialise one
vulnerability class:

`deep_sqli` · `deep_xss` · `deep_cmdi` · `deep_auth` · `deep_idor` ·
`deep_ssrf` · `deep_path_traversal` · `deep_xxe` · `deep_business_logic` ·
`deep_prompt_injection` · `deep_race_condition` · `deep_mass_assignment` ·
`deep_ssti`

`attack_surface_index.py` is what the Oracle plans *against*; `attack_graph.py`
accumulates confirmed exploits into multi-step attack paths.

Caps live in `base_deep_agent.py`: `MAX_HYPOTHESES = 10`,
`PARALLEL_BATCH = 3`, `MAX_ATTEMPTS_PER_HYPOTHESIS = 5`. If you add a new agent,
subclass `BaseDeepAgent` rather than copying an existing one — the dead-route
guard and the baseline-timing logic live in the base class.

---

## `observability/` — must never break the scan

`events.py::emit()` is **contractually incapable of raising**. If you extend it,
keep the blanket `try/except`. Adding a new event type needs no schema change:
consumers tolerate unknown types by design, which is what lets a new phase start
emitting before `health.py` knows about it.

`health.py` aggregates the log into the panel behind `cyphex status`.
`trace.py` feeds the live per-phase trace deck.

To add telemetry: call `self._emit("name", **fields)` in `cli_engine.py`, then
consume it in `health.py`.

---

## `council/` — advisory, never authoritative

`model_selector.py` scores every available Ollama model for the three roles —
`detector`, `validator`, `patcher`. Scoring is deliberately blunt: parameter
count drives it, code specialisation is only a 15% bonus.

`debate_protocol.py` runs the vote; `patch_council.py` and
`analysis_council.py` are its two consumers; `reasoning_strategy.py` routes each
finding to a patch-generation strategy by severity, CWE and VRAM tier.

**The council's verdict cannot pre-empt the Verify Gate.** A patch the council
rejected but that is still present on disk still goes through `verifier.py`.
That ordering is intentional — the deterministic check is the authority.

---

## `rag/` — context without a vector DB

No embeddings on the default path. `code_indexer.py` builds a regex code tree;
`knowledge_tree.py` builds a PageIndex-style tree over your repo plus the
bundled corpus in `security_docs/` and `security_kb.json`; `tree_navigator.py`
walks it. The fast path is 0-LLM: `CWE + file:line` → enclosing function, fix
recipe, in-repo secure example. Cached at `.cyphex/knowledge_tree.json`.

`cognee_memory.py` is the one exception — the optional `.[memory]` extra, which
uses `nomic-embed-text` (768 dims) into a local LanceDB for cross-project patch
recall. It is guarded everywhere; without the extra installed the pipeline runs
unchanged.

---

## `backend/immune/` — the behavioural genome

`behavioral_genome.py` extracts the 15-dimension feature vector and scores it as
`max(isolation-forest, heuristic)`, blocking at ≥ `GENOME_BLOCK_THRESHOLD`
(0.7). The heuristic path alone still works without numpy/scikit-learn.

`mutation_engine.py` is the red team; `evolution_controller.py` runs the
co-evolution loop (10 generations × 20 payloads, early-stop at ≥99% block rate
for 3 consecutive generations).

Genomes persist with an **HMAC-SHA256 sidecar** (`.pkl` + `.pkl.hmac`, key mode
`0600`) and refuse to load an unsigned or tampered file. Attack history
round-trips too, so run *N+1* keeps hardening from run *N*'s bypasses.

---

## Conventions in this directory

- **Comments explain *why*, not *what*.** Many of them document the specific bug
  a line prevents. Preserve that when editing near them.
- **Fail closed.** A guard that cannot run reports "unknown", never "fine".
- **No new hardcoded thresholds.** If a number gates behaviour it belongs beside
  the other constants, with a comment justifying its value.
- **Cross-platform resolution goes through `platform_compat.py`.** A bare
  `"tsc"` or `"npm"` is a `.cmd` shim on Windows that non-shell `subprocess`
  cannot launch even when `shutil.which()` finds it. Use `resolve_binary_cmd()`,
  and `sys.executable` rather than a literal `"python"`.

Run `python -m pytest tests/ -q` before claiming a change here works.
