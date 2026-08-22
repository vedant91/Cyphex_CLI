# `tests/` — 388 tests, ~50 s, no network

```bash
pip install -e ".[dev]"
pytest                    # 388 tests, ~50s
pytest -m integration     # the slow ones — real local models, needs Ollama
pytest tests/test_verifier.py -q          # just the Verify Gate
```

389 tests are collected; **1 is deselected by default** via
`addopts = "-m 'not integration'"` in `pyproject.toml`. That marker is not a
workaround for a slow suite — `test_cross_project_recall` drives cognee's
`cognify()` through a local LLM and takes minutes. Do not remove it to "fix"
runtime.

---

## What each file pins down

| File | Guards |
|---|---|
| `test_verifier.py` | **The Verify Gate.** The five checks, the tri-state algebra, and the rollback path. The most important file here |
| `test_scoring.py` | The 0-100 posture score — monotonicity across the whole domain, and that nobody hand-copies the formula |
| `test_patch_pipeline.py` | Resolver → applier → verifier end to end |
| `test_patch_council.py` | The multi-model vote and its advisory-only status |
| `test_patch_memory.py` | The semantic-hash cache of previously verified fixes |
| `test_templates.py` | The four deterministic CWE transforms (89, 78, 798, 942) |
| `test_manifest_migration.py` | Old `patches.json` shapes still load |
| `test_debate_protocol.py` | Council debate mechanics |
| `test_reasoning.py` · `test_reasoning_strategy.py` | Reflexion, self-consistency, and strategy routing by severity/CWE/VRAM tier |
| `test_rag_context.py` | The 0-LLM fast path: `CWE + file:line` → function, recipe, secure example |
| `test_cognee_memory.py` | Cross-project recall (contains the one `integration` test) |
| `test_vram_manager.py` | Tier detection, LRU eviction, "can these two models co-reside" |
| `test_core.py` | Scanner and engine basics |
| `test_autonomy.py` | The autonomous decision loop |
| `test_nl_router.py` | The plain-English router **only ever emits a known command or refuses** |
| `test_trace.py` | Per-phase trace timings and the summary deck |
| `test_deck_input.py` · `test_deck_input_safety.py` | The raw-mode input editor — including termios restoration on fatal signals and that OSC/DCS/APC escape bodies are never injected as text |
| `test_mascot_render.py` | The tiered mascot renderer's fixed-canvas guarantee |

---

## Two suites worth reading before you change anything

**`test_verifier.py` is mutation-checked.** Every invariant it asserts was
deliberately broken first, to confirm the suite actually catches it. If you
change what counts as a verified fix, change this file in the same commit.

**`test_scoring.py::test_no_hand_copied_band_clamp_remains` walks the AST of
every root-level `*.py`.** It exists because three different score formulas once
diverged silently after being hand-copied out of `scoring.py`. It will fail your
change if you reintroduce a `min(score, <int>)` clamp anywhere outside
`scoring.py`. That is the intended behaviour, not a false positive.

---

## Conventions

- No network. Anything that needs a live model gets `@pytest.mark.integration`.
- `asyncio_mode = "auto"` — `async def test_*` needs no decorator.
- CI runs `pytest tests/ -v --tb=short` across ubuntu/macos/windows ×
  Python 3.11/3.12/3.13, plus a `LANG=C` locale job and an Alpine/musl job.
  A failure fails the build; there is no `|| echo` swallow, because there used
  to be one and a genuinely broken test sat green behind it.
