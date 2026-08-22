# Contributing to CYPHEX

Thanks for looking. This file covers setup, what to run before opening a PR, and
the handful of invariants a change genuinely must not break.

If you are an **AI coding agent**, read [AGENTS.md](AGENTS.md) instead — it is
the same material, structured for acting rather than reading.

---

## Setup

```bash
git clone --recurse-submodules https://github.com/Punya23/Cyphex_CLI.git
cd Cyphex_CLI
pip install -e ".[dev]"
# Already cloned without the flag? git submodule update --init

ollama pull qwen2.5-coder:7b
ollama pull llama3.1:8b

cyphex doctor        # confirms binaries, Ollama, models, hardware tier
pytest               # 388 tests, ~50s, no network needed
```

Extras: `.[dev]` (pytest), `.[memory]` (cognee cross-project graph),
`.[reasoning]`, `.[cloud]`.

You do **not** need Ollama running to work on most of the codebase — the default
test suite drives no models. You do need it to run a real scan.

---

## Before opening a PR

```bash
pytest                              # must be green — CI does not swallow failures
python -c "import cx"               # the workspace must import (Windows readline guard)
cyphex verify --ci                  # your own Verify Gate toolchain is healthy
```

If you changed a renderer, also:

```bash
LANG=C LC_ALL=C python -c "import terminal_ui as ui; ui.soc.print('✓ ▲ ● ◆ ┏┅┅┓')"
```

CI runs ubuntu/macos/windows × Python 3.11/3.12/3.13, plus a `LANG=C` locale job
and an Alpine/musl job. The last two exist because a win32-only UTF-8 fix once
crashed every non-UTF-8 POSIX environment, and nothing caught it.

---

## The invariants

These are not style preferences. Each one is a bug that already shipped once.

**1. The Verify Gate's tri-state is load-bearing.**
`finding_gone` and `builds` are `True` / `False` / `None`. `None` means
*unmeasured* and must **never** be coerced into a `PASS`. A check that ran and
failed outranks one that never ran. Everything CYPHEX claims about itself rests
on this. → `backend/patch/verifier.py`

**2. `scoring.py` is the only place the score is computed.**
Never hand-copy the formula or the band thresholds. Three copies once diverged
silently. `tests/test_scoring.py::test_no_hand_copied_band_clamp_remains` walks
the AST of every root-level `*.py` to enforce it and will fail your change if
you reintroduce a `min(score, <int>)` clamp elsewhere.

**3. Observability must never break the scan.**
`backend/observability/events.py::emit()` is contractually incapable of raising.
Keep the blanket `try/except` if you extend it. New event types need no schema
change — consumers tolerate unknown types by design.

**4. Only verified patches move the score.**
Remediation is tracked by vulnerability *object identity*, not file-path
substring, so patching one finding cannot silently clear a file's others.

**5. Every terminal surface degrades twice.**
Rich unavailable → plain text. Terminal can't render box-drawing glyphs → ASCII,
via `_ascii_mode()` / `_box()`. Take `box=` from `_box(console)`, never a
hardcoded value, and route severity glyphs through `_sev_style()`.

**6. Cross-platform resolution goes through `platform_compat`.**
A bare `"tsc"` or `"npm"` is a `.cmd` shim on Windows that non-shell
`subprocess` cannot launch even when `shutil.which()` finds it. Use
`resolve_binary_cmd()`. Use `sys.executable`, never a literal `"python"`.

**7. Don't gate a fix on `sys.platform == "win32"` when the real condition is
the encoding.** UTF-8 forcing keys off `sys.stdout.encoding`. A POSIX box with
`LANG=C` has the identical failure mode.

**8. `cyphex verify|status|benchmark` are intercepted before argparse.**
See `cyphex/cli.py::_run_panel` and its docstring for why. `_cmd_verify`'s int
return under `--ci` must become the process exit code, or the CI gate is
decorative.

---

## Where to change what

| Task | Start here |
|---|---|
| Add or modify a scan phase | `cli_engine.py::CyphexEngine.run()` — phases go through `self._step(num, title)` |
| Change what counts as a verified fix | `backend/patch/verifier.py` **and** `tests/test_verifier.py`, same commit |
| Add a maintainer-facing metric | `backend/patch/verify_health.py` → `terminal_ui.py::render_verify_health()` |
| Add a telemetry event | `self._emit("name", **fields)` in `cli_engine.py`; consume in `backend/observability/health.py` |
| Add a slash command | `cx.py`: `_cmd_X()` + `COMMANDS` + `_handle()` case + `main()` argv branch + both help texts. If it should also be `cyphex <cmd>`, add it to `cyphex/cli.py` — see invariant 8 |
| Add a Rich panel | `terminal_ui.py` — follow `render_verify_health()`'s shape, use `_box(c)` |
| Change the score | `scoring.py` only |
| Add a patch template | `backend/patch/templates.py` |
| Add an attack agent | subclass `BaseDeepAgent` in `backend/deepagents/` — don't copy a sibling |

---

## Style

- **Comments explain *why*, not *what*.** This codebase's comments frequently
  document the specific bug a line prevents. That is the house style; preserve
  it when editing nearby.
- **Fail closed.** A guard that cannot run reports "unknown", never "fine".
- **No new hardcoded thresholds.** If a number gates behaviour, put it beside
  the other constants with a comment justifying its value.
- **Local imports for heavy modules** inside `cx.py` command handlers — REPL
  startup time is a feature.
- Match the surrounding code's density and idiom rather than importing your own.

## Documentation

If a change alters the command surface, a measured number, or a limitation,
update the docs in the same PR:

- [README.md](README.md) — the human reference
- [AGENTS.md](AGENTS.md) — agent orientation and invariants
- [llms.txt](llms.txt) and [llms-full.txt](llms-full.txt) — the machine-readable
  summaries. **`llms-full.txt` is self-contained**, so a stale number there is a
  wrong answer given confidently. Treat it like code.
- the affected directory's own `README.md`

Numbers in docs should be measured, not remembered. `pytest` prints the test
count; `cyphex benchmark` prints the immune metrics.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Licence

MIT. Contributions are accepted under the same terms.
