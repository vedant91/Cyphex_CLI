# AGENTS.md

Orientation for coding agents working in this repository. Humans should start at [README.md](README.md); this file exists so an agent can act correctly without first reading 650 lines of prose.

## What this project is

CYPHEX is a local-first autonomous security scanner. It deploys a target app in a sandbox, attacks it with local-LLM agents, patches what it confirms, and re-scans to prove the fix. All inference goes to Ollama on `127.0.0.1:11434` — there is no cloud LLM, no API key, and no outbound telemetry. Python 3.11+, MIT.

**The two deliverables everything else serves:** the **Verify Gate**
(`backend/patch/verifier.py`) and the **Maintainability Panel**
(`backend/patch/verify_health.py` + `terminal_ui.py::render_verify_health()`).
Treat changes near either as higher-risk than their diff size suggests — see
invariant 1.

## Setup

```bash
pip install -e ".[dev]"     # extras: .[memory] .[reasoning] .[cloud]
python -m pytest tests/ -q  # 392 tests, ~45s, no network needed
```

The default pytest config deselects `-m integration` (those need a live Ollama). Do not remove that marker to "fix" a slow suite.

## Repository layout

| Path | Role |
|---|---|
| `cli_engine.py` | Scan pipeline driver — `CyphexEngine.run()`, 9 phases. The largest file; most scan behaviour lives here. |
| `cx.py` | Interactive workspace (REPL) + slash commands. The default UX (`cyphex` with no args). |
| `cyphex_cli.py` | argparse driver behind `cyphex scan` etc. |
| `cyphex/cli.py` | Installed console-script entry point (`cyphex = "cyphex.cli:main"`). |
| `trace_deck.py` | Live per-phase trace deck + end-of-scan summary. |
| `nl_router.py` | Plain English → slash command, guardrailed, local Ollama. |
| `deck_input.py` | Raw-mode single-line editor behind the REPL's boxed input field. |
| `mascot*.py` | Tiered terminal pixel-art mascot (8 modules). Always imported defensively. |
| `terminal_ui.py` | All Rich rendering. Every `render_*` function. |
| `scoring.py` | **Sole** source of truth for the 0-100 posture score. |
| `backend/patch/` | Patch generation, application, and the Verify Gate. |
| `backend/observability/` | Event log + health aggregation. |
| `backend/deepagents/` | The 13 Oracle-guided attack agents. |
| `backend/council/` | Multi-model patch review. |
| `backend/rag/` | Code indexing, knowledge tree, cross-project memory. |
| `backend/network/` | Network discovery and behavioural flow monitoring. |
| `backend/platform_compat.py` | Cross-platform binary/shell resolution. |
| `tests/` | 392 tests (393 collected, 1 `integration` deselected). See [tests/README.md](tests/README.md). |

## Invariants — do not break these

**1. The Verify Gate's tri-state is load-bearing.**
`finding_gone` and `builds` are `True`/`False`/`None`. `None` means *unmeasured* and must **never** be coerced into a `PASS`. A check that ran and failed outranks one that never ran. This is the property the entire honesty claim rests on. See `backend/patch/verifier.py`.

**2. `scoring.py` is the only place the score is computed.**
`terminal_ui.py` and `cli_engine.py` both import from it. Never hand-copy the formula or the band thresholds — that exact duplication caused a shipped bug where three different formulas silently diverged. `tests/test_scoring.py::test_no_hand_copied_band_clamp_remains` walks the AST of every root-level `*.py` to enforce this; it will fail your change if you reintroduce a `min(score, <int>)` clamp.

**3. Observability must never break the scan.**
`backend/observability/events.py::emit()` is contractually incapable of raising. If you extend it, keep the blanket try/except. Adding a new event type needs no schema change — consumers tolerate unknown types by design.

**4. Only verified patches move the score.**
Remediation is tracked by vulnerability *object identity*, not file-path substring, so patching one finding cannot silently clear a file's other findings.

**5. Every terminal surface degrades twice.**
Rich unavailable → plain-text renderer. Terminal can't render box-drawing glyphs → ASCII fallback via `_ascii_mode()` / `_box()`. When adding a panel, take `box=` from `_box(console)`, not a hardcoded `CANOPY`, and route severity glyphs through `_sev_style()`.

**6. Cross-platform resolution goes through `platform_compat`.**
A bare `"tsc"` or `"npm"` is a `.cmd` shim on Windows that non-shell `subprocess` cannot launch, even when `shutil.which()` finds it. Use `resolve_binary_cmd()`. Use `sys.executable`, never a literal `"python"` — many Linux distros and macOS have no bare `python` on PATH.

**7. Don't gate a fix on `sys.platform == "win32"` when the real condition is the encoding.**
UTF-8 forcing must key off `sys.stdout.encoding`, not the platform — a POSIX box with `LANG=C` has the same failure mode.

**8. `cyphex verify|status|benchmark` are intercepted BEFORE argparse.**
`cyphex/cli.py::main()` routes these three to `_run_panel()` on `sys.argv[1]` before `parse_args()` runs, because argparse cannot forward an option-looking tail (`--ci`, `--selftest`, `--watch`) through a subparser — even `nargs=REMAINDER` lets the parent parser claim a leading `--flag` and die with "unrecognized arguments". Their subparsers exist only so `cyphex --help` lists them. `_cmd_verify`'s int return under `--ci` **must** become the process exit code or the CI gate is decorative.

## Where to change what

| Task | Start here |
|---|---|
| Add/modify a scan phase | `cli_engine.py::CyphexEngine.run()` — phases go through `self._step(num, title)` |
| Change what counts as a verified fix | `backend/patch/verifier.py` — then update `tests/test_verifier.py` |
| Add a maintainer-facing metric | `backend/patch/verify_health.py` → `terminal_ui.py::render_verify_health()` |
| Add a telemetry event | `self._emit("name", **fields)` in `cli_engine.py`; consume in `backend/observability/health.py` |
| Add a slash command | `cx.py`: `_cmd_X()` + `COMMANDS` list + `_handle()` case + `main()` argv branch + both help texts. If it should also be a `cyphex <cmd>`, add it to `cyphex/cli.py` — see invariant 8 |
| Add a Rich panel | `terminal_ui.py` — follow `render_verify_health()`'s shape; use `_box(c)` |
| Change the score | `scoring.py` only |
| Add a patch template | `backend/patch/templates.py` |

## Conventions

- **Comments explain *why*, not *what*.** This codebase's comments frequently document the bug a line prevents. Preserve that when editing near them.
- **Fail closed.** A guard that cannot run reports "unknown", never "fine".
- **No new hardcoded thresholds.** If a number gates behaviour, it belongs beside the other constants with a comment justifying its value.
- **Local imports for heavy modules** inside `cx.py` command handlers, to keep REPL startup fast.
- Run `python -m pytest tests/ -q` before claiming a change works. CI does not swallow failures.

## Things that look wrong but are deliberate

- **Verification re-enables comment-matching** even though ordinary scans ignore matches inside comments — otherwise a patch that merely comments out the vulnerable line would read as "finding gone" and PASS.
- **The council's verdict is advisory.** It cannot pre-empt the deterministic Verify Gate; a rejected-but-present patch still goes to the gate.
- **`UNVERIFIABLE` patches stay applied on disk** but do not count toward the score. That asymmetry is intentional.
- **The Alpine CI job installs only `rich httpx`**, not the full extras — numpy/scikit-learn lack musllinux wheels and would trigger a multi-minute source build. The modules under test import neither at module scope.

## Further reading

- [docs/VERIFICATION_MAINTAINABILITY_PANEL.md](docs/VERIFICATION_MAINTAINABILITY_PANEL.md) — the verification surface in depth
- [CYPHEX_PRD.md](CYPHEX_PRD.md) — living specification, known gaps, roadmap
- [llms.txt](llms.txt) — condensed project summary ([llmstxt.org](https://llmstxt.org))
- [llms-full.txt](llms-full.txt) — self-contained brief: enough to answer most questions without opening another file
- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, PR checklist, the invariants above restated for humans
- [SECURITY.md](SECURITY.md) — CYPHEX's own threat model and disclosure policy
- Per-directory READMEs: [`cyphex/`](cyphex/README.md) · [`backend/`](backend/README.md) · [`tests/`](tests/README.md) · [`docs/`](docs/README.md) · [`benchmarks/`](benchmarks/README.md) · [`sdks/node/`](sdks/node/README.md) · [`scripts/`](scripts/README.md) · [`assets/`](assets/README.md)
