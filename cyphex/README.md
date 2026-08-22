# `cyphex/` — the installed package

This is the only directory `pip install -e .` actually installs as a package
(`[tool.setuptools.packages.find] include = ["cyphex*"]`). The engine modules it
imports live at the repo root and are exposed separately via `py-modules`.

Entry point: `cyphex = "cyphex.cli:main"`.

| File | Role |
|---|---|
| `cli.py` | The `cyphex <cmd>` argparse surface and dispatch |
| `scanner.py` | Static analysis — Semgrep plus 16 built-in regex rulesets, merged, de-duplicated, confidence-scored |
| `dynamic_scanner.py` | Nuclei / OWASP ZAP integration (the non-DeepAgents DAST path) |
| `docker_sandbox.py` | Hardened container deployment, with a resource-capped subprocess fallback |
| `daemon.py` | The `/watch` auto-heal daemon on `127.0.0.1:3004` |
| `doctor.py` | Environment check — binaries, Ollama reachability, pulled models, hardware |
| `hardware.py` | VRAM detection, tier selection, model choice per tier |
| `onboarder.py` | Zero-click injection of the RASP shield into a target app |
| `github_hook.py` | The opt-in PR flow — **the one path that leaves your machine** |
| `formatters.py` | `table` / `json` / `sarif` / `markdown` output |

---

## `cli.py` — the one non-obvious thing

`verify`, `status` and `benchmark` are intercepted in `main()` **before**
`parse_args()` runs, and routed to `_run_panel()`, which delegates to `cx.py`'s
existing handlers.

This is not stylistic. argparse cannot forward an option-looking tail
(`--ci`, `--selftest`, `--watch`) through a subparser: even `nargs=REMAINDER`
lets the *parent* parser claim a leading `--flag` and die with
`unrecognized arguments: --ci`. Their subparsers are still registered, but only
so `cyphex --help` lists them.

`_cmd_verify` returns an `int` only under `--ci`, and that int **is** the CI
verdict (`0` healthy / `1` degraded / `2` unusable). It has to become the
process exit code or the gate is decorative.

Adding a command that takes flags? Follow the same shape. Adding one that does
not? A normal subparser is fine.

---

## Scanner notes

- Semgrep never runs `--config auto` — that uploads project metadata on every
  run. The ladder is: a local `cyphex/semgrep_rules.yml` if present (fully
  offline) → the static `p/owasp-top-ten` pack, cached after the first fetch.
  No local rules file is bundled today, so a genuinely air-gapped first run has
  built-in rules only.
- `--metrics=off` is always passed.
- Confidence starts at 0.90 (Semgrep) or 0.85 (built-in regex). Findings at or
  below `FP_DROP_THRESHOLD` (0.15) are dropped from ordinary scans — but a match
  inside a comment, scored 0.0, stays **visible to the verifier**. See the
  Verify Gate section of [`../README.md`](../README.md) for why.

## Sandbox notes

Docker flags are `--cap-drop ALL`, `--memory 512m`, `--cpus 1`,
`--pids-limit 200`, `no-new-privileges`, non-root user, and a port bound to
`127.0.0.1` only. `npm install --ignore-scripts` blocks postinstall RCE. The
subprocess environment is an explicit allow-list — never `os.environ.copy()`.

Without Docker, deployment falls back to a resource-capped native subprocess and
says so rather than failing.

## Terminal output

Every surface degrades twice: no Rich → plain text; a terminal that cannot
render box-drawing glyphs → pure ASCII. UTF-8 forcing in `cli.py` keys off
`sys.stdout.encoding`, **not** `sys.platform` — a POSIX box with `LANG=C` has
the same failure mode Windows does, and CI has a job that proves it.
