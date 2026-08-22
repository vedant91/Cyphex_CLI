# `scripts/`

Convenience shell scripts for end-to-end runs. **Bash only** — there is no
native `.ps1` / `.cmd` equivalent yet, so on Windows these need WSL or Git Bash.
The `cyphex` CLI itself does not.

All three assume a venv at `.venv/` in the repo root.

| Script | Does |
|---|---|
| `run_pipeline_one_command.sh [target_path] [output_file]` | Full scan pipeline in one shot. Defaults: `backend/sandbox/vulncorp` → `cyphex_output.txt`. `GENERATIONS` (default 10) overrides the co-evolution generation count |
| `start_platform_stack.sh` | Brings up the backend API stack |
| `run_api_e2e_scan.sh [target_url]` | Drives a scan **through the HTTP API** and polls to completion. Needs the stack already running. `API_BASE` (default `http://localhost:8000`), `TARGET_URL` (default `http://localhost:3001`), `TIMEOUT_SECS` (default 1800) |

Typical API path:

```bash
./scripts/start_platform_stack.sh          # terminal 1
./scripts/run_api_e2e_scan.sh http://localhost:3001    # terminal 2
```

For ordinary use you want the CLI, not these:

```bash
cyphex scan ./my-app
```

These scripts exist for the API-driven path and for reproducing full pipeline
runs with a fixed generation count.
