# `frontend/` — experimental dashboard

> **Status: experimental. Not wired into the CLI.**
> Nothing in `cyphex scan`, `cyphex verify` or the workspace touches this
> directory, and nothing here is installed by `pip install -e .`. Do not
> describe it as a shipped feature of CYPHEX.

A React + TypeScript + Vite prototype of a scan-results dashboard — agent table,
remediation cards, charts. It reads no live data today; the CLI writes its
artifacts to `.cyphex/` and the two are not connected.

## Running it

```bash
cd frontend
npm install
npm run dev        # vite
npm run build      # tsc -b && vite build
npm run lint
```

Stack: React 19, Vite, TailwindCSS 4, framer-motion, lucide-react,
`@react-three/fiber`.

## If you plan to finish it

The scan pipeline already emits everything a dashboard needs — start there
rather than inventing a new format:

| Source | Contains |
|---|---|
| `.cyphex/patches.json` (per scan) | Every patch and its `PASS` / `FAIL` / `UNVERIFIABLE` verdict |
| `events.jsonl` (per scan) | Append-only phase timings, agent outcomes, errors |
| `cyphex scan --format json` / `--format sarif` | The findings themselves |
| `backend/patch/verify_health.py` | The aggregation the `cyphex verify` panel already computes |
| `cyphex verify --json out.json` · `cyphex status --json out.json` | Both panels, machine-readable |

The tri-state verdict is load-bearing: `UNVERIFIABLE` is **not** a soft pass and
must never be rendered as one. See the Verify Gate section of
[`../README.md`](../README.md).

`package.json` still carries the scaffold's `"name": "customapp"`.
