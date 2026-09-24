## graphify

This project has a graphify knowledge graph in `graphify-out/` (git-ignored).
The `graphify` CLI is the Python tool `graphifyy` (installed via
`pipx install "git+https://github.com/Graphify-Labs/graphify"`); it is a
Python CLI, not `npx`. Git hooks (`graphify hook install`) rebuild the graph on
every commit and checkout, so it stays current on its own.

Rules:
- For codebase or architecture questions, when `graphify-out/graph.json` exists,
  first run `graphify query "<question>"` (or `graphify path "<A>" "<B>"` /
  `graphify explain "<concept>"`); these return a scoped subgraph, usually much
  smaller than `GRAPH_REPORT.md` or raw grep output. All read commands default
  to `graphify-out/graph.json`.
- For change-impact ("what breaks if I touch X"), use `graphify affected "X"`
  (reverse traversal) instead of generic traversal. `graphify god-nodes` lists
  the most-connected architectural hubs.
- Read `graphify-out/GRAPH_REPORT.md` only for broad architecture review, or
  when `query` / `path` / `explain` / `affected` do not surface enough context.
- The graph auto-rebuilds via the git hooks. To refresh it by hand after code
  changes (deterministic, no LLM), run `graphify update .`; `graphify check-update .`
  reports whether a semantic re-extraction is pending. `graphify export wiki`
  emits browsable wiki markdown if you prefer navigating that over raw files.
- `graphify-out/` is git-ignored; do not commit it. SQL parsing needs the
  `graphifyy[sql]` extra (already installed here).
