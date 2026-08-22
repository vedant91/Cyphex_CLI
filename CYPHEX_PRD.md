# CYPHEX — Product Requirements Document (PRD)

> **CYPHEX** — *Autonomous, offline-first AI cyber-defence engine.* It scans an app, attacks it in a sandbox, debates findings with a panel of local AI models, evolves a self-taught "immune system," and auto-patches the source code — **100% on your machine, with no cloud API keys.**

| Field | Value |
|---|---|
| **Product** | CYPHEX CLI |
| **Version (code)** | 0.1.0 (Alpha) · UI build v4.4 |
| **Document version** | 1.0 |
| **Status** | Living document — reflects the code on branch `updates_p1` |
| **Runtime** | Python ≥ 3.11, local [Ollama](https://ollama.com) models only |
| **License** | MIT |

---

## Table of Contents

**Part I — Product**
1. [Executive Summary](#1-executive-summary)
2. [Vision & Mission](#2-vision--mission)
3. [The Problem](#3-the-problem)
4. [The Solution — Five Paradigms in One Command](#4-the-solution--five-paradigms-in-one-command)
5. [Goals & Non-Goals](#5-goals--non-goals)
6. [Target Users & Personas](#6-target-users--personas)
7. [Guiding Principles](#7-guiding-principles)
8. [Differentiators](#8-differentiators)

**Part II — System**
9. [System Overview & Architecture](#9-system-overview--architecture)
10. [Glossary — Every Term at a Glance](#10-glossary--every-term-at-a-glance)
11. [Concept Reference (the detailed core)](#11-concept-reference)
12. [End-to-End Pipeline Walkthrough (the 9 waypoints)](#12-end-to-end-pipeline-walkthrough)
13. [Data Model & Artifacts](#13-data-model--artifacts)

**Part III — Requirements & Governance**
14. [Functional Requirements](#14-functional-requirements)
15. [Non-Functional Requirements](#15-non-functional-requirements)
16. [Metrics & Success Criteria](#16-metrics--success-criteria)
17. [Ethics, Safety & Compliance](#17-ethics-safety--compliance)
18. [Current Implementation Status & Known Gaps](#18-current-implementation-status--known-gaps)
19. [Risks & Mitigations](#19-risks--mitigations)
20. [Roadmap / Future Scope](#20-roadmap--future-scope)
21. [Appendices](#21-appendices)

---
---

# Part I — Product

## 1. Executive Summary

CYPHEX is a command-line security platform that does something most tools don't: it **finds vulnerabilities AND fixes them**, without sending a single byte of your code to the cloud.

You point it at a folder or a GitHub URL. It:
1. **Reads** the source code and flags risky patterns (static analysis).
2. **Runs** the app inside an isolated sandbox and attacks it like a real hacker (dynamic analysis + AI attack agents).
3. **Debates** every finding across several local AI models to weed out false alarms.
4. **Grows an "immune system"** — a self-taught model of what *normal* traffic looks like for *your* app — and hardens it by making an AI red-team and blue-team fight each other.
5. **Auto-patches** the vulnerable source code, has other AI models review each fix, and only accepts a fix if a re-scan proves the bug is actually gone.

Everything runs on **local Ollama models** (small 6–8-billion-parameter models that fit on a laptop or even a Raspberry Pi). No OpenAI key, no billing, no data leakage. The whole run is presented in a "glass-cockpit" terminal UI that reads like a fighter-jet HUD.

---

## 2. Vision & Mission

- **Vision:** Every developer — especially those "vibe-coding" with AI assistants — should have an autonomous security teammate that catches and fixes vulnerabilities before they ship, without cost, cloud dependency, or security expertise.
- **Mission:** Collapse the entire security lifecycle — *scan → attack → verify → fix → harden* — into a single offline command that anyone can run.
- **One-line pitch:** *"An offline-first, multi-agent autonomous security platform that scans, attacks, debates, evolves, and patches — all without a single API key."*

---

## 3. The Problem

> **Vibe coding is the future. But vibe-coded apps ship with vulnerabilities that no one checks.**

Developers build fast with AI assistance, and security becomes an afterthought. Existing tools have structural gaps:

| Gap | Why it hurts |
|---|---|
| **Static scanners (SAST)** find code patterns but can't see runtime behavior. | Miss injection/auth bugs that only appear when the app runs. |
| **Dynamic scanners (DAST)** attack the running app but don't understand the source. | Produce a URL, not a file to fix. |
| **Neither one fixes anything.** | Developers get noisy reports and zero patches. |
| **Cloud tools require API keys** and upload your code to third-party servers. | Your proprietary code leaves your machine — a security risk in itself — and it costs money. |
| **No tool adapts.** | They run the same rules every time and never learn your app's behavior. |

**Result:** vulnerabilities reach production, breaches happen, and the fix always lands on an already-overloaded developer.

---

## 4. The Solution — Five Paradigms in One Command

CYPHEX fuses five security paradigms into one CLI:

| # | Paradigm | What CYPHEX does |
|---|---|---|
| 1 | **Static Analysis (SAST)** | Scans source across 20+ languages using Semgrep rules **+** a built-in regex engine (findings from both are merged). |
| 2 | **Dynamic Analysis (DAST)** | Deploys the app in a sandbox and attacks it with Nuclei **+ 10 specialized AI attack agents**. |
| 3 | **AI Verdict Council** | Multiple local LLMs independently review each finding/fix and vote to eliminate false positives. |
| 4 | **Behavioral Immune System** | A self-evolving "genome" (Isolation-Forest ML) that learns what *normal* looks like for *your* app and blocks anomalies. |
| 5 | **Auto-Patching + Verification** | AI writes fixes, the council reviews them, and a verification gate confirms the vulnerability is truly resolved before counting it fixed. |

**Why offline-first?** *Security tools that upload your code to the cloud are themselves a security vulnerability.* CYPHEX runs 100% locally via Ollama; source code, reports, and patches never leave the machine.

---

## 5. Goals & Non-Goals

### Goals
- **G1 — Find and fix, locally.** Detect vulnerabilities *and* produce verified source-code patches, entirely offline.
- **G2 — Zero-config.** No API keys, no model selection, no cloud setup; auto-detect hardware and pick the best local models.
- **G3 — Honest results.** A fix only counts as "fixed" if a re-scan proves it; unverifiable results are never silently claimed.
- **G4 — Adaptive defense.** Learn each app's normal behavior and harden against novel/mutated attacks via adversarial co-evolution.
- **G5 — Measurable.** Provide reproducible metrics (precision/recall/F1) for the immune system, usable as a CI gate.
- **G6 — Portable.** Run from a high-end GPU workstation down to a Raspberry Pi 5 (graceful degradation to heuristics when ML libraries are absent).

### Non-Goals
- **NG1** — Not a cloud SaaS; no multi-tenant hosted service is in scope for this document.
- **NG2** — Not an external/live-internet attack tool. **All offensive activity is sandbox-only, against the user's own code** (see [§17 Ethics](#17-ethics-safety--compliance)).
- **NG3** — Not a replacement for human security review on high-stakes systems; it augments, not replaces, expert judgment.
- **NG4** — Not dependent on any paid cloud LLM (an optional Groq cloud fallback exists but is off by default).

---

## 6. Target Users & Personas

| Persona | Who they are | What they need from CYPHEX |
|---|---|---|
| **Sam, the vibe-coder** | Solo/indie dev shipping AI-generated apps fast, limited security knowledge. | One command that finds *and* fixes bugs before deploy, with plain-English explanations. |
| **Priya, the security-conscious startup engineer** | Full-stack dev at a small team, no budget for enterprise scanners. | A free, local, no-API-key scanner that produces real patches and a SARIF report for CI. |
| **Ravi, the privacy-bound engineer** | Works on proprietary/regulated code that legally cannot leave the machine. | 100% offline scanning and patching; nothing uploaded. |
| **The CI pipeline** | Automated build/test system. | Non-interactive scanning, deterministic JSON/SARIF artifacts, and a benchmark gate that fails the build on regressions. |
| **The maintainer/reviewer** | Owns the repo's security posture over time. | A visible before/after story, reproducible metrics, and clear ethics posture. |

---

## 7. Guiding Principles

1. **Local-first, offline-capable.** Default path uses only local Ollama models and local tools. The app must remain usable with no network.
2. **Graceful degradation.** If a heavy dependency (Docker, scikit-learn, cognee, Semgrep, Nuclei) is missing, degrade to a simpler mode rather than crash.
3. **Honesty over hype.** Only *verified* fixes move the score. Unmeasurable outcomes are marked `UNVERIFIABLE`, never "fixed."
4. **Fail-closed security.** Path containment, symlink rejection, HMAC-signed model caches, and backup/rollback protect the user's files and machine.
5. **Sandbox-only offense.** Attacks run only against the user's own app inside an isolated sandbox — never against live external systems.
6. **Adapt to hardware.** Auto-detect VRAM and pick the largest models that fit; never ask the user to choose.

---

## 8. Differentiators

- **Find *and* fix, offline.** Most tools do one; CYPHEX closes the loop locally.
- **The behavioral immune system.** A self-taught, per-endpoint anomaly model that learns *your* app rather than matching a signature database — and hardens itself via red-team/blue-team co-evolution.
- **Multi-model council.** Small local models cross-check each other's findings and patches, compensating for any single model's weakness.
- **Verification gate.** A fix is accepted only after a re-scan confirms the bug is gone, syntax is valid, and the change is within a blast-radius budget.
- **RASP + auto-heal.** A drop-in runtime shield that not only blocks live attacks but pinpoints the exact vulnerable source line (via stack trace) and triggers an AI patch.

---
---

# Part II — System

## 9. System Overview & Architecture

CYPHEX is a pipeline. A target (folder or GitHub URL) flows through a series of stages ("waypoints"), each enriching a shared **`ScanContext`** object, ending in verified patches and a security score.

```
                          ┌─────────────────────────────────────────────────────────────┐
   target path / URL ───▶ │                     CYPHEX ENGINE (cli_engine.py)            │
                          └─────────────────────────────────────────────────────────────┘
                                     │
   1. GET SOURCE ────────────────────┤  copy/clone target → sandbox copy
   2. STATIC ANALYSIS (SAST) ────────┤  Semgrep + built-in 20-lang scanner  ──► findings
   3. DEPLOY SANDBOX ────────────────┤  Docker container (auto Dockerfile) or native fallback
   3b. NETWORK SCAN (optional) ──────┤  netmap host/port sweep + network genome
   4. DYNAMIC ANALYSIS (DAST) ───────┤  Nuclei + Crawler + 10 DeepAgents (Oracle-guided)
   5. IMMUNE SYSTEM: BUILD GENOME ───┤  learn "normal", adversarial co-evolution
   6. ATTACK SIMULATION ARENA ───────┤  BEFORE/AFTER genome defense demo
   7. SECURITY REPORT ───────────────┤  Analysis Council writes + validates report
   8. AI PATCH + VERIFY ─────────────┤  Template→RAG→LLM→Council→Verify (per vuln)
   9. FINAL BANNER ──────────────────┘  before/after score + patch counts
```

**Supporting layers** (used throughout):
- **Local models** (Ollama): `qwen2.5-coder:7b` (patcher/planner), `llama3.1:8b` (analyst/reviewer), `deepseek-coder:6.7b` (reviewer), `nomic-embed-text` (embeddings).
- **Memory**: per-project patch cache, cross-project knowledge graph (cognee), cross-scan session memory.
- **Immune system**: behavioral genome, co-evolution, RASP.
- **Glass-cockpit UI**: waypoints, DEFCON/genome status rail, before/after panels.

---

## 10. Glossary — Every Term at a Glance

| Term | Plain-English meaning |
|---|---|
| **ScanContext** | The shared "clipboard" object that carries endpoints, forms, evidence, and confirmed vulnerabilities through every stage. |
| **Sandbox** | An isolated copy of the target app that CYPHEX runs (in a Docker container or a local process) so it can safely attack it. |
| **SAST** | Static Application Security Testing — reading the source code to find risky patterns. |
| **DAST** | Dynamic Application Security Testing — attacking the *running* app. |
| **DeepAgent** | A specialized AI attacker (one per vulnerability class) that adapts its attacks based on the app's responses. |
| **Oracle** | The local LLM "brain" that plans attacks, judges responses, and mutates payloads for the DeepAgents. |
| **Attack Surface Index (ASI)** | A running summary of everything CYPHEX has learned about the target's endpoints, fed to the Oracle as context. |
| **Behavioral Genome** | A machine-learned model of what *normal* input looks like for each endpoint; flags anomalies. |
| **Feature Vector** | The 15 numbers CYPHEX measures from any input string — the "DNA" the genome reasons over. |
| **Co-Evolution** | An AI red team (mutating attacks) and blue team (hardening the genome) fighting across "generations." |
| **RASP** | Runtime Application Self-Protection — a drop-in shield that blocks attacks on the *live* app. |
| **Council** | A panel of local LLMs that vote on whether a finding is real or a fix is good. |
| **Vectorless RAG** | Giving the AI relevant code context using a keyword index — no embeddings or vector database. |
| **Verification Gate** | The objective check that a patch actually removed the vulnerability before it's counted as fixed. |
| **Blast Radius** | How many lines a patch changed; capped per severity to prevent over-broad rewrites. |
| **Security Posture Score** | A 0–100 number summarizing how secure the app is (higher = safer). |
| **Waypoint** | One numbered stage of the scan pipeline, shown in the UI. |
| **Reflexion** | Retrying a rejected patch after feeding the reviewers' criticism back to the model. |

---

## 11. Concept Reference

> This is the detailed core. Every concept is documented as **What / How / Why / Where** so it stays simple but complete. Sections are grouped by subsystem.

### 11.1 Entry Points & the CLI

**Three-layer entry architecture.**
- **What:** three ways to start CYPHEX that stack on each other — the installed `cyphex` command, the interactive `cx` workspace (REPL), and the low-level `cyphex_cli.py` engine driver.
- **How:** `cyphex` (pip console-script → `cyphex.cli:main`) with no subcommand opens the workspace by importing the `cx` module. The `cx` REPL parses slash-commands and, for scans/network/watch, shells out to `cyphex_cli.py` (an argparse CLI) which drives the async `CyphexEngine` in `cli_engine.py`.
- **Why:** a friendly always-open "cockpit" like modern AI CLIs, with a scriptable command backend underneath for automation/CI.
- **Where:** `cyphex/cli.py`, `cx.py`, `cyphex_cli.py`, `cli_engine.py`.

**The `cx` interactive REPL (workspace).**
- **What:** a persistent prompt where you type slash-commands or just a path/URL to scan.
- **How:** a loop repaints the status deck, reads a line, and dispatches via `match/case`. Keeps in-memory session state (`last_path`, `last_target`, `history`). Ctrl+C starts a fresh line; Ctrl+D quits. Bare input is auto-scanned; Tab autocompletes commands.
- **Why:** one always-open interface instead of long argparse invocations.
- **Where:** `cx.py`.

### 11.2 Commands

| Command (aliases) | What it does |
|---|---|
| **`/scan <target>`** | Core command: static + standard DAST scan of a path or GitHub URL, then auto-patch (unless `--no-patch`). |
| **`/deep <target>`** (`/deepagents`) | Adds the Oracle-guided **DeepAgents** attack swarm (implies `--network`). |
| **`/full <target>`** | Everything: DeepAgents **+** network sweep. |
| **`/net [host]`** (`/netmap`) | Network discovery / audit; trains network-genome baselines. |
| **`/netwatch`** | Continuous behavioral network anomaly monitor (live IDS). |
| **`/netaudit <host>`** | Deep single-host audit. |
| **`/watch`** | Starts the **RASP auto-heal daemon** (localhost:3004). |
| **`/setup`** | Installs Semgrep & Nuclei; checks Ollama & Docker. |
| **`/doctor`** | Health check: models, tools, dependencies. |
| **`/benchmark`** (`cx benchmark`) | Scores the immune system (precision/recall/F1) over a labelled corpus. |
| **`/verify [path]`** (`cx verify`) | **Verify Gate maintainability panel** — config (blast-radius caps, toolchain readiness), status (durability rate, per-CWE breakdown, scan-over-scan trend), and next steps. `--selftest` live-drives each check against a synthetic fixture instead of just probing tool presence; `--ci` prints a PASS/DEGRADED/UNUSABLE verdict and returns a CI-gateable exit code (0/1/2); `--watch [s]` live-refreshes; `--json <file>` writes the report. |
| **`/status [path]`** (`cx status`) | **System Observability dashboard** — reads the append-only event log a scan writes (`backend/observability`) and shows the last scan's phase timings, DeepAgents swarm outcomes, cognee recall/persist rates, and a recent-errors tail, alongside a one-line Verify Gate summary. Same `--watch [s]` / `--json <file>` flags as `/verify`. |
| **`/models`, `/history`, `/version`, `/clear`, `/help`, `/exit`** | Utility commands. |

**Scan flags:** `--network`/`-n` (network sweep), `--deepagents` (attack swarm), `--full`/`--all` (both), `--no-patch`/`--scan-only` (skip patching), `--verbose`/`-v` (show full pipeline detail — per-payload DAST narration, per-file SAST hits, patch-loop internals — instead of the concise phase-summary default). These map to `cyphex_cli.py scan` flags `--network`, `--use-deepagents`, `--no-patch`, `--verbose`.

**Scan intensity differences.** `scan` = static + standard DAST + immune + patch. `deep` = + DeepAgents (+ network). `full` = deep + network. All three run the same waypoint pipeline; the flags just toggle the network step and swap the DAST implementation for DeepAgents.

**`cyphex_cli.py scan` (engine driver).** The real argparse command: `--repo`/`--path` (one required), `--branch` (default `main`), `--generations` (default `10`), `--no-patch`, `--judge`, `--non-interactive`, `--network`, `--use-deepagents`, `--verbose`. Runs `asyncio.run(engine.run(...))`.

### 11.2b Observability

- **What:** a structured, best-effort JSONL event log (`backend/observability/events.py`) written during every scan, plus a maintainer health aggregator (`backend/observability/health.py`) that reads it back. Fixes the prior state where scan telemetry was three uncoordinated, ephemeral surfaces: Rich console prints that vanish on scroll, a cumulative session-memory JSON with no phase timings, and a cognee-recall failure path that produced zero signal at all.
- **How:** `CyphexEngine._emit(event, **fields)` appends one JSON line per event (`scan_start`, `phase_start`, `deepagent_result`/`_timeout`/`_error`, `cognee_recall_result`, `cognee_persist_result`, `patch_verdict`, `scan_end`) to `<scan sandbox>/.cyphex/events.jsonl` — same storage convention as `PatchManifest`'s `patches.json`, discoverable with the same `backend/sandboxes/*/.cyphex/*` glob. `emit()` never raises; a full disk or bad field degrades to a silent no-op, never a scan-breaking crash.
- **Why:** a maintainer needs to answer "is the pipeline healthy right now, and what happened on the last scan" without re-reading scrollback — phase durations, DeepAgents swarm success/timeout/error counts, and cognee's actual persist rate.
- **Where:** `backend/observability/events.py`, `backend/observability/health.py`; surfaced via `/status` (`terminal_ui.render_observability`).

### 11.2c Verbosity (`--verbose`)

- **What:** `CyphexEngine.verbose` (default `False`) gates the pipeline's highest-volume chatter — per-payload DAST attack narration, per-file SAST match dumps, raw docker-retry/log-tail noise, and per-vulnerability patch-loop internals — behind `self._vprint()`/`self._vconsole()`.
- **How:** phase-boundary banners (`_step`), one-shot phase-completion summaries ("SAST: N files scanned", "SANDBOX LIVE AT ...", the final APPLIED/REJECTED line per patch), and `_final_banner()` always print regardless of `--verbose` — only the per-item chatter inside the two largest loops (`_dynamic_scan()`'s attack-agent loop, `_patch_workflow()`'s per-vuln loop) is gated.
- **Why:** the default scan output had grown to ~325 print/console.print call sites, the bulk of them inside per-payload/per-file/per-vuln loops rather than firing once per phase — a single scan could print hundreds of lines. Gating keeps the CLI focused on phase banners and final results by default, with the full trace still one flag away.
- **Where:** `cli_engine.py` (`CyphexEngine._vprint`/`_vconsole`), wired through `cyphex_cli.py --verbose` and `cx.py`'s `/scan --verbose`.

### 11.3 Configuration

- **What:** all settings live in one dataclass (`CyphexConfig`), overridable by environment variables (loaded from `.env`).
- **Key knobs (defaults):**

| Setting | Default | Meaning |
|---|---|---|
| `AI_BACKEND_MODE` | `local` | `local` (Ollama), `groq` (cloud fallback), `cerebras` (legacy). |
| `OLLAMA_URL` / `OLLAMA_MODEL` | `localhost:11434` / `qwen2.5-coder:7b` | Local model server + default coding model. |
| `SCAN_TIMEOUT_SECONDS` | `1800` | Max scan time (30 min). |
| `MAX_PARALLEL_AGENTS` | `6` | Parallelism cap. |
| `GENOME_BLOCK_THRESHOLD` | `0.7` | Anomaly score above this = BLOCK. |
| `EVOLUTION_GENERATIONS` | `10` | Co-evolution generations per run. |
| `EVOLUTION_PAYLOADS_PER_GEN` | `20` | Attack payloads per generation. |
| `EVOLUTION_CONVERGENCE_THRESHOLD` | `0.99` | Block-rate at which evolution stops early. |
| `COGNEE_RECALL_TIMEOUT_S` / `COGNEE_REMEMBER_TIMEOUT_S` | `20` / `300` | Knowledge-graph read/write time budgets. |
| `API_BIND_HOST` / `API_BIND_PORT` | `127.0.0.1` / `8000` | Optional API server binding (localhost-only by default). |

- **Where:** `backend/backend/config.py`, `.env.example`.

### 11.4 Local Models, Hardware Tiers & VRAM

**Local model roster & hardware tiers.**
- **What:** a catalog of Ollama models tagged by role and VRAM need, grouped into tiers that decide which models the machine can run.
- **How:** `hardware.py` detects VRAM (nvidia-smi / Apple `hw.memsize × 0.75` / rocm-smi) and buckets it into `ultra (24GB+) / high (12+) / mid (6+) / low (4+) / minimal (2+) / cloud (<2)`. It recommends the best-fitting code + general model (and a diverse validator), requiring **≥7B params** to patch/debate ("always use the largest model your hardware can run").
- **Why:** small models write poor patches; adapt to hardware without asking the user to choose.
- **Where:** `cyphex/hardware.py`.

**ModelSelector (role brain).** Discovers actually-installed models via `/api/tags`, scores them (code models get a bonus on code tasks), and assigns roles — **detector, validator, patcher** — with an execution strategy: `SOLO_POWERHOUSE` (1 model, self-review), `DUAL_SPECIALIST` (2 in parallel), or `FULL_COUNCIL` (3+). Reviewers **always exclude the patcher** so a model never reviews its own patch. *(`backend/council/model_selector.py`)*

**VRAMManager.** Tracks loaded models against a budget (`VRAM − 2GB`, minimum ~4GB); with ≥8GB it runs two models in parallel, otherwise sequentially, evicting least-recently-used models (`keep_alive=0`) to stay within budget. *(`backend/council/council_orchestrator.py`)*

**Default role assignment:** `qwen2.5-coder:7b` = patcher / planner / report-writer; `llama3.1:8b` = analyst / reviewer / validator; `deepseek-coder:6.7b` = second reviewer; `nomic-embed-text` = embeddings (cognee, 768-dim).

### 11.5 The Glass-Cockpit UI

- **What:** a "fighter-jet HUD" terminal presentation of the pipeline.
- **How:** `terminal_ui.py` renders **waypoint** headers (numbered stages with progress dots), mastheads, before/after panels, and a **command deck status rail** showing POSTURE, THREAT counts, GENOME version, a DEFCON level (1–5), an EKG heartbeat, and a weapons indicator (`SAFE/ARMED/HOT`). Degrades cleanly to plain ANSI when `rich` or a TTY is unavailable.
- **Why:** frames CYPHEX as a SOC/immune-system command deck and makes abstract progress tangible and demo-ready.
- **Note:** the genome version tag (`v14`) and DEFCON default are **cosmetic labels**, not driven by real genome-version or computed threat state.
- **Where:** `terminal_ui.py`.

### 11.6 Sandbox & Deployment

**Three-tier deploy fallback (`_deploy`).** CYPHEX runs the target so it can attack it, choosing the best available method:
1. **Docker Compose** — if the target has `docker-compose.yml`, deploy the full stack (app + DB), tearing down stale containers first.
2. **Docker single container** — if Docker is available (with or without a Dockerfile), **build and run a real container**; if the target has no Dockerfile, CYPHEX **auto-generates one** (Node → `node:*`, Python → `python:*`) and captures `docker logs`.
3. **Native subprocess** — fallback: `npm install` + start (or `python app.py`) as a local process, streaming stdout/stderr to a persistent `_cyphex_sandbox.log`.
- **Why:** a real container gives isolation + retrievable logs; the native path keeps the tool working when Docker isn't usable.
- **Safety:** ZIP packaging guards against zip-slip / zip-bomb / symlink escapes; containers/processes are torn down on completion.
- **Where:** `cli_engine.py` (`_deploy`), `backend/backend/sandbox_manager.py`, `cyphex/docker_sandbox.py`.

### 11.7 Static Analysis (SAST)

- **What:** reads source code across 20+ languages to flag risky patterns, without running it.
- **How:** runs **Semgrep** (rich ruleset, telemetry disabled for local-first) **and** a **built-in 20-language regex scanner** (`LANGUAGE_PATTERNS`), then **merges** the results (deduped by file:line:rule) — previously they were mutually exclusive, which shrank coverage. Findings are normalized into `StaticFinding` objects with CWE IDs; parameterized-query patterns are suppressed as false positives.
- **Why:** cheap, fast, source-aware detection; merging maximizes coverage and works offline (the built-in scanner needs no network).
- **Where:** `cyphex/scanner.py`.

### 11.8 Dynamic Analysis (DAST)

- **What:** attacks the *running* sandboxed app to find runtime bugs.
- **How:** runs **Nuclei** (streaming `-jsonl` results, generic detection templates — the heavy `cve` template set is excluded because it never matches a bespoke app and stalls), and optionally **OWASP ZAP**. Findings become `DynamicFinding` objects. (The heavy lifting is done by the DeepAgents, §11.12.)
- **Why:** static analysis can't see runtime injection/auth flaws; DAST attacks the live app.
- **Where:** `cyphex/dynamic_scanner.py`.

### 11.9 Crawler & Route/API Discovery

**Live HTML crawler (Agent 02).** Fetches pages, discovers links, forms, and parameters on the running sandbox.

**Vectorless code indexer (`CodeIndexer`).** Walks the source tree (skipping `node_modules`, `.git`, `.cyphex`, secret files, and files >512KB) and records per file: routes, functions, imports, and `has_db`/`has_auth`/`has_input` flags — a keyword index with **no embeddings/vector DB**.

**Source-code route extraction (`extract_api_routes`).** Parses Express/Nest/Flask route definitions from the code to learn the real API surface (mount prefixes + method + path + params), so the scanner probes actual endpoints, not guesses.

**Live API probing + SPA detection (Agent 02b).** When there are no HTML forms (a single-page app), CYPHEX probes the discovered routes directly, creates synthetic forms for login endpoints, and **prunes dead (404) routes** so attackers never waste time on non-existent endpoints.

- **Where:** `backend/rag/code_indexer.py`, `cli_engine.py` (crawler + API discovery).

### 11.10 Network Scanning

**NetworkDiscovery.** Host sweep + port scan of a subnet or host; scores each host's risk, guesses services, classifies device type, and reads the ARP cache. **NetworkVulnMapper** adds a static knowledge base + active service checks.

**Network Behavioral Genome (25-D).** The immune-system idea applied to network traffic: a per-device Isolation-Forest baseline over a **25-dimension** feature vector (traffic volume, port behavior, protocol mix, temporal patterns, destinations, scan indicators). Anomalies report the top deviating features for explainability, with severity by score.

**FlowCollector + `/netwatch`.** Continuously samples live traffic, scores each window against saved baselines, and — on an anomaly — prints device/score/severity/features and enriches via **NetworkOracle** (threat scenario + MITRE technique + containment actions).

**TopologyBuilder.** Builds a network graph and analyzes attack paths.

- **Where:** `backend/network/*` (`network_genome.py`, `flow_collector.py`, `oracle_network.py`, `models.py`).

### 11.11 ScanContext (shared data model)

- **What:** the single object that flows through the whole pipeline, carrying discovered endpoints, forms, parameters, raw evidence, and confirmed vulnerabilities.
- **Why:** every stage reads and enriches the same state, so later stages (genome, patching, reporting) can use everything found earlier.

### 11.12 DeepAgents & the Oracle

**BaseDeepAgent — the Observe → Think → Act loop.**
- **What:** each attack agent runs an adaptive loop: probe the target, let the Oracle judge the response, and adapt.
- **How:** the agent measures a baseline response time, asks the Oracle to **plan** hypotheses, then tests each hypothesis in parallel batches. Per hypothesis it probes up to `MAX_ATTEMPTS_PER_HYPOTHESIS` (5) times; the Oracle **decides** `confirmed / adapt / abandoned`; on `adapt` it **mutates** the payload and retries. A **dead-route guard** immediately abandons any endpoint that returns 404/connection-error (no wasted LLM calls on non-existent routes). Confirmed findings are written back into `ScanContext`.
- **Params:** `MAX_HYPOTHESES=10`, `MAX_ATTEMPTS_PER_HYPOTHESIS=5`, parallel batching, confidence threshold for a confirmed finding.
- **Where:** `backend/deepagents/base_deep_agent.py`.

**The Oracle (`AttackOracle`).** The local-LLM brain the agents share:
- **`plan()`** — turns the attack-surface summary into an ordered list of 5–8 attack **hypotheses** (JSON, ordered highest-CVSS / cheapest-test first). Planner model: `qwen2.5-coder:7b`.
- **`decide()`** — judges one probe response (status, size, timing vs baseline, body) and returns `confirmed/adapt/abandoned` with a confidence and, when confirmed, a structured vuln. Analyst model: `llama3.1:8b`. Encodes time-based rules (e.g. `>4s` + a sleep payload = strong signal).
- **`mutate()`** — evolves a failing payload into new variants.
- **Where:** `backend/deepagents/oracle_attack.py`.

**The 10 specialized DeepAgents.** Each targets one vulnerability class with a curated payload library:

| Agent | Targets (PRIMARY_VULN_CLASS) |
|---|---|
| `DeepSQLiAgent` | SQL Injection |
| `DeepXSSAgent` | Cross-Site Scripting |
| `DeepCMDiAgent` | Command Injection |
| `DeepAuthAgent` | Authentication Bypass / Privilege Escalation |
| `DeepIDORAgent` | Insecure Direct Object Reference |
| `DeepSSRFAgent` | Server-Side Request Forgery |
| `DeepSSTIAgent` | Server-Side Template Injection |
| `DeepPathTraversalAgent` | Path Traversal / LFI |
| `DeepXXEAgent` | XML External Entity Injection |
| `DeepBusinessLogicAgent` | Business-Logic Flaws |

*(Payload libraries live in `backend/deepagents/payloads/*.py`; attack constants in `backend/config/dast_constants.py`. Note: the README's "14 agents" also counts the crawler / API-discovery / network reconnaissance agents.)*

### 11.13 Attack Surface Index & Attack Chains

**Attack Surface Index (ASI) — vectorless RAG for the Oracle.**
- **What:** a running profile of every endpoint CYPHEX has seen (methods, params, observed status codes, whether it leaks tokens/sensitive data), with an `interest_score`.
- **How:** `ingest_response()` records each probe; `summarise_for_prompt()` renders the top "high-value endpoints" as text context injected into every Oracle prompt. **Dead routes (only-ever-404) are excluded** so the Oracle never plans attacks against endpoints that don't exist.
- **Where:** `backend/deepagents/attack_surface_index.py`.

**AttackGraph & attack chains.** Confirmed findings are linked into multi-step exploitation chains (e.g. *unauthenticated data leak → admin escalation*), surfacing higher-severity combined risks. *(`backend/deepagents/attack_graph.py`)*

### 11.14 The Behavioral Immune System

> CYPHEX's signature differentiator: instead of matching a database of known attack signatures, it **learns what normal traffic looks like for the target app** and blocks anything statistically abnormal.

**Behavioral Genome (blue-team defense).**
- **What:** a per-endpoint anomaly detector that learns each URL/form's normal input and scores every payload from normal (0.0) to anomalous (1.0).
- **How:** for each endpoint it builds an `EndpointProfile`, generates ~100 synthetic "realistic normal" samples (emails, usernames, searches, paths), converts each to a **15-dimension feature vector**, and trains a scikit-learn **Isolation Forest** (100 trees, CPU-only). Scoring takes the **max** of the ML anomaly score and a hand-written heuristic score, so either signal can flag an input.
- **Why:** signature WAFs miss zero-days; "learn normal, block abnormal" catches unseen attacks while ideally not blocking real users. Runs on a Raspberry Pi 5.
- **Params:** `n_estimators=100`, contamination clamped `[0.01, 0.4]`, `random_state=42`, `n_jobs=1`; `+0.15` confidence boost when ML and heuristic agree.
- **Where:** `backend/backend/immune/behavioral_genome.py`, `backend/backend/models/genome.py`.

**The 15-Dimension Feature Vector (`extract_features`).** The "DNA" measured from any input string, in order:

| # | Feature | # | Feature | # | Feature |
|---|---|---|---|---|---|
| 0 | input_length | 5 | digit_ratio | 10 | traversal_depth |
| 1 | Shannon entropy | 6 | max_token_length | 11 | bracket_imbalance |
| 2 | special_char_ratio | 7 | keyword_score | 12 | unicode_ratio |
| 3 | url_encoding_ratio | 8 | sqli_pattern_score | 13 | repetition_ratio |
| 4 | uppercase_ratio | 9 | null_byte | 14 | token_count |

*The vector is deliberately frozen at 15 dims — new attack classes (SSTI/NoSQLi/SSRF/LDAP/CRLF) were folded into `sqli_pattern_score` rather than adding dimensions, so previously-trained genomes still load.*

**Combined scoring (`score_request`).** Fuses the Isolation-Forest ML score with a rule-based heuristic and takes the max (plus the agreement boost). Falls back to heuristic-only if scikit-learn is unavailable.

**Verdict & block threshold.** A payload is **BLOCKED** when its score ≥ `GENOME_BLOCK_THRESHOLD` (0.7), else **ALLOWED**. A post-scan "Genome Scoring" table demonstrates this on representative payloads (SQLi/XSS/CMDi → BLOCK; `normal search`, `John O'Brien` → ALLOW — proving it doesn't block apostrophe names that trip naive regex WAFs).

**Adversarial Co-Evolution (`EvolutionController`) — the core innovation.**
- **What:** an AI red team and blue team fight across "generations," each making the other stronger.
- **How:** Gen 0 builds the genome and generates initial attacks. Each generation: score all payloads → those ≥ threshold are BLOCKED, the rest BYPASSED. The **blue team retrains** the genome on the successful (bypassed) attacks; the **red team mutates** blocked payloads to evade and breeds variants from successful ones. Repeats, recording block-rate per generation.
- **Why:** simulates how real polymorphic attack tools evolve and forces the defense to generalize — the genome ends "hardened against N patterns it discovered itself," fully offline.
- **Params:** 10 generations × 20–30 payloads (defaults); Gen 0 splits across SQLi/XSS/CMDi.
- **Where:** `backend/backend/immune/evolution_controller.py`.

**Block-rate convergence & early stopping.** If block-rate ≥ 0.99 for **3 consecutive generations**, evolution stops early ("Genome converged"). The rising curve (e.g. 63% → 100%) is the headline demo.

**Accumulating retrain (blue-team learning).** The genome remembers **every** bypassed attack across all past generations (capped at the last 500 per endpoint) and retrains on normal + all accumulated attacks — so this generation's bypasses become next generation's caught attacks.

**Mutation Engine (red-team mutator).** Generates evolved, obfuscated payloads using 8 techniques (URL/double-URL/Unicode encoding, comment injection, case mutation, whitespace substitution, string-concat splitting, `CHAR()` functions) plus **targeted evasions** based on which feature triggered detection. An optional LLM path adds context-aware creativity; the default string path is <1ms and fully offline. *(`backend/backend/immune/mutation_engine.py`)*

**Attack-Simulation Arena (BEFORE vs AFTER).** After training, CYPHEX fires 12 canned inputs (8 malicious + 4 benign) at the genome and shows a BEFORE (unprotected = all allowed) vs AFTER (genome verdict) table, with a **defense rate** and **false-positive** count — a jury-friendly "with CYPHEX these attacks now get blocked without breaking real traffic" story. *(`cli_engine.py`, `terminal_ui.py`)*

**Genome persistence & versioning (HMAC-signed).** A trained genome is saved (`joblib` `.pkl` + metadata `.json`) per target, plus an **HMAC-SHA256 signature** (`.pkl.hmac`) over the file using a per-install secret. `load()` refuses to deserialize an unsigned/tampered pickle — preventing code execution via a poisoned cache. On re-scan, the existing genome is reloaded so evolution *continues* rather than resetting. *(`GENOME_STORAGE_DIR/genome_<hash>.pkl`)*

**Graceful degradation.** If numpy/scikit-learn are missing, a stub is installed, `HAS_SKLEARN=False`, and detection runs on **heuristics only** — the immune system disables ML rather than crashing.

### 11.15 RASP & the Auto-Heal Daemon

**CYPHEX-RASP (`cyphex-rasp.js`).**
- **What:** a zero-dependency Express middleware the developer adds with one line that inspects every incoming request in real time and blocks attacks with an HTTP 403.
- **How:** extracts all user-controlled inputs (query, body, params, suspicious headers, decoded path) and runs each against 5 signature groups (SQLi/XSS/CMDi/Path-Traversal/SSRF) + a keyword heuristic to produce a confidence 0–1. Above the threshold (0.7) it blocks with a 403 (JSON: error, reason, blocked_field, cyphex_id) and fires telemetry to the daemon.
- **Why:** RASP defends the **live** app at runtime and, crucially, sees *inside* the app — solving the "DAST disconnect" where an external scanner only knows the URL.
- **Where:** `sdks/node/cyphex-rasp.js`.

**RASP stack-trace capture.** At detection time RASP throws an `Error` to capture the JavaScript stack, walks past framework frames, and finds the first **application** frame — yielding the exact `{file, line}` of the vulnerable handler (no guessing). Sent to the daemon so the fix targets real code.

**`/watch` auto-heal daemon.** A background FastAPI server (localhost:3004) that receives attack telemetry from RASP; if confidence ≥ 0.7 it derives the vulnerable `file:line`, safely reads a window around it (rejecting symlink/`../` escapes), sends it to the **PatchCouncil**, and — if approved — writes the fix back to disk. Closes the loop: *detected in production → blocked → AI-patched*. Exposes `/api/status` and `/api/heal-log`. *(`cyphex/daemon.py`)*

**RASP onboarder.** Auto-injects the RASP SDK into a target Express app — inserts the `app.use(cyphexRasp(...))` line right after the body-parser middleware (so it sees parsed bodies), idempotently. *(`cyphex/onboarder.py`)*

### 11.16 The Immune Benchmark

- **What:** a reproducible test that runs the **real** genome detector over a labelled corpus and reports the metrics a jury/CI asks for.
- **How:** `run_benchmark` scores every sample with a fresh `BehavioralGenome.score_request` at a threshold (default 0.5) and computes a confusion matrix, precision/recall/F1/accuracy/FPR, per-attack-class detection rates, and lists misses & false positives — rendered in the HUD and written to `benchmark_report.json`. Exits non-zero if recall < 80% or FPR > 10% (a CI regression gate).
- **Corpus:** `benchmarks/immune_corpus.json` — 76 fully-synthetic, CC0 samples across 10 attack classes (46 attack + 30 benign), deliberately including **hard benign** cases (apostrophe names, SQL words in prose, relative paths) that break naive WAFs. `--data <csv>` ingests external labelled sets (e.g. CSE-CIC-IDS2018).
- **Measured result:** **recall 91.3%, precision 97.7%, F1 94.4%, accuracy 93.4%, FPR 3.3%, ~0.04 ms/sample.**
- **Where:** `cyphex_benchmark.py`, `benchmarks/immune_corpus.json`.

### 11.17 The AI Remediation Pipeline (5 stages)

Every confirmed vulnerability runs through five stages; only a *verified* fix counts.

**Stage 1 — Template Match (deterministic).** Before any AI, a hard-coded regex transform fixes common CWEs with a guaranteed-correct rewrite: CWE-89 (parameterize SQL), CWE-78 (`execSync` → `execFile` with an argv array), CWE-798 (secrets → `process.env.X`), CWE-942 (wildcard CORS → allowlist). Deliberately **bails out** (falls through to the LLM) when a shell command contains metacharacters. *(`backend/patch/templates.py`)*

**Stage 2 — Vectorless RAG Context.** Assembles read-only context for the model: the enclosing function, the file's imports, a CWE fix recipe from the Security KB, and an in-repo secure example — with **no embeddings/vector DB**. Kept strictly separate from the exact code window the model must rewrite. *(`backend/rag/code_indexer.py`, `backend/patch/context.py`, `backend/rag/security_kb.py`)*

**Stage 3 — LLM Patch Generation.** The patcher model (default `qwen2.5-coder:7b`) generates a drop-in replacement for the vulnerable window, for all vulns in one **batch** (model loaded once), under strict anti-regression rules (preserve braces/try-catch, minimal change, no suppression comments, real code not stubs) plus a CWE directive. *(`backend/council/patch_council.py`)*

**Stage 4 — AI Council Review.** Two **different** reviewer models (never the patcher) each vote approve/reject on every patch, in parallel when VRAM allows. A strict tally guard prevents a model's literal string `"false"` from counting as approval. Verdict: `safe` / `review_needed` / `rejected`. **The verdict is advisory** — a `rejected` vote only hard-blocks when there's no code to apply; otherwise the patch proceeds to the objective verify gate (small reviewers over-reject legit multi-line fixes). *(`backend/council/patch_council.py`, `council_orchestrator.py`)*

**Stage 5 — Verification Gate (`verify_static`).** The objective arbiter, with four sub-checks:
1. **Finding gone** — re-scan the patched file; the same CWE must no longer appear near that line.
2. **Builds** — syntax valid (`node --check` / `py_compile` / `tsc --noEmit`).
3. **No suppression** — the patch didn't add `nosemgrep`/`eslint-disable`/`# noqa`/`@ts-ignore`, and didn't delete >70% of the code.
4. **Blast radius** — the real line-diff is within a severity-scaled cap (Critical 80 / High 60 / Medium 40 / Low 30).

Verdict: any failed check → `FAIL` (**rolled back**); all green → `PASS`; unmeasurable → `UNVERIFIABLE` (never counted as fixed). *(`backend/patch/verifier.py`)*

**Supporting components:**
- **Location Resolver** (`resolver.py`) — turns a finding's endpoint into a `file:line` (static) or `url` (dynamic); the security choke-point that guarantees writes stay inside the scanned directory (rejects symlinks & path-traversal).
- **Route Tracer** (`route_tracer.py`) — maps dynamic (DAST/DeepAgent) findings whose endpoint is a URL/relative path back to a concrete source `file:line`, so runtime-discovered bugs can be patched too.
- **Function-span extraction** (`context.py`) — replaces the *whole brace-balanced enclosing function* (not an arbitrary window), which keeps braces balanced and prevents "invalid-syntax → rollback" failures.
- **Patch Applier** (`applier.py`) — atomic write (tmp + `os.replace`) with backup, post-write syntax check, and **auto-rollback** on failure; double path-containment guard against TOCTOU.
- **Patch Manifest** (`manifest.py`) — records every attempt (verdict + before/after hashes) in `.cyphex/patches.json` for durability stats.

### 11.18 Vectorless RAG & the Security Knowledge Base

**Vectorless RAG.** Gives a small local model precise, high-signal context (function + imports + CWE recipe + repo secure example) using a **keyword/regex index** — no embeddings, no vector DB, no VRAM/latency cost, fully offline. `find_for_vuln` ranks files by score (route match +10, exact-file +20, CWE-type +5, has-input +2, payload-term +3).

**Security Knowledge Base.** A static JSON of proven fix strategies, example patterns, and anti-patterns per CWE (10 CWEs: 89, 79, 78, 22, 798, 918, 942, 693, 614, 287), formatted into the prompt so the model fixes bugs "the proven way" and avoids known-bad approaches. *(`backend/rag/security_kb.py` + `security_kb.json`)*

### 11.19 The AI Council (deeper)

- **What:** the multi-model panel used both to review findings and to review patches.
- **How:** `CouncilOrchestrator._call` is the shared base: it appends universal anti-hallucination rules (no invented CVEs, CWE whitelist, JSON-only), calls Ollama `/api/chat` with `format=json`, robustly parses the JSON (fence-stripping, bracket-balanced extraction, retry-once), and enforces the VRAM budget. Reviewers are always ≠ the patcher; self-review (single-model hardware) can never yield `safe`, only `review_needed`.
- **Where:** `backend/council/council_orchestrator.py`, `patch_council.py`, `analysis_council.py`.

### 11.20 Reasoning Strategies & Meta-Reasoning

- **What:** a registry of named reasoning strategies (the "16 cognitive architectures") with a router that picks the cheapest strategy that fits each vulnerability's difficulty.
- **How:** `select_strategy(cwe, severity)` routes: **Critical or hard CWE (78/918/89/94/77/22) → Self-Consistency**; **High → Chain-of-Thought**; **else → Standard**. Patch review is always **Adversarial Debate** (the dual council); a failed patch → **Self-Reflection** (reflexion). Hardware tier gates which strategies are allowed (minimal: standard/CoT only → ultra: all 16).
- **Self-Consistency patch voting** — for hard vulns, generate K=3 candidates at rising temperatures and keep the fingerprint the majority agree on.
- **Honesty note:** the 16 strategies are a mix of active and declared-for-future; the full "cognitive architecture" enhancement only executes if the optional `agent_reasoning` package is installed, otherwise a strategy is *labelled* for the UI and the call falls back to a plain Ollama request (see [§18](#18-current-implementation-status--known-gaps)).
- **Where:** `backend/council/reasoning_strategy.py`, `backend/reasoning/oracle_adapter.py`.

### 11.21 Reflexion Loop

- **What:** rejected patches are retried (up to 2 rounds) with the reviewers' criticism fed back into the prompt.
- **How:** after review, `rejected` patches with dissent reasons re-enter generation with a `PREVIOUS ATTEMPT WAS REJECTED` prefix + the joined critique, then are **re-reviewed by the same quorum** (fail-closed: a missing re-review never auto-promotes to `safe`).
- **Why:** lets the model self-correct from concrete feedback instead of discarding a rejected fix.
- **Where:** `backend/council/patch_council.py`, `backend/reasoning/reflexion.py`.

### 11.22 Memory Systems

CYPHEX has three complementary memories so it gets smarter over time:

| Memory | Scope | What it stores | Where |
|---|---|---|---|
| **Patch Memory** | Per-project | `(CWE, semantic-hash-of-function) → verified fix`, so identical vulnerable code is re-fixed from cache; plus a CWE→preferred-strategy library. | `.cyphex/patch_memory.json` |
| **Cognee Knowledge Graph** | Cross-project | Verified fixes across *all* projects, semantically recalled before generating a new patch (`add()`+`cognify()`; recall via `search(CHUNKS)`). Ollama-backed (LLM + `nomic-embed-text` embeddings), fully local. | `.cognee_data/` |
| **Session Memory** | Per-repo, cross-scan | A persistent thread with "lessons learned" and per-patch reasoning entries, injected into future scans' prompts. | `.cyphex/sessions/{thread_id}.json` |

**Reasoning Trees.** For each patch, a JSON tree captures the step-by-step thought traversal (root → thoughts → action → verification) for auditability. *(`.cyphex/reasoning_trees/{tree_id}.json`)*

### 11.23 Security Posture Score

- **What:** the 0–100 headline number (higher = safer), computed before *and* after patching.
- **How:** `penalty = Σ weight_s·(1−decay_s**n_s)/(1−decay_s)` — a finite geometric series per severity (weights Critical 62, High 16, Medium 6, Low 2; decays 0.25/0.30/0.55/0.65) — `score = clamp(100 − penalty, 0, 100)`. The first finding of a severity always costs exactly that severity's weight (the series identity `P(1)=weight`), which is what guarantees a single open Critical always scores <40 — by construction, with no severity-band clamp layered on top. (An earlier version *did* clamp to a flat 39/59/79 whenever a Critical/High/Medium was open; that clamp collapsed genuinely different post-patch states to the same displayed score and was removed.) The **after** score recomputes over only the vulnerabilities whose *verified* patches passed (matched by object identity, so fixing one finding never clears others in the same file, and `UNVERIFIABLE` never counts).
- **Why:** one trackable number; diminishing returns per severity (50 duplicate lows don't collapse the score) without an external clamp that could re-introduce the collapse bug; only verified fixes move it.
- **Where:** `scoring.py` — the single source of truth, imported by both `terminal_ui.py` and `cli_engine.py` (never hand-copied). *(A separate, unrelated, unused `SecurityPostureCalculator` with letter grades/percentile exists in `backend/backend/security_posture_score.py` — dead code, not imported anywhere, and **not** the one used for the CLI banner.)*

### 11.24 Reporting Council & Judge Artifacts

**Analysis / Report Council.** One model (code-aware `qwen2.5-coder:7b`) drafts a technical report per finding (root cause, attack scenario, OWASP/CWE, risk level, business impact); a **different** model validates that no vulnerabilities were invented. Only a genuine cross-model pass earns a "validated" badge. *(`backend/council/analysis_council.py`)*

**Deterministic judge artifacts.** Exports the report as **JSON + Markdown + SARIF 2.1.0** (`cyphex_judge_artifacts/`), so it integrates with GitHub code-scanning and gives a stable artifact independent of the LLM narrative.

---

## 12. End-to-End Pipeline Walkthrough

A `/full` scan proceeds through these waypoints (as shown in the UI):

| # | Waypoint | What happens |
|---|---|---|
| 01 | **Getting Source Code** | Copy/clone the target into a sandbox working copy; detect framework & entry point. |
| 02 | **Static Code Analysis** | SAST: built-in scanner + Semgrep, merged into findings. |
| 03 | **Deploying Sandbox** | Build & run a Docker container (auto-Dockerfile) or native fallback; expose a live URL. |
| 03b | **Network Security Scan** *(optional)* | `netmap` host/port sweep + risk scoring + network-genome baselines. |
| 04 | **Dynamic Vulnerability Scan** | Crawler + API discovery + Nuclei + **10 DeepAgents** (Oracle-guided) attack the live app. |
| 05 | **Immune System — Build Genome** | Learn "normal" per endpoint; run adversarial co-evolution until block-rate converges. |
| 06 | **AI Attack Simulation — Genome Defense** | BEFORE/AFTER arena: fire attacks + benign inputs; report defense rate & false positives. |
| 07 | **Security Report** | Analysis Council drafts + validates a business-impact report. |
| 08 | **AI Patch + Verify** | Per vuln: Template → RAG → LLM → Council → Verify gate; apply & re-scan. |
| 09 | **Final Banner** | Before/after Security Posture Score, remaining vuln counts, applied/total patches. |

---

## 13. Data Model & Artifacts

**In-memory:** `ScanContext` (endpoints, forms, params, `raw_evidence`, `confirmed_vulns`).

**Written to the target's `.cyphex/` folder:**
- `patches.json` — patch manifest (verdicts + hashes + durability).
- `patch_memory.json` — per-project verified-fix cache.
- `sessions/{thread_id}.json` — cross-scan session memory & lessons.
- `reasoning_trees/{tree_id}.json` — per-patch audit trees.

**Written elsewhere:**
- `backend/sandboxes/cli_<id>/` — deployed sandbox copies (with `_cyphex_sandbox.log`).
- `<WORKING_DIR>/genomes/genome_<hash>.pkl` (+ `.json`, `.pkl.hmac`) — trained app genomes.
- `~/.cyphex/network_genome/network_genome.pkl` (+ `.sig`) — network genomes.
- `.cognee_data/` — cross-project knowledge graph.
- `benchmark_report.json` — last immune-benchmark result.
- `cyphex_judge_artifacts/report.{json,md,sarif}` — exportable reports.

> **Important:** CYPHEX's own `.cyphex/` artifacts are **excluded** from the code indexer, so a prior scan's output is never re-ingested as "source."

---
---

# Part III — Requirements & Governance

## 14. Functional Requirements

| ID | Requirement |
|---|---|
| **FR-1** | Accept a local path or GitHub URL as a scan target. |
| **FR-2** | Perform static analysis across 20+ languages (Semgrep + built-in), merged & deduped. |
| **FR-3** | Deploy the target in an isolated sandbox (Docker container preferred, native fallback) and expose a live URL with retrievable logs. |
| **FR-4** | Perform dynamic analysis via Nuclei and 10 Oracle-guided DeepAgents against the sandbox. |
| **FR-5** | Discover the real API/route surface from source and prune dead (404) routes before attacking. |
| **FR-6** | Optionally scan the local network (`netmap`/`netwatch`) with a per-device behavioral genome. |
| **FR-7** | Cross-check findings and patches via a multi-model council; exclude self-review. |
| **FR-8** | Build a per-endpoint behavioral genome and harden it via adversarial co-evolution to convergence. |
| **FR-9** | Demonstrate defense with a BEFORE/AFTER attack-simulation arena (defense rate + false positives). |
| **FR-10** | Auto-patch confirmed vulnerabilities (template or LLM) with RAG context and CWE recipes. |
| **FR-11** | Verify every applied patch (re-scan finding-gone + syntax + no-suppression + blast radius); roll back on failure. |
| **FR-12** | Map dynamic findings back to source `file:line` so runtime-discovered bugs are patchable. |
| **FR-13** | Compute a before/after Security Posture Score from only verified fixes. |
| **FR-14** | Persist and reuse memory (patch cache, knowledge graph, session lessons, genomes) across scans. |
| **FR-15** | Provide a runtime shield (RASP) + auto-heal daemon for live protection. |
| **FR-16** | Export deterministic JSON/Markdown/SARIF reports for CI/judges. |
| **FR-17** | Benchmark the immune system (precision/recall/F1) with a CI gate. |
| **FR-18** | Run non-interactively (auto-apply patches) for CI use. |

## 15. Non-Functional Requirements

| ID | Requirement |
|---|---|
| **NFR-1 — Offline** | Default operation requires no internet and no cloud API keys. |
| **NFR-2 — Local privacy** | Source code, reports, and patches never leave the machine. |
| **NFR-3 — Portability** | Run from a 24GB+ GPU down to a Raspberry Pi 5; degrade to heuristics without ML libs. |
| **NFR-4 — Resource safety** | Respect a VRAM budget; never overflow consumer GPUs (VRAMManager). |
| **NFR-5 — File safety** | All writes contained within the scanned directory; symlink/traversal rejected; atomic write + rollback. |
| **NFR-6 — Supply-chain safety** | Model caches are HMAC-signed; poisoned pickles are refused. |
| **NFR-7 — Performance** | Scan bounded by `SCAN_TIMEOUT_SECONDS` (30 min default); genome scoring ~0.04 ms/sample. |
| **NFR-8 — Honesty** | Only verified fixes count; unmeasurable outcomes marked `UNVERIFIABLE`. |
| **NFR-9 — Resilience** | Missing optional dependency (Docker/cognee/Semgrep/Nuclei/sklearn) degrades gracefully, never crashes. |
| **NFR-10 — Determinism for CI** | JSON/SARIF artifacts and the benchmark are reproducible and stable. |

## 16. Metrics & Success Criteria

- **Immune-system quality (measured):** recall **91.3%**, precision **97.7%**, F1 **94.4%**, accuracy **93.4%**, FPR **3.3%**, ~0.04 ms/sample over 76 samples.
- **CI gate:** benchmark exits non-zero if **recall < 80%** or **FPR > 10%**.
- **Co-evolution:** block-rate should climb to ≥ 99% and converge (e.g. 63% → 100%).
- **Patching honesty:** every "fixed" finding must pass the verification gate; `UNVERIFIABLE` is never counted.
- **Score movement:** the after-score reflects only verified fixes on the reduced vuln set.

## 17. Ethics, Safety & Compliance

- **Sandbox-only offense.** All attack activity runs against the user's own app inside an isolated sandbox — **never against live external networks**. This is a hard constraint.
- **No data exfiltration.** Offline-first by design; nothing is uploaded.
- **File containment.** Patching and auto-heal only ever write inside the scanned repository, with symlink/traversal guards.
- **Dataset ethics.** The bundled benchmark corpus is fully synthetic and CC0; external datasets (e.g. CSE-CIC-IDS2018) must be cited with their license and a real-vs-synthetic disclosure.
- **Responsible framing.** Any offensive capability is presented for defensive testing of one's own systems.

## 18. Current Implementation Status & Known Gaps

*A PRD should be honest about what's wired vs. declared. As of branch `updates_p1`:*

**Fully working:** the scan pipeline, sandbox (container + logs), SAST (merged), DAST (Nuclei fixed), DeepAgents (dead-route guard), immune system + co-evolution + benchmark, RASP + daemon, the 5-stage patch pipeline with verification & rollback, memory systems, scoring, and reporting.

**Declared-but-not-yet-wired (intended, currently inert):**
- **Oracle pre-generation reasoning** (`_oracle_reason`) — references an undefined helper, so it's a silent no-op today (patches still generate normally).
- **Dynamic verification** (`verify_dynamic`, exploit-replay) — fully implemented but not called by the patch workflow; only `verify_static` runs. URL-only findings that can't be mapped to source are reported as `dynamic_only`.
- **16 cognitive architectures** — only ~8 are active; the full set only truly enhances output if the optional `agent_reasoning` package is installed, otherwise a strategy is labelled for the UI and a plain Ollama call is used.
- **Autonomy ladder** (L1–L4) and **proof-carrying regression-test generator** — implemented but not wired into the run.
- **Cosmetic HUD labels** — genome `v14` and the DEFCON level are presentation defaults, not driven by real state.

*These are transparency notes, not blockers — the core find-and-fix loop is functional.*

## 19. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Small local models write low-quality patches | Council review + verification gate + reflexion + self-consistency + template-first for easy CWEs. |
| Local model returns invalid JSON | Robust JSON parsing (fence-strip, bracket-balance, retry) + anti-hallucination rules. |
| Patch corrupts a file | Whole-function replacement + atomic write + syntax check + auto-rollback. |
| Genome false positives block real users | Max(ML, heuristic) tuned for low FPR; hard-benign corpus in the benchmark; measured FPR 3.3%. |
| Poisoned genome cache → code execution | HMAC-signed pickles; unsigned/tampered caches refused. |
| Path traversal via crafted finding endpoint | Resolver/applier contain all writes inside the repo; reject symlinks. |
| Docker unavailable | Native subprocess fallback with captured logs. |
| ML libraries unavailable | Heuristic-only degradation. |
| Long scans on big targets | `SCAN_TIMEOUT_SECONDS` cap; dead-route pruning; batch model loading. |

## 20. Roadmap / Future Scope

- **Wire the intended paths:** enable dynamic exploit-replay verification, the Oracle reasoning step, the autonomy ladder, and the regression-test generator.
- **Federated genome sharing:** privacy-preserving cross-org sharing of hardened genomes / zero-day patterns.
- **Network genome from real flows:** validate `NetworkBehavioralGenome` against approved intrusion datasets (CSE-CIC-IDS2018).
- **More languages & frameworks** for template fixes and route tracing.
- **Richer live posture:** drive the DEFCON/genome HUD from real computed state.
- **IDE / CI integrations:** SARIF-native GitHub Action, editor plugin.

## 21. Appendices

### A. Model Roster

| Model | Role(s) | Approx VRAM |
|---|---|---|
| `qwen2.5-coder:7b` | Patcher, Oracle planner, report writer | ~4.5 GB |
| `llama3.1:8b` | Oracle analyst, reviewer, validator | ~5 GB |
| `deepseek-coder:6.7b` | Second reviewer | ~4 GB |
| `nomic-embed-text` | Embeddings (cognee, 768-dim) | small |

Hardware tiers: `ultra (24GB+) / high (12+) / mid (6+) / low (4+) / minimal (2+) / cloud (<2)`. Patching/debate require ≥7B-param models.

### B. CWE Coverage (fix recipes / templates)

CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (Command Injection), CWE-22 (Path Traversal), CWE-798 (Hardcoded Secrets), CWE-918 (SSRF), CWE-942 (CORS), CWE-287 (Auth), CWE-352 (CSRF), CWE-693, CWE-614. Attack agents additionally cover IDOR, SSTI, XXE, and business-logic flaws.

### C. Command Cheat-Sheet

```
/scan <target> [--network] [--deepagents] [--full] [--no-patch] [--verbose]
/deep <target>          # + DeepAgents swarm
/full <target>          # DeepAgents + network
/net [host]             # network discovery / audit
/netwatch               # live network anomaly monitor
/watch                  # RASP auto-heal daemon (:3004)
/setup                  # install Semgrep, Nuclei; check Ollama/Docker
/doctor                 # health check
/benchmark [corpus]     # score the immune system (precision/recall/F1)
/verify [path] [--selftest] [--ci] [--watch [s]] [--json f]   # Verify Gate maintainability panel
/status [path] [--watch [s]] [--json f]                       # System Observability dashboard
/models /history /version /clear /help /exit
```

### D. Key File Map

| Area | Files |
|---|---|
| Orchestrator | `cli_engine.py` |
| Entry points | `cyphex/cli.py`, `cx.py`, `cyphex_cli.py` |
| Config / hardware | `backend/backend/config.py`, `cyphex/hardware.py` |
| Sandbox | `backend/backend/sandbox_manager.py`, `cyphex/docker_sandbox.py` |
| SAST / DAST | `cyphex/scanner.py`, `cyphex/dynamic_scanner.py` |
| Code index / RAG | `backend/rag/code_indexer.py`, `backend/patch/context.py`, `backend/rag/security_kb.py` |
| DeepAgents / Oracle | `backend/deepagents/*`, `backend/reasoning/oracle_adapter.py` |
| Immune system | `backend/backend/immune/*`, `backend/network/network_genome.py` |
| RASP / daemon | `sdks/node/cyphex-rasp.js`, `cyphex/daemon.py`, `cyphex/onboarder.py` |
| Patch pipeline | `backend/patch/*`, `backend/council/*` |
| Verify Gate health | `backend/patch/verify_health.py` (`/verify`) |
| Observability | `backend/observability/*` (`/status`) |
| Memory | `backend/rag/patch_memory.py`, `backend/rag/cognee_memory.py`, `backend/reasoning/session_memory.py` |
| Benchmark | `cyphex_benchmark.py`, `benchmarks/immune_corpus.json` |
| UI | `terminal_ui.py` |

---

*End of document — CYPHEX PRD v1.0.*
