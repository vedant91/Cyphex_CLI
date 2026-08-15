<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Ollama-Local_LLM-000000?style=for-the-badge&logo=ollama&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Sandbox-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<h1 align="center">🛡️ CYPHEX</h1>

<p align="center">
  <b>Point CYPHEX at a repo. It deploys the app in a sandbox, attacks it with local-LLM agents,<br/>
  patches what it confirms, and re-scans to prove the fix. No cloud LLM, no API keys, no billing.</b>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> · <a href="#-what-a-scan-actually-does">Sample Run</a> ·
  <a href="#-the-verify-gate">Verify Gate</a> · <a href="#-how-it-works--the-8-step-pipeline">Pipeline</a> ·
  <a href="#-usage">Usage</a> · <a href="#-what-cyphex-cant-do-yet">Limitations</a> ·
  <a href="CYPHEX_PRD.md">Full Docs (PRD)</a>
</p>

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/Punya23/Cyphex_CLI.git
cd Cyphex_CLI

# 2. Install  (extras: '.[memory]' cognee graph · '.[reasoning]' · '.[dev]')
pip install -e .

# 3. Pull at least one local model
ollama pull qwen2.5-coder:7b     # patcher / oracle
ollama pull llama3.1:8b          # reviewer / analyst

# 4. Verify your machine, then scan the bundled vulnerable Express app
cyphex doctor
cyphex scan ./vuln-webapp
```

> **Does it edit my code?** **No — not during a scan.** `cyphex scan <path|--repo>` copies your tree into a per-scan sandbox under `backend/sandboxes/<scan_id>/` and patches *that copy*; your working tree is never touched. The **only** component that writes to your real source is the opt-in `/watch` auto-heal daemon, which patches in place by design.

### Prerequisites

| Tool | Required | Why |
|---|---|---|
| **Python 3.11+** | ✅ | Runtime |
| **Ollama** | ✅ | Local models — all inference hits `127.0.0.1:11434` |
| **Docker** | ⚡ Recommended | Hardened sandbox (auto-generated Dockerfile). Without it, a resource-capped local subprocess is used instead |
| **Node.js 18+** | ⚡ Recommended | Deploying and syntax-checking JS/TS targets |
| **Semgrep / Nuclei** | 🔧 Optional | Extra SAST rules / DAST templates — `cyphex setup` installs both (Nuclei's binary is SHA256-verified against the release checksums) |
| **numpy / scikit-learn** | 🔧 Optional | Isolation-Forest layer of the immune system. Missing → CYPHEX falls back to the heuristic detector instead of crashing |

---

## 📟 What a Scan Actually Does

Measured end-to-end run, 2026-08-11 — a deliberately-vulnerable Express storefront (8 source files), standard scan with auto-patch, Apple Silicon laptop, 7B + 8B local models, exit code 0.

| Stage | Measured result |
|---|---|
| **Static** | 8 files scanned; Semgrep contributed **+3** findings over the built-in rules (2× SQLi CWE-89, 1× CMDi CWE-78 in `src/routes/orders.js`) |
| **Council validation** | 2 findings confirmed, 0 discarded as false positives (SQLi 3/3 votes; Sensitive Data Exposure 1/3) |
| **Genome** | 15 endpoints profiled; adversarial co-evolution converged to a **100% block rate by generation 3** (gen 0: 90.0%, 27/30); hardened against 20 attack patterns |
| **Attack arena** | Defense rate **7/8 (88%)**, **0** false positives on benign traffic |
| **Vectorless RAG** | 12 files indexed · 4 function-level extractions · 1 window fallback · 4 CWE-KB fix strategies applied · Knowledge-Tree recipe enrichment active |
| **Meta-reasoning** | 9 of 16 reasoning strategies enabled; reflexion loop re-tried 2 council-rejected patches |
| **Patching** | 5 attempted → **4 applied *and* verified**; 1 rejected by the Verify Gate for invalid syntax and auto-rolled-back |
| **Memory** | 4/4 verified fixes persisted to the cognee cross-project knowledge graph |
| **Security Posture Score** | **51/100 → 67/100** (computed from verified fixes only) |
| **Wall clock** | **~1093 s (~18 min)** |

Eighteen minutes is the honest number for a full run with patching on 7B/8B local models — most of it is LLM time. Static-only and `--no-patch` runs are far quicker.

### Artifacts it leaves behind

| Path | Contents |
|---|---|
| `report.json` (scan dir) | Findings, severities, `file:line`, posture score, duration |
| `cyphex_judge_artifacts/report.{json,md,sarif}` | Deterministic report set, written under `--judge` |
| `.cyphex/patches.json` | Patch manifest — every applied patch and its verdict |
| `.cyphex/patch_memory.json` | Verified-fix cache, reused on later scans with zero AI calls |
| `.cyphex/sessions/<id>.json` | Reasoning trace / session memory for the run |
| `benchmark_report.json` | Immune-system metrics (from `--json`) |
| genome storage dir | `genome_<target>.pkl` + HMAC sidecar — evolution resumes here next scan |

```jsonc
// excerpt from a real report.json
{ "scan_id": "cli_82a5c0f4", "score": 14,
  "summary": { "critical": 2, "high": 16, "medium": 1, "total_vulns": 19, "duration_seconds": 214.8 },
  "vulnerabilities": [
    { "name": "[STATIC] SQL Injection (Template Literal)", "severity": "Critical", "endpoint": "app.js:405" },
    { "name": "[STATIC] Container Running as Root",        "severity": "Medium",   "endpoint": "Dockerfile:20" }
  ] }
```

---

## ✅ The Verify Gate

*A patch counts as "fixed" only if a re-scan proves it.* Every candidate must clear all of:

- the finding is **gone on re-scan**;
- the file still **compiles** (`node --check` / `py_compile`);
- **no suppression comments** were added, and **no more than 70%** of the file's non-blank lines were deleted;
- the diff stays inside a **severity-scaled blast radius**, with the target line range validated before any splice.

A **FAIL** verdict is **rolled back** to the original bytes. An **UNVERIFIABLE** verdict (the re-scan could not run) leaves the patch applied but **never counts toward the score** — the before/after Security Posture Score is computed from **PASS-verified fixes only**. Failures aren't wasted either: a FAIL writes a "try a different remediation approach" lesson into session memory, and a PASS stores a reusable `CWE:strategy` pattern plus a cross-project memory entry.

---

## 🔬 How It Works — the 8-Step Pipeline

<p align="center"><img src="cyphex_final_architecture.png" width="820" alt="CYPHEX architecture" /></p>

| # | Waypoint | What happens |
|---|---|---|
| 1 | **Get Source** | Copy/clone the target into a per-scan sandbox copy; detect framework. Clone URLs are restricted to `https://` / `git@` / `ssh://`. |
| 2 | **Static Analysis** | Semgrep (`--metrics=off`, never `--config auto`) **+** a built-in 16-ruleset regex scanner — 12 languages plus Dockerfile/YAML/SQL/`.env` — **merged and de-duplicated**, then [confidence-scored](#-false-positive-scoring) to drop the obvious false positives. |
| 3 | **Deploy Sandbox** | Docker container from an auto-generated Dockerfile (`--cap-drop ALL`, `--memory 512m`, `--cpus 1`, `--pids-limit 200`, `no-new-privileges`, non-root user, port published on `127.0.0.1` only), or a resource-capped native subprocess fallback. |
| 3b | **Network Scan** *(opt)* | Host/port sweep + per-device network genome. |
| 4 | **Dynamic Scan** | Crawler + API discovery, then **either** the built-in agent suite with Nuclei/ZAP (`/scan`) **or** the **13 Oracle-guided DeepAgents** (`/deep`, `/full`) — the two paths are mutually exclusive. A multi-model council then debates the findings and drops the false positives. |
| 5 | **Build Genome** | Learn "normal" per endpoint, then run adversarial co-evolution to convergence. Genomes are loaded from disk for the same target, so evolution *continues* across scans. |
| 6 | **Attack Arena** | BEFORE/AFTER defence demo — defence rate plus false positives on benign traffic. |
| 7 | **Security Report** | The AI council writes it; a **second model fact-checks** it for invented findings. |
| 8 | **Patch + Verify + Score** | Per vuln: **patch-memory cache** → deterministic **template** → **council** (LLM generates, multiple models vote, prompted with Vectorless-RAG + Knowledge-Tree context) → **[Verify Gate](#-the-verify-gate)** → before/after posture score from PASS-verified fixes only. |

### 🎯 False-positive scoring

Every static finding carries a `confidence` (0.0–1.0) and, when it's been marked down, a `fp_reason`. Semgrep hits start at 0.90, built-in regex hits at 0.85. Three rules move the number:

| Signal | Effect |
|---|---|
| SQL call is already parameterised (`?` / `$1` / params array / `prepare(`) | dropped outright — on **every** path |
| Match sits inside a code comment | confidence 0.0, dropped from scans |
| File is test / fixture / mock code | −0.45, kept but marked |

The first two are asymmetric on purpose, and the asymmetry is what keeps the Verify Gate honest. A patch that parameterises a query *must* read as "finding gone", so that suppression applies during verification too. A patch that merely **comments the vulnerable line out** must *not* — so the verifier re-scans with comment-matching switched back on, and commenting-out is scored as still-vulnerable and rolled back.

On the bundled `vuln-webapp` this removes 2 Critical false positives, both of which were the scanner matching its own English prose: `query (should` inside `// Safe: parameterized query (should NOT be flagged)`.

Semgrep never runs with `--config auto`, which uploads project metadata to semgrep.dev on every run and cannot be cached. CYPHEX prefers a local `cyphex/semgrep_rules.yml` if you drop one in (fully offline), else the static `p/owasp-top-ten` pack, which Semgrep caches locally after the first fetch.

---

## ⭐ What Makes CYPHEX Different

### 🕵️ 1. DeepAgents — an Oracle-guided attack swarm

**13 specialized AI attack agents**, one per vulnerability class, that don't run a fixed script — they *adapt*. Each runs an **Observe → Think → Act** loop: probe the live app, let the Oracle judge the response, mutate the payload, try again.

| Agent | Targets | Agent | Targets |
|---|---|---|---|
| `DeepSQLiAgent` | SQL Injection | `DeepXXEAgent` | XML External Entity |
| `DeepXSSAgent` | Cross-Site Scripting | `DeepBusinessLogicAgent` | Business-Logic Flaws |
| `DeepCMDiAgent` | Command Injection | `DeepPromptInjectionAgent` | Prompt Injection / LLM safety bypass (CWE-1336, OWASP LLM01) |
| `DeepAuthAgent` | Auth Bypass / Priv-Esc | `DeepRaceConditionAgent` | Race Condition / TOCTOU (CWE-362) |
| `DeepIDORAgent` | Insecure Direct Object Ref | `DeepMassAssignmentAgent` | Mass Assignment / Parameter Pollution (CWE-915) |
| `DeepSSRFAgent` | SSRF — incl. the AWS metadata endpoint `169.254.169.254` | `DeepSSTIAgent` | Template Injection |
| `DeepPathTraversalAgent` | Path Traversal / LFI | | |

*Plus crawler, API-discovery and network-recon agents. A **dead-route guard** stops agents wasting budget on endpoints that don't exist, and confirmed exploits are chained into **multi-step attack paths** (unauth data leak → admin takeover).*

### 🧠 2. The Oracle — local-model reasoning, spent where it pays

The Oracle is the local-LLM brain behind every DeepAgent. It `plan()`s 5–8 ranked attack hypotheses from the attack surface, `decide()`s each probe's response (status, size, **timing vs. baseline**, body) as *confirmed / adapt / abandoned* with a confidence score, and `mutate()`s failing payloads into evasion variants.

A **meta-reasoning router** picks a generation strategy per finding, out of a bank of 16 (**9 enabled**). The built-in router — always on, no extra install — sends Critical severity *or* a hard CWE (CMDi, SSRF, SQLi, code injection, path traversal) to **Self-Consistency** K-vote, High to **Chain-of-Thought**, and everything else to direct generation. Installing the optional `.[reasoning]` extra swaps in a richer router: CWE override first, then severity — Critical → Self-Consistency · High → **Self-Reflection** (draft → critique → improve) · Medium/Low → Chain-of-Thought, with CWE overrides to **Tree-of-Thoughts** (CMDi, SSRF) or **Decomposition** (auth bypass, IDOR), and expensive strategies gated off on low-VRAM tiers. Every patch keeps its reasoning tree for audit. → [PRD §11.20](CYPHEX_PRD.md)

### 📚 3. Vectorless RAG + Knowledge Tree — context without a vector DB

Small models write good patches only with good context. The RAG path uses **no embeddings and no vector store**: a keyword/regex **code-tree index** extracts, per vulnerability, the whole brace-balanced enclosing function, the file's imports, a **CWE fix recipe**, and an **in-repo secure example** so patches match the codebase's own style.

On top sits a **PageIndex-style Knowledge Tree** (`backend/rag/`) — a hierarchical JSON tree of `code_tree` + `knowledge_tree` + a deterministic `cwe_index`, built from your repo plus a bundled security corpus (OWASP Top-10 notes, CWE fix patterns, Express secure-coding patterns) and cached under `.cyphex/`. Its **fast path is 0-LLM**: CWE + `file:line` → enclosing function, fix recipe, secure example, related knowledge. Its deep path shows the model only branch *summaries*, never the whole tree.

> No embeddings in the RAG context path. *(The optional `[memory]` extra — cognee cross-project memory — is the exception: it does use `nomic-embed-text` at 768 dims over a local LanceDB store.)*

---

## 🧬 The Behavioural Immune System

Instead of matching known signatures, CYPHEX **learns what *normal* looks like for *your* app** and blocks the anomalies.

- **Behavioural Genome** — a per-endpoint detector over a **15-dimension feature vector** (entropy, special-char ratio, injection patterns, traversal depth, bracket imbalance…). Scoring is `max(isolation-forest, heuristic)` — the heuristic layer is 15 threshold rules over those features, one of which is fed by a **24-pattern injection bank** — plus a small agreement boost when both detectors fire. **BLOCK ≥ 0.7**. Without numpy/scikit-learn the heuristic layer alone still scores.
- **Coverage** goes well past SQLi/XSS: SSTI, NoSQLi, SSRF/cloud-metadata, LDAP injection, CRLF header injection and XXE are all in the pattern bank (100% detection on each of those classes in the benchmark corpus).
- **Adversarial Co-Evolution** — an AI red team mutates attacks while the blue team retrains the genome, breeding from both blocked *and* bypassed payloads plus fresh diversity injection, until the block rate converges to ~100% (early-stop at ≥99% for 3 straight generations). Starting rates vary run to run and the curve is **not strictly monotonic**.
- **Persistence** — genomes are saved with an **HMAC sidecar** and refuse to load an unsigned or tampered `.pkl` (no pickle-swap attacks). Attack history round-trips too, so run *N+1* keeps hardening from run *N*'s bypasses.

### Benchmarked quality

**91.3% recall · 97.7% precision · 94.4% F1 · 3.3% FPR · ~0.04 ms/sample** — on a **76-sample corpus (46 attack / 30 benign; 42 TP, 1 FP, 4 FN)**. Small *n*: treat as directional, not certified. The co-evolution block rates are measured against payloads CYPHEX generated itself — in-distribution, not a generalization claim.

```bash
python3 cyphex_benchmark.py                       # exits non-zero if recall < 80% or FPR > 10% → CI gate
python3 cyphex_benchmark.py --data cic-ids2018.csv --threshold 0.6 --json out.json
./cx benchmark --data cic-ids2018.csv             # same engine from the launcher (reports the gate
                                                  # verdict, but does NOT set an exit code)
```

Output includes the full confusion matrix, per-attack-class detection rates, and the exact list of missed attacks and false positives. `--data` accepts any labelled CSV corpus (e.g. CSE-CIC-IDS2018 web-attack payloads).

---

## 🛡️ RASP + Auto-Heal Daemon

A **zero-dependency Express shield** (`sdks/node/cyphex-rasp.js`, a single `app.use()` — or let `python3 cyphex_cli.py onboard --path <app>` inject it for you) inspects query strings, recursively-flattened JSON bodies, and cookie / referer / x-forwarded-for / user-agent headers. It blocks attacks with a **403** above a tunable `confidenceThreshold`, or runs in **detect-only mode** (`blockMode: false`) for a staged rollout.

It then ships the event to the **`/watch` auto-heal daemon** on `127.0.0.1:3004`, which applies its own 70% confidence floor before handing the finding to the AI council to **patch your real source in place**. `GET /api/status` and `GET /api/heal-log` expose uptime, healed/rejected counts and the full healing history. The daemon enforces API-key auth, so **the same `CYPHEX_API_KEY` must be set on both sides** or telemetry is silently dropped.

> **Stack-trace caveat.** The RASP captures a stack trace to resolve the calling application frame. Mounted globally via `app.use()` it fires *before* any route handler runs, so no app frame is on the stack and no `file:line` is resolved. **Mount it per-route** (`app.get('/x', cyphexRasp(opts), handler)`) to get the exact vulnerable `file:line`.

---

## 💻 Usage

**Non-interactive CLI** — `cyphex <command>`:

```bash
cyphex scan ./my-app                    # bare positional target (path or URL) also works
cyphex scan --repo https://github.com/user/app.git --deepagents --network
cyphex scan --path ./vuln-webapp --deep --format sarif      # --deep aliases --deepagents
cyphex scan --path ./my-app --judge                         # deterministic JSON/MD/SARIF artifacts
cyphex setup | doctor | council-doctor | version
cyphex                                  # no args → slash-command workspace (also: repl / workspace / shell)
```

`--format {table,json,sarif,markdown}` · `--network` · `--no-patch`. `--mode {full,standard,lite,cloud}` is declared but **not yet wired to the engine** — see limitations. (`--branch` exists only on the legacy `python3 cyphex_cli.py scan`.)

**REPL / workspace** — these are slash commands *inside* `cyphex`, not shell commands:

```
/scan <target> [--network] [--deepagents] [--full] [--no-patch]
/deep <target>     · /full <target>     # DeepAgents swarm · + network sweep
/net [host]        · /netaudit · /netwatch
/watch                                  # RASP auto-heal daemon
/benchmark [--threshold N] [--json out.json]
/setup /doctor /models /version /history /clear /help /exit
<bare path or URL>                      # auto-scans it; Tab completes commands
```

**`./cx` launcher** — the same engine, non-interactively: `cx scan`, `cx deep`, `cx net`, `cx benchmark`, `cx doctor`, `cx models`, `cx --version`, or `cx <path|url>` to auto-scan.

**Legacy entry points** (`python3 cyphex_cli.py <cmd>`): `watch`, `github-hook`, `onboard`, `netmap`, `netwatch`, `netaudit` — not yet ported to the `cyphex` binary.

---

## ⚠️ What CYPHEX Can't Do (Yet)

- **Not a substitute for human review or a formal pentest.** It's a fast, verified first pass.
- **A full run with patching takes ~18 minutes** on a laptop with 7B/8B models. Most of that is LLM latency.
- **Nuclei/ZAP and the DeepAgents never run in the same scan** — `--deepagents` replaces them.
- **The built-in static scanner is regex-based**: 16 rulesets, broad but shallow. Semgrep does the deep work wherever it's installed. Confidence scoring trims the obvious false positives but is itself heuristic — a finding marked "test file" can still be real.
- **`p/owasp-top-ten` needs one online fetch** before Semgrep can serve it from cache. Genuinely air-gapped runs need a local `cyphex/semgrep_rules.yml`; none is bundled.
- **Sandbox deployment is strongest on Node/Express** targets; other stacks may need your own Dockerfile. The RASP shield is **Express-only** today.
- **Benchmark numbers come from a 76-sample corpus.** Directional, not certified.
- **Hardware detection keys off GPU VRAM.** A machine with no detectable GPU reports 0 GB and `cyphex doctor` will flag it; the `--mode` override is declared but not yet read by the engine.
- **Known gaps in the patch applier**: its own path-containment guard is currently inert because the CLI does not pass `source_dir` (containment is still enforced a layer up, at patch resolution), and a legacy **non-atomic** write path is still used when the v2 patcher is unavailable. Atomic writes also replace the file via `os.replace`, so a patched file **loses its original permission bits and any hard links**.
- **Older RASP copies vendored into a target app predate daemon auth** — they send no `X-API-Key`, so the daemon silently drops their telemetry. Always take the current `sdks/node/cyphex-rasp.js`.

---

## 🛠️ Tech Stack

| Layer | Tech |
|---|---|
| **Local AI** | Ollama — `qwen2.5-coder:7b` (patcher/oracle), `llama3.1:8b` (analyst/reviewer), `deepseek-coder:6.7b` (reviewer), `nomic-embed-text` (optional cognee memory only) |
| **SAST** | Semgrep + built-in 16-ruleset regex scanner (12 languages + Dockerfile/YAML/SQL/`.env`) |
| **DAST** | Crawler + API discovery, then Nuclei & OWASP ZAP **or** 13 DeepAgents |
| **Sandbox** | Docker (auto-Dockerfile, cap-drop, non-root, loopback-only) / resource-capped native subprocess |
| **Immune System** | 15-rule heuristic over a 24-pattern injection bank + scikit-learn Isolation Forest (CPU-only, degrades gracefully) |
| **Memory** | patch-memory cache · Knowledge Tree · cognee cross-project graph · cross-scan session memory |
| **Core** | Python 3.11+ · httpx · rich · numpy |

---

## 🔐 Security & Ethics

- **Local-first AI.** Every model call goes to your own Ollama at `127.0.0.1:11434`. No cloud LLM, no LLM API key, no billing — your source, findings and patches are only ever sent to that local model.
- **Not network-isolated, though.** Deploying a target runs `npm install` / `pip install` / `docker build` against public registries; `cyphex setup` downloads Semgrep and Nuclei; the optional cognee extra fetches a tokenizer from HuggingFace on first use; and the opt-in `github-hook` mode pushes a fix branch and opens a PR via `api.github.com` with your `GITHUB_TOKEN`. **That PR flow is the only path that sends your code off-box** — everything else stays local. For an air-gapped run, pre-warm those caches and leave those features off.
- **Offense goes wherever you point it.** `cyphex scan <path>` and `--repo` attack only the sandboxed copy of your app. But `cyphex scan http://…` and `/net <cidr>` attack the host or range you name **directly, with no sandbox and no built-in authorization check** — only use them against systems you own or are contractually permitted to test.
- **Hardened against the code it scans.** `npm install --ignore-scripts` blocks install-time RCE from a malicious `postinstall`; the sandbox environment is an explicit allow-list (never `os.environ.copy()`) so a scanned app can't read your tokens; archives are extracted with path-traversal guards and a 1 GB zip-bomb cap; the target is force-rebound to `127.0.0.1` so a deliberately-vulnerable app is never exposed to the LAN.
- **Quiet by default.** Nuclei runs with `-duc -ni` (no update check, no out-of-band interactsh callbacks), Semgrep with `--metrics=off` and never `--config auto` (which would upload project metadata to semgrep.dev on every run). The local API binds `127.0.0.1` and compares tokens with `hmac.compare_digest`.
- **Fail-closed patching.** Symlinked targets refused, line ranges validated before splicing, atomic temp-file + `os.replace` writes, auto-rollback on syntax failure, HMAC-signed genome caches. *(See [limitations](#-what-cyphex-cant-do-yet) for where this isn't yet airtight.)*
- **Graceful degradation.** Missing Docker / scikit-learn / Semgrep / Nuclei → CYPHEX degrades and tells you, rather than crashing.

---

## 📚 Full Documentation

Everything below lives in **[CYPHEX_PRD.md](CYPHEX_PRD.md)**:

| Your question | Section |
|---|---|
| What files does a scan write? | §13 Data Model & Artifacts |
| What *can't* it do? | §5 Goals & Non-Goals · §18 Implementation Status & Known Gaps |
| What hardware / VRAM do I need? | §11.4 Local Models, Hardware Tiers & VRAM |
| Which CWEs are covered? | Appendix B CWE Coverage |
| Every command and flag | §11.2 Commands · Appendix C Command Cheat-Sheet |
| How does patching actually work? | §11.17 AI Remediation Pipeline |
| How is the posture score computed? | §11.23 Security Posture Score |
| Architecture & end-to-end walkthrough | §9 System Overview · §12 Pipeline Walkthrough |
| Where's the code for X? | Appendix D Key File Map |

---

## 📄 License

MIT — see [LICENSE](LICENSE).

<p align="center"><br><b>CYPHEX</b> — find → attack → verify → fix → harden, on your own machine.<br>
<i>Oracle-guided attacks · AI council debate · Adversarial evolution · Auto-patching that has to prove itself.</i></p>
