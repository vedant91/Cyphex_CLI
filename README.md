<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Ollama-Local_LLM-000000?style=for-the-badge&logo=ollama&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Sandbox-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/tests-136_passing-2ea44f?style=for-the-badge" />
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
  <a href="#-usage">Usage</a> · <a href="#-configuration">Config</a> ·
  <a href="#-troubleshooting">Troubleshooting</a> · <a href="#-what-cyphex-cant-do-yet">Limitations</a>
</p>

---

## Table of Contents

| | |
|---|---|
| **[Why CYPHEX exists](#-why-cyphex-exists)** | The gap it fills |
| **[Quick Start](#-quick-start)** · [Prerequisites](#prerequisites) · [Hardware tiers](#hardware-tiers) | Getting running |
| **[What a scan actually does](#-what-a-scan-actually-does)** · [Artifacts](#artifacts-it-leaves-behind) | Measured output |
| **[The Verify Gate](#-the-verify-gate)** | The honesty guarantee |
| **[The 8-step pipeline](#-how-it-works--the-8-step-pipeline)** · [FP scoring](#-false-positive-scoring) | End-to-end mechanics |
| **[DeepAgents](#-1-deepagents--an-oracle-guided-attack-swarm)** · [Oracle](#-2-the-oracle--local-model-reasoning-spent-where-it-pays) · [RAG](#-3-vectorless-rag--knowledge-tree--context-without-a-vector-db) · [Council](#-4-the-council--multi-model-validation) | The four subsystems |
| **[Immune system](#-the-behavioural-immune-system)** · [Benchmark](#benchmarked-quality) | Anomaly detection |
| **[Network scanning](#-network-scanning-optional)** · [RASP + auto-heal](#-rasp--auto-heal-daemon) | Beyond the codebase |
| **[Usage](#-usage)** · [Configuration](#-configuration) · [CI](#-using-cyphex-in-ci) | Operating it |
| **[Repository layout](#-repository-layout)** · [Testing](#-testing) · [Troubleshooting](#-troubleshooting) | Working on it |
| **[Limitations](#-what-cyphex-cant-do-yet)** · [Security & ethics](#-security--ethics) | What to know before trusting it |

---

## 🎯 Why CYPHEX Exists

Most security tooling stops one step short of being useful.

- **SAST** tells you a line looks dangerous. It cannot tell you whether the endpoint is reachable, whether the input is actually attacker-controlled, or whether the finding is one of the many false positives a regex produces.
- **DAST** proves an endpoint is exploitable but has no idea which line of source caused it. You get a URL, not a fix.
- **Neither writes the patch.** You get a report, and the actual work is still yours.
- **Cloud AI tools** will write a patch — after uploading your proprietary source to somebody else's servers, on somebody else's billing.

CYPHEX closes that loop locally: **find → attack → verify → fix → prove**. Static findings and live exploits are correlated back to `file:line`, a local model writes the patch with real code context, and — the part that matters — **the patch only counts if a re-scan confirms the finding is gone.** Everything runs against your own Ollama on `127.0.0.1`.

The design bias throughout is *refusing to overclaim*. A patch that cannot be verified is reported as UNVERIFIABLE, not as success. A benchmark on 76 samples is labelled directional, not certified. Where a guard is not yet airtight, [it says so](#-what-cyphex-cant-do-yet).

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

`cyphex doctor` is worth running first — it reports which binaries are present, whether Ollama is up, which models are pulled, and what hardware tier you land in, so you find out about a missing dependency before an 18-minute scan does.

> **Does it edit my code?** **No — not during a scan.** `cyphex scan <path|--repo>` copies your tree into a per-scan sandbox under `backend/sandboxes/<scan_id>/` and patches *that copy*; your working tree is never touched. The **only** component that writes to your real source is the opt-in `/watch` auto-heal daemon, which patches in place by design.

### Prerequisites

| Tool | Required | Why |
|---|---|---|
| **Python 3.11+** | ✅ | Runtime |
| **Ollama** | ✅ | Local models — all inference hits `127.0.0.1:11434` |
| **Docker** | ⚡ Recommended | Hardened sandbox (auto-generated Dockerfile). Without it, a resource-capped local subprocess is used instead |
| **Node.js 18+** | ⚡ Recommended | Deploying and syntax-checking JS/TS targets. Without it, JS patches return `parse_valid=None` → UNVERIFIABLE rather than PASS |
| **Semgrep / Nuclei** | 🔧 Optional | Extra SAST rules / DAST templates — `cyphex setup` installs both (Nuclei's binary is SHA256-verified against the release checksums) |
| **numpy / scikit-learn** | 🔧 Optional | Isolation-Forest layer of the immune system. Missing → CYPHEX falls back to the heuristic detector instead of crashing |
| **tsc** | 🔧 Optional | TypeScript syntax validation for `.ts`/`.tsx` patches |

### Hardware tiers

CYPHEX detects usable VRAM / unified memory and picks the largest models that will actually fit. Small models produce poor patches, so the selector always reaches for the biggest one your machine can hold.

| Tier | VRAM | Code model | General model |
|---|---|---|---|
| `ultra` | 24+ GB | `qwen2.5-coder:14b` | `llama3.1:14b` |
| `high` | 12+ GB | `qwen2.5-coder:7b` | `llama3.1:8b` |
| `mid` | 6+ GB | `deepseek-coder:6.7b` | `phi3:medium` |
| `low` | 4+ GB | `deepseek-coder:1.3b` | `phi3:mini` |
| `minimal` | 2+ GB | `deepseek-coder:1.3b` | — |
| `cloud` | < 2 GB | cloud API | cloud API |

The tier also gates which reasoning strategies are allowed, so a low-VRAM machine never tries to run a 5-call Tree-of-Thoughts pass. See [The Oracle](#-2-the-oracle--local-model-reasoning-spent-where-it-pays).

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

### How the Security Posture Score is computed

A log-scaled penalty per severity bucket, subtracted from 100 and clamped to `[0, 100]`:

```
penalty = 0
if critical: penalty += 20 + 10 · log₂(1 + n_critical)
if high:     penalty += 10 +  8 · log₂(1 + n_high)
if medium:   penalty +=  3 +  4 · log₂(1 + n_medium)
if low/info: penalty +=  1 +  2 · log₂(1 + n_low)

score = clamp(100 − penalty, 0, 100)
```

The log scaling means the *first* Critical costs 30 points and the tenth costs a few — the intent is to distinguish "has Criticals" from "has none", not to rank two badly-broken apps against each other. The **after** score reuses the identical coefficients over the vulns that remain, and there is a hard guard: **zero applied patches ⇒ `score_after = score_before`**, so a run that fixed nothing can never show improvement.

### Artifacts it leaves behind

| Path | Contents |
|---|---|
| `report.json` (scan dir) | Findings, severities, `file:line`, posture score, duration |
| `cyphex_judge_artifacts/report.{json,md,sarif}` | Deterministic report set, written under `--judge` |
| `.cyphex/patches.json` | Patch manifest — every applied patch and its verdict |
| `.cyphex/patch_memory.json` | Verified-fix cache, reused on later scans with zero AI calls |
| `.cyphex/sessions/<id>.json` | Reasoning trace / session memory for the run |
| `.cyphex/knowledge_tree.json` | Cached Knowledge Tree for the target |
| `benchmark_report.json` | Immune-system metrics (from `--json`) |
| genome storage dir | `genome_<target>.pkl` + `.hmac` sidecar — evolution resumes here next scan |

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

*A patch counts as "fixed" only if a re-scan proves it.* This is the single most important thing in the codebase — everything else produces candidates, and this decides which of them are real.

Every candidate must clear all of:

- the finding is **gone on re-scan**;
- the file still **compiles** (`node --check` / `py_compile` / `tsc --noEmit`);
- **no suppression comments** were added (`nosemgrep`, `eslint-disable`, `# noqa`, `@ts-ignore`, `@ts-expect-error`, `noinspection`, `pragma: no cover`);
- **no more than 70%** of the file's non-blank lines were deleted;
- the diff stays inside a **severity-scaled blast radius** — Critical 80 lines · High 60 · Medium 40 · Low 30 — with the target line range validated before any splice.

### The three verdicts

| Verdict | Meaning | Effect |
|---|---|---|
| **PASS** | Every check ran and passed | Counts toward the score; stores a reusable `CWE:strategy` pattern + a cross-project memory entry |
| **FAIL** | A check ran and failed | **Rolled back** to the original bytes; writes a "try a different remediation approach" lesson into session memory |
| **UNVERIFIABLE** | A check could not be run at all | Patch stays applied but **never counts toward the score** |

The tri-state matters more than it looks. `finding_gone` and `builds` are `True`/`False`/`None`, and `None` means *this was not measured* — a missing scanner, an unsupported file type. The verdict logic refuses to coerce `None` into a PASS, which is exactly how an unsupported language or a crashed scanner used to produce false success. A check that ran and failed always outranks one that never ran.

### Why comment-matching flips during verification

Ordinary scans treat a regex match inside a code comment as a false positive — a commented-out example query is not a vulnerability. If the re-scan did the same, a patch that simply **comments the vulnerable line out** would read as "finding gone" and PASS.

So the verifier re-scans with comment-matching switched back on. Commenting-out is scored as still-vulnerable and rolled back. Meanwhile the *parameterised-SQL* suppression stays active in both directions, because a patch that adds placeholders genuinely is a fix and must verify as one. That asymmetry is deliberate and is covered by tests.

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

### The patch ladder (step 8, in order)

Each rung is tried before the one below it, so the expensive path runs only when the cheap ones can't answer:

1. **Patch-memory cache** — a semantic hash of the enclosing function (whitespace- and comment-insensitive) keyed by CWE. A hit reuses a previously *verified* fix with **zero model calls**.
2. **Deterministic template** — a pure regex transform for the four CWEs that have one. No model involved, no variance:

   | CWE | Transform |
   |---|---|
   | CWE-89 | `` db.query(`...${id}`) `` → `db.query("...?", [id])` |
   | CWE-78 | `` execSync(`ping ${host}`) `` → `execFileSync("ping", [host])` — removes the shell entirely |
   | CWE-798 | `const password = "hunter2"` → `const password = process.env.PASSWORD` |
   | CWE-942 | `cors({ origin: "*" })` → `cors({ origin: [process.env.ALLOWED_ORIGIN ...] })` |

3. **Council generation** — the LLM path, prompted with Vectorless-RAG + Knowledge-Tree context, with multiple models voting on the result.
4. **Verify Gate** — and on FAIL, a **reflexion** retry that feeds the failure evidence back into the next prompt.

### 🎯 False-positive scoring

Every static finding carries a `confidence` (0.0–1.0) and, when it's been marked down, a `fp_reason`. Semgrep hits start at 0.90, built-in regex hits at 0.85. Findings at or below `FP_DROP_THRESHOLD` (0.15) are dropped from ordinary scans.

| Signal | Effect |
|---|---|
| SQL call is already parameterised (`?` / `$1` / params array / `prepare(`) | dropped outright — on **every** path, verification included |
| Match sits inside a code comment | confidence 0.0 — dropped from scans, but **visible to the verifier** |
| File is test / fixture / mock code | −0.45, kept but marked |

On the bundled `vuln-webapp` this removes 2 Critical false positives, both of which were the scanner matching its own English prose: `query (should` inside `// Safe: parameterized query (should NOT be flagged)`.

Semgrep never runs with `--config auto`, which uploads project metadata to semgrep.dev on every run and cannot be cached. The ladder is: a local `cyphex/semgrep_rules.yml` if you drop one in (fully offline) → the static `p/owasp-top-ten` pack, which Semgrep caches locally after the first fetch.

---

## ⭐ The Four Subsystems

### 🕵️ 1. DeepAgents — an Oracle-guided attack swarm

**13 specialized AI attack agents**, one per vulnerability class, that don't run a fixed script — they *adapt*.

| Agent | Targets | Agent | Targets |
|---|---|---|---|
| `DeepSQLiAgent` | SQL Injection | `DeepXXEAgent` | XML External Entity |
| `DeepXSSAgent` | Cross-Site Scripting | `DeepBusinessLogicAgent` | Business-Logic Flaws |
| `DeepCMDiAgent` | Command Injection | `DeepPromptInjectionAgent` | Prompt Injection / LLM safety bypass (CWE-1336, OWASP LLM01) |
| `DeepAuthAgent` | Auth Bypass / Priv-Esc | `DeepRaceConditionAgent` | Race Condition / TOCTOU (CWE-362) |
| `DeepIDORAgent` | Insecure Direct Object Ref | `DeepMassAssignmentAgent` | Mass Assignment / Parameter Pollution (CWE-915) |
| `DeepSSRFAgent` | SSRF — incl. the AWS metadata endpoint `169.254.169.254` | `DeepSSTIAgent` | Template Injection |
| `DeepPathTraversalAgent` | Path Traversal / LFI | | |

**The loop each agent runs:**

1. **Baseline** — one GET against the root to establish a response-time baseline, so timing-based inference (blind SQLi, sleep payloads) has something to compare against.
2. **Plan** — the Oracle reads the attack-surface summary and returns ranked hypotheses. Capped at `MAX_HYPOTHESES = 10`.
3. **Probe** — hypotheses execute in parallel batches of `PARALLEL_BATCH = 3`, each getting up to `MAX_ATTEMPTS_PER_HYPOTHESIS = 5` probes.
4. **Decide** — after each probe the Oracle judges the response as *confirmed / adapt / abandoned*. "Abandoned" ends that hypothesis immediately rather than burning all 5 attempts on slow local-LLM calls.
5. **Mutate** — on *adapt*, the Oracle evolves the payload into an evasion variant and the loop repeats.
6. **Chain** — a confirmed exploit updates the shared **attack graph**, and newly-discovered edges (`unauth data leak → admin takeover`) are surfaced as multi-step attack paths.

A **dead-route guard** keeps agents from spending budget on endpoints that don't exist. Crawler, API-discovery and network-recon agents feed the attack-surface index the Oracle plans against.

### 🧠 2. The Oracle — local-model reasoning, spent where it pays

The Oracle is the local-LLM brain behind every DeepAgent, with three entry points:

- **`plan()`** — reads the attack surface, returns 5–8 ranked attack hypotheses (highest impact / cheapest to test first).
- **`decide()`** — judges a probe's response using status, body, size **and timing vs. the measured baseline**, returning confirmed/adapt/abandoned plus a confidence score and structured evidence.
- **`mutate()`** — evolves a failing payload into evasion variants.

A **meta-reasoning router** then picks a *patch-generation* strategy per finding, out of a bank of 16 (**9 enabled**):

| Router | Availability | Routing |
|---|---|---|
| **Built-in** | Always on | Critical **or** a hard CWE (78, 918, 89, 94, 77, 22) → **Self-Consistency** K-vote · High → **Chain-of-Thought** · everything else → direct generation |
| **`.[reasoning]` extra** | Optional install | CWE override first, then severity: Critical → Self-Consistency · High → **Self-Reflection** (draft → critique → improve) · Medium/Low → CoT. CWE overrides send CMDi/SSRF → **Tree-of-Thoughts**, auth-bypass/IDOR → **Decomposition**, path traversal → **Least-to-Most**. Expensive strategies are gated off on low-VRAM tiers. |

Every patch keeps its reasoning tree for audit. → [PRD §11.20](CYPHEX_PRD.md)

### 📚 3. Vectorless RAG + Knowledge Tree — context without a vector DB

Small models write good patches only with good context. The RAG path uses **no embeddings and no vector store**: a keyword/regex **code-tree index** extracts, per vulnerability, the whole brace-balanced enclosing function, the file's imports, a **CWE fix recipe**, and an **in-repo secure example** so patches match the codebase's own style.

On top sits a **PageIndex-style Knowledge Tree** (`backend/rag/`) — a hierarchical JSON tree of `code_tree` + `knowledge_tree` + a deterministic `cwe_index`, built from your repo plus a bundled security corpus (OWASP Top-10 notes, CWE fix patterns, Express secure-coding patterns) and cached under `.cyphex/knowledge_tree.json`.

Its **fast path is 0-LLM**: `CWE + file:line` → enclosing function, fix recipe, secure example, related knowledge. Measured on `vuln-webapp`, a CWE-89 lookup returns a 502-char fix recipe, a 543-char function body and a 547-char in-repo secure example. The deep path shows the model only branch *summaries*, never the whole tree.

> No embeddings in the RAG context path. *(The optional `[memory]` extra — cognee cross-project memory — is the exception: it does use `nomic-embed-text` at 768 dims over a local LanceDB store.)*

### 🏛️ 4. The Council — multi-model validation

One model writing and grading its own patch is a single point of failure. CYPHEX assigns **three roles** — `detector`, `validator`, `patcher` — and scores every available Ollama model for each.

The scoring heuristic is deliberately blunt: **parameter count is the primary driver**, and code specialisation is a 15% bonus rather than an override. An 8B general model beats a 7B code model at most tasks, including code, because the extra parameters buy better reasoning; the code model only wins on pure generation.

The council then runs a **debate protocol** — the patcher proposes, validators vote with reasons, and the finding is confirmed, sent back, or dropped as a false positive. A separate **fact-check pass** has a second model re-read the written report specifically hunting for findings the first model invented.

`cyphex council-doctor` reports which model landed in which role.

---

## 🧬 The Behavioural Immune System

Instead of matching known signatures, CYPHEX **learns what *normal* looks like for *your* app** and blocks the anomalies.

**The 15-dimension feature vector**, extracted per input string:

| # | Feature | # | Feature |
|---|---|---|---|
| 1 | `input_length` | 9 | `sqli_pattern_score` (24-pattern injection bank) |
| 2 | `entropy` (Shannon) | 10 | `null_byte_present` |
| 3 | `special_char_ratio` | 11 | `path_traversal_depth` |
| 4 | `url_encoding_ratio` | 12 | `bracket_imbalance` |
| 5 | `uppercase_ratio` | 13 | `unicode_ratio` |
| 6 | `digit_ratio` | 14 | `repetition_ratio` |
| 7 | `max_token_length` | 15 | `token_count` |
| 8 | `sql_keyword_score` | | |

- **Scoring** is `max(isolation-forest, heuristic)` — the heuristic layer is 15 threshold rules over those features, one fed by the 24-pattern injection bank — plus a small agreement boost when both detectors fire. **BLOCK ≥ 0.7** (`GENOME_BLOCK_THRESHOLD`). Without numpy/scikit-learn the heuristic layer alone still scores.
- **Coverage** goes well past SQLi/XSS: SSTI, NoSQLi, SSRF/cloud-metadata, LDAP injection, CRLF header injection and XXE are all in the pattern bank (100% detection on each of those classes in the benchmark corpus).
- **Adversarial co-evolution** — an AI red team mutates attacks while the blue team retrains the genome, breeding from both blocked *and* bypassed payloads plus fresh diversity injection. Defaults: 10 generations × 20 payloads, early-stop at ≥99% block rate for 3 consecutive generations. Starting rates vary run to run and the curve is **not strictly monotonic**.
- **Persistence** — genomes are saved with an **HMAC sidecar** (`.pkl` + `.pkl.hmac`, key mode `0600`) and refuse to load an unsigned or tampered file, so a poisoned pickle can't be swapped in. Attack history round-trips too, so run *N+1* keeps hardening from run *N*'s bypasses.

Sample scores (`/search` endpoint, untrained genome):

| Payload | Score | Verdict |
|---|---|---|
| `' OR 1=1--` | 1.00 | BLOCK |
| `<script>alert(1)</script>` | 1.00 | BLOCK |
| `; cat /etc/passwd` | 1.00 | BLOCK |
| `http://169.254.169.254/latest/meta-data/` | 0.80 | BLOCK |
| `{{7*7}}` | 0.80 | BLOCK |
| `normal search query` | 0.00 | allow |

### Benchmarked quality

**91.3% recall · 97.7% precision · 94.4% F1 · 3.3% FPR · ~0.04 ms/sample** — on a **76-sample corpus (46 attack / 30 benign; 42 TP, 1 FP, 4 FN)**. Small *n*: treat as directional, not certified. The co-evolution block rates are measured against payloads CYPHEX generated itself — in-distribution, not a generalization claim.

```bash
python3 cyphex_benchmark.py                       # exits non-zero if recall < 80% or FPR > 10% → CI gate
python3 cyphex_benchmark.py --data cic-ids2018.csv --threshold 0.6 --json out.json
./cx benchmark --data cic-ids2018.csv             # same engine from the launcher (reports the gate
                                                  # verdict, but does NOT set an exit code)
```

Output includes the full confusion matrix, per-attack-class detection rates, and the exact list of missed attacks and false positives — the four current misses are `admin'--`, `" OR ""="`, `| whoami` and a Windows-style traversal path. `--data` accepts any labelled CSV corpus with `payload,label[,attack]` columns.

---

## 🌐 Network Scanning (optional)

`--network` / `/net` adds a layer below the application: host discovery and port sweep, service and device-type inference from banners, and a per-host risk score. High-risk ports (21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432…) and cleartext protocols (21, 23, 25, 80, 110, 143, 8080) are weighted into that score, and a `NetworkVulnMapper` correlates open services against known weaknesses.

There is a **separate 25-dimension network genome** for traffic-level anomalies — including ARP rate, ICMP rate and SYN-without-ACK rate as scan indicators — with its own HMAC-signed persistence. `/netwatch` runs it as a live monitor.

> `/net <cidr>` attacks the range you name **directly** — no sandbox, no authorization check. See [Security & Ethics](#-security--ethics).

---

## 🛡️ RASP + Auto-Heal Daemon

A **zero-dependency Express shield** (`sdks/node/cyphex-rasp.js`, a single `app.use()` — or let `python3 cyphex_cli.py onboard --path <app>` inject it for you) inspects query strings, recursively-flattened JSON bodies, and cookie / referer / x-forwarded-for / user-agent headers. It blocks attacks with a **403** above a tunable `confidenceThreshold` (default 0.7), or runs in **detect-only mode** (`blockMode: false`) for a staged rollout.

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

| Flag | Effect |
|---|---|
| `--path` / `--repo` / bare positional | Target: local dir, git URL, or live URL |
| `--deepagents` (alias `--deep`) | Oracle-guided swarm instead of Nuclei/ZAP |
| `--network` | Add the host/port sweep |
| `--no-patch` | Scan and report only — no remediation |
| `--format {table,json,sarif,markdown}` | Output format (default `table`) |
| `--judge` | Deterministic artifact set for benchmarking |
| `--mode {full,standard,lite,cloud}` | **Declared but not yet read by the engine** — see limitations |

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

**Legacy entry points** (`python3 cyphex_cli.py <cmd>`): `watch`, `github-hook`, `onboard`, `netmap`, `netwatch`, `netaudit`, and a `scan` that additionally accepts `--branch` — not yet ported to the `cyphex` binary.

---

## ⚙️ Configuration

Defaults live in `backend/backend/config.py`; environment variables override them.

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_URL` | `http://localhost:11434` | Local model endpoint |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` | Default model when the selector has nothing better |
| `CYPHEX_API_KEY` | — | Shared secret between the RASP SDK and the `/watch` daemon. **Must match on both sides** |
| `CYPHEX_API_HOST` / `CYPHEX_API_PORT` | `127.0.0.1` / `8000` | Local API bind address |
| `CYPHEX_GIT_ALLOWED_HOSTS` | — | Allow-list for `--repo` clone hosts |
| `GITHUB_TOKEN` | — | Only for the opt-in `github-hook` PR flow |
| `GITHUB_WEBHOOK_SECRET` | — | Verifies inbound webhook signatures |
| `COGNEE_EMBEDDING_MODEL` | `nomic-embed-text` | Optional `[memory]` extra only |
| `COGNEE_RECALL_TIMEOUT_S` | `20.0` | Memory recall budget |
| `COGNEE_REMEMBER_TIMEOUT_S` | `300.0` | `cognify()` runs an LLM extraction pass — hence the wide budget |

Notable non-env knobs:

| Setting | Default | Purpose |
|---|---|---|
| `SCAN_TIMEOUT_SECONDS` | `1800` | Hard ceiling on a single scan |
| `COMMAND_TIMEOUT_SECONDS` | `60` | Per-command default |
| `MAX_PARALLEL_AGENTS` | `6` | Concurrency cap for the agent suite |
| `GENOME_BLOCK_THRESHOLD` | `0.7` | Anomaly score at/above which a payload is blocked |
| `EVOLUTION_GENERATIONS` | `10` | Co-evolution generations per run |
| `EVOLUTION_PAYLOADS_PER_GEN` | `20` | Payloads bred per generation |
| `EVOLUTION_CONVERGENCE_THRESHOLD` | `0.99` | Early-stop block rate |

> `config.py` also carries `GROQ_*` / `CEREBRAS_* `/ `AI_BACKEND_MODE` fields for a cloud fallback path. The default is `AI_BACKEND_MODE = "local"` and the documented, tested path is local-only — setting a cloud key sends your code off-box.

---

## 🤖 Using CYPHEX in CI

The immune benchmark is the piece designed as a gate — it exits non-zero if recall drops below 80% or FPR climbs above 10%:

```yaml
- name: Immune-system regression gate
  run: python3 cyphex_benchmark.py

- name: Security scan (report only, no patching)
  run: cyphex scan . --no-patch --format sarif > results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Use `--no-patch` in CI. A full patching run needs Ollama with pulled models and takes ~18 minutes; `--judge` gives you a deterministic artifact set if you want to diff scan-over-scan.

---

## 📂 Repository Layout

```
cyphex/                     # The pip-installed package — CLI entry point
  cli.py                    #   argparse surface, `cyphex <cmd>`
  scanner.py                #   static analysis: Semgrep + 16 built-in rulesets + FP scoring
  dynamic_scanner.py        #   Nuclei / ZAP integration
  docker_sandbox.py         #   hardened container deployment
  daemon.py                 #   /watch auto-heal daemon (127.0.0.1:3004)
  doctor.py  hardware.py    #   environment checks, VRAM tiering, model selection
  onboarder.py              #   zero-click RASP injection into a target app
  github_hook.py            #   opt-in PR flow (the one path that leaves your machine)

backend/
  deepagents/               # 13 Oracle-guided attack agents + attack graph + surface index
  council/                  # multi-model debate, model selection, reasoning strategies
  rag/                      # vectorless code index, Knowledge Tree, security KB, cognee memory
  reasoning/                # reflexion, self-consistency, session memory, reasoning trees
  patch/                    # resolver → applier → verifier → templates → manifest → regression
  network/                  # discovery, network genome, topology, vuln mapping
  backend/immune/           # behavioural genome + adversarial evolution controller
  backend/agents/           # the classic (non-Deep) agent suite
  sandboxes/                # per-scan working copies (gitignored)

sdks/node/cyphex-rasp.js    # the runtime shield
cli_engine.py               # pipeline orchestrator — wires all of the above together
cyphex_benchmark.py         # immune-system benchmark + CI gate
tests/                      # 136 tests
vuln-webapp/                # bundled deliberately-vulnerable Express app
```

---

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest                      # 136 tests, ~7s
pytest -m integration       # slow tests that drive real local models (needs Ollama)
```

Integration tests are excluded by default via `addopts = "-m 'not integration'"` in `pyproject.toml`. They are excluded for a reason: `test_cross_project_recall` runs cognee's `cognify()` through a local LLM and takes minutes.

The Verify Gate tests are the ones worth reading if you want to understand the system's guarantees — they are mutation-checked, meaning each of the gate's invariants was deliberately broken to confirm the suite catches it.

---

## 🔧 Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `ModuleNotFoundError` on `cyphex` | Editable install didn't take. Re-run `pip install -e .` from the repo root |
| `cyphex doctor` reports 0 GB VRAM | No detectable GPU. CYPHEX still runs on CPU, just slowly; `--mode` is declared but not yet wired |
| Scan finds nothing on a real repo | Check `cyphex doctor` for Semgrep. Without it you're on the 16 built-in regex rulesets only |
| Every patch comes back UNVERIFIABLE | The re-scan or syntax check couldn't run — usually missing `node` for a JS target. Install Node 18+ |
| Patches are slow | Expected: ~18 min for a full patching run on 7B/8B. Use `--no-patch` to scan only |
| RASP telemetry never reaches the daemon | `CYPHEX_API_KEY` must be identical on both sides, and the vendored RASP copy must be the current `sdks/node/cyphex-rasp.js` (older copies send no `X-API-Key`) |
| RASP reports no `file:line` | It's mounted globally. Mount per-route to get an app frame on the stack |
| Sandbox deploy fails | Docker missing or the target needs its own Dockerfile. CYPHEX falls back to a resource-capped subprocess |
| `pytest` hangs | You ran integration tests. Default `pytest` excludes them |

---

## ⚠️ What CYPHEX Can't Do (Yet)

- **Not a substitute for human review or a formal pentest.** It's a fast, verified first pass.
- **A full run with patching takes ~18 minutes** on a laptop with 7B/8B models. Most of that is LLM latency.
- **Nuclei/ZAP and the DeepAgents never run in the same scan** — `--deepagents` replaces them.
- **The built-in static scanner is regex-based**: 16 rulesets, broad but shallow. Semgrep does the deep work wherever it's installed. Confidence scoring trims the obvious false positives but is itself heuristic — a finding marked "test file" can still be real.
- **`p/owasp-top-ten` needs one online fetch** before Semgrep can serve it from cache. Genuinely air-gapped runs need a local `cyphex/semgrep_rules.yml`; none is bundled.
- **Only 4 CWEs have deterministic templates** (89, 78, 798, 942). Everything else goes through the LLM path, with the variance that implies.
- **Sandbox deployment is strongest on Node/Express** targets; other stacks may need your own Dockerfile. The RASP shield is **Express-only** today.
- **Benchmark numbers come from a 76-sample corpus.** Directional, not certified.
- **Hardware detection keys off GPU VRAM.** A machine with no detectable GPU reports 0 GB and `cyphex doctor` will flag it; the `--mode` override is declared but not yet read by the engine.
- **Known gaps in the patch applier**: its own path-containment guard is currently inert because the CLI does not pass `source_dir` (containment is still enforced a layer up, at patch resolution), and a legacy **non-atomic** write path is still used when the v2 patcher is unavailable. Atomic writes also replace the file via `os.replace`, so a patched file **loses its original permission bits and any hard links**.
- **No bracket-balance guard in the applier.** The council *prompt* instructs the model to preserve net brace depth, but nothing enforces it — an orphaned brace is caught one step later by `node --check`, which then auto-rolls-back.
- **Older RASP copies vendored into a target app predate daemon auth** — they send no `X-API-Key`, so the daemon silently drops their telemetry. Always take the current `sdks/node/cyphex-rasp.js`.

---

## 🛠️ Tech Stack

| Layer | Tech |
|---|---|
| **Local AI** | Ollama — `qwen2.5-coder:7b` (patcher/oracle), `llama3.1:8b` (analyst/reviewer), `deepseek-coder:6.7b` (reviewer), `nomic-embed-text` (optional cognee memory only) |
| **SAST** | Semgrep + built-in 16-ruleset regex scanner (12 languages + Dockerfile/YAML/SQL/`.env`) with confidence scoring |
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
