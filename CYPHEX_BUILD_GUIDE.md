# CYPHEX — Complete Build-From-Scratch Reference

> **Autonomous Security Scanner + Cyber Immune System**
> Scan any codebase. Find vulns. Patch. Push.

This document contains **everything** needed to understand and rebuild CYPHEX from scratch — architecture, every file's purpose, data flow, algorithms, and configuration.

---

## Table of Contents

1. [What CYPHEX Is](#1-what-cyphex-is)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Project Structure](#3-project-structure)
4. [The 8-Step Pipeline](#4-the-8-step-pipeline)
5. [Data Models](#5-data-models)
6. [File-by-File Breakdown](#6-file-by-file-breakdown)
7. [The Immune System (Core Innovation)](#7-the-immune-system-core-innovation)
8. [The Sandbox Manager](#8-the-sandbox-manager)
9. [AI / LLM Integration](#9-ai--llm-integration)
10. [Frontend Dashboard](#10-frontend-dashboard)
11. [IoT Edge Module](#11-iot-edge-module)
12. [Dependencies & Setup](#12-dependencies--setup)
13. [CLI Usage](#13-cli-usage)
14. [Key Algorithms Explained](#14-key-algorithms-explained)

---

## 1. What CYPHEX Is

CYPHEX is a **multi-agent autonomous security scanner** with an **adversarial co-evolution immune system**. It:

1. **Clones** any GitHub repository (or accepts a local path)
2. **Statically analyzes** code for vulnerabilities (regex pattern matching)
3. **Deploys** the app into an isolated sandbox (auto-detects stack, runs `npm install` + `npm start`)
4. **Dynamically attacks** the live app with 7 specialized agents (Crawler, XSS, SQLi, Auth, CMDi, LFI, Logic)
5. **Evolves** an AI immune system genome (Red Team generates attacks → Blue Team learns to block → repeat for N generations)
6. **Simulates** real-world attacks against the trained genome firewall
7. **Reports** a security score (0-100) with detailed findings
8. **Patches** vulnerable code using a local LLM (Ollama) and optionally pushes fixes to GitHub

**What makes it unique:** The Adversarial Co-Evolution loop — a Red Team AI and Blue Team AI fight each other in a closed feedback loop, making the defense progressively stronger. This is biologically inspired (like how the human immune system works).

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CYPHEX CLI                               │
│                    cyphex_cli.py (entrypoint)                   │
│                    cli_engine.py (core logic)                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
    ┌─────────▼─────────┐   ┌──────────▼──────────┐
    │  STATIC ANALYSIS  │   │  SANDBOX MANAGER    │
    │  (regex patterns) │   │  (deploy + run app) │
    │  cli_engine.py    │   │  sandbox_manager.py │
    └─────────┬─────────┘   └──────────┬──────────┘
              │                         │
              │               ┌─────────▼─────────┐
              │               │  DYNAMIC AGENTS   │
              │               │  Agent 02: Crawler │
              │               │  Agent 03: SQLi    │
              │               │  Agent 04: XSS     │
              │               │  Agent 05: Auth    │
              │               │  Agent 06: CMDi    │
              │               │  Agent 07: LFI     │
              │               │  Agent 08: Logic   │
              │               └─────────┬─────────┘
              │                         │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │    IMMUNE SYSTEM        │
              │  BehavioralGenome (Blue)│
              │  MutationEngine  (Red)  │
              │  EvolutionController    │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │    PATCH + REPORT       │
              │  LLM-generated patches  │
              │  Security Score 0-100   │
              │  SARIF/JSON/MD export   │
              └─────────────────────────┘
```

---

## 3. Project Structure

```
cyphex_v3/
├── cyphex_cli.py                  # CLI entrypoint (argparse, banner, launches engine)
├── cli_engine.py                  # Core 8-step pipeline (CyphexEngine class)
├── run_cyphex.bat                 # Windows batch launcher
│
├── backend/
│   └── backend/
│       ├── config.py              # Central configuration (AI keys, thresholds)
│       ├── sandbox_manager.py     # Deploy target apps into sandboxes
│       ├── scan_orchestrator.py   # Web API orchestrator (for dashboard mode)
│       ├── main.py                # FastAPI server (for dashboard mode)
│       ├── api.py                 # REST endpoints (for dashboard mode)
│       ├── live_log_queue.py      # Real-time log streaming via WebSocket
│       ├── security_posture_score.py  # Score calculation
│       │
│       ├── agents/                # 11 Security Agents + support
│       │   ├── base_agent.py      # Base class (LLM integration, logging)
│       │   ├── agent_01_recon.py  # Fingerprint server, headers, tech stack
│       │   ├── agent_02_crawler.py # Discover pages, forms, parameters
│       │   ├── agent_03_sqli.py   # SQL injection testing
│       │   ├── agent_04_xss.py    # Cross-site scripting testing
│       │   ├── agent_05_auth.py   # Authentication weakness testing
│       │   ├── agent_06_cmdi.py   # Command injection testing
│       │   ├── agent_07_lfi.py    # Local file inclusion testing
│       │   ├── agent_08_logic.py  # CORS, business logic testing
│       │   ├── agent_09_analysis.py # AI-powered analysis report
│       │   ├── agent_10_patch.py  # AI-powered patch generation
│       │   ├── agent_11_supply_chain.py # Dependency/manifest checks
│       │   ├── agent_ai_fuzzer.py # AI-powered fuzzing
│       │   ├── agent_injection.py # Advanced injection techniques
│       │   └── terminal.py        # Safe command execution wrapper
│       │
│       ├── immune/                # The Cyber Immune System
│       │   ├── behavioral_genome.py    # Blue Team: Isolation Forest anomaly detector
│       │   ├── mutation_engine.py      # Red Team: Payload obfuscation/mutation
│       │   └── evolution_controller.py # Orchestrates Red vs Blue loop
│       │
│       ├── models/                # Data models (dataclasses)
│       │   ├── scan.py            # ScanContext, Vuln, FormData, ParamData, Evidence
│       │   ├── genome.py          # EndpointProfile, GenomeState, EvolutionResult
│       │   └── agent_result.py    # AgentResult (per-agent output)
│       │
│       ├── sandboxes/             # Runtime: cloned repos deployed here
│       ├── sandbox/vulncorp/      # Built-in vulnerable test target
│       ├── target1z/target1/      # Built-in vulnerable test target (SQLi)
│       └── target2z/target2/      # Built-in vulnerable test target (XSS)
│
├── frontend/                      # React + Vite dashboard UI
│   ├── src/
│   │   ├── App.tsx                # Main app with routing
│   │   ├── pages/Overview.tsx     # Scan overview dashboard
│   │   ├── pages/Modules.tsx      # Agent modules view
│   │   ├── pages/Report.tsx       # Final report page
│   │   ├── pages/SandboxPage.tsx  # Sandbox management UI
│   │   ├── components/            # UI components (AgentTable, Sidebar, etc.)
│   │   └── contexts/PipelineContext.tsx # Real-time scan state management
│   └── package.json
│
├── finetune/                      # Model fine-tuning data
│   ├── training_data.py           # Generate JSONL training pairs
│   ├── train.py                   # Fine-tune script
│   └── Modelfile                  # Ollama model configuration
│
├── iot/                           # IoT edge hardware module
│   ├── wokwi_main.py             # MicroPython firmware for ESP32
│   ├── wokwi_diagram.json        # Wokwi simulator circuit
│   └── iot_serial_bridge.py      # USB serial bridge to main scanner
│
├── cyphex_training_data.jsonl     # Pre-built fine-tuning dataset
├── demo_immune_system.py          # Standalone immune system demo
├── test_immune_system.py          # Pytest tests for immune system
├── test_live_target.py            # Integration tests against live targets
└── test_portfolio.py              # Portfolio/showcase tests
```

---

## 4. The 8-Step Pipeline

The core pipeline lives in `cli_engine.py` inside the `CyphexEngine.run()` method:

### Step 1: GET SOURCE CODE (`_get_source`)
- **Input:** `--repo <github_url>` or `--path <local_dir>`
- **Action:** Clones repo with `git clone --depth 1` OR copies local directory
- **Output:** `self.source_dir` — path to extracted codebase
- **Framework Detection:** Reads `package.json` to identify Express/Next.js/NestJS/etc.

### Step 2: STATIC CODE ANALYSIS (`_analyze_code_files`)
- **Input:** Source directory
- **Action:** Walks all `.js/.ts/.py/.php` files. Applies **regex patterns** to detect:
  - SQL Injection (f-strings in queries, string concat in SQL)
  - XSS (innerHTML, document.write, dangerouslySetInnerHTML)
  - Command Injection (exec, os.system, shell=True)
  - Path Traversal (readFile with user input)
  - Hardcoded Secrets (password/token = "...")
  - Missing Auth (admin routes without middleware)
- **Output:** List of `Vuln` objects with file:line references

### Step 3: DEPLOY SANDBOX (`_deploy`)
- **Input:** Source directory
- **Action:**
  1. Creates a ZIP of the source
  2. Calls `deploy_sandbox()` which extracts, runs `npm install`, detects entry file
  3. If monorepo → looks for `backend/`, `server/`, `api/` subdirectories
  4. If direct deploy fails → tries static HTTP server
  5. If everything fails → returns `"offline_mode"` (graceful fallback)
- **Output:** `http://localhost:<port>` URL of the running app (or `"offline_mode"`)

### Step 4: DYNAMIC VULNERABILITY SCAN (`_dynamic_scan`)
- **Input:** Live target URL
- **Action:** 7 agents attack the live app:
  - **Agent 02 (Crawler):** Follows all `<a href>` links, discovers `<form>` elements
  - **Agent 04 (XSS):** Injects `<script>alert(1)</script>` into all form inputs, checks if reflected
  - **Agent 03 (SQLi):** Injects `' OR 1=1--` and `UNION SELECT`, looks for SQL error strings
  - **Agent 05 (Auth):** Tries default credentials (admin:admin) on login forms
  - **Agent 07 (LFI):** Tries `../../etc/passwd` on file download endpoints
  - **Agent 06 (CMDi):** Tries `; id` and `| whoami` on ping/command endpoints
  - **Agent 08 (Logic):** Checks CORS headers for `Access-Control-Allow-Origin: *`
  - **Agent 11 (Supply Chain):** Checks if `/package.json` or `/requirements.txt` is publicly exposed
- **Output:** `ScanContext` populated with confirmed vulns, endpoints, forms

### Step 5: IMMUNE SYSTEM — BUILD GENOME (`_build_and_evolve`)
- **Input:** ScanContext with discovered endpoints
- **Action:**
  1. Blue Team builds `BehavioralGenome` — profiles each endpoint's "normal" traffic
  2. Red Team generates initial attack payloads (SQLi, XSS, CMDi)
  3. Runs N generations of Adversarial Co-Evolution (see Section 7)
- **Output:** Trained genome with convergent block rate

### Step 6: AI ATTACK SIMULATION (`_simulate_attacks`)
- **Input:** Trained genome
- **Action:** Tests 12 hardcoded attacks (9 malicious + 3 normal) against genome
- **Output:** Genome accuracy %, false positive rate, false negative rate

### Step 7: SECURITY REPORT (`_print_report`)
- **Input:** All confirmed vulns
- **Action:** Calculates score: `100 - (Critical×25) - (High×10) - (Medium×5) - (Low×1)`
- **Output:** Score 0-100, formatted terminal report, optional JSON/SARIF export

### Step 8: PATCH & VERIFY (`_patch_workflow`)
- **Input:** Critical/High vulns with file:line references
- **Action:**
  1. Shows the vulnerable code snippet
  2. Sends snippet to local LLM (Ollama) asking for: `unsafe_reason`, `fixed_code`, `patch_safety`
  3. Shows diff to user
  4. In interactive mode: asks `Apply this patch? (y/n/q)`
  5. In non-interactive mode: auto-applies
  6. Optionally pushes patches to GitHub
- **Output:** Patched files, optional git push

---

## 5. Data Models

### `ScanContext` (the shared state)
```python
@dataclass
class ScanContext:
    target_url: str = ""
    # Recon
    framework: Optional[str] = None
    headers: dict = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    # Crawler
    all_forms: list[FormData] = field(default_factory=list)
    all_endpoints: list[str] = field(default_factory=list)
    all_params: list[ParamData] = field(default_factory=list)
    # Attack results
    confirmed_vulns: list[Vuln] = field(default_factory=list)
```

### `Vuln` (a single vulnerability)
```python
@dataclass
class Vuln:
    name: str          # "[STATIC] XSS" or "[DYNAMIC] Reflected XSS"
    severity: str      # Critical | High | Medium | Low
    endpoint: str = "" # "frontend/src/App.tsx:340" or "http://localhost:8080/login"
    payload: str = ""  # The attack payload that worked
    confirmed: bool = False
```

### `EndpointProfile` (genome learns what "normal" looks like)
```python
@dataclass
class EndpointProfile:
    endpoint: str
    method: str                    # GET/POST
    input_fields: list[str]
    input_length_mean: float       # Average input length for this endpoint
    input_length_std: float
    input_entropy_mean: float      # Average Shannon entropy
    input_entropy_std: float
    sample_count: int
```

### `EvolutionResult` (one generation of Red vs Blue)
```python
@dataclass
class EvolutionResult:
    generation: int
    payloads_generated: int
    payloads_blocked: int
    payloads_bypassed: int
    block_rate: float              # blocked / total
    new_features_learned: list[str]
    duration_seconds: float
```

---

## 6. File-by-File Breakdown

### `cyphex_cli.py` — CLI Entrypoint
- Parses arguments: `scan --repo/--path`, `doctor`
- Sets UTF-8 encoding for Windows compatibility
- Prints ASCII banner
- Lazy-imports `CyphexEngine` from `cli_engine.py`
- Calls `asyncio.run(engine.run(...))` for scans
- Calls `engine.doctor()` for readiness checks

### `cli_engine.py` — Core Pipeline (CyphexEngine)
- **1081 lines**, the heart of CYPHEX
- Contains `CyphexEngine` class with the full 8-step pipeline
- Inline implementation of all dynamic agents (not using the agent classes from `backend/agents/` — those are for the web dashboard mode)
- Patch workflow uses local Ollama LLM for code fixes
- Judge mode: deterministic output, SARIF export

### `config.py` — Configuration
- AI backend: `local` (Ollama), `groq` (cloud), `cerebras` (legacy)
- Models: `qwen2.5-coder:7b` (local), `llama-3.3-70b-versatile` (Groq)
- Immune system: `GENOME_BLOCK_THRESHOLD=0.7`, `EVOLUTION_GENERATIONS=10`, `EVOLUTION_PAYLOADS_PER_GEN=20`
- Convergence: stops early if block rate ≥ 0.99 for 3 consecutive generations

### `sandbox_manager.py` — Sandbox Deployment
- Extracts uploaded ZIP → installs dependencies → starts the server
- Universal stack detection: reads `package.json` scripts (start, dev, start:dev)
- Auto-detects Prisma: runs `npx prisma generate` if needed
- Port patching: rewrites hardcoded `const port = 3000` to use `process.env.PORT`
- Windows-safe: `_robust_rmtree` kills stale `node.exe` processes
- Entry file detection priority: `app_standalone.js > app.js > server.js > index.js > main.js > package.json scripts`

### `behavioral_genome.py` — Blue Team Defense
- Per-endpoint anomaly detector using scikit-learn `IsolationForest`
- Extracts 9-dimensional feature vector from every input:
  1. `input_length`
  2. `entropy` (Shannon entropy)
  3. `special_char_ratio`
  4. `url_encoding_ratio`
  5. `uppercase_ratio`
  6. `digit_ratio`
  7. `max_token_length`
  8. `sql_keyword_score` (47 keywords)
  9. `sqli_pattern_score` (12 regex patterns)
- Combined scoring: `max(ml_score, heuristic_score)` + boost if both agree
- Retrain with attack history accumulation across generations

### `mutation_engine.py` — Red Team Attacker
- 8 obfuscation techniques:
  1. URL encoding (`' → %27`)
  2. Double URL encoding (`' → %2527`)
  3. Unicode escape (`< → \u003c`)
  4. Hex encoding (`'admin' → 0x61646d696e`)
  5. Comment injection (`SELECT → SEL/**/ECT`)
  6. Case mutation (`or → oR`)
  7. Whitespace substitution (`space → %09`)
  8. CONCAT split (`'admin' → CONCAT('ad','min')`)
- 28 base payloads: 10 SQLi + 10 XSS + 8 CMDi
- Smart mutation: reads genome feedback (which features triggered blocking) and applies targeted evasion
- Optional LLM-powered mutation via Ollama/Groq

### `evolution_controller.py` — The Loop
- Generation 0: Build genome + generate initial payloads
- Generation 1..N: Score payloads → blocked/bypassed → Blue retrains on bypassed → Red mutates blocked → repeat
- Convergence: stops at ≥99% block rate for 3 gens
- Emits progress events for real-time dashboard

---

## 7. The Immune System (Core Innovation)

```
┌──────────────────────────────────────────────────────────────┐
│                    GENERATION 0                               │
│  Red: Generate 30 raw payloads (SQLi + XSS + CMDi)          │
│  Blue: Build profiles from crawled endpoints                 │
│  Score: 70% block rate (baseline)                            │
├──────────────────────────────────────────────────────────────┤
│                    GENERATION 1                               │
│  Red: Take BLOCKED payloads → mutate (URL encode, case mix) │
│  Blue: Take BYPASSED payloads → retrain Isolation Forest     │
│  Score: 82% block rate                                       │
├──────────────────────────────────────────────────────────────┤
│                    GENERATION 2                               │
│  Red: Harder mutations (double encode, comment inject)       │
│  Blue: Accumulated attack history → better decision boundary │
│  Score: 91% block rate                                       │
├──────────────────────────────────────────────────────────────┤
│                    ...                                        │
├──────────────────────────────────────────────────────────────┤
│                    GENERATION N                               │
│  Score: 100% → CONVERGED → genome is hardened                │
└──────────────────────────────────────────────────────────────┘
```

### Feature Vector (9 dimensions)
Every input string is converted into a 9-number vector:
```
[length, entropy, special_ratio, url_ratio, upper_ratio, digit_ratio, max_token, keyword_score, pattern_score]
```

Example:
- `"hello world"` → `[11, 3.2, 0.09, 0, 0, 0, 5, 0, 0]` → Score: 0.0 → ALLOWED
- `"' OR 1=1--"` → `[11, 3.1, 0.36, 0, 0.09, 0.18, 4, 0.5, 0.5]` → Score: 0.95 → BLOCKED

### Scoring Formula
```python
combined = max(ml_score, heuristic_score)
if ml_score > 0.3 and heuristic > 0.3:
    combined = min(1.0, combined + 0.15)  # Bonus for agreement
if combined >= 0.7:  # GENOME_BLOCK_THRESHOLD
    verdict = "BLOCKED"
```

---

## 8. The Sandbox Manager

The sandbox manager handles deploying **any** web application:

### Universal Stack Support
```python
# Entry file detection order:
1. Direct files: app_standalone.js, app.js, server.js, index.js, main.js
2. package.json scripts:
   - "start:dev" → npm run start:dev  (NestJS)
   - "dev"       → npm run dev        (Vite/Next.js)
   - "start"     → npm run start      (Express)
3. package.json "main" field
4. Glob *.js files
```

### Auto-Prisma Detection
```python
# If prisma is in dependencies:
deps = {**pkg.get("dependencies",{}), **pkg.get("devDependencies",{})}
if "prisma" in deps:
    await _run_cmd("npx prisma generate", ...)
```

### Port Patching
Rewrites hardcoded ports so the sandbox uses the dynamically assigned port:
```javascript
// Before:
const port = 3000;
// After:
const port = parseInt(process.env.PORT) || 54321;
```

### Offline Mode Fallback
If nothing works → returns `"offline_mode"` → pipeline skips dynamic scan but still patches static findings.

---

## 9. AI / LLM Integration

CYPHEX uses AI in two places:

### 1. Patch Generation (Step 8)
```python
# Sends to Ollama (local):
POST http://localhost:11434/api/generate
{
    "model": "qwen2.5-coder:7b",
    "prompt": "You are a secure code patch assistant. Return JSON: {unsafe_reason, fixed_code, patch_safety}",
    "stream": false
}
```

### 2. Red Team Mutation (Optional)
```python
# Can use Ollama or Groq for adaptive payload generation:
# Sends blocked payloads + genome feedback → gets evasion variants
```

### LLM Fallback Chain
```
1. Try Ollama (local) → if fail →
2. Try Groq (cloud, free) → if fail →
3. Use heuristic/string-manipulation fallback
```

---

## 10. Frontend Dashboard

A React + Vite + TypeScript dashboard for visual scan monitoring:

- **Overview:** Real-time scan progress, agent status
- **Modules:** Per-agent findings with evidence
- **Report:** Security score, vulnerability table, evolution chart
- **Sandbox:** Upload ZIP, deploy, manage running instances

Communicates with the backend via:
- REST API (`/api/scan/start`, `/api/scan/status`)
- WebSocket (`/ws/logs`) for real-time log streaming

---

## 11. IoT Edge Module

Hardware extension for running CYPHEX on a Raspberry Pi / ESP32:

- `wokwi_main.py`: MicroPython firmware with LED status indicators
- `iot_serial_bridge.py`: Bridges USB serial from ESP32 to the main scanner
- `wokwi_diagram.json`: Wokwi simulator circuit for testing without hardware

---

## 12. Dependencies & Setup

### Python Requirements
```
httpx>=0.27.0          # Async HTTP client (for scanning + LLM calls)
fastapi>=0.115.0       # Web API framework (dashboard mode)
uvicorn[standard]>=0.30.0  # ASGI server
websockets>=12.0       # WebSocket support
numpy>=1.26.0          # Feature vectors
scikit-learn>=1.4.0    # Isolation Forest (ML anomaly detection)
joblib>=1.3.0          # Model serialization
```

### System Requirements
```
Python 3.12+
Node.js 18+ (for sandbox deployment)
Git (for cloning repos)
Ollama (for local LLM — optional but needed for patching)
```

### Quick Setup
```bash
# 1. Install Python deps
pip install httpx numpy scikit-learn joblib

# 2. Install Ollama + model (for patching)
# Download from https://ollama.ai
ollama pull qwen2.5-coder:7b

# 3. Run a scan
python cyphex_cli.py scan --repo https://github.com/user/repo
```

---

## 13. CLI Usage

```bash
# Scan a GitHub repo
python cyphex_cli.py scan --repo https://github.com/user/repo

# Scan a local directory
python cyphex_cli.py scan --path ./my-app

# Scan with specific branch
python cyphex_cli.py scan --repo https://github.com/user/repo --branch develop

# Scan with more evolution generations
python cyphex_cli.py scan --repo https://github.com/user/repo --generations 20

# Skip patching
python cyphex_cli.py scan --repo https://github.com/user/repo --no-patch

# Non-interactive (auto-apply patches)
python cyphex_cli.py scan --repo https://github.com/user/repo --non-interactive

# Judge mode (deterministic, exports SARIF)
python cyphex_cli.py scan --path ./target --judge

# Save report to file
python cyphex_cli.py scan --repo https://github.com/user/repo --output report.json

# Check system readiness
python cyphex_cli.py doctor
```

---

## 14. Key Algorithms Explained

### Shannon Entropy
Measures randomness of a string. Normal text ≈ 3.0-4.0. Encoded/obfuscated attacks ≈ 4.5-6.0.
```python
def _shannon_entropy(text):
    freq = Counter(text)
    length = len(text)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())
```

### Isolation Forest (scikit-learn)
Unsupervised ML model that learns "normal" patterns. Anything statistically different = anomaly.
- Trained on synthetic "normal" samples (random alphanumeric strings)
- Low contamination (0.01-0.4) so it learns the normal distribution
- Inference: `decision_function()` returns anomaly score (lower = more anomalous)
- Mapped to 0-1 scale: `ml_score = max(0, min(1, 0.5 - raw_score))`

### Heuristic Scoring
Pattern-matching rules that catch attacks the ML might miss:
```
Length > 100     → +0.2
Length > 500     → +0.3
Entropy > 4.0   → +0.2
Entropy > 5.0   → +0.3
Special > 30%   → +0.2
URL encoding     → +0.15
SQL keywords     → +0.3 to +0.5
Regex patterns   → +0.5 to +0.8
```

### Security Score Formula
```python
score = max(0, 100 - critical*25 - high*10 - medium*5 - low*1)
```
- 100 = no vulnerabilities
- 0 = catastrophic (4+ critical vulns)

---

## Summary

CYPHEX is built from 5 core systems:
1. **CLI Pipeline** (`cyphex_cli.py` + `cli_engine.py`) — the 8-step orchestrator
2. **Static Analyzer** (regex patterns in `cli_engine.py`) — finds code-level vulns
3. **Sandbox Manager** (`sandbox_manager.py`) — deploys any web app locally
4. **Dynamic Agents** (inline in `cli_engine.py`) — attack the live app
5. **Immune System** (`behavioral_genome.py` + `mutation_engine.py` + `evolution_controller.py`) — adversarial co-evolution

Everything flows through `ScanContext` → agents write findings → genome trains → report generates → patches apply.
