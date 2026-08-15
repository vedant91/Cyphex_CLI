# CYPHEX — Proposed Solution in 6 Phases

> The autonomous loop: **Ingest → Detect → Exploit → Immunise → Patch → Verify.**
> Every phase runs **local-first and offline**, and all offensive activity is
> confined to an **isolated Docker sandbox against the user's own code** — never
> live external networks (HACK4HUMANITY Section-2 compliant by architecture).

---

### Phase 1 — Ingest & Isolate
**Goal:** get the target code in, and wall it off before anything runs.

- **In:** a GitHub repo (webhook server or `cyphex` CLI), or a local directory.
- **Runs:** `cyphex doctor` (environment/model self-check) → **sandbox creation**
  → a **Docker container** + **Android emulator (ADB)** for mobile targets.
- **Out:** a fully isolated, reproducible copy of the target ready to be attacked
  safely.
- **Why it matters:** isolation is the *ethics guarantee* — the sandbox is a
  required stage, not an option, so CYPHEX can never touch live infrastructure.

### Phase 2 — Detect (SAST + DAST)
**Goal:** map every candidate weakness, statically and dynamically.

- **Runs:** **CYPHEX SAST** → Semgrep (5,000+ rules); **CYPHEX DAST** → Nuclei
  (8,000+ templates); **Android SAST** (Manifest Analyzer, 19 Kotlin/Java rules,
  XML config scanner). Findings are written into the **cognee** knowledge graph
  as shared context.
- **Out:** a ranked candidate-vulnerability list with CWE/OWASP tags and file:line.
- **Proof:** on `vuln-webapp` this confirmed **2 × High, CWE-200 (Sensitive Data
  Exposure)** at `src/server.js:47` and `src/routes/admin.js:8`.

### Phase 3 — Exploit / Prove (DeepAgents swarm)
**Goal:** turn "possible bug" into "proven, reproducible exploit" — kill false
positives.

- **Runs:** the **DeepAgents swarm** on an **OODA loop
  (Observe → Think → Adapt → Attack)** — specialised agents for SQLi, XSS, RCE,
  SSRF, GraphQL, Prompt-Injection, Auth, Logic, Crypto, TLS/SSL, DNS, Cloud,
  Container, File-upload, AI-fuzzer, Android security/storage, Network.
- **Out:** each candidate is either **confirmed with a working exploit** (inside
  the sandbox) or discarded — so downstream patching only spends effort on real,
  demonstrable vulnerabilities.
- **Why it matters:** this is the "purple-team" step existing SAST tools skip —
  evidence, not just a warning.

### Phase 4 — Immunise (adaptive defense)
**Goal:** generalise from known exploits to *unseen* (zero-day) attacks.

- **Runs:** the **Immune System** — a **Behavioral Genome** (stops zero-day) +
  **Mutation Engine** + **Extended 21-D Feature Vector** that scores traffic by
  behaviour, not signatures.
- **Out:** a runtime shield that blocks attack *classes*, not just seen strings.
- **Proof:** vs. a naive baseline WAF it **blocked 7/8 attack payloads** (SQLi,
  XSS, CMDi, LFI) with **0/4 false positives** on benign traffic — including the
  apostrophe name "John O'Brien" that breaks regex filters; **1 honest miss**
  (SSRF), flagged as the next hardening target.

### Phase 5 — Reason & Patch (RAG + Oracle)
**Goal:** generate a correct, context-aware fix for each proven vulnerability.

- **Runs:** **Vectorless RAG** (Code Indexer, Security KB, Route Tracer, Patch
  Memory) feeds the **Oracle reasoning layer** — Chain-of-Thought, ReAct,
  Tree-of-Thought, Metacognitive Monitoring, Hypothesis-driven testing — with
  **session memory (thread-id) + context**, then **multi-model patch generation**.
- **Out:** a minimal, targeted code patch grounded in the real function + CWE
  guidance + prior patches.
- **Proof:** patch engine uses function-extract + CWE-KB + repo examples, with a
  **Reflexion loop** (evidence-fed retry, up to 3 rounds).

### Phase 6 — Verify & Push (closed loop)
**Goal:** prove the patch actually defeats the exploit, then ship it.

- **Runs:** re-run the Phase-3 exploit against the patched code; only on a clean
  pass does CYPHEX **✅ verify → push the change** (PR / commit).
- **Out:** a merged fix with the exploit that motivated it, fully documented.
- **Why it matters:** this closes the loop **no existing tool closes** — find →
  prove → fix → *re-prove the fix* → deliver, autonomously and offline.

---

**One-line summary:** *CYPHEX ingests and isolates your repo, detects weaknesses
statically and dynamically, proves them with an agent swarm, immunises against
their zero-day variants, reasons out a patch, and verifies-then-ships it — every
phase local-first, sandbox-only, and offline.*
