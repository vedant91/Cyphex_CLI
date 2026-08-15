# CYPHEX — HACK4HUMANITY 2026 (JCTS) · Round-1 Delivery Deck

> 6 slides for the Round-1 solution document / pitch. The 6 slides map **1:1** to
> the workshop's required *"Six Blocks Every Strong Submission Has"* (deck p.20),
> so every slide is aimed at rubric points, not just description.

---

## AUDIT — read before you build the deck

**Alignment to the brief (what the judges score):**

| Rubric item | Points | Which slide carries it |
|---|---|---|
| Problem Clarity & Relevance | 25 | Slide 1 |
| Innovation & Novelty | 25 | Slide 1 + 2 |
| Technical Feasibility | 20 | Slide 2 |
| Theme Alignment | 20 | Slide 1 (pillar) + Slide 3 (ethics) |
| Presentation Clarity | 10 | all |
| **Qualify** | **≥60/100** | Problem+Innovation alone = 50 |

**Pillar anchor — pick ONE (the brief says "don't try to cover all"):**
- **Recommended: T — Threat Modelling.** CYPHEX's swarm of offensive agents is a
  near-verbatim match to the pillar text: *"adversarial simulation — AI-driven
  attack-chain generation with purple-team feedback loops … proactively uncover
  security weaknesses, prioritize remediation."*
- **Adjacent strength: C — Cyber Resilience** (the Immune System / self-heal /
  RASP daemon = *"withstand, recover from, and adapt to evolving threats"*).
  Mention it as a bridge, but anchor on **T**.

**Must-fix before submitting (judges will notice these):**
1. **Agent count is inconsistent.** The architecture PNG says *"20 DeepAgents"*
   but lists **"Network Agent" twice** (so 19 unique), and commit `c5398ab` says
   *"10 agents."* Make the number identical across the diagram, README, deck, and
   code. Recommend: dedupe to one **Network Agent**, state the honest count.
2. **Ethics framing must lead, not trail.** A judge who sees *"DDoS Agent",
   "RCE Agent"* will immediately test you against Section 2 (*"no scanning /
   probing of live networks — disqualification"*). Pre-empt it on Slide 3:
   everything runs **only inside the isolated Docker sandbox, against the user's
   own code.** Consider relabeling *"DDoS Agent" → "DoS-Resilience Test"*.
3. **Docker must be running for the live demo.** The real run log shows
   *"Docker not found → sandbox deployment failed → dynamic scan skipped."* Have
   Docker up for the DAST/sandbox path, or a recorded fallback.
4. **Round-2 originality rule (strategic, flag now).** Round 1 explicitly wants
   *an existing repo + pitch video* — CYPHEX fits perfectly. But the **12-hr
   Finale forbids pre-existing codebases.** Plan a *new CYPHEX module you build
   on-site* (e.g. a new attack agent, or the federated zero-day genome-sharing
   feature) so you're compliant in Round 2. Decide this before 15 July.

---

## SLIDE 1 — Idea & Approach  *(Block 1 · Problem Clarity 25 + Innovation 25)*

**Title:** CYPHEX — an autonomous purple-team that ships secure code, offline.

Answer the four Block-1 questions in order:

- **Who is harmed today?** Solo developers and 2–5-person startup teams shipping
  **AI-generated ("vibe-coded") applications** with no security engineer and no
  budget for a pentest. They merge code with SQLi, XSS, RCE, and leaked secrets
  that *no human ever reviews.*
- **What's the current gap?** SAST (Semgrep/Snyk/SonarQube) only *flags* and is
  noisy; DAST/pentest is expensive, slow, and cloud-bound; Copilot Autofix
  *suggests* fixes but never **proves the vuln or verifies the fix.** Nothing
  closes the loop, and nothing runs **local-first / offline.**
- **What's your core idea (1–2 sentences)?** CYPHEX is an autonomous security
  team inside your CLI: it **finds → proves by exploiting in an isolated sandbox
  → patches → verifies the patch defeats the exploit → pushes** — plus an
  adaptive *Immune System* that generalizes its defense to unseen (zero-day)
  attacks.
- **Why now / why us?** AI code-gen exploded the volume of unreviewed code;
  local LLMs (Ollama) now make offline autonomous reasoning feasible; **we've
  already built and run the full loop** (see Slide 5).

**Novelty line (say it out loud):** *"Every existing tool stops at 'here's a
problem.' CYPHEX is the first local-first agent that proves it, fixes it,
verifies the fix, and opens the PR — with no code or data leaving your machine."*

---

## SLIDE 2 — Tech Stack & Methodology  *(Block 2 · Technical Feasibility 20)*

**Title:** How the pieces connect (not a tool list — a closed loop).

**The pipeline (left→right, straight from the architecture diagram):**

1. **Ingest** — GitHub webhook server / `cyphex` CLI / local directory.
2. **Sandbox** — Docker container environment + Android emulator (ADB). *Isolation is the product's ethics guarantee.*
3. **Detect (SAST + DAST)** — CYPHEX SAST → **Semgrep (5,000+ rules)**; CYPHEX
   DAST → **Nuclei (8,000+ templates)**; **Android SAST** (Manifest Analyzer,
   19 Kotlin/Java rules, XML config scanner).
4. **Memory** — **cognee** knowledge-graph layer feeds context across stages.
5. **Attack** — **DeepAgents swarm** running an **OODA loop
   (Observe → Think → Adapt → Attack)**: SQLi, XSS, RCE, SSRF, GraphQL, Prompt-
   Injection, Auth, Logic, Crypto, TLS/SSL, DNS, Cloud, Container, File-upload,
   AI-fuzzer, Android security/storage, Network. *(Confirm final count.)*
6. **Immune System** — **Behavioral Genome (stops zero-day)** + **Mutation
   Engine** + **Extended 21-D Feature Vector** = adaptive detection that
   generalizes beyond signatures.
7. **Patch** — **Vectorless RAG** (Code Indexer, Security KB, Route Tracer, Patch
   Memory) + **Oracle reasoning layer** (Chain-of-Thought, ReAct, Tree-of-Thought,
   Metacognitive Monitoring, Hypothesis-driven testing) + **session memory** →
   **multi-model patch generation** → **✅ verify** → **push the change.**

**Methodology (maps to the brief's Define→Acquire→Build→Validate→Harden):**
scope + success metric → pull benchmark/own-repo data → run core find→patch loop
→ validate patch against the reproduced exploit → immune-system hardening pass.

**Feasibility proof:** local-first (Ollama), offline-capable, multi-model Oracle,
already runs end-to-end today.

---

## SLIDE 3 — Dataset Operation  *(Block 3 · Ethics + Theme Alignment)*

**Title:** Real data, sandbox-only — zero live-network risk.

- **What data:** the user's **own source repos**, **intentionally-vulnerable
  benchmark apps** (our `vuln-webapp`, OWASP-style targets), a **CWE Knowledge
  Base**, and the **Semgrep / Nuclei** public rule/template corpora. All
  **self-owned, synthetic, or public** — nothing scraped from live services.
- **Source → Document → Process → Disclose** (the brief's 4 steps): cite rule
  corpora + benchmark licenses in the README; feature-engineer the 21-D vector on
  labelled benign/malicious payloads; state clearly what's real vs. synthetic.
- **★ Ethical-constraint alignment (Section 2 — say this explicitly):** *All
  offensive activity executes exclusively inside an isolated Docker sandbox,
  against code the user owns. CYPHEX never scans, probes, or tests live external
  networks, cloud services, or event infrastructure.* This is enforced by
  architecture (sandbox creation is a required pipeline stage), not policy.

---

## SLIDE 4 — Future Scope & Analysis  *(Block 4 · Scalability / Real-World Feasibility)*

**Title:** From CLI demo to a security layer teams actually ship on.

- **Day 1 (demo):** full find → patch → verify loop on `vuln-webapp`, offline.
- **Month 1–3:** ship the **GitHub App** (webhook server already built) so CYPHEX
  runs on every PR in CI/CD; **pilot** with one real partner — a student dev team
  or a local MSME shipping AI-generated code.
- **Beyond:** promote the **Immune System to a runtime RASP daemon** (`cx watch`)
  for production self-healing; grow the agent library; **federated zero-day
  genome sharing** across CYPHEX nodes (this is the bridge into Pillar J — Joint
  Intelligence — if you later expand); SOC-2 / compliance pathway.

---

## SLIDE 5 — Benefits & Results  *(Block 5 · quantify, honestly)*

**Title:** Measured, not claimed. (Real run: scan `cli_a9958419`, `vuln-webapp`.)

**Immune-System benchmark (21-D vector vs. a naive baseline WAF):**

| Payload | Baseline | CYPHEX | Score |
|---|---|---|---|
| SQLi auth-bypass `' OR '1'='1' --` | ALLOWED | **BLOCKED** | 1.00 |
| SQLi UNION | ALLOWED | **BLOCKED** | 1.00 |
| XSS `<script>` | ALLOWED | **BLOCKED** | 1.00 |
| XSS event-handler | ALLOWED | **BLOCKED** | 1.00 |
| CMDi `; whoami` | ALLOWED | **BLOCKED** | 0.50 |
| CMDi `| cat /etc/passwd` | ALLOWED | **BLOCKED** | 0.60 |
| LFI `../../etc/passwd` | ALLOWED | **BLOCKED** | 1.00 |
| SSRF `169.254.169.254` | ALLOWED | ALLOWED *(miss)* | 0.10 |
| 4× benign (search, "John O'Brien", email, number) | ALLOWED | **ALLOWED** ✓ | 0.00 |

- **Benchmark (`cx benchmark`, 76-sample labelled corpus, 9 attack classes):**
  **recall 91.3% · precision 97.7% · F1 94.4% · false-positive rate 3.3%**,
  ~0.04 ms/sample, fully offline. Reproducible → `benchmark_report.json`.
- **Before → after hardening (the honest story judges love):** the benchmark
  first exposed blind spots (SSTI/NoSQLi/SSRF/LDAPi at 0–20%); we added the
  missing detection patterns and **recall jumped 60.9% → 91.3% with no new false
  positives.** Define → Validate → Harden, measured.
- **Detection: blocks 7 / 8 attack payloads; 0 / 4 false positives** on the
  original demo set — including the apostrophe name that breaks naive regex
  WAFs. Residual misses (bare `admin'--`, Windows-path traversal) shown openly.
- **Static findings:** confirmed **2 × High, CWE-200 (Sensitive Data Exposure)**
  at `src/server.js:47` and `src/routes/admin.js:8` — mapped to OWASP + CWE.
- **Patch engine:** Vectorless RAG (function-extract + CWE-KB + repo examples) +
  **Reflexion loop** (evidence-fed retry, up to 3 rounds).
- **For the beneficiary:** replaces a paid pentest / manual review for a team of
  0 security engineers — **free, offline, minutes not weeks.**
- **For the sector:** the same loop generalizes to any repo — 50+ small teams
  could adopt it unchanged.

---

## SLIDE 6 — Outcomes Expected  *(Block 6 · concrete Round-2 checklist)*

**Title:** What will exist at the demo — named, not aspirational.

1. **Working prototype** — the `cx` CLI: `cx scan <repo|url>`, `cx deep` (full
   DeepAgents + sandbox), `cx watch` (RASP daemon), `cx doctor` — running the core
   detect → exploit → patch → verify → push loop **live, offline.**
2. **Documented GitHub repo** — README, the architecture diagram, clear commit
   history, open-source license.
3. **A measurable result** — *"Immune System: 91.3% recall / 3.3% FPR across 9
   attack classes (`cx benchmark`, reproducible JSON); confirms + locates 2
   High-severity CWE-200 exposures; auto-generates a verified patch."*
4. **A clear next step** — pilot with one named partner (a student dev team / MSME)
   and ship the PR-time GitHub App.

**Closing line:** *"CYPHEX gives every developer without a security team an
autonomous one — that finds the bug, proves it, fixes it, and never lets your
code leave your machine."*

---

### Speaker-note reminders
- Lead with the **beneficiary + gap** (25+25 pts hinge on Slide 1).
- Foreground **sandbox-only ethics** early — it's a disqualifier if unclear.
- Use the **real 7/8 table** — honest numbers beat superlatives to this jury.
- State **one pillar (T)**; don't sprawl across all four.
