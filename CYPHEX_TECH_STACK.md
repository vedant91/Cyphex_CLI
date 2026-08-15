# CYPHEX — Tech Stack

> **One-liner (title banner):**
> *Agentic, local-first cyber-defense — a multi-model LLM Oracle over a Hybrid
> GraphRAG memory, an evolutionary Immune System, and a sandboxed autonomous
> agent swarm. Offline-capable. Zero data egress.*

---

## The stack, by layer

| # | Layer | Buzzword headline | Built with (real) |
|---|---|---|---|
| 1 | **Interface & Orchestration** | Agentic CLI · event-driven ingestion | `cx` REPL (Rich TUI), GitHub App / webhook server, Git-native triggers |
| 2 | **Reasoning — the Oracle** | Multi-model LLM ensemble · agentic reasoning | Local **Ollama** inference · DeepSeek + Mistral routing · **ReAct · Tree-of-Thought · Chain-of-Thought · Reflexion · metacognitive monitoring** |
| 3 | **Memory & Retrieval** | **Hybrid GraphRAG** · Vectorless-first + dense vector search | **cognee** knowledge-graph memory · **Vectorless RAG** (Code Indexer, Security KB, Route Tracer, Patch Memory) · **embedded vector store: LanceDB / pgvector / Qdrant** · session memory (thread-id) |
| 4 | **Detection Engine** | Unified SAST + DAST + behavioral IAST | **Semgrep** (5k rules) · **Nuclei** (8k templates) · Android SAST · **21-D behavioral feature vector** |
| 5 | **Offensive Swarm** | Autonomous multi-agent red team · OODA loop | **DeepAgents** framework · 18+ specialised agents (SQLi, XSS, RCE, SSRF, GraphQL, Prompt-Injection, …) |
| 6 | **Adaptive Immune System** | Evolutionary self-healing · zero-day generalization | **Behavioral Genome** · **Mutation Engine** (genetic/evolutionary) · anomaly-scoring WAF |
| 7 | **Execution & Isolation** | Sandboxed, ephemeral, zero-trust runtime | **Docker** micro-sandbox · **Android emulator (ADB)** · sandbox-only enforcement |
| 8 | **Knowledge Base** | Curated threat intelligence corpus | **CWE Knowledge Base** · OWASP mappings · Patch Memory store |

---

## Buzzword bank (all defensible — every term maps to something you actually run)

**Agentic AI · Multi-agent orchestration · Autonomous OODA loop · Multi-model
LLM ensemble · Local-first / edge inference · Zero data egress · Hybrid GraphRAG
· Vectorless RAG · Knowledge-graph memory · Semantic (dense) vector retrieval ·
Reflexion self-correction · Tree-of-Thought reasoning · Metacognitive monitoring
· RASP (Runtime Application Self-Protection) · Behavioral Genome · Evolutionary
Mutation Engine · 21-D behavioral feature vector · Unified SAST/DAST/IAST ·
Sandboxed zero-trust execution · Purple-team automation · Closed-loop
auto-remediation**

---

## Retrieval layer — say this precisely (protects you in Q&A)

CYPHEX runs **Hybrid GraphRAG**, not a naive vector-DB lookup:

- **Structured / Vectorless path (primary):** `cognee` knowledge graph +
  function-extraction + CWE-KB + repo examples → precise, explainable retrieval
  with no embedding drift. *This is the novel headline.*
- **Dense / vector path (complement):** an **embedded, offline vector store**
  — **LanceDB** (recommended: file-based, zero-infra, fully offline), or
  **pgvector** / self-hosted **Qdrant** — for semantic code-similarity and
  patch-precedent search.
- **Why not a cloud vector DB?** Pinecone / Weaviate Cloud would break CYPHEX's
  *offline / zero-egress* promise. Local vector stores keep the pitch honest.

> ⚠️ If you haven't literally wired the vector store yet, adding **LanceDB** is a
> half-day task and makes "Hybrid GraphRAG" fully true — worth doing before the
> demo so the buzzword survives a judge asking *"which vector DB, and does it
> leave the machine?"*

---

## Slide-ready condensed version (for the deck)

**REASON** Ollama · multi-model Oracle · ReAct / ToT / Reflexion
**REMEMBER** Hybrid GraphRAG — cognee KG + LanceDB vector store
**DETECT** Semgrep · Nuclei · Android SAST · 21-D vector
**ATTACK** DeepAgents swarm · OODA loop · 18+ agents
**DEFEND** Behavioral Genome · Mutation Engine (evolutionary)
**ISOLATE** Docker sandbox · Android emulator · zero-egress

*Everything local-first. Nothing leaves your machine.*
