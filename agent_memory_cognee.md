# 🧠 Agent Memory with Cognee — Updated Architecture

## Correction: We USE Cognee

Since the hackathon requires Cognee for agent memory, the architecture changes. The **good news**: Cognee supports Ollama natively, so it CAN run 100% locally. We keep the offline-first promise.

---

## How Cognee Fits Into Cyphex

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CYPHEX SCAN ENGINE                           │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ Agent 02     │  │ Agent 03     │  │ Agent 09     │  ... (×14)  │
│  │ Crawler      │  │ SQLi         │  │ IDOR         │             │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │
│         │                 │                 │                       │
│         ▼                 ▼                 ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   COGNEE MEMORY LAYER                       │   │
│  │                                                             │   │
│  │   remember()  →  Ingest findings into knowledge graph       │   │
│  │   cognify()   →  Extract entities, build relationships      │   │
│  │   recall()    →  Query graph for relevant context           │   │
│  │   forget()    →  Clean stale data between targets           │   │
│  │                                                             │   │
│  │   Storage: Local LanceDB (vectors) + NetworkX (graph)       │   │
│  │   LLM:     Ollama (llama3.1:8b) — entity extraction         │   │
│  │   Embeddings: Ollama (nomic-embed-text) — semantic search   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│         │                 │                 │                       │
│         ▼                 ▼                 ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              ORACLE REASONING ENGINE                         │   │
│  │   Patch gen gets: Cognee context + Oracle reasoning          │   │
│  │   16 cognitive architectures × rich memory = smart patches   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Cognee Configuration for Cyphex

```env
# .env — Cognee configured for 100% local operation via Ollama
LLM_PROVIDER=ollama
LLM_MODEL=ollama/llama3.1
LLM_ENDPOINT=http://localhost:11434

EMBEDDING_PROVIDER=ollama
EMBEDDING_MODEL=ollama/nomic-embed-text
EMBEDDING_ENDPOINT=http://localhost:11434

# Skip connection tests for faster startup
COGNEE_SKIP_CONNECTION_TEST=true
```

Required models:
```bash
ollama pull llama3.1       # For entity extraction + reasoning
ollama pull nomic-embed-text  # For embedding (lightweight, CPU-friendly)
```

---

## The Three Memory Operations in Cyphex

### 1. `remember()` — Agents Write Findings

Each agent calls `cognee.remember()` to store its discoveries in the knowledge graph:

```python
# Agent 02 (Crawler) writes what it found
await cognee.remember(
    text=f"""
    SECURITY SCAN DISCOVERY:
    Target: {target_url}
    Agent: Crawler (Agent 02)
    Discovery Type: API Endpoint
    Endpoint: GET /api/users/search
    Parameters: q (string, user input)
    Response: JSON array of user objects
    Technology: Express.js with CORS enabled
    Auth Required: No
    Risk Assessment: Accepts unvalidated user input — potential injection point
    """,
    dataset_name=f"scan_{scan_id}"
)
```

```python
# Agent 03 (SQLi) writes a confirmed finding
await cognee.remember(
    text=f"""
    CONFIRMED VULNERABILITY:
    Agent: SQLi Agent (Agent 03)
    CWE: CWE-89 (SQL Injection)
    Endpoint: GET /api/users/search?q=
    Payload: ' OR '1'='1
    Evidence: SQL error keyword "sqlite_master" found in response body
    Severity: Critical
    MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
    Source File: src/routes/users.js (line 18)
    Vulnerable Pattern: db.query(`SELECT * FROM users WHERE name LIKE '%${{q}}%'`)
    Recommended Fix: Use parameterized query with ? placeholder
    """,
    dataset_name=f"scan_{scan_id}"
)
```

### 2. `cognify()` — Build the Knowledge Graph

After agents finish writing, Cognee processes all memories into a connected graph:

```python
# After all 14 agents have written their findings
await cognee.cognify()

# Cognee now has a graph like:
#
#   /api/users/search ──[vulnerable_to]──> CWE-89 (SQL Injection)
#                     ──[accepts_param]──> q (string, user input)
#                     ──[served_by]────> src/routes/users.js
#                     ──[uses_tech]────> Express.js
#   
#   CWE-89 ──[maps_to]──> T1190 (MITRE ATT&CK)
#          ──[fixed_by]──> Parameterized Query Pattern
#          ──[found_by]──> Agent 03 (SQLi)
#
#   src/routes/users.js ──[also_contains]──> CWE-78 (CMDi on line 45)
#                        ──[imports]──────> express, sqlite3
```

### 3. `recall()` — Query Memory for Context

Agents and the patch engine query Cognee for context:

```python
# Agent 09 (IDOR) queries: "What endpoints have ID parameters?"
results = await cognee.recall(
    query_text="Which API endpoints accept user ID parameters and have been confirmed as live?"
)
# Cognee returns: /api/users/profile/:id, /api/orders/:orderId
# Agent 09 now knows EXACTLY where to test for IDOR

# Patch engine queries: "How should I fix CWE-89 in this codebase?"
results = await cognee.recall(
    query_text="What is the secure coding pattern for SQL queries in this Express.js application? Show parameterized query examples."
)
# Cognee returns: existing secure patterns from the codebase + CWE knowledge
```

---

## What Each Agent Writes to Cognee

| Agent | What It `remember()`s | Tags/Entities Cognee Extracts |
|-------|----------------------|------------------------------|
| **02 Crawler** | Discovered pages, endpoints, response types | Endpoint, Technology, Parameter |
| **02b API Disc** | Live API routes with params and methods | Route, Parameter, Method, DataType |
| **03 SQLi** | Confirmed SQLi + payload + evidence | Vulnerability, CWE-89, Payload, Endpoint |
| **04 XSS** | Confirmed XSS + reflected payload | Vulnerability, CWE-79, Payload |
| **05 Auth** | Weak creds, JWT analysis, session issues | Credential, JWT, AuthMechanism |
| **06 CMDi** | Command injection + shell evidence | Vulnerability, CWE-78, Command |
| **07 LFI** | Path traversal + accessed files | Vulnerability, CWE-22, FilePath |
| **09 IDOR** | Sequential ID access + auth bypass | Vulnerability, CWE-284, IDParameter |
| **10 SSRF** | Internal service access | Vulnerability, CWE-918, InternalURL |
| **11 Supply** | CVE in dependencies | CVE, Package, Version |
| **12 Data Exp** | Debug info, env leaks | DataExposure, ConfigLeak |
| **14 JWT** | Token weaknesses | JWT, Algorithm, Secret |
| **Patcher** | Applied fix + verification result | Fix, CWE, Pattern, Verified |

## What Each Agent Reads via `recall()`

| Agent | What It `recall()`s | Why |
|-------|---------------------|-----|
| **03 SQLi** | "What endpoints accept user input parameters?" | Knows WHERE to test |
| **04 XSS** | "What endpoints return HTML with reflected params?" | Knows WHERE to test |
| **05 Auth** | "Is there a login endpoint? What auth mechanism?" | Targets auth testing |
| **06 CMDi** | "What endpoints accept format, cmd, exec params?" | Targeted CMDi testing |
| **07 LFI** | "What endpoints accept file or path parameters?" | Targeted LFI testing |
| **09 IDOR** | "What endpoints have :id params and were confirmed live?" | Targeted IDOR testing |
| **10 SSRF** | "What endpoints accept URL or callback parameters?" | Targeted SSRF testing |
| **14 JWT** | "What auth mechanism is used? JWT secret found?" | Knows JWT context |
| **Patcher** | "What fix patterns worked for this CWE in this codebase?" | Grounded patches |
| **Patcher** | "What secure patterns already exist in this repo?" | Consistent style |

---

## Document Ingestion — Security Knowledge Base

Before the scan starts, we ingest security knowledge into Cognee so agents have expert context:

```python
async def ingest_security_knowledge():
    """Load security knowledge into Cognee's graph ONCE on first run."""
    
    # 1. CWE Database (top 25 most dangerous)
    await cognee.remember(
        text="""
        CWE-89: SQL Injection. Occurs when user input is concatenated into SQL queries 
        without parameterization. Fix: Use prepared statements with ? placeholders.
        Severity: Critical. MITRE: T1190. Common in: PHP, Node.js, Python, Java.
        
        CWE-78: OS Command Injection. Occurs when user input is passed to shell commands
        (exec, system, execSync). Fix: Use execFile with argument arrays, never concat.
        Severity: Critical. MITRE: T1059. Common in: Node.js, Python, PHP.
        
        CWE-79: Cross-Site Scripting. Occurs when user input is reflected in HTML without
        encoding. Fix: HTML-encode all output, use CSP headers.
        Severity: High. MITRE: T1189. Common in: all web frameworks.
        ...
        """,
        dataset_name="security_knowledge"
    )
    
    # 2. OWASP Top 10 mapping
    await cognee.remember(
        text="""OWASP Top 10 2024 mapping to CWEs:
        A01 Broken Access Control → CWE-284, CWE-287, CWE-306, CWE-862
        A02 Cryptographic Failures → CWE-798, CWE-327, CWE-328
        A03 Injection → CWE-89, CWE-78, CWE-79, CWE-918
        ...""",
        dataset_name="security_knowledge"
    )
    
    # 3. MITRE ATT&CK technique descriptions
    await cognee.remember(
        text="""MITRE ATT&CK Web Application Techniques:
        T1190 Exploit Public-Facing Application: Adversary exploits a vulnerability
        in an internet-facing application (SQLi, XSS, CMDi) to gain initial access.
        T1059 Command and Scripting Interpreter: Adversary executes commands via 
        shell interpreters to interact with the system...
        ...""",
        dataset_name="security_knowledge"
    )
    
    # Build the knowledge graph
    await cognee.cognify()
```

**Result:** When Agent 03 finds a SQLi, the patcher can `recall()` the full CWE-89 description, OWASP classification, MITRE ATT&CK mapping, AND the repo's own secure patterns — all from one query.

---

## Integration Module: `backend/reasoning/cognee_memory.py`

```python
"""
CYPHEX × Cognee — Agent Memory Bridge

Wraps Cognee's remember/recall/cognify API for use by Cyphex agents.
Configures Cognee for 100% local operation via Ollama.

Usage:
    memory = CyphexMemory(scan_id="scan_abc123")
    await memory.agent_remember("agent_03", "SQLi confirmed on /api/users", {...})
    context = await memory.agent_recall("What endpoints accept user input?")
    await memory.build_graph()  # cognify
"""

import cognee
import os
from typing import Optional

class CyphexMemory:
    """Cognee-powered memory layer for Cyphex agents."""
    
    def __init__(self, scan_id: str, target_url: str = ""):
        self.scan_id = scan_id
        self.target_url = target_url
        self.dataset = f"cyphex_scan_{scan_id}"
        self._initialized = False
    
    async def initialize(self):
        """Configure Cognee for local Ollama operation."""
        if self._initialized:
            return
        # Cognee reads from env vars — ensure they're set
        os.environ.setdefault("LLM_PROVIDER", "ollama")
        os.environ.setdefault("LLM_MODEL", "ollama/llama3.1")
        os.environ.setdefault("LLM_ENDPOINT", "http://localhost:11434")
        os.environ.setdefault("EMBEDDING_PROVIDER", "ollama")
        os.environ.setdefault("EMBEDDING_MODEL", "ollama/nomic-embed-text")
        os.environ.setdefault("EMBEDDING_ENDPOINT", "http://localhost:11434")
        self._initialized = True
    
    async def agent_remember(self, agent_id: str, finding_type: str, 
                              content: str, metadata: dict = None):
        """Agent writes a finding to Cognee memory."""
        await self.initialize()
        
        # Structure the memory entry for better graph extraction
        structured = f"""
CYPHEX AGENT MEMORY ENTRY
Agent: {agent_id}
Scan: {self.scan_id}
Target: {self.target_url}
Type: {finding_type}
Content: {content}
"""
        if metadata:
            for k, v in metadata.items():
                structured += f"{k}: {v}\n"
        
        await cognee.remember(text=structured, dataset_name=self.dataset)
    
    async def agent_recall(self, query: str, limit: int = 5) -> list:
        """Agent queries Cognee memory for relevant context."""
        await self.initialize()
        results = await cognee.recall(query_text=query)
        return results[:limit] if results else []
    
    async def recall_for_prompt(self, query: str, max_chars: int = 1500) -> str:
        """Get recall results formatted for LLM prompt injection."""
        results = await self.agent_recall(query)
        if not results:
            return ""
        
        parts = ["=== AGENT MEMORY (from Cognee knowledge graph) ==="]
        char_count = 0
        for r in results:
            text = getattr(r, 'text', str(r))
            if char_count + len(text) > max_chars:
                break
            parts.append(text)
            char_count += len(text)
        parts.append("=== END AGENT MEMORY ===\n")
        return "\n".join(parts)
    
    async def build_graph(self):
        """Process all remembered data into knowledge graph."""
        await self.initialize()
        await cognee.cognify()
    
    async def reset(self):
        """Clear memory for a fresh scan."""
        await self.initialize()
        await cognee.forget(everything=True)
    
    async def ingest_security_kb(self):
        """Load CWE/OWASP/MITRE knowledge (run once)."""
        await self.initialize()
        # Check if already ingested
        test = await cognee.recall(query_text="CWE-89 SQL Injection")
        if test:
            return  # Already loaded
        
        # ... ingest CWE DB, OWASP Top 10, MITRE ATT&CK ...
        await cognee.cognify()
```

---

## Scan Pipeline with Cognee

```
SCAN START
  │
  ├── Initialize CyphexMemory(scan_id)
  │     └── Configure Cognee for Ollama
  │
  ├── Ingest security KB (CWE, OWASP, MITRE) — if not already done
  │
  ├── Agent 02 (Crawler)
  │     └── memory.agent_remember("agent_02", "DISCOVERY", "Found /api/users ...")
  │
  ├── memory.build_graph()  ← cognify after crawler (others need this context)
  │
  ├── Agent 03 (SQLi)
  │     ├── context = memory.agent_recall("endpoints with user input parameters")
  │     ├── ... tests endpoints from context ...
  │     └── memory.agent_remember("agent_03", "FINDING", "SQLi on /api/users ...")
  │
  ├── Agent 04-14 (same pattern: recall → test → remember)
  │
  ├── memory.build_graph()  ← cognify after all agents
  │
  ├── Patch Generation
  │     ├── context = memory.recall_for_prompt("fix pattern for CWE-89 in Express")
  │     ├── Oracle Reasoning: CoT/ToT/Reflexion with Cognee context
  │     └── memory.agent_remember("patcher", "FIX", "Applied parameterized query ...")
  │
  ├── Final memory.build_graph()  ← complete knowledge graph for this scan
  │
  └── Report (enriched with Cognee context: attack paths, entity relationships)
```

---

## Why Cognee + Cyphex = Hackathon Winner

| What Cognee Brings | What Cyphex Brings |
|--------------------|--------------------|
| Graph-vector hybrid memory | 14 specialized attack agents that GENERATE the data |
| Entity extraction + relationship mapping | CWE/OWASP/MITRE knowledge to ingest |
| Cross-session persistence | Session memory + reasoning trees for continuity |
| Semantic recall (meaning-based search) | Oracle Reasoning (16 cognitive architectures) |
| Self-hosted via Ollama | Already 100% Ollama-native |
| Knowledge graph visualization | Attack path visualization from graph data |

**The pitch:**
> "Most AI agents use Cognee to remember conversations. Cyphex uses Cognee to build a **living security knowledge graph** — where every vulnerability, attack path, fix pattern, and agent finding becomes a connected node that the system can reason over. Every scan makes the graph smarter. Every fix teaches the model. The immune system literally evolves."

---

## Dependencies to Add

```bash
pip install cognee
ollama pull nomic-embed-text   # Lightweight embedding model (~274MB)
```

Add to `pyproject.toml`:
```toml
[project.optional-dependencies]
memory = ["cognee>=0.1.0"]
```
