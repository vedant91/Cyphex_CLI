# CypheX v3 - Graphify Knowledge Graph Configuration

## Project Overview
**CypheX** is an autonomous AI-powered cybersecurity platform that operates 100% locally without API keys. It combines 5 security paradigms: SAST, DAST, AI Verdict Council, Behavioral Immune System, and Auto-Patching.

## Graph Purpose
This knowledge graph maps the complete CypheX architecture including:
- 14+ specialized attack agents
- Multi-model AI council system  
- Behavioral immune system (Red Team vs Blue Team)
- Oracle reasoning engine with 16 cognitive architectures
- Vectorless RAG system for code intelligence
- Scan orchestration and agent coordination
- REST API and WebSocket real-time communication
- Frontend dashboard integration

## Key Extraction Targets

### Core Concepts (God Nodes Expected)
- ScanOrchestrator
- BaseAgent
- ScanContext
- CouncilOrchestrator
- BehavioralGenome
- OracleAdapter
- CodeIndexer
- PatchAgent

### Major Subsystems
1. **Agent System** (14 specialized agents)
2. **Council System** (Multi-model consensus)
3. **Immune System** (Adversarial co-evolution)
4. **Reasoning Engine** (16 cognitive architectures)
5. **RAG System** (Vectorless code indexing)
6. **API Layer** (FastAPI + WebSockets)
7. **Patch Pipeline** (Verification + templates)

### Critical Relationships
- Agent inheritance from BaseAgent
- ScanContext flow through pipeline stages
- Council debate protocol
- Evolution controller Red/Blue interaction
- Oracle strategy selection logic
- RAG retrieval scoring
- WebSocket event broadcasting

## Expected Graph Metrics
- **Nodes**: 150-250 (classes, functions, agents, models)
- **Edges**: 400-800 (imports, calls, inherits, uses)
- **Communities**: 8-12 (agent system, council, immune, reasoning, rag, api, frontend, utils)
- **God Nodes**: ScanOrchestrator, BaseAgent, ScanContext, CouncilOrchestrator, BehavioralGenome

## Surprising Connections to Look For
- How Oracle reasoning strategies are auto-selected based on CWE types
- How RAG retrieval avoids embeddings but still provides context
- How multiple agents share ScanContext without race conditions
- How council debate eliminates false positives through multi-model consensus
- How behavioral genome uses Isolation Forest for anomaly detection
- How patch verification gates prevent bad fixes from being applied
