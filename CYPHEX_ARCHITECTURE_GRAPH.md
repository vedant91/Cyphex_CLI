# CypheX v3 - Architecture Graph (Mermaid)

## Complete System Architecture

```mermaid
graph TB
    subgraph Orchestration["🎯 Orchestration Layer"]
        SO[ScanOrchestrator<br/>5-Stage Pipeline]
        SC[ScanContext<br/>Shared State]
        SO -->|manages| SC
    end

    subgraph Agents["⚔️ Agent System"]
        BA[BaseAgent<br/>Abstract Parent]
        R1[ReconAgent<br/>Stage 1]
        R2[CrawlerAgent<br/>Stage 2]
        INJ[InjectionAgent<br/>SQLi + CMDi]
        XSS[XSSAgent<br/>XSS Testing]
        AUTH[AuthAgent<br/>Auth Testing]
        TERM[CVS Terminal<br/>Virtual Linux]
        
        R1 -.->|inherits| BA
        R2 -.->|inherits| BA
        INJ -.->|inherits| BA
        XSS -.->|inherits| BA
        AUTH -.->|inherits| BA
        BA -->|uses| TERM
    end

    subgraph Council["🏛️ Council System"]
        CO[CouncilOrchestrator<br/>Multi-Model Coord]
        PC[PatchCouncil<br/>3-Stage Review]
        DP[DebateProtocol<br/>False Positive Filter]
        
        CO -->|coordinates| PC
        CO -->|coordinates| DP
    end

    subgraph Immune["🧬 Immune System"]
        BG[BehavioralGenome<br/>Blue Team ML]
        ME[MutationEngine<br/>Red Team Attack]
        EC[EvolutionController<br/>Co-Evolution]
        
        EC -->|evolves| BG
        EC -->|coordinates| ME
        BG <-.->|adversarial| ME
    end

    subgraph Reasoning["🧠 Reasoning Engine"]
        OA[OracleAdapter<br/>16 Architectures]
        RT[ReasoningTree<br/>Thought Traces]
        
        OA -->|generates| RT
    end

    subgraph RAG["📚 RAG System"]
        CI[CodeIndexer<br/>Vectorless Retrieval]
        KT[KnowledgeTreeBuilder<br/>Hierarchical Context]
        
        CI -.->|integrates| KT
    end

    subgraph API["🌐 API Layer"]
        FA[FastAPI<br/>REST + WebSocket]
    end

    subgraph Patch["🔧 Patch Pipeline"]
        PA[PatchAgent<br/>Auto-Patching]
    end

    %% Cross-community connections
    SO -->|executes| R1
    SO -->|executes| R2
    SO -->|executes| INJ
    SO -->|emits events| FA
    FA -->|triggers| SO
    
    BA -->|modifies| SC
    
    PA -->|uses| OA
    PA -->|uses| CI
    PC -->|uses| OA
    DP -->|validates| SC
    
    style SO fill:#FF6B6B
    style SC fill:#FF6B6B
    style BA fill:#4ECDC4
    style OA fill:#AA96DA
    style CO fill:#95E1D3
    style BG fill:#F38181
    style CI fill:#FCBAD3
```

## God Nodes Visualization

```mermaid
mindmap
  root((God Nodes))
    ScanOrchestrator
      45 connections
      Pipeline coordinator
      Stage management
    ScanContext
      42 connections
      Data flow backbone
      Thread-safe state
    OracleAdapter
      40 connections
      16 strategies
      Intelligence amplification
    BaseAgent
      38 connections
      Agent foundation
      14 children
    CouncilOrchestrator
      35 connections
      Multi-model consensus
      VRAM-aware
    BehavioralGenome
      32 connections
      Isolation Forest ML
      15D feature vector
    CodeIndexer
      30 connections
      Vectorless RAG
      0 VRAM overhead
```

## Data Flow Pipeline

```mermaid
sequenceDiagram
    participant API as FastAPI
    participant SO as ScanOrchestrator
    participant SC as ScanContext
    participant R1 as ReconAgent
    participant R2 as CrawlerAgent
    participant ATK as Attack Agents
    participant CO as Council
    participant PA as PatchAgent
    
    API->>SO: POST /api/scan
    SO->>SC: Create context
    SO->>R1: Stage 1: Recon
    R1->>SC: Update (framework, server)
    SO->>R2: Stage 2: Crawl
    R2->>SC: Update (endpoints, forms)
    
    par Parallel Attack
        SO->>ATK: InjectionAgent
        SO->>ATK: XSSAgent
        SO->>ATK: AuthAgent
    end
    
    ATK->>SC: Update (vulnerabilities)
    SO->>CO: Validate findings
    CO->>SC: Confirm/Reject vulns
    SO->>PA: Generate patches
    PA->>SC: Add cure plan
    SO->>API: Return report
```

## Immune System Evolution

```mermaid
flowchart LR
    A[Red Team<br/>Generate Payloads] --> B{Blue Team<br/>Score Payloads}
    B -->|Blocked| C[Red Team<br/>Mutate with Obfuscation]
    B -->|Bypassed| D[Blue Team<br/>Retrain Model]
    C --> B
    D --> B
    B -->|Block Rate >= 99%| E[Converged<br/>Save Genome]
    
    style A fill:#F38181
    style C fill:#F38181
    style B fill:#4ECDC4
    style D fill:#4ECDC4
    style E fill:#95E1D3
```

## Council Debate Flow

```mermaid
stateDiagram-v2
    [*] --> Vulnerability
    Vulnerability --> ModelA: Review
    ModelA --> ModelB: Vote recorded
    ModelB --> ModelC: Vote recorded
    ModelC --> Consensus: Vote recorded
    
    Consensus --> Confirmed: Majority CONFIRM
    Consensus --> Rejected: Majority REJECT
    
    Confirmed --> [*]
    Rejected --> [*]
    
    note right of Consensus
        Majority vote required
        No single model can
        hallucinate a vuln
    end note
```

## Patch Generation Pipeline

```mermaid
flowchart TD
    V[Vulnerability] --> ORA[Oracle<br/>Select Strategy]
    ORA --> RAG[RAG Indexer<br/>Retrieve Context]
    RAG --> GEN[LLM Generator<br/>Create Patch]
    GEN --> REV1[Reviewer 1<br/>Validate]
    REV1 -->|Rejected| CRIT[Critique Feedback]
    CRIT --> GEN
    REV1 -->|Approved| REV2[Reviewer 2<br/>Validate]
    REV2 -->|Rejected| CRIT
    REV2 -->|Approved| VER[Verification Gate]
    VER --> SYN[Syntax Check]
    SYN -->|Fail| CRIT
    SYN -->|Pass| BLAST[Blast Radius]
    BLAST -->|Too Wide| CRIT
    BLAST -->|Safe| RESCAN[Re-scan Test]
    RESCAN -->|Vuln Still Exists| CRIT
    RESCAN -->|Vuln Fixed| APPLY[Apply Patch]
    APPLY --> DONE[Complete]
    
    style ORA fill:#AA96DA
    style RAG fill:#FCBAD3
    style VER fill:#95E1D3
    style APPLY fill:#4ECDC4
```

## Community Boundaries

```mermaid
graph LR
    subgraph O[Orchestration]
        SO1[ScanOrchestrator]
        SC1[ScanContext]
    end
    
    subgraph A[Agents]
        BA1[BaseAgent]
        R11[ReconAgent]
    end
    
    subgraph C[Council]
        CO1[CouncilOrchestrator]
    end
    
    subgraph I[Immune]
        BG1[BehavioralGenome]
    end
    
    subgraph R[Reasoning]
        OA1[OracleAdapter]
    end
    
    subgraph RAG1[RAG]
        CI1[CodeIndexer]
    end
    
    SO1 -.->|executes| R11
    BA1 -.->|modifies| SC1
    CO1 -.->|uses| OA1
    C -.->|validates| SC1
    
    style O fill:#FF6B6B,stroke:#333,stroke-width:2px
    style A fill:#4ECDC4,stroke:#333,stroke-width:2px
    style C fill:#95E1D3,stroke:#333,stroke-width:2px
    style I fill:#F38181,stroke:#333,stroke-width:2px
    style R fill:#AA96DA,stroke:#333,stroke-width:2px
    style RAG1 fill:#FCBAD3,stroke:#333,stroke-width:2px
```

---

## Legend

**Node Types:**
- 🎯 **Orchestration** - Pipeline coordination
- ⚔️ **Agents** - Attack agents (14 total)
- 🏛️ **Council** - Multi-model validation
- 🧬 **Immune** - Adversarial evolution
- 🧠 **Reasoning** - Oracle strategies
- 📚 **RAG** - Code intelligence
- 🌐 **API** - Web interface
- 🔧 **Patch** - Auto-remediation

**Edge Types:**
- Solid line: Direct dependency/call
- Dotted line: Inheritance/integration
- Dashed bidirectional: Adversarial relationship

**Colors:**
- Red (#FF6B6B): Orchestration
- Teal (#4ECDC4): Agents
- Mint (#95E1D3): Council
- Pink (#F38181): Immune
- Purple (#AA96DA): Reasoning
- Light Pink (#FCBAD3): RAG
- Yellow (#FFFFD2): API
- Light Blue (#A8D8EA): Patch
