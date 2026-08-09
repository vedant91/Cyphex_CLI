# Graph Report - D:\cyphex_v3  (2026-08-09)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 2056 nodes · 3860 edges · 136 communities (119 shown, 17 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 381 edges (avg confidence: 0.51)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `2dccb826`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- AgentResult
- test_vibemart.py
- VRAMManager
- vuln-webapp/src/server.js
- ScanContext
- AgentOrchestrator
- HttpRequest
- SupplyChainAgent
- ModelSelector
- AgentTerminal
- KnowledgeTreeBuilder
- get_selector
- verifier.py
- C
- ParamData
- CyphexMemory
- run_doctor
- ScanOrchestrator
- Vuln
- PatchCouncil
- cli_engine.py
- compilerOptions
- dynamic_scanner.py
- ReasoningTree
- dependencies
- devDependencies
- .build_from_scan
- oracle_attack.py
- db.js
- DeepAgent
- CyphexEngine
- index.ts
- terminal_ui.py
- EndpointProfile
- TreeNavigator
- demo_immune_system.py
- compilerOptions
- PromptInjectionAgent
- EvolutionController
- PatchManifest
- node/package.json
- BehavioralGenome
- sandbox_manager.py
- deep_xxe.py
- SQLiAgent
- cyphex.py
- CodeIndexer
- CyphexReasoner
- TestFormatters
- docker_sandbox.py
- App.tsx
- Overview.tsx
- PatchMemory
- vibemart/package.json
- TestVRAMManager
- ReconAgent
- CMDiAgent
- LogicAgent
- NetworkSecurityAgent
- api.py
- MutationEngine
- SecurityPostureCalculator
- AttackGraph
- DeepSSTIAgent
- templates.py
- security_kb.py
- cyphex_cli.py
- vulnapp/src/server.js
- usePipelineContext
- AIFuzzerAgent
- generate_regression_test
- github_hook.py
- _make_mock_selector
- evolution_controller.py
- app_standalone.js
- AttackSurfaceIndex
- app.js
- canvas-reveal-effect.tsx
- cyphex-rasp.js
- CerebrasAnalysisAgent
- .call_cerebras
- reflexion.py
- dependencies
- dependencies
- dependencies
- frontend/package.json
- SandboxPage.tsx
- get_sandboxes
- deepagents/__init__.py
- ._deploy
- onboarder.py
- PipelineContext.tsx
- .autonomous_exploit_loop
- .mutate_blocked_payloads
- self_consistency.py
- vuln-webapp/package.json
- train.py
- upload_sandbox
- DeepXXEAgent
- vulncorp/package.json
- vulnapp/package.json
- HeroSection.tsx
- _check_server_up
- ._dynamic_scan
- ._get_llm_fix_package
- index.js
- sandbox_websocket
- .generate_variants
- .mutate_with_llm
- LiveLogQueue
- ._assess_patch_safety
- training_data.py
- CyphexConfig
- eval.py
- Header.tsx
- tsconfig.json
- dast_constants.py
- immune/__init__.py
- council/__init__.py
- patch/__init__.py
- rag/__init__.py
- reasoning/__init__.py
- cyphex/__init__.py
- create_repo.py
- cyphex

## God Nodes (most connected - your core abstractions)
1. `ScanContext` - 199 edges
2. `Vuln` - 141 edges
3. `AgentResult` - 83 edges
4. `CyphexEngine` - 60 edges
5. `BaseAgent` - 50 edges
6. `BehavioralGenome` - 48 edges
7. `HttpRequest` - 45 edges
8. `AgentOrchestrator` - 41 edges
9. `BaseDeepAgent` - 37 edges
10. `ScanOrchestrator` - 36 edges

## Surprising Connections (you probably didn't know these)
- `C` --uses--> `CyphexEngine`  [INFERRED]
  cyphex_cli.py → cli_engine.py
- `C` --uses--> `CyphexEngine`  [INFERRED]
  cyphex/github_hook.py → cli_engine.py
- `C` --uses--> `BehavioralGenome`  [INFERRED]
  cli_engine.py → backend/backend/immune/behavioral_genome.py
- `CyphexEngine` --uses--> `BehavioralGenome`  [INFERRED]
  cli_engine.py → backend/backend/immune/behavioral_genome.py
- `C` --uses--> `BehavioralGenome`  [INFERRED]
  demo_immune_system.py → backend/backend/immune/behavioral_genome.py

## Import Cycles
- None detected.

## Communities (136 total, 17 thin omitted)

### Community 0 - "AgentResult"
Cohesion: 0.10
Nodes (29): ABC, CYPHEX — Agent 01: Reconnaissance Agent Performs initial target fingerprinting:…, CYPHEX — Agent 02: Web Crawler Agent Builds the full attack surface: - Crawls…, CYPHEX — Agent 03: SQL Injection Agent Tests for SQL injection vulnerabilities:…, CYPHEX — Agent 04: XSS (Cross-Site Scripting) Agent Tests for XSS…, CYPHEX — Agent 05: Authentication & Authorization Agent Tests for auth…, CYPHEX — Agent 06: Command Injection & SSTI Agent Tests for: - OS command…, CYPHEX — Agent 07: LFI / File Upload / XXE Agent Tests for: - Local File… (+21 more)

### Community 1 - "test_vibemart.py"
Cohesion: 0.07
Nodes (46): apply_patch(), ApplyResult, CYPHEX — Range-Accurate Patch Applier Replaces the destructive blank-all-lines…, Restore a file to its pre-patch state., Check if the patched file has valid syntax. Returns True (valid), False…, Result of a patch application attempt., Apply a patch to a specific line range in a file. Args: file_path: Absolute…, rollback() (+38 more)

### Community 2 - "VRAMManager"
Cohesion: 0.07
Nodes (28): AnalysisCouncil, ConsensusError, CouncilCallError, ModelNotFoundError, Model cannot be loaded within VRAM budget., Ollama model not pulled. Direct user to run ollama pull., Model returned non-JSON or timed out., Council could not reach minimum consensus after round 2. (+20 more)

### Community 3 - "vuln-webapp/src/server.js"
Cohesion: 0.05
Nodes (35): { exec }, express, router, express, jwt, router, users, express (+27 more)

### Community 4 - "ScanContext"
Cohesion: 0.08
Nodes (18): AuthAgent, Test default credentials against login form., Run hydra for brute force testing., Analyze JWT tokens found in cookies or responses., Test JWT algorithm none attack., Test for username enumeration via response differences., Test if login endpoint has rate limiting., Test for IDOR on user endpoints. (+10 more)

### Community 5 - "AgentOrchestrator"
Cohesion: 0.08
Nodes (28): AgentOrchestrator, AttackPlan, FeedbackLoop, CYPHEX — Agent Orchestrator (The Brain) Coordinates the 3-tier attack system:…, Endpoints with confirmed vulns likely have more., The brain that coordinates Semgrep, Nuclei, and 15 DeepAgents. Flow: 1. Ingest…, Execute DeepAgents in parallel groups based on Cognee intelligence. FULL…, Represents a planned attack sequence with parallel groups. (+20 more)

### Community 6 - "HttpRequest"
Cohesion: 0.10
Nodes (22): BaseDeepAgent, HypothesisResult, CYPHEX DeepAgents — BaseDeepAgent Upgraded with: - Multi-model Oracle…, GET the root URL once to establish a response-time baseline., Send the HTTP request and return (status, body, elapsed_s, headers)., Append a raw Evidence record to the shared ScanContext., Test one hypothesis through up to MAX_ATTEMPTS_PER_HYPOTHESIS probes. On…, Standalone DeepAgent base — full Observe->Think->Act adaptive loop. Uses only… (+14 more)

### Community 7 - "SupplyChainAgent"
Cohesion: 0.08
Nodes (18): Probe target for exposed dependency manifest files., Validate that content looks like a real manifest, not a 404 or generic page., Probe for exposed build configs & CI pipelines., Check for exposed JavaScript source maps., Parse a discovered manifest and check for vulnerable/suspicious deps., Parse npm package.json dependencies., Parse Python requirements.txt., Parse PHP composer.json. (+10 more)

### Community 8 - "ModelSelector"
Cohesion: 0.08
Nodes (23): _extract_param_size(), _is_code_model(), ModelInfo, ModelSelector, _quality_score(), CYPHEX — Intelligent Model Selector (Resource-Aware Brain) Automatically…, Check if a model is specialized for code tasks., Estimate VRAM usage in GB for a quantized model. (+15 more)

### Community 9 - "AgentTerminal"
Cohesion: 0.08
Nodes (19): execute_cvs_command(), Any, Tries to execute a shell command purely in Python (Cyphex Virtual Subsystem).…, AgentTerminal, Any, Print text safely, handling encoding errors on Windows., Print a single line of output., Execute a real terminal command with backoff for resilience. Streams output… (+11 more)

### Community 10 - "KnowledgeTreeBuilder"
Cohesion: 0.10
Nodes (29): _agentic_parse_document(), build_code_tree(), build_cwe_index(), build_knowledge_tree(), _extract_cwes_from_text(), _extract_handler(), _has_toc_structure(), _ingest_flat_document() (+21 more)

### Community 11 - "get_selector"
Cohesion: 0.09
Nodes (18): Uses the patcher model (code specialist) to write security analysis, and a…, DebateProtocol, Agent-Centric Batch Debate: loads each validator model ONCE and debates ALL…, Check if the installed models are large enough for reliable debate. Models <7B…, Multi-model debate for false-positive filtering. IMPORTANT: Errors/timeouts…, get_selector(), Get or create the global ModelSelector singleton., Dynamically selects models: - Patcher: best coding model (generates the fix) -… (+10 more)

### Community 12 - "verifier.py"
Cohesion: 0.10
Nodes (30): _check_blast_radius(), _check_exploit_indicators(), _check_liveness(), _check_no_suppression(), _paths_match(), CYPHEX — Patch Verification Gate The core guarantee: a patch is ONLY accepted…, Verify a dynamic finding by replaying the exploit. Args: location: Location…, Reject patches that add scanner-suppression comments. (+22 more)

### Community 13 - "C"
Cohesion: 0.08
Nodes (25): create_session(), _find_session_for_repo(), list_sessions(), load_session(), CYPHEX — Persistent Session Memory UUID-based session tracking so models retain…, Serialize to JSON-compatible dict., Deserialize from dict., Create a new session or load an existing one for this repo. If a prior session… (+17 more)

### Community 14 - "ParamData"
Cohesion: 0.10
Nodes (17): CrawlerAgent, Extract all links from HTML., Resolve a relative URL to absolute., Extract all forms from HTML., Extract URL query parameters., Extract API-like endpoints from HTML., Extract API endpoints from JavaScript source., LFIAgent (+9 more)

### Community 15 - "CyphexMemory"
Cohesion: 0.08
Nodes (17): CyphexMemory, MemoryEntry, CYPHEX × Cognee — Agent Memory Bridge Wraps Cognee's remember/recall/cognify…, Cognee-powered memory layer for Cyphex agents. When Cognee is available: Uses…, Configure Cognee for local Ollama operation., Agent writes a finding to memory. Args: agent_id: e.g. "agent_03_sqli"…, Agent queries memory for relevant context. Returns list of {content, agent_id,…, Get recall results formatted for LLM prompt injection. Returns a string ready… (+9 more)

### Community 16 - "run_doctor"
Cohesion: 0.09
Nodes (28): _install_nuclei_binary(), main(), CYPHEX CLI — Main Entry Point Usage: cyphex scan ./my-app # Scan local source…, Download Nuclei binary directly from GitHub releases., Auto-install optional security tools for enhanced scanning., _setup_tools(), _check_binary(), _check_ollama_models() (+20 more)

### Community 17 - "ScanOrchestrator"
Cohesion: 0.10
Nodes (16): PatchAgent, Generate patches without AI., main(), parse_args(), CYPHEX — CLI Entry Point Usage: python main.py --target http://localhost:3000…, Continuously pulls logs from the queue and emits to the UI., Emit terminal log entries as events (now stripped down since streaming handles…, Remove duplicate vulnerability findings. (+8 more)

### Community 18 - "Vuln"
Cohesion: 0.11
Nodes (15): Test a form for reflected XSS., Test a URL parameter for reflected XSS., Check for DOM-based XSS patterns in page source., Test for stored XSS by submitting payloads and checking if stored., Test admin/dashboard pages for reflected XSS and broken access control., Run dalfox XSS scanner., XSSAgent, A confirmed vulnerability. (+7 more)

### Community 19 - "PatchCouncil"
Cohesion: 0.11
Nodes (17): PatchCouncil, Maps dynamic (DAST) HTTP vulnerabilities back to static source code files and…, Takes a mixed list of static and dynamic Vulns. Attempts to resolve the…, Matches a DAST finding to a SAST finding based on vulnerability type and path…, Scans the codebase for files registering this route., RouteTracer, _auto_heal(), C (+9 more)

### Community 20 - "cli_engine.py"
Cohesion: 0.11
Nodes (24): detect_language(), extract_function(), extract_imports(), _extract_js_function(), _extract_python_function(), _is_brace_balanced(), CYPHEX — Code Context Extractor Extracts the enclosing function + imports for a…, Walk backwards from target line to find enclosing function, then forward to… (+16 more)

### Community 21 - "compilerOptions"
Cohesion: 0.07
Nodes (26): compilerOptions, allowImportingTsExtensions, baseUrl, erasableSyntaxOnly, ignoreDeprecations, jsx, lib, module (+18 more)

### Community 22 - "dynamic_scanner.py"
Cohesion: 0.14
Nodes (24): Run Nuclei/ZAP DAST tools and ingest findings into Cognee. Returns…, DynamicFinding, nuclei_available(), _nuclei_to_finding(), _parse_zap_report(), CYPHEX — Dynamic Analysis Engine Integrates industry-standard DAST tools for…, Convert a Nuclei JSON result to DynamicFinding., Check if OWASP ZAP is installed and its API is reachable. (+16 more)

### Community 23 - "ReasoningTree"
Cohesion: 0.10
Nodes (18): list_trees(), load_tree(), CYPHEX — Reasoning Tree Schema Captures the full thought traversal for each…, Build a linear CoT tree from thinking steps., Build a reflection tree (draft → critique → improve)., Build a Tree-of-Thoughts tree from branches. Args: branches: list of…, Serialize to JSON-compatible dict., Get a compact summary of the reasoning tree. (+10 more)

### Community 24 - "dependencies"
Cohesion: 0.08
Nodes (25): clsx, framer-motion, dependencies, clsx, framer-motion, lucide-react, react-dom, react-router-dom (+17 more)

### Community 25 - "devDependencies"
Cohesion: 0.08
Nodes (25): eslint, @eslint/js, eslint-plugin-react-hooks, eslint-plugin-react-refresh, devDependencies, eslint, @eslint/js, eslint-plugin-react-hooks (+17 more)

### Community 26 - ".build_from_scan"
Cohesion: 0.12
Nodes (13): Score a request for anomaly. Returns 0.0 (normal) to 1.0 (anomalous). COMBINED…, Retrain the genome for a specific endpoint with attack data. Called after each…, Train an Isolation Forest for a specific endpoint., Build a behavioral profile from scan context data., Generate synthetic "normal" traffic samples for an endpoint. Uses REALISTIC…, Generate a realistic input string for a given field type., Heuristic scoring based on feature thresholds. Catches attacks that Isolation…, Shannon entropy — measures randomness of input. (+5 more)

### Community 27 - "oracle_attack.py"
Cohesion: 0.12
Nodes (15): test(), AttackOracle, AttackPlan, Decision, _get_available_models(), _ollama_call(), CYPHEX DeepAttack Oracle — standalone Ollama-based attack reasoning. Model…, Call Ollama and return parsed JSON. When agent-reasoning is available, routes… (+7 more)

### Community 28 - "db.js"
Cohesion: 0.08
Nodes (18): orders, products, IMPORTANT: The query() method intentionally uses string interpolation, users, { execSync }, express, os, router (+10 more)

### Community 29 - "DeepAgent"
Cohesion: 0.11
Nodes (12): DeepAgent, Subclasses implement their specific attack logic here. Args: context: Shared…, Query Cognee for relevant prior knowledge before attacking., Write all findings + lessons to Cognee for future scans., Record a blocked payload for later mutation., Mutate blocked payloads and retry them., Enhanced agent with Cognee memory, mutation engine, and adaptive attack loop.…, Test mutated payloads against the target. Subclasses can override for agent-… (+4 more)

### Community 30 - "CyphexEngine"
Cohesion: 0.15
Nodes (7): CyphexEngine, Apply a horizontal gradient across text., Save deterministic judge artifacts in JSON, Markdown, and SARIF., Premium cyber-themed splash screen., Show what tools are available before scanning starts., Check if Semgrep CLI is installed., semgrep_available()

### Community 31 - "index.ts"
Cohesion: 0.16
Nodes (18): initialAgents, SEVERITY_RISK, usePipeline(), VULN_ICON_MAP, connectScanWebSocket(), getScan(), listScans(), startScan() (+10 more)

### Community 32 - "terminal_ui.py"
Cohesion: 0.10
Nodes (12): _gradient_bar(), CYPHEX SOC Terminal UI — Cyber Command Center Premium Rich-based terminal…, tools: list of (name, ok, hint), votes: list of (model_name, approved:bool, reason), patches: list of (vuln_name, cwe, file, method, verdict, status), Colored progress bar based on value. Returns a Text object., render_council_vote(), render_final_banner() (+4 more)

### Community 33 - "EndpointProfile"
Cohesion: 0.11
Nodes (13): EndpointProfile, Behavioral profile for a single endpoint., _get_language_for_file(), Detect language from file extension., CYPHEX — Core Test Suite Tests the critical components without requiring…, Test static scanner pattern matching., Test hardware detection., Test configuration safety. (+5 more)

### Community 34 - "TreeNavigator"
Cohesion: 0.13
Nodes (11): CYPHEX — Tree Navigator (PageIndex-Style Traversal) Two retrieval modes: 1.…, Get a specific subtree (code_tree or knowledge_tree)., Find the handler function from the code tree by file + line., Find an existing secure pattern in the codebase for this CWE., Find the import block for a given file from the tree., LLM-guided tree search for complex queries. The LLM sees ONLY the branch…, Ask local LLM which branches are relevant to the query., Navigates the knowledge tree to retrieve context for patching. Usage: nav =… (+3 more)

### Community 35 - "demo_immune_system.py"
Cohesion: 0.19
Nodes (17): build_genome(), create_scan_context(), demo_red_team(), header(), info(), main(), pause(), CYPHEX Immune System — Full Visual Demo… (+9 more)

### Community 36 - "compilerOptions"
Cohesion: 0.10
Nodes (20): compilerOptions, allowImportingTsExtensions, erasableSyntaxOnly, lib, module, moduleDetection, moduleResolution, noEmit (+12 more)

### Community 37 - "PromptInjectionAgent"
Cohesion: 0.17
Nodes (10): PromptInjectionAgent, Find AI/chat/LLM endpoints from discovered endpoints., Probe common AI endpoint paths if none were discovered., Send a message to an AI endpoint and return the response., Escape text for JSON string embedding., Test if we can extract the system prompt., Test if AI can be jailbroken to bypass safety., Test if AI can be tricked into leaking data. (+2 more)

### Community 38 - "EvolutionController"
Cohesion: 0.14
Nodes (11): EvolutionController, Execute one generation: 1. Score all payloads against genome 2. Partition into…, Prepare payloads for the next generation. Red team mutates blocked payloads AND…, Orchestrates the Adversarial Co-Evolution loop. The core innovation: red team…, Get blocked payloads from last generation (real results, not re-scored)., Get bypassed payloads from last generation (used as mutation seeds)., Analyze which detection features triggered blocking., Return the full evolution history for the dashboard. (+3 more)

### Community 39 - "PatchManifest"
Cohesion: 0.13
Nodes (9): PatchManifest, CYPHEX — Patch Manifest Tracks what has been patched, with what verdict, for…, Read/write .cyphex/patches.json for patch durability tracking., Record a patch attempt with its verification verdict., Check if this location was already patched (and verified)., Count patches that actually passed verification., Count patches applied but not verified., Compute patch durability statistics. (+1 more)

### Community 40 - "node/package.json"
Cohesion: 0.11
Nodes (18): auto-patch, cyphex, rasp, security, sqli, waf, xss, description (+10 more)

### Community 41 - "BehavioralGenome"
Cohesion: 0.17
Nodes (6): BehavioralGenome, Blue Team Defense — learns what "normal" looks like for each endpoint and…, Serialize genome to disk., Load genome from disk., Test Behavioral Genome core functionality., TestGenome

### Community 42 - "sandbox_manager.py"
Cohesion: 0.14
Nodes (17): deploy_sandbox(), _detect_entry_file(), _find_free_port(), _get_node_env(), get_sandbox(), _patch_port_in_entry(), CYPHEX — Sandbox Manager Handles uploading, deploying, and managing sandbox…, Extract a ZIP file, install deps, and start the sandbox app. Returns {… (+9 more)

### Community 43 - "deep_xxe.py"
Cohesion: 0.12
Nodes (9): DeepXXEAgent — Oracle-guided XML External Entity injection., Authentication-related payloads., CYPHEX DeepAgents — Payload Library Tier 1: Fast/cheap, high signal-to-noise…, Path traversal / LFI / RFI payloads., SQL Injection payloads — 3-tier system., SSRF payloads and cloud metadata endpoints., Server-Side Template Injection payloads., XSS payloads — reflected, DOM, stored, CSP bypass. (+1 more)

### Community 44 - "SQLiAgent"
Cohesion: 0.16
Nodes (9): Run sqlmap against forms and URL parameters., Test a form with SQL injection payloads., After confirming SQLi, attempt to dump real credentials., Test URL parameters for SQL injection., Test for time-based blind SQL injection., SQLiAgent, InjectionAgent, Combined Injection Agent: Runs SQLi and CMDi together. Strategy: 1. Run SQLi… (+1 more)

### Community 45 - "cyphex.py"
Cohesion: 0.21
Nodes (16): _check_ollama_models(), _check_tool(), cmd_doctor(), cmd_setup(), dispatch(), main(), _parse_flags(), CYPHEX — Interactive CLI Shell v4.4 Autonomous cyber-defence · Local-first ·… (+8 more)

### Community 46 - "CodeIndexer"
Cohesion: 0.12
Nodes (9): CodeIndexer, CYPHEX — Vectorless Code Indexer Walks the source directory and builds a…, Extract API routes from source code by parsing framework-specific patterns.…, Find files most relevant to a vulnerability. Returns list of {path, score,…, Find an existing secure pattern in the repo for a given CWE. "Fix it the way…, Get content of a specific file by relative path., Extract dependency information from package.json or requirements.txt., Vectorless keyword index of a source tree. (+1 more)

### Community 47 - "CyphexReasoner"
Cohesion: 0.12
Nodes (10): CyphexReasoner, Result from a reasoning-enhanced model call., Central reasoning adapter for CYPHEX. Wraps Oracle's ReasoningInterceptor for…, True if Oracle agent-reasoning is active., Get strategies available for current VRAM tier., Select the optimal reasoning strategy based on task, severity, and CWE.…, Generate a response using the optimal reasoning strategy. Routes through…, Return reasoning call statistics. (+2 more)

### Community 48 - "TestFormatters"
Cohesion: 0.16
Nodes (13): format_output(), CYPHEX — Output Formatters Converts scan results into different output formats:…, Map CYPHEX severity to SARIF level., Format scan result in the specified format., Format scan result as pretty JSON., Format scan result as SARIF v2.1.0. Compatible with GitHub Code Scanning, VS…, Format scan result as a Markdown report., _severity_to_sarif_level() (+5 more)

### Community 49 - "docker_sandbox.py"
Cohesion: 0.15
Nodes (15): cleanup_all_sandboxes(), deploy_docker_sandbox(), _detect_app_type(), docker_available(), _find_free_port(), _generate_dockerfile(), CYPHEX — Docker Sandbox Manager Containerized sandbox for cross-platform,…, Build and run the target app in a Docker container. Returns: {"sandbox_id",… (+7 more)

### Community 50 - "App.tsx"
Cohesion: 0.22
Nodes (13): App(), AnalysisPage(), AuthPage(), CrawlerPage(), CurePlannerPage(), InjectionPage(), LFIPage(), LogicPage() (+5 more)

### Community 51 - "Overview.tsx"
Cohesion: 0.19
Nodes (10): RiskChart(), VulnerabilityChart(), Props, RemediationCard(), getDiscoveryIcon(), IconContainer(), Radar(), Overview() (+2 more)

### Community 52 - "PatchMemory"
Cohesion: 0.18
Nodes (7): PatchMemory, CYPHEX — Patch Memory Two stores: 1. Exact cache: (semantic_hash(function),…, Verified-fix cache for patch reuse., Check if we have a verified fix for this (cwe, function_code) combo. Returns…, Store a verified patch for future reuse., Get the strategy that has worked most for this CWE., Hash of code with comments and whitespace stripped. Reformatting/renames don't…

### Community 53 - "vibemart/package.json"
Cohesion: 0.13
Nodes (14): dependencies, cors, dotenv, express, description, cors, express, main (+6 more)

### Community 54 - "TestVRAMManager"
Cohesion: 0.18
Nodes (8): asyncio, fixture, Deepseek (1.0) + Phi-3 (2.2) = 3.2 GB — must fit within 5.5 GB budget, Loading Qwen-7B (4.5 GB) when Phi-3 (2.2 GB) is loaded must exceed budget, Qwen (4.5) + any other model exceeds 5.5 GB — must evict others first, After unload(), model no longer counted in VRAM budget, ensure_loaded must evict models when needed to fit new model, TestVRAMManager

### Community 55 - "ReconAgent"
Cohesion: 0.21
Nodes (7): Parse HTTP headers from curl -I output., Detect technologies from headers., Detect technologies from HTML content., Check for missing security headers., Analyze content of sensitive files., Parse nmap output to update context., ReconAgent

### Community 56 - "CMDiAgent"
Cohesion: 0.23
Nodes (7): CMDiAgent, Run commix automated command injection testing., Test a form for command injection., Test a URL parameter for command injection., Check if command injection was successful., Test a form for Server-Side Template Injection., Attempt to escalate SSTI to RCE.

### Community 57 - "LogicAgent"
Cohesion: 0.21
Nodes (7): LogicAgent, Test for mass assignment vulnerabilities., Test for Server-Side Request Forgery., Check for missing CSRF tokens on state-changing forms., Test for CORS misconfiguration., Test HTTP method tampering on restricted endpoints., Test for IDOR on API endpoints.

### Community 58 - "NetworkSecurityAgent"
Cohesion: 0.22
Nodes (6): NetworkSecurityAgent, Async port scanner using Python sockets., Check TLS configuration for weaknesses., Audit HTTP response headers for security best practices., Check for information disclosure in response headers., Enumerate common subdomains via DNS resolution.

### Community 59 - "api.py"
Cohesion: 0.21
Nodes (13): broadcast_event(), broadcast_sandbox_event(), make_event_callback(), CYPHEX — FastAPI Web Server + WebSocket API Bridges the Python scan engine to…, Returns an async callback function that the ScanOrchestrator will call for…, Start a new vulnerability scan., Run the full scan pipeline in the background., Send an event to all WebSocket clients watching this scan. (+5 more)

### Community 60 - "MutationEngine"
Cohesion: 0.14
Nodes (8): MutationEngine, Replace spaces with alternative whitespace: space → %09 (tab), Split strings: 'admin' → CONCAT('ad','min'), Convert chars to CHAR() calls: 'a' → CHAR(97), Red Team Mutator — generates evolved payloads that try to bypass the genome.…, Double encoding: ' → %2527, Unicode substitution for key characters., Hex encoding for SQL: 'admin' → 0x61646d696e

### Community 61 - "SecurityPostureCalculator"
Cohesion: 0.18
Nodes (8): Convert score to letter grade., Calculate industry percentile (simplified). In production, this would query a…, Generate prioritized recommendations., Generate an SVG badge for the security score., Generate a human-readable summary., Calculates Security Posture Score from scan results., Calculate SPS from scan context., SecurityPostureCalculator

### Community 62 - "AttackGraph"
Cohesion: 0.20
Nodes (7): AttackEdge, AttackGraph, AttackNode, CYPHEX AttackGraph — upgraded with priority chains and lateral movement logic.…, Shared mutable state across all DeepAgents in a scan session. Updated in real-…, Find endpoints that likely require authentication., When one agent finds something, compute the follow-up attack chain. Returns new…

### Community 63 - "DeepSSTIAgent"
Cohesion: 0.18
Nodes (7): DeepCMDiAgent — Oracle-guided Command Injection with sync/time-based/blind…, DeepSSTIAgent, DeepSSTIAgent — Oracle-guided Server-Side Template Injection with engine…, Server-Side Template Injection agent. Phase 1: Math probes to detect template…, Phase 1: Try math probes to detect template evaluation., Phase 2: Attempt RCE via engine-specific payloads., Command injection payloads.

### Community 64 - "templates.py"
Cohesion: 0.14
Nodes (13): _fix_cmdi_exec_concat(), _fix_cmdi_execsync(), _fix_hardcoded_secret(), _fix_sqli_concatenation(), _fix_sqli_template_literal(), _fix_wildcard_cors(), CYPHEX — Deterministic Template Transforms 100%-deterministic fixes for high-…, Replace exec/execSync with string concatenation containing user input. Handles… (+5 more)

### Community 65 - "security_kb.py"
Cohesion: 0.21
Nodes (13): detect_framework(), format_for_prompt(), get_anti_patterns(), get_fix_recipe(), get_fix_strategies(), _load_kb(), CYPHEX — Security Knowledge Base Loader Loads security_kb.json and provides CWE…, Detect the web framework from dependency info. (+5 more)

### Community 66 - "cyphex_cli.py"
Cohesion: 0.18
Nodes (13): C, _load_engine(), load_env_file(), main(), CYPHEX CLI — One-command security scanner Usage: python cyphex_cli.py scan…, Lightweight, standard-library-only .env file loader., Import the engine lazily so we can show a clean dependency error instead of a…, create_daemon_app() (+5 more)

### Community 67 - "vulnapp/src/server.js"
Cohesion: 0.14
Nodes (11): app, cookieParser, cors, crypto, db, { execSync }, express, FILES_BASE (+3 more)

### Community 68 - "usePipelineContext"
Cohesion: 0.19
Nodes (10): MatrixBackground(), Layout(), items, Sidebar(), usePipelineContext(), ModuleLayout(), ReportPage(), SEVERITY_BG (+2 more)

### Community 69 - "AIFuzzerAgent"
Cohesion: 0.23
Nodes (7): AIFuzzerAgent, Test an AI-generated payload against a form., Generate novel XSS payloads using LLM., Uses local/cloud LLM to generate novel attack payloads. Simulates WormGPT-style…, Generate logic flaw exploits using LLM., Learn from failed attempts and generate improved payloads. This simulates how…, Generate novel SQLi payloads using LLM.

### Community 70 - "generate_regression_test"
Cohesion: 0.18
Nodes (10): Ingest Semgrep/built-in scanner findings into Cognee. Called after Step 2…, _generate_dynamic_test(), generate_regression_test(), _generate_static_test(), CYPHEX — Proof-Carrying Regression Test Generator For each verified fix,…, Generate a test that checks the scanner rule at the patched location., Write generated regression tests to the test directory. Args: tests: List of…, Generate a security regression test for a verified fix. Args: vuln: The… (+2 more)

### Community 71 - "github_hook.py"
Cohesion: 0.17
Nodes (11): C, console, create_github_hook_app(), _create_pull_request(), _process_push(), CYPHEX GitHub Hook — Zero-Command Security for Vibe Coders HOW IT WORKS FOR THE…, Create a Pull Request on GitHub via the REST API., Create the FastAPI app for receiving GitHub webhooks. (+3 more)

### Community 72 - "_make_mock_selector"
Cohesion: 0.21
Nodes (8): _make_mock_selector(), asyncio, Bad patch rejected by both -> safety=rejected, fixed_code still returned, Patch output must not contain CVE- pattern, Return a deterministic ModelSelector mock that doesn't call Ollama., VRAMManager must unload all models before loading cyphex-patch, Parameterised query patch approved by both validators -> safety=safe, Incomplete patch rejected by one validator -> safety=review_needed

### Community 73 - "evolution_controller.py"
Cohesion: 0.21
Nodes (6): CYPHEX — Behavioral Genome (Blue Team Defense) Per-endpoint anomaly detector…, CYPHEX — Evolution Controller (The Core Loop) Orchestrates the Adversarial Co-…, CYPHEX — Mutation Engine (Red Team Payload Mutator) Takes blocked payloads and…, GenomeState, CYPHEX — Genome Data Models Data structures for the Behavioral Genome and Co-…, Complete behavioral genome for an application.

### Community 74 - "app_standalone.js"
Cohesion: 0.20
Nodes (10): app, { exec }, express, fs, initSqlJs, jwt, path, query() (+2 more)

### Community 75 - "AttackSurfaceIndex"
Cohesion: 0.24
Nodes (5): AttackSurfaceIndex, EndpointProfile, Generate a structured text summary of what we know about the target. This is…, Vectorless RAG over observed HTTP behaviour. No embeddings, no external APIs —…, Extract structured knowledge from a raw HTTP response. No embeddings — just…

### Community 76 - "app.js"
Cohesion: 0.20
Nodes (10): app, crypto, { exec }, express, fs, initDB(), jwt, mysql (+2 more)

### Community 77 - "canvas-reveal-effect.tsx"
Cohesion: 0.20
Nodes (8): react, CanvasRevealEffect(), cn(), DotMatrix(), DotMatrixProps, ShaderProps, Uniforms, react

### Community 78 - "cyphex-rasp.js"
Cohesion: 0.25
Nodes (10): analyzePayload(), ATTACK_SIGNATURES, captureStackTrace(), cyphexRasp(), DEFAULTS, extractInputs(), http, path (+2 more)

### Community 79 - "CerebrasAnalysisAgent"
Cohesion: 0.29
Nodes (5): CerebrasAnalysisAgent, Build evidence package from all confirmed vulns., Format terminal logs for AI consumption., Generate a report without AI., Identify attack chains from vulnerability combinations.

### Community 80 - ".call_cerebras"
Cohesion: 0.27
Nodes (5): Call AI backend for analysis and decision-making. Supports modes: 'local'…, Call Groq cloud API (FREE, OpenAI-compatible, 300+ tokens/sec). Uses Llama 3.3…, Call local Ollama server (runs on laptop GPU or Pi CPU)., Call Cerebras cloud API (legacy — currently broken)., Log a message to console with color coding.

### Community 81 - "reflexion.py"
Cohesion: 0.24
Nodes (9): _build_feedback(), patch_with_reflexion(), CYPHEX — Grounded Reflexion Draft → Apply → Verify → Feed REAL failure evidence…, Build concrete feedback from verifier evidence. Never asks "are you sure?" —…, Get max reflexion rounds based on hardware tier., Result of a grounded reflexion loop., Grounded reflexion loop for patch generation. Args: vuln: The Vuln to fix…, ReflexionResult (+1 more)

### Community 82 - "dependencies"
Cohesion: 0.20
Nodes (10): dependencies, express, jsonwebtoken, mysql2, sql.js, express, jsonwebtoken, jsonwebtoken (+2 more)

### Community 83 - "dependencies"
Cohesion: 0.20
Nodes (10): dependencies, cors, express, multer, node-fetch, cors, express, node-fetch (+2 more)

### Community 84 - "dependencies"
Cohesion: 0.20
Nodes (10): cookie-parser, dependencies, cookie-parser, cors, ejs, express, cookie-parser, cors (+2 more)

### Community 85 - "frontend/package.json"
Cohesion: 0.20
Nodes (9): name, private, scripts, build, dev, lint, preview, type (+1 more)

### Community 86 - "SandboxPage.tsx"
Cohesion: 0.33
Nodes (9): connectSandboxWebSocket(), uploadSandbox(), buildZipBlob(), crc32(), getCRC32Table(), SandboxInfo, SandboxPage(), TerminalLine (+1 more)

### Community 87 - "get_sandboxes"
Cohesion: 0.22
Nodes (9): get_sandboxes(), get_scan(), get_scans(), Get scan status and/or final report., List all scans (most recent first)., List currently active sandboxes, list_sandboxes(), List all sandboxes with current status. (+1 more)

### Community 88 - "deepagents/__init__.py"
Cohesion: 0.28
Nodes (5): DeepAuthAgent, DeepAuthAgent — Oracle-guided Auth Bypass, JWT attacks, session fixation., Oracle-guided Auth testing agent. Covers: - Default credentials brute force -…, Try JWT alg:none and weak-secret attacks on discovered JWTs., CYPHEX DeepAgents — Public exports 10 specialized autonomous vulnerability…

### Community 89 - "._deploy"
Cohesion: 0.22
Nodes (4): If frontend served as static, look for backend running on nearby port., Parse docker-compose.yml to find the app's exposed port., Remove obsolete 'version' key from docker-compose.yml to prevent warnings., Find services that have valid Dockerfiles or use pre-built images.

### Community 90 - "onboarder.py"
Cohesion: 0.28
Nodes (8): C, _find_express_entry(), _inject_rasp(), onboard_project(), CYPHEX Onboarder — Zero-Click Vibe Coder Integration Automatically injects the…, Main entrypoint for the onboarder. Accepts either a GitHub URL (clones it) or a…, Heuristically find the main Express entry point., Injects the RASP middleware into the Express app's entry file.

### Community 91 - "PipelineContext.tsx"
Cohesion: 0.36
Nodes (7): AgentTable(), Props, PipelineContext, PipelineContextType, PipelineProvider(), Agent, LogEntry

### Community 92 - ".autonomous_exploit_loop"
Cohesion: 0.25
Nodes (4): Extract JSON from text (handles markdown code blocks)., AI-driven ReAct loop for advanced exploitation using the Cyphex Virtual…, Each agent implements this. Context has data from previous agents., Register a confirmed vulnerability.

### Community 93 - ".mutate_blocked_payloads"
Cohesion: 0.25
Nodes (4): Random case changes: or → oR, Or, OR, Take payloads that were BLOCKED by genome and generate variants designed to…, Standard URL encoding: ' → %27, Insert SQL comments between keywords: OR → O/**/R

### Community 94 - "self_consistency.py"
Cohesion: 0.29
Nodes (7): ConsistencyResult, k_for_tier(), patch_with_consistency(), CYPHEX — Self-Consistency with Verifier as Judge Generate K candidate patches…, Get K (number of candidates) based on hardware tier., Result of self-consistency patch generation., Generate K patches with different strategies, keep the one that passes…

### Community 95 - "vuln-webapp/package.json"
Cohesion: 0.25
Nodes (7): description, main, name, scripts, dev, start, version

### Community 96 - "train.py"
Cohesion: 0.32
Nodes (7): check_dependencies(), load_training_data(), CYPHEX — Fine-Tuning Script for qwen2.5-coder:7b Uses QLoRA (4-bit) to fine-…, Check if fine-tuning dependencies are installed., Load JSONL training data., Run QLoRA fine-tuning., train()

### Community 97 - "upload_sandbox"
Cohesion: 0.29
Nodes (7): kill_sandbox(), Upload a zipped source code application (sandbox) and deploy it. Accepts ZIP…, upload_sandbox(), Stop a running sandbox., stop_sandbox(), post, UploadFile

### Community 98 - "DeepXXEAgent"
Cohesion: 0.38
Nodes (4): DeepXXEAgent, XML External Entity injection agent. Detects XML-accepting endpoints from…, Find endpoints that likely accept XML input., Inject XXE payloads into XML-accepting endpoints.

### Community 99 - "vulncorp/package.json"
Cohesion: 0.29
Nodes (6): description, main, name, scripts, start, version

### Community 100 - "vulnapp/package.json"
Cohesion: 0.29
Nodes (6): description, main, name, scripts, start, version

### Community 101 - "HeroSection.tsx"
Cohesion: 0.33
Nodes (4): HeroSection(), Props, BackgroundScene(), BackgroundSceneProps

### Community 102 - "_check_server_up"
Cohesion: 0.33
Nodes (6): _check_server_up(), health_check_sandbox(), Check if a server is responding., Check if a sandbox is still alive and responding. Returns True if healthy,…, Restart a crashed sandbox. Re-launches the Node/Python process on the same port…, restart_sandbox()

### Community 103 - "._dynamic_scan"
Cohesion: 0.33
Nodes (4): get_memory(), Get or create the active memory instance for the current scan., CLI-focused dynamic scan with explicit per-agent visibility., Step 4b: Deploy DeepAgents via the AgentOrchestrator. This is the Tier 2…

### Community 104 - "._get_llm_fix_package"
Cohesion: 0.33
Nodes (3): Any, Try Ollama (local LLM) first, then fall back to built-in rule-based patches., Built-in patches for common vulnerability types. Works 100% offline.

### Community 105 - "index.js"
Cohesion: 0.33
Nodes (5): allowedOrigins, app, cors, cyphexRasp, express

### Community 106 - "sandbox_websocket"
Cohesion: 0.40
Nodes (5): Real-time event stream for a scan., Real-time terminal feed for a sandbox. Streams all scan terminal_log events to…, sandbox_websocket(), websocket_endpoint(), websocket

### Community 111 - "training_data.py"
Cohesion: 0.50
Nodes (3): generate_training_file(), CYPHEX — Fine-Tuning Dataset Generator Generates training data for fine-tuning…, Generate JSONL training file for fine-tuning.

## Knowledge Gaps
- **235 isolated node(s):** `express`, `mysql`, `jwt`, `{ exec }`, `fs` (+230 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **17 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ScanContext` connect `ScanContext` to `AgentResult`, `AgentOrchestrator`, `HttpRequest`, `SupplyChainAgent`, `C`, `ParamData`, `ScanOrchestrator`, `Vuln`, `.build_from_scan`, `DeepAgent`, `CyphexEngine`, `demo_immune_system.py`, `PromptInjectionAgent`, `EvolutionController`, `BehavioralGenome`, `SQLiAgent`, `cyphex.py`, `ReconAgent`, `CMDiAgent`, `LogicAgent`, `NetworkSecurityAgent`, `SecurityPostureCalculator`, `DeepSSTIAgent`, `AIFuzzerAgent`, `evolution_controller.py`, `CerebrasAnalysisAgent`, `deepagents/__init__.py`, `.autonomous_exploit_loop`, `DeepXXEAgent`, `._dynamic_scan`?**
  _High betweenness centrality (0.151) - this node is a cross-community bridge._
- **Why does `CyphexEngine` connect `CyphexEngine` to `VRAMManager`, `ScanContext`, `AgentOrchestrator`, `ModelSelector`, `KnowledgeTreeBuilder`, `get_selector`, `verifier.py`, `C`, `ParamData`, `CyphexMemory`, `run_doctor`, `Vuln`, `PatchCouncil`, `cli_engine.py`, `ReasoningTree`, `TreeNavigator`, `EvolutionController`, `PatchManifest`, `BehavioralGenome`, `CodeIndexer`, `PatchMemory`, `MutationEngine`, `cyphex_cli.py`, `github_hook.py`, `._deploy`, `._dynamic_scan`, `._get_llm_fix_package`, `._assess_patch_safety`?**
  _High betweenness centrality (0.118) - this node is a cross-community bridge._
- **Why does `Vuln` connect `Vuln` to `AgentResult`, `ScanContext`, `AgentOrchestrator`, `HttpRequest`, `SupplyChainAgent`, `C`, `ParamData`, `ScanOrchestrator`, `PatchCouncil`, `DeepAgent`, `CyphexEngine`, `demo_immune_system.py`, `PromptInjectionAgent`, `SQLiAgent`, `ReconAgent`, `CMDiAgent`, `LogicAgent`, `NetworkSecurityAgent`, `SecurityPostureCalculator`, `DeepSSTIAgent`, `AIFuzzerAgent`, `CerebrasAnalysisAgent`, `deepagents/__init__.py`, `.autonomous_exploit_loop`, `DeepXXEAgent`, `._dynamic_scan`?**
  _High betweenness centrality (0.057) - this node is a cross-community bridge._
- **Are the 40 inferred relationships involving `ScanContext` (e.g. with `ReconAgent` and `CrawlerAgent`) actually correct?**
  _`ScanContext` has 40 INFERRED edges - model-reasoned connections that need verification._
- **Are the 38 inferred relationships involving `Vuln` (e.g. with `ReconAgent` and `CrawlerAgent`) actually correct?**
  _`Vuln` has 38 INFERRED edges - model-reasoned connections that need verification._
- **Are the 33 inferred relationships involving `AgentResult` (e.g. with `ReconAgent` and `CrawlerAgent`) actually correct?**
  _`AgentResult` has 33 INFERRED edges - model-reasoned connections that need verification._
- **Are the 27 inferred relationships involving `CyphexEngine` (e.g. with `BehavioralGenome` and `EvolutionController`) actually correct?**
  _`CyphexEngine` has 27 INFERRED edges - model-reasoned connections that need verification._