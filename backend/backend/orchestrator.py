"""
CYPHEX — Agent Orchestrator (The Brain)

Coordinates the 3-tier attack system:
  Tier 1: Semgrep (SAST) + Nuclei (DAST) — deterministic, fast
  Tier 2: DeepAgents (10 agents) — adaptive, LLM-powered, parallel groups
  Tier 3: Autonomous exploit loops — multi-step chains

DeepAgents (all run unconditionally — Oracle skips if no surface exists):
  Group 1: DeepSQLiAgent, DeepXSSAgent, DeepAuthAgent (always run)
  Group 2: DeepPathTraversalAgent, DeepCMDiAgent, DeepSSRFAgent,
           DeepIDORAgent, DeepSSTIAgent, DeepXXEAgent (always run)
  Group 3: DeepBusinessLogicAgent (uses full graph intelligence)

Uses Cognee as the central memory hub:
  - Ingests SAST/DAST findings into knowledge graph
  - Queries graph to build smart attack plans
  - Feeds agent findings back for cross-agent intelligence

Genome integration:
  - Phase A (Red Team): DeepAgents attack BEFORE genome is built
  - Phase B (Genome Build): BehavioralGenome learns normal patterns
  - Phase C (Validation): Same attacks re-run to confirm genome blocks them
"""

import asyncio
import os
import time
import logging
from typing import Optional
from dataclasses import dataclass, field

from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult
from config import config

logger = logging.getLogger("cyphex.orchestrator")


@dataclass
class AttackPlan:
    """Represents a planned attack sequence with parallel groups."""
    groups: list[list] = field(default_factory=list)  # Each group runs in parallel
    skipped_agents: list[str] = field(default_factory=list)
    tech_signals: dict = field(default_factory=dict)
    priority_endpoints: list[str] = field(default_factory=list)


class FeedbackLoop:
    """
    Tracks findings across agent groups to enable adaptive routing.
    When SQLi finds creds, Auth agent uses them.
    When Recon finds AI endpoint, PromptInjection agent targets it.
    """

    def __init__(self):
        self.confirmed_vulns: list[Vuln] = []
        self.confirmed_endpoints: set = set()
        self.discovered_creds: list[dict] = []
        self.discovered_sessions: list[str] = []
        self.has_file_params: bool = False
        self.has_exec_sinks: bool = False
        self.has_id_routes: bool = False
        self.has_url_params: bool = False
        self.has_jwt_tokens: bool = False
        self.has_ai_endpoints: bool = False
        self.has_graphql: bool = False

    def ingest_context(self, context: ScanContext):
        """Analyze recon results to determine which agents to deploy."""
        for form in context.all_forms:
            for inp in form.inputs:
                inp_lower = inp.lower()
                if any(kw in inp_lower for kw in ["file", "path", "dir", "document"]):
                    self.has_file_params = True
                if any(kw in inp_lower for kw in ["url", "uri", "callback", "redirect", "next"]):
                    self.has_url_params = True

        for ep in context.all_endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in ["chat", "ai", "llm", "completion", "prompt", "generate", "assistant"]):
                self.has_ai_endpoints = True
            if "/graphql" in ep_lower:
                self.has_graphql = True
            # Check for ID-parameterized routes
            if any(pat in ep for pat in ["/:id", "/:userId", "?id=", "?user_id="]):
                self.has_id_routes = True

        if context.graphql_endpoint:
            self.has_graphql = True

    def ingest_findings(self, vulns: list[Vuln]):
        """Update feedback from new findings."""
        for v in vulns:
            self.confirmed_vulns.append(v)
            if v.endpoint:
                self.confirmed_endpoints.add(v.endpoint.split("?")[0])
            if v.dumped_data:
                self.discovered_creds.append({
                    "data": v.dumped_data,
                    "source": v.name,
                    "endpoint": v.endpoint,
                })

    def get_priority_targets(self) -> list[str]:
        """Endpoints with confirmed vulns likely have more."""
        return list(self.confirmed_endpoints)


class AgentOrchestrator:
    """
    The brain that coordinates Semgrep, Nuclei, and 15 DeepAgents.

    Flow:
      1. Ingest SAST (Semgrep) findings into Cognee
      2. Run DAST (Nuclei) and ingest findings into Cognee
      3. Query Cognee to build adaptive attack plan
      4. Execute DeepAgents in parallel groups
      5. Feed findings back for cross-agent intelligence
      6. Run autonomous exploit loops on critical findings
    """

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        source_dir: str,
        cognee_memory=None,
        council=None,
        event_callback=None,
        sandbox_info=None,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.source_dir = source_dir
        self.memory = cognee_memory
        self.council = council
        self.feedback = FeedbackLoop()
        self._emit = event_callback
        self.sandbox_info = sandbox_info

    # ===================================================
    # TIER 1: DETERMINISTIC TOOLS (Semgrep + Nuclei)
    # ===================================================

    async def ingest_sast_findings(self, static_findings: list) -> None:
        """
        Ingest Semgrep/built-in scanner findings into Cognee.
        Called after Step 2 (Static Analysis) completes.
        """
        if not self.memory or not static_findings:
            return

        await self.memory.initialize()
        logger.info(f"Ingesting {len(static_findings)} SAST findings into Cognee")

        for f in static_findings:
            cwe = getattr(f, "cwe", "")
            name = getattr(f, "name", str(f))
            file_path = getattr(f, "file_path", "")
            line = getattr(f, "line_number", 0)
            snippet = getattr(f, "code_snippet", "")
            source = getattr(f, "source", "builtin")
            confidence = getattr(f, "confidence", 0.85)

            await self.memory.agent_remember(
                agent_id="sast_engine",
                memory_type="FINDING",
                content=(
                    f"[STATIC/{source}] {cwe}: {name} at {file_path}:{line}. "
                    f"Code: {snippet[:150]}"
                ),
                metadata={
                    "cwe": cwe,
                    "file": file_path,
                    "line": line,
                    "code_snippet": snippet[:300],
                    "source": source,
                    "confidence": confidence,
                    "scan_phase": "sast",
                },
                tags=[cwe, "static", "sast", source],
                confidence=confidence,
            )

        # Build graph after SAST ingestion
        await self.memory.build()
        logger.info("SAST findings ingested and graph built")

    async def run_dast_tools(self, target_url: str) -> list:
        """
        Run Nuclei/ZAP DAST tools and ingest findings into Cognee.
        Returns DynamicFinding[] for the pipeline.
        """
        dast_findings = []
        tool_used = "none"

        try:
            from cyphex.dynamic_scanner import run_dynamic_analysis
            dast_findings, tool_used = await run_dynamic_analysis(target_url)
            logger.info(f"DAST ({tool_used}): {len(dast_findings)} findings")
        except ImportError:
            logger.warning("dynamic_scanner not available, skipping Nuclei/ZAP")
        except Exception as e:
            logger.warning(f"DAST tools failed: {e}")

        # Ingest DAST findings into Cognee
        if self.memory and dast_findings:
            for f in dast_findings:
                await self.memory.agent_remember(
                    agent_id="dast_engine",
                    memory_type="FINDING",
                    content=(
                        f"[DAST/{f.source}] {f.cwe}: {f.name} at {f.url}. "
                        f"Template: {f.template_id}. Evidence: {f.evidence[:100]}"
                    ),
                    metadata={
                        "cwe": f.cwe,
                        "url": f.url,
                        "method": f.method,
                        "template_id": f.template_id,
                        "evidence": f.evidence[:300],
                        "curl_command": f.curl_command[:300],
                        "source": f.source,
                        "scan_phase": "dast",
                    },
                    tags=[f.cwe, f.severity.lower(), "dynamic", "dast", f.source],
                    confidence=0.95,
                )

            # Rebuild graph with DAST findings
            await self.memory.build()
            logger.info("DAST findings ingested and graph rebuilt")

        return dast_findings

    # ===================================================
    # TIER 2: DEEPAGENT ATTACK (Adaptive, Parallel)
    # ===================================================

    async def execute_agents(self, context: ScanContext) -> ScanContext:
        """
        Execute DeepAgents in parallel groups based on Cognee intelligence.

        FULL VISIBILITY: Shows every agent deployment decision, payload, and finding.
        """
        from agents.terminal import Colors

        # Analyze what we know
        self.feedback.ingest_context(context)

        # Query Cognee for prior intelligence
        prior_intel = []
        if self.memory:
            try:
                prior_intel = await self.memory.agent_recall(
                    f"vulnerabilities on {self.target_url}", limit=10
                )
            except Exception:
                pass

        # Build adaptive attack plan
        if self.sandbox_info and "services" in self.sandbox_info:
            plan = self._build_multiservice_attack_plan(context, prior_intel, self.sandbox_info["services"])
        else:
            plan = self._build_attack_plan(context, prior_intel)

        # -- Show attack plan --
        total_agents = sum(len(g) for g in plan.groups)
        print(f"\n  {Colors.CYAN}{Colors.BOLD}+{'-' * 60}+{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}|  [HEADER] ATTACK PLAN{'':>43}|{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}|  Agents: {total_agents} active | Groups: {len(plan.groups)} parallel{'':>17}|{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}+{'-' * 60}+{Colors.RESET}")

        for gi, group in enumerate(plan.groups):
            agent_names = [getattr(a, 'agent_id', a.__class__.__name__) for a in group]
            print(f"  {Colors.DIM}  Group {gi+1}: {', '.join(agent_names)}{Colors.RESET}")

        if plan.skipped_agents:
            print(f"  {Colors.DIM}  Skipped: {', '.join(plan.skipped_agents)}{Colors.RESET}")
        print()

        # Execute each group
        for group_idx, group in enumerate(plan.groups):
            if not group:
                continue

            group_names = [getattr(a, 'agent_id', a.__class__.__name__) for a in group]

            # -- Sandbox health check before each group --
            try:
                from sandbox_manager import ensure_sandbox_alive, active_sandboxes
                sandbox_id = None
                for sid, sinfo in active_sandboxes.items():
                    if sinfo.get("url") and self.target_url.startswith(sinfo.get("url", "")):
                        sandbox_id = sid
                        break
                if not sandbox_id:
                    for sid in active_sandboxes:
                        if self.scan_id in sid:
                            sandbox_id = sid
                            break
                if sandbox_id:
                    is_alive = await ensure_sandbox_alive(sandbox_id)
                    if not is_alive:
                        print(f"  {Colors.RED}  [ERR] Sandbox dead — skipping remaining groups{Colors.RESET}")
                        break
            except Exception as hc_err:
                logger.debug(f"Health check skipped: {hc_err}")

            # -- Group header --
            print(f"  {Colors.CYAN}{Colors.BOLD}{'-' * 60}{Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}  > GROUP {group_idx + 1}/{len(plan.groups)}: "
                  f"{', '.join(group_names)} (parallel){Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}{'-' * 60}{Colors.RESET}")

            # Run agents in parallel within each group
            tasks = [agent.run(context) for agent in group]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect findings from this group
            group_vulns = []
            for agent, result in zip(group, results):
                if isinstance(result, AgentResult):
                    service_name = getattr(agent, "service_name", None)
                    if service_name:
                        for v in result.vulns:
                            v.service_name = service_name
                    group_vulns.extend(result.vulns)
                elif isinstance(result, Exception):
                    print(f"  {Colors.RED}  [ERR] Agent error: {result}{Colors.RESET}")

            # Council validates findings (if available)
            validated = group_vulns
            if self.council and group_vulns:
                try:
                    print(f"  {Colors.DIM}  [Council] Council validating {len(group_vulns)} findings...{Colors.RESET}")
                    validated = await self._council_validate(group_vulns)
                    rejected = len(group_vulns) - len(validated)
                    if rejected > 0:
                        print(f"  {Colors.YELLOW}     Council rejected {rejected} false positives{Colors.RESET}")
                except Exception:
                    validated = group_vulns

            # Add to context
            context.confirmed_vulns.extend(validated)

            # Real-time SPS update
            if validated and self._emit:
                try:
                    from security_posture_score import SecurityPostureCalculator
                    calc = SecurityPostureCalculator()
                    sps = calc.calculate(context)
                    # Use asyncio.create_task if _emit is an async callback
                    asyncio.create_task(self._emit({
                        "type": "security_score_update",
                        "score": sps.score,
                        "grade": sps.grade,
                        "critical": sps.critical_count,
                        "high": sps.high_count,
                        "vuln_count": sps.total_vulns,
                    }))
                except Exception as e:
                    logger.debug(f"Failed to emit score update: {e}")

            # -- Group summary --
            if validated:
                print(f"\n  {Colors.GREEN}{Colors.BOLD}  [OK] Group {group_idx + 1} findings: {len(validated)} vulnerabilities{Colors.RESET}")
                for v in validated:
                    sev_color = Colors.RED if v.severity in ("Critical", "High") else Colors.YELLOW
                    print(f"  {sev_color}     [{v.severity}] {v.name}{Colors.RESET}")
                    if v.payload:
                        print(f"  {Colors.DIM}       Payload: {v.payload[:80]}{Colors.RESET}")
            else:
                print(f"\n  {Colors.DIM}  [OK] Group {group_idx + 1}: No vulnerabilities found{Colors.RESET}")

            # Feed back into loop for next group
            self.feedback.ingest_findings(validated)

            # Rebuild Cognee graph between groups (fire-and-forget — don't block next group)
            if self.memory and group_vulns:
                asyncio.create_task(self._rebuild_memory_background())
            print()

        # ===============================================================
        # PHASE B — GENOME BUILD: Learn what "normal" looks like
        # ===============================================================
        phase_b_genome = None
        try:
            from immune.behavioral_genome import BehavioralGenome
            print(f"\n  {Colors.CYAN}{Colors.BOLD}{'-' * 60}{Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}  [DNA] [PHASE B] GENOME BUILD — Learning normal behaviour{Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}{'-' * 60}{Colors.RESET}")
            phase_b_genome = BehavioralGenome()
            genome_state = phase_b_genome.build_from_scan(context)
            n_endpoints = len(genome_state.endpoints)
            print(
                f"  {Colors.GREEN}  [OK] BehavioralGenome trained on {n_endpoints} endpoint(s){Colors.RESET}"
            )
            print(f"  {Colors.DIM}    Isolation Forest models fitted — anomaly detection ACTIVE{Colors.RESET}")
        except ImportError:
            logger.warning("BehavioralGenome not available — skipping genome build")
        except Exception as e:
            logger.warning(f"Genome build failed (non-fatal): {e}")

        # ===============================================================
        # PHASE C — GENOME VALIDATION: Prove same attacks are now BLOCKED
        # ===============================================================
        if phase_b_genome and context.confirmed_vulns:
            print(f"\n  {Colors.CYAN}{Colors.BOLD}{'-' * 60}{Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}  [PHASE C] GENOME VALIDATION — Attack replay{Colors.RESET}")
            print(f"  {Colors.CYAN}{Colors.BOLD}{'-' * 60}{Colors.RESET}")
            print(
                f"  {Colors.DIM}  Replaying {len(context.confirmed_vulns)} confirmed payload(s) "
                f"through genome anomaly detector...{Colors.RESET}"
            )
            blocked_count = 0
            passed_count = 0
            GENOME_BLOCK_THRESHOLD = 0.5
            for v in context.confirmed_vulns[:10]:
                payload = v.payload or ""
                if not payload:
                    continue
                try:
                    endpoint = v.endpoint or self.target_url
                    anomaly_score = phase_b_genome.score_request(endpoint, payload)
                    is_blocked = anomaly_score >= GENOME_BLOCK_THRESHOLD
                    if is_blocked:
                        blocked_count += 1
                        print(
                            f"  {Colors.GREEN}  BLOCKED{Colors.RESET} [{v.severity}] {v.name[:50]}"
                            f"  {Colors.DIM}(score={anomaly_score:.2f}){Colors.RESET}"
                        )
                    else:
                        passed_count += 1
                        print(
                            f"  {Colors.YELLOW}  EVADED{Colors.RESET}  [{v.severity}] {v.name[:50]}"
                            f"  {Colors.DIM}(score={anomaly_score:.2f} — more training needed){Colors.RESET}"
                        )
                except Exception as ge:
                    logger.debug(f"Genome validation probe failed: {ge}")
            print(
                f"\n  {Colors.GREEN}{Colors.BOLD}  Genome Defence Summary: "
                f"{blocked_count} blocked | {passed_count} evaded{Colors.RESET}"
                f"  {Colors.DIM}(accuracy improves with each scan){Colors.RESET}\n"
            )
        elif context.confirmed_vulns and not phase_b_genome:
            print(f"  {Colors.DIM}  [PHASE C skipped — genome not built]{Colors.RESET}")

        return context

    async def _rebuild_memory_background(self) -> None:
        """
        Build the Cognee knowledge graph in the background without blocking
        the next agent group. Launched via asyncio.create_task() between groups.
        """
        try:
            await self.memory.build(timeout=120.0)
            print(f"  {Colors.DIM}  [Cognee] Cognee graph ready (background rebuild complete){Colors.RESET}")
        except Exception as e:
            logger.debug(f"Background Cognee rebuild failed (non-fatal): {e}")

    def _build_attack_plan(
        self, context: ScanContext, prior_intel: list
    ) -> AttackPlan:
        """
        Build an adaptive attack plan using DeepAgents (Oracle-guided).
        Shared AttackGraph + ASI + Oracle enable cross-agent intelligence.

        ALL 10 DeepAgents run unconditionally — the Oracle's plan() will
        generate zero hypotheses if the surface has nothing to test, so
        agents self-terminate cleanly without skipping at the orchestrator level.
        This ensures every vulnerability class is always evaluated.
        """
        from agents.terminal import Colors
        plan = AttackPlan()

        # Import DeepAgents — log verbosely on failure so we know EXACTLY why
        try:
            import sys as _sys
            _backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _backend_root not in _sys.path:
                _sys.path.insert(0, _backend_root)

            from deepagents.deep_sqli import DeepSQLiAgent
            from deepagents.deep_xss import DeepXSSAgent
            from deepagents.deep_auth import DeepAuthAgent
            from deepagents.deep_cmdi import DeepCMDiAgent
            from deepagents.deep_path_traversal import DeepPathTraversalAgent
            from deepagents.deep_ssrf import DeepSSRFAgent
            from deepagents.deep_ssti import DeepSSTIAgent
            from deepagents.deep_xxe import DeepXXEAgent
            from deepagents.deep_idor import DeepIDORAgent
            from deepagents.deep_business_logic import DeepBusinessLogicAgent
            # NEW v4.4 agents
            from deepagents.deep_prompt_injection import DeepPromptInjectionAgent
            from deepagents.deep_race_condition import DeepRaceConditionAgent
            from deepagents.deep_mass_assignment import DeepMassAssignmentAgent
            from deepagents.oracle_attack import AttackOracle
            from deepagents.attack_graph import AttackGraph as DeepAttackGraph
            from deepagents.attack_surface_index import AttackSurfaceIndex
            print(f"  {Colors.GREEN}[OK] All 13 DeepAgents loaded successfully{Colors.RESET}")
        except ImportError as e:
            import traceback
            tb = traceback.format_exc()
            logger.error(f"DeepAgent import FAILED: {e}\n{tb}")
            print(f"  {Colors.RED}[ERR] DeepAgent import failed: {e}{Colors.RESET}")
            print(f"  {Colors.YELLOW}  -> Falling back to legacy agents{Colors.RESET}")
            print(f"  {Colors.DIM}{tb[:500]}{Colors.RESET}")
            return self._build_legacy_plan(context, prior_intel)

        # -- Create shared infrastructure --
        graph = DeepAttackGraph()
        asi = AttackSurfaceIndex()
        oracle = AttackOracle()

        # -- Seed ASI from recon data (bridge recon -> deepagents) --
        for ep in context.all_endpoints:
            asi.ingest_response(ep, "GET", "", 200, "", {})
        for form in context.all_forms:
            body_parts = "&".join(f"{inp}=test" for inp in form.inputs) if form.inputs else ""
            asi.ingest_response(form.action, form.method.upper(), body_parts, 200, "", {})
        for param in context.all_params:
            full_url = f"{param.url}?{param.name}=test"
            asi.ingest_response(full_url, "GET", "", 200, "", {})
        # Seed from discovered paths (recon agent finds these even on API-only servers)
        for path in context.discovered_paths:
            asi.ingest_response(path, "GET", "", 200, "", {})
        # Seed from all crawled links
        for link in context.all_links:
            asi.ingest_response(link, "GET", "", 200, "", {})
        # If still empty, seed with the target URL itself so agents have something to test
        if not asi.endpoints:
            asi.ingest_response(self.target_url, "GET", "", 200, "", {})

        logger.info(f"ASI seeded: {len(asi.endpoints)} endpoints profiled")
        print(f"  {Colors.DIM}  ASI: {len(asi.endpoints)} endpoint(s) profiled for DeepAgents{Colors.RESET}")

        # Helper to create DeepAgent with shared infrastructure
        def make_deep(agent_cls):
            return agent_cls(
                scan_id=self.scan_id,
                target_url=self.target_url,
                attack_graph=graph,
                asi=asi,
                oracle=oracle,
            )

        # ===============================================================
        # PHASE A — RED TEAM: All 13 DeepAgents attack BEFORE genome build
        # The Oracle will self-terminate if surface has nothing to probe.
        # ===============================================================
        print(f"  {Colors.RED}{Colors.BOLD}  [PHASE A] RED TEAM — Pre-genome attack phase{Colors.RESET}")

        # -- Group 1: Core injection (always run — every app has input fields) --
        group1 = [
            make_deep(DeepSQLiAgent),
            make_deep(DeepXSSAgent),
            make_deep(DeepAuthAgent),
        ]
        plan.groups.append(group1)

        # -- Group 2: All surface-dependent agents (always run — Oracle self-skips) --
        group2 = [
            make_deep(DeepPathTraversalAgent),
            make_deep(DeepCMDiAgent),
            make_deep(DeepSSRFAgent),
            make_deep(DeepIDORAgent),
            make_deep(DeepSSTIAgent),
            make_deep(DeepXXEAgent),
        ]
        plan.groups.append(group2)

        # -- Group 3: Business logic (uses full graph intelligence) --
        plan.groups.append([make_deep(DeepBusinessLogicAgent)])

        # -- Group 4: Modern attack surface (v4.4 — Prompt Injection, Race, Mass Assignment) --
        group4 = [
            make_deep(DeepPromptInjectionAgent),
            make_deep(DeepRaceConditionAgent),
            make_deep(DeepMassAssignmentAgent),
        ]
        plan.groups.append(group4)

        return plan

    def _build_multiservice_attack_plan(
        self, context: ScanContext, prior_intel: list, services: dict
    ) -> AttackPlan:
        from agents.terminal import Colors
        plan = AttackPlan()

        try:
            import sys as _sys
            _backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _backend_root not in _sys.path:
                _sys.path.insert(0, _backend_root)

            from cyphex.agent_routing import get_agents_for_service
            from deepagents.oracle_attack import AttackOracle
            from deepagents.attack_graph import AttackGraph as DeepAttackGraph
            from deepagents.attack_surface_index import AttackSurfaceIndex
        except ImportError as e:
            logger.error(f"Failed to load modules for multiservice plan: {e}")
            return self._build_legacy_plan(context, prior_intel)

        # -- Shared infrastructure across ALL services --
        graph = DeepAttackGraph()
        asi = AttackSurfaceIndex()
        oracle = AttackOracle()

        # Seed ASI for all services
        for ep in context.all_endpoints:
            asi.ingest_response(ep, "GET", "", 200, "", {})
        for form in context.all_forms:
            body_parts = "&".join(f"{inp}=test" for inp in form.inputs) if form.inputs else ""
            asi.ingest_response(form.action, form.method.upper(), body_parts, 200, "", {})
        for param in context.all_params:
            full_url = f"{param.url}?{param.name}=test"
            asi.ingest_response(full_url, "GET", "", 200, "", {})
        for path in context.discovered_paths:
            asi.ingest_response(path, "GET", "", 200, "", {})
        for link in context.all_links:
            asi.ingest_response(link, "GET", "", 200, "", {})

        # Also seed each service's URL
        for s_name, s_data in services.items():
            asi.ingest_response(s_data["url"], "GET", "", 200, "", {})

        logger.info(f"Multiservice ASI seeded: {len(asi.endpoints)} endpoints across {len(services)} services")
        print(f"  {Colors.RED}{Colors.BOLD}  [PHASE A] RED TEAM — Multi-service Pre-genome attack phase{Colors.RESET}")

        flat_agents = []
        for s_name, s_data in services.items():
            target_url = s_data["url"]
            stack = s_data.get("stack", "unknown")
            agent_classes = get_agents_for_service(s_name, stack)
            for agent_cls in agent_classes:
                agent = agent_cls(
                    scan_id=self.scan_id,
                    target_url=target_url,
                    attack_graph=graph,
                    asi=asi,
                    oracle=oracle,
                )
                # Monkeypatch service_name onto agent for later extraction when vulns are created
                agent.service_name = s_name
                # Also override agent_id to include service name for display
                agent.agent_id = f"{agent_cls.__name__} ({s_name})"
                flat_agents.append(agent)
                
        # Split flat_agents into chunks of 5 to avoid overwhelming docker host
        chunk_size = 5
        for i in range(0, len(flat_agents), chunk_size):
            plan.groups.append(flat_agents[i:i+chunk_size])

        return plan

    def _build_legacy_plan(
        self, context: ScanContext, prior_intel: list
    ) -> AttackPlan:
        """Fallback: legacy agents if DeepAgent import fails."""
        plan = AttackPlan()
        try:
            from agents.agent_03_sqli import SQLiAgent
            from agents.agent_04_xss import XSSAgent
            from agents.agent_05_auth import AuthAgent
        except ImportError:
            return plan

        def make(agent_cls):
            return agent_cls(self.scan_id, self.target_url)

        group1 = []
        if context.all_forms or context.all_endpoints:
            group1.append(make(SQLiAgent))
            group1.append(make(XSSAgent))
        if context.all_forms:
            group1.append(make(AuthAgent))
        if group1:
            plan.groups.append(group1)
        return plan

    def _has_cwe_in_intel(self, cwe: str, intel: list) -> bool:
        """Check if a CWE was found in prior Cognee intelligence."""
        return any(cwe in str(item) for item in intel)

    async def _council_validate(self, vulns: list[Vuln]) -> list[Vuln]:
        """Run council debate to validate findings (reduce false positives)."""
        if not self.council:
            return vulns
        try:
            # Only debate High/Critical findings to save time
            to_debate = [v for v in vulns if v.severity in ("Critical", "High")]
            others = [v for v in vulns if v.severity not in ("Critical", "High")]

            if not to_debate:
                return vulns

            validated = []
            for vuln in to_debate:
                result = await self.council.debate(
                    finding=vuln.to_dict(),
                    context={"target": self.target_url},
                )
                if result.get("consensus", "") != "false_positive":
                    validated.append(vuln)
                else:
                    logger.info(f"Council rejected: {vuln.name}")

            return validated + others
        except Exception:
            return vulns

    # ===================================================
    # TIER 3: AUTONOMOUS EXPLOIT CHAINS
    # ===================================================

    async def run_exploit_chains(self, context: ScanContext) -> None:
        """
        For critical findings, run autonomous multi-step exploit chains.
        Uses the ReAct loop from BaseAgent.autonomous_exploit_loop().
        """
        critical_vulns = [
            v for v in context.confirmed_vulns
            if v.severity == "Critical" and v.confirmed
        ]

        if not critical_vulns:
            return

        logger.info(f"Running exploit chains on {len(critical_vulns)} critical vulns")

        # Import a generic exploit agent
        try:
            from deep_agent import DeepAgent
        except ImportError:
            return

        for vuln in critical_vulns[:3]:  # Limit to 3 chains
            # Build chain description
            chain_desc = (
                f"You found {vuln.name} at {vuln.endpoint}. "
                f"Payload that worked: {vuln.payload[:100] if vuln.payload else 'N/A'}. "
                f"Now try to: 1) Extract sensitive data, "
                f"2) Escalate privileges, 3) Demonstrate maximum impact. "
                f"Use the confirmed vulnerability as your entry point."
            )

            # Use any available agent to run the chain
            try:
                from agents.agent_03_sqli import SQLiAgent
                chain_agent = SQLiAgent(self.scan_id, self.target_url)
                if self.memory and hasattr(chain_agent, "memory"):
                    chain_agent.memory = self.memory
                await chain_agent.autonomous_exploit_loop(
                    context, chain_desc, max_steps=5
                )
                # Add any new vulns found during the chain
                context.confirmed_vulns.extend(chain_agent.vulns)
            except Exception as e:
                logger.warning(f"Exploit chain failed: {e}")
