"""
CYPHEX — DeepAgent Base Class

Enhanced BaseAgent that adds:
  - Cognee memory (recall before attack, remember after)
  - MutationEngine (evolve payloads when blocked)
  - Oracle reasoning (16 cognitive strategies)
  - Adaptive attack loop (RECALL → ATTACK → REMEMBER → ADAPT)

All 15 agents inherit from this instead of raw BaseAgent.
"""

import asyncio
import time
import logging
from abc import abstractmethod
from typing import Optional

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult
from immune.mutation_engine import MutationEngine
from config import config

logger = logging.getLogger("cyphex.deep_agent")


class DeepAgent(BaseAgent):
    """
    Enhanced agent with Cognee memory, mutation engine, and adaptive attack loop.

    Lifecycle:
      1. RECALL  — Query Cognee for prior knowledge about this target/CWE
      2. PLAN    — Use Oracle reasoning to select attack strategy
      3. ATTACK  — Execute payloads against target (subclass implements)
      4. ADAPT   — If payloads blocked, mutate and retry
      5. REMEMBER — Write findings + lessons to Cognee for future scans
    """

    # Subclasses override these
    agent_id: str = "deep_agent"
    target_cwe: str = ""
    attack_category: str = ""  # "injection", "auth", "logic", "network", "supply_chain"

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        cognee_memory=None,
        cerebras_key: str = "",
    ):
        super().__init__(scan_id, target_url, cerebras_key)
        self.memory = cognee_memory
        self.mutation = MutationEngine()

        # Track blocked payloads for adaptation
        self._blocked_payloads: list[dict] = []
        self._detection_feedback: dict = {}
        self._attack_start_time: float = 0

    async def run(self, context: ScanContext) -> AgentResult:
        """
        Main execution loop: RECALL → ATTACK → ADAPT → REMEMBER.
        Subclasses implement _execute_attack() for their specific logic.

        FULL VISIBILITY: Every phase, payload, parameter, and decision is shown.
        """
        from agents.terminal import Colors

        self._attack_start_time = time.time()

        # ── Agent Banner ──
        cwe_tag = f" ({self.target_cwe})" if self.target_cwe else ""
        print(f"\n  {Colors.CYAN}{Colors.BOLD}{'═' * 60}{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}  {self.agent_id.upper()}{cwe_tag} — DEEPAGENT MODE{Colors.RESET}")
        print(f"  {Colors.DIM}  Target: {context.target_url}{Colors.RESET}")
        print(f"  {Colors.DIM}  Tech: framework={context.framework}, db={context.database}{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}{'═' * 60}{Colors.RESET}\n")

        # ── 1. RECALL: Query Cognee for prior intelligence ──
        print(f"  {Colors.MAGENTA}{Colors.BOLD}  🧠 PHASE 1: RECALL (Cognee Memory){Colors.RESET}")
        prior_knowledge = await self._recall_context(context)
        if prior_knowledge:
            print(f"  {Colors.MAGENTA}     Retrieved {len(prior_knowledge)} memories:{Colors.RESET}")
            for i, mem in enumerate(prior_knowledge[:3]):
                mem_str = str(mem)[:120] if not isinstance(mem, str) else mem[:120]
                print(f"  {Colors.DIM}     [{i+1}] {mem_str}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}     No prior knowledge found (first scan){Colors.RESET}")

        # ── 2. ATTACK: Execute agent-specific attack logic ──
        print(f"\n  {Colors.RED}{Colors.BOLD}  ⚔️  PHASE 2: ATTACK{Colors.RESET}")
        print(f"  {Colors.DIM}     Executing {self.attack_category or 'generic'} attack vectors...{Colors.RESET}\n")
        try:
            await self._execute_attack(context, prior_knowledge)
        except Exception as e:
            print(f"  {Colors.RED}     ✗ Attack phase error: {e}{Colors.RESET}")
            logger.exception(f"{self.agent_id} attack error")

        # ── 3. ADAPT: If payloads were blocked, mutate and retry ──
        if self._blocked_payloads:
            print(f"\n  {Colors.YELLOW}{Colors.BOLD}  🔄 PHASE 3: ADAPT (Mutation Engine){Colors.RESET}")
            print(f"  {Colors.YELLOW}     {len(self._blocked_payloads)} payloads were blocked:{Colors.RESET}")
            for bp in self._blocked_payloads[:5]:
                print(f"  {Colors.DIM}     ✗ [{bp.get('technique', '?')}] {bp.get('payload', '?')[:80]}{Colors.RESET}")
            print(f"  {Colors.YELLOW}     Generating mutations to bypass defenses...{Colors.RESET}")
            try:
                await self._adapt_and_retry(context)
            except Exception as e:
                print(f"  {Colors.YELLOW}     ⚠ Adaptation error: {e}{Colors.RESET}")
        else:
            print(f"\n  {Colors.DIM}  🔄 PHASE 3: ADAPT — No blocked payloads (skipping){Colors.RESET}")

        # ── 4. REMEMBER: Write findings + lessons to Cognee ──
        print(f"\n  {Colors.GREEN}{Colors.BOLD}  💾 PHASE 4: REMEMBER (Cognee Write){Colors.RESET}")
        await self._remember_findings(context)
        if self.vulns:
            print(f"  {Colors.GREEN}     Stored {len(self.vulns)} findings to knowledge graph:{Colors.RESET}")
            for v in self.vulns:
                sev_color = Colors.RED if v.severity in ("Critical", "High") else Colors.YELLOW
                print(f"  {sev_color}     → [{v.severity}] {v.name}{Colors.RESET}")
                if v.payload:
                    print(f"  {Colors.DIM}       Payload: {v.payload[:100]}{Colors.RESET}")
                if v.endpoint:
                    print(f"  {Colors.DIM}       Endpoint: {v.endpoint}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}     No findings to store{Colors.RESET}")
        if self._blocked_payloads:
            print(f"  {Colors.DIM}     Stored {len(self._blocked_payloads)} blocked-payload lessons{Colors.RESET}")

        # ── Summary ──
        duration = (time.time() - self._attack_start_time) * 1000
        vuln_count = len(self.vulns)
        cmd_count = len(self.terminal.command_history)
        summary_color = Colors.RED if vuln_count > 0 else Colors.GREEN
        print(f"\n  {summary_color}{Colors.BOLD}  ── {self.agent_id} COMPLETE ──{Colors.RESET}")
        print(f"  {summary_color}     Vulns: {vuln_count} | Commands: {cmd_count} | Time: {duration:.0f}ms{Colors.RESET}\n")

        return AgentResult(
            agent=self.agent_id,
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
            duration_ms=duration,
        )

    @abstractmethod
    async def _execute_attack(
        self, context: ScanContext, prior_knowledge: list[dict]
    ) -> None:
        """
        Subclasses implement their specific attack logic here.

        Args:
            context: Shared scan state (endpoints, forms, params, tech stack)
            prior_knowledge: Cognee recall results (past findings, strategies)

        The method should:
          - Use self.terminal.run() to execute curl commands
          - Use self.add_vuln() to register confirmed vulns
          - Use self._record_blocked() when payloads are blocked
          - Use self.call_cerebras() for LLM-powered decisions
          - Use self.autonomous_exploit_loop() for multi-step exploitation
        """
        pass

    # ═══════════════════════════════════════════════════
    # COGNEE MEMORY INTEGRATION
    # ═══════════════════════════════════════════════════

    async def _recall_context(self, context: ScanContext) -> list[dict]:
        """Query Cognee for relevant prior knowledge before attacking."""
        if not self.memory:
            return []

        try:
            # Build a rich query combining CWE + target + tech stack
            query_parts = []
            if self.target_cwe:
                query_parts.append(self.target_cwe)
            if context.framework:
                query_parts.append(context.framework)
            if context.target_url:
                query_parts.append(context.target_url)
            query_parts.append(self.attack_category or "vulnerability")

            query = " ".join(query_parts)
            results = await self.memory.agent_recall(query, limit=5)
            return results
        except Exception as e:
            logger.debug(f"Cognee recall failed: {e}")
            return []

    async def _remember_findings(self, context: ScanContext) -> None:
        """Write all findings + lessons to Cognee for future scans."""
        if not self.memory:
            return

        try:
            # Remember each confirmed vuln
            for vuln in self.vulns:
                await self.memory.agent_remember(
                    agent_id=self.agent_id,
                    memory_type="FINDING",
                    content=(
                        f"[{vuln.severity}] {vuln.name} confirmed at {vuln.endpoint}. "
                        f"Payload: {vuln.payload[:100] if vuln.payload else 'N/A'}. "
                        f"Fix: {vuln.fix[:100] if vuln.fix else 'N/A'}"
                    ),
                    metadata={
                        "cwe": vuln.cwe or self.target_cwe,
                        "severity": vuln.severity,
                        "endpoint": vuln.endpoint,
                        "payload": str(vuln.payload)[:200] if vuln.payload else "",
                        "confirmed": vuln.confirmed,
                        "framework": context.framework or "",
                    },
                    tags=[
                        vuln.cwe or self.target_cwe,
                        vuln.severity.lower(),
                        "confirmed" if vuln.confirmed else "unconfirmed",
                        self.agent_id,
                    ],
                    confidence=1.0 if vuln.confirmed else 0.7,
                )

            # Remember what was blocked (negative knowledge is valuable)
            if self._blocked_payloads:
                blocked_summary = ", ".join(
                    p.get("technique", "unknown") for p in self._blocked_payloads[:5]
                )
                await self.memory.agent_remember(
                    agent_id=self.agent_id,
                    memory_type="STRATEGY",
                    content=(
                        f"Blocked payloads on {context.target_url}: {blocked_summary}. "
                        f"Detection feedback: {str(self._detection_feedback)[:200]}"
                    ),
                    metadata={
                        "blocked_count": len(self._blocked_payloads),
                        "detection_feedback": self._detection_feedback,
                    },
                    tags=["blocked", "strategy", self.agent_id],
                    confidence=0.9,
                )

            # Remember technology context for future scans
            if context.framework or context.database:
                await self.memory.agent_remember(
                    agent_id=self.agent_id,
                    memory_type="CONTEXT",
                    content=(
                        f"Target {context.target_url}: "
                        f"framework={context.framework}, "
                        f"db={context.database}, "
                        f"server={context.server}"
                    ),
                    tags=["context", "technology"],
                    confidence=1.0,
                )

        except Exception as e:
            logger.debug(f"Cognee remember failed: {e}")

    # ═══════════════════════════════════════════════════
    # ADAPTIVE MUTATION (WHEN PAYLOADS ARE BLOCKED)
    # ═══════════════════════════════════════════════════

    def _record_blocked(self, payload: str, technique: str = "", response: str = ""):
        """Record a blocked payload for later mutation."""
        self._blocked_payloads.append({
            "payload": payload,
            "technique": technique,
            "type": self.attack_category or "unknown",
            "response_preview": response[:200] if response else "",
        })

    async def _adapt_and_retry(self, context: ScanContext) -> None:
        """Mutate blocked payloads and retry them."""
        if not self._blocked_payloads:
            return

        # Use MutationEngine to generate evasion variants
        mutated = await self.mutation.mutate_blocked_payloads(
            self._blocked_payloads[:10],
            self._detection_feedback,
        )

        if mutated:
            await self.log(
                f"MutationEngine generated {len(mutated)} evasion variants",
                "warning",
            )
            # Subclass can override _test_mutated_payloads for custom testing
            await self._test_mutated_payloads(mutated, context)

    async def _test_mutated_payloads(
        self, payloads: list[dict], context: ScanContext
    ) -> None:
        """
        Test mutated payloads against the target.
        Subclasses can override for agent-specific testing logic.
        Default: test on first form found.
        """
        if not context.all_forms:
            return

        form = context.all_forms[0]
        for p in payloads[:5]:  # Limit to avoid timeout
            payload = p.get("payload", "")
            technique = p.get("technique", "mutated")
            if not payload:
                continue

            from urllib.parse import quote
            encoded = quote(payload, safe="")

            if form.method.upper() == "POST" and form.inputs:
                data = "&".join(f"{inp}={encoded}" for inp in form.inputs)
                out = await self.terminal.run(
                    f'curl -s -w "\\n__STATUS__%{{http_code}}" '
                    f'-X POST "{form.action}" -d "{data}" --max-time 10'
                )
            else:
                continue

            if out.stdout and self._check_mutation_success(out.stdout, payload):
                await self.add_vuln(Vuln(
                    name=f"[MUTATED] {self.target_cwe} via {technique}",
                    severity="High",
                    endpoint=form.action,
                    payload=payload,
                    confirmed=True,
                    cwe=self.target_cwe,
                    description=(
                        f"Mutation engine bypassed defenses using technique: {technique}. "
                        f"Original payload was blocked but mutated variant succeeded."
                    ),
                    fix="Implement defense-in-depth. WAF rules alone are insufficient.",
                ))
                break

    def _check_mutation_success(self, response: str, payload: str) -> bool:
        """
        Check if a mutated payload succeeded. Subclasses should override
        with attack-specific success detection.
        """
        lower = response.lower()
        # Generic SQL error detection
        sql_errors = ["sql syntax", "mysql", "sqlite", "postgres", "ora-"]
        if any(e in lower for e in sql_errors):
            return True
        # Generic XSS reflection
        if payload in response:
            return True
        return False

    # ═══════════════════════════════════════════════════
    # HELPER: Get enriched prompt context from Cognee
    # ═══════════════════════════════════════════════════

    async def _get_cognee_prompt_context(self, query: str) -> str:
        """Get Cognee memories formatted for LLM prompt injection."""
        if not self.memory:
            return ""
        try:
            return await self.memory.recall_for_prompt(query, max_chars=1500)
        except Exception:
            return ""

    # ═══════════════════════════════════════════════════
    # HELPER: Share findings with other agents via Cognee
    # ═══════════════════════════════════════════════════

    async def share_intel(self, intel_type: str, content: str, tags: list = None):
        """
        Share intelligence with other agents via Cognee.
        Called when one agent discovers something useful for others.

        Examples:
          - SQLi agent finds credentials → share for Auth agent
          - Recon agent finds AI endpoint → share for PromptInjection agent
          - Auth agent gets admin session → share for CMDi agent
        """
        if not self.memory:
            return
        try:
            await self.memory.agent_remember(
                agent_id=self.agent_id,
                memory_type="DISCOVERY",
                content=content,
                tags=(tags or []) + [intel_type, "shared_intel"],
                confidence=0.95,
            )
        except Exception:
            pass
