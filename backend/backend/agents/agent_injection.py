"""
CYPHEX — Combined Injection Agent (SQLi + CMDi)

A unified injection testing agent that coordinates SQL Injection and
Command Injection attacks. If SQLi fails to extract credentials/data,
CMDi is escalated simultaneously to attempt RCE-based data extraction.

This agent wraps the existing SQLiAgent and CMDiAgent WITHOUT modifying
their internal logic — it simply coordinates their execution strategy.
"""

from agents.base_agent import BaseAgent
from agents.agent_03_sqli import SQLiAgent
from agents.agent_06_cmdi import CMDiAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class InjectionAgent(BaseAgent):
    """
    Combined Injection Agent: Runs SQLi and CMDi together.

    Strategy:
      1. Run SQLi first (fast, targeted at forms/params)
      2. If SQLi finds auth bypass but NO credential dump,
         escalate CMDi simultaneously to attempt RCE extraction
      3. If SQLi finds nothing, run CMDi independently
      4. Both agents' vulns are merged into a single result
    """

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("=== COMBINED INJECTION AGENT ===", "info")
        await self.log("Phase 1: Running SQLi Agent...", "info")

        # --- Phase 1: SQLi Agent ---
        sqli_agent = SQLiAgent(
            self.scan_id,
            self.target,
            self.cerebras_key,
        )
        sqli_result = await sqli_agent.run(context)

        sqli_vulns = sqli_result.vulns
        sqli_got_creds = any(
            v.dumped_data and len(v.dumped_data) > 3
            for v in sqli_vulns
            if hasattr(v, 'dumped_data') and v.dumped_data
        )
        sqli_found_injection = len(sqli_vulns) > 0

        # Merge SQLi results immediately
        self.vulns.extend(sqli_vulns)

        # --- Phase 2: CMDi Agent ---
        if sqli_found_injection and sqli_got_creds:
            await self.log(
                "SQLi extracted credentials — CMDi still running for full coverage...",
                "success",
            )
        elif sqli_found_injection and not sqli_got_creds:
            await self.log(
                "SQLi found injection but NO credential dump — escalating to CMDi for RCE...",
                "warning",
            )
        else:
            await self.log(
                "SQLi found nothing — running CMDi independently...",
                "info",
            )

        await self.log("Phase 2: Running CMDi/SSTI Agent...", "info")
        cmdi_agent = CMDiAgent(
            self.scan_id,
            self.target,
            self.cerebras_key,
        )
        cmdi_result = await cmdi_agent.run(context)

        # Merge CMDi results
        self.vulns.extend(cmdi_result.vulns)

        # --- Summary ---
        total = len(self.vulns)
        sqli_count = len(sqli_vulns)
        cmdi_count = len(cmdi_result.vulns)

        await self.log(
            f"Injection testing complete: {total} vulns "
            f"(SQLi={sqli_count}, CMDi/SSTI={cmdi_count})",
            "success" if total == 0 else "danger",
        )

        # Merge terminal logs from both sub-agents
        merged_logs = sqli_result.terminal_logs + cmdi_result.terminal_logs

        return AgentResult(
            agent="InjectionAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=merged_logs,
        )
