"""
CYPHEX — Agent 09: Cerebras AI Analysis Agent

Uses Cerebras AI to:
  - Analyze all confirmed vulnerabilities
  - Generate professional pentest report
  - Identify attack chains (how vulns combine)
  - Calculate business impact
  - Produce executive summary
"""

import json

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class CerebrasAnalysisAgent(BaseAgent):

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("=== AI ANALYSIS PHASE ===", "info")
        await self.log(
            f"Analyzing {len(context.confirmed_vulns)} confirmed vulnerabilities...",
            "info",
        )

        # Build evidence package from ALL previous agents
        evidence = self._build_evidence_package(context)

        system_prompt = """You are an elite penetration tester at Offensive Security.
You have just exploited a web application and have REAL confirmation 
of each vulnerability — actual HTTP request/response pairs, 
tool outputs, and execution results.

Your job: produce a professional pentest report.

Rules:
- CVSS 3.1 scores with full vector strings
- Show attack chains: how vulns combine for complete compromise
- Business impact (data breach cost, regulatory fines, downtime)
- Sort by CVSS descending
- JSON only, no markdown, no preamble
- Only report CONFIRMED vulns (confirmed=true in evidence)

Output this EXACT JSON schema:
{
  "executive_summary": "string - 2-3 sentences summarizing the overall risk",
  "total_risk_score": 0-100,
  "confirmed_vulns": [{
    "name": "",
    "severity": "Critical|High|Medium|Low",
    "cvss_score": 0.0,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "description": "",
    "proof_of_concept": "",
    "business_impact": "",
    "fix": ""
  }],
  "attack_chains": [{
    "name": "e.g. Complete Account Takeover",
    "steps": ["Step 1: ...", "Step 2: ..."],
    "impact": ""
  }]
}"""

        user_prompt = f"""
TARGET: {context.target_url}
FRAMEWORK: {context.framework or 'Unknown'}
DATABASE: {context.database or 'Unknown'}
OS: {context.os_type or 'Unknown'}
SERVER: {context.server or 'Unknown'}
TECHNOLOGIES: {', '.join(context.technologies) if context.technologies else 'Unknown'}

CONFIRMED EXPLOIT EVIDENCE ({len(context.confirmed_vulns)} vulns):
{json.dumps(evidence, indent=2)}

TOOL OUTPUTS (actual terminal results):
{self._format_terminal_logs(context.terminal_logs[-30:])}

Generate the full pentest report as JSON.
"""

        response = await self.call_cerebras(system_prompt, user_prompt)

        # Parse AI response
        report = self._parse_json(response)
        if not report:
            await self.log("AI response parse failed — generating fallback report", "warning")
            report = self._generate_fallback_report(context)
        else:
            await self.log("AI analysis report generated successfully", "success")

        # Print summary
        if isinstance(report, dict):
            risk = report.get("total_risk_score", "?")
            summary = report.get("executive_summary", "N/A")
            if not isinstance(summary, str):
                summary = str(summary)
            chains = report.get("attack_chains", [])

            await self.log(f"Total Risk Score: {risk}/100", "danger" if int(str(risk).replace("?","0")) > 70 else "warning")
            await self.log(f"Executive Summary: {summary[:200]}", "info")

            if chains:
                await self.log(f"Attack Chains Identified: {len(chains)}", "danger")
                for chain in chains:
                    if isinstance(chain, dict):
                        impact = chain.get("impact", "")
                        if not isinstance(impact, str):
                            impact = str(impact)
                        await self.log(
                            f"  ⛓ {chain.get('name', 'Unknown')}: "
                            f"{impact[:100]}",
                            "warning",
                        )

        return AgentResult(
            agent="CerebrasAnalysisAgent",
            report=report,
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    def _build_evidence_package(self, context: ScanContext) -> list[dict]:
        """Build evidence package from all confirmed vulns."""
        evidence = []
        for vuln in context.confirmed_vulns:
            evidence.append(vuln.to_dict())
        return evidence

    def _format_terminal_logs(self, logs) -> str:
        """Format terminal logs for AI consumption."""
        formatted = []
        for log in logs:
            if hasattr(log, 'to_dict'):
                d = log.to_dict()
                formatted.append(
                    f"$ {d['command']}\n"
                    f"  stdout: {d['stdout'][:200]}\n"
                    f"  exit: {d['exit_code']}"
                )
            elif isinstance(log, dict):
                formatted.append(
                    f"$ {log.get('command', '?')}\n"
                    f"  stdout: {log.get('stdout', '')[:200]}"
                )
        return "\n".join(formatted[-20:]) if formatted else "No terminal logs"

    def _generate_fallback_report(self, context: ScanContext) -> dict:
        """Generate a report without AI."""
        vulns = context.confirmed_vulns
        crits = [v for v in vulns if v.severity == "Critical"]
        highs = [v for v in vulns if v.severity == "High"]
        meds = [v for v in vulns if v.severity == "Medium"]

        avg_cvss = (
            sum(v.cvss_score for v in vulns) / len(vulns)
            if vulns else 0
        )
        risk_score = min(99, int(avg_cvss * 10))

        return {
            "executive_summary": (
                f"Penetration test of {context.target_url} revealed "
                f"{len(vulns)} vulnerabilities: {len(crits)} critical, "
                f"{len(highs)} high, {len(meds)} medium. "
                f"Overall risk score: {risk_score}/100."
            ),
            "total_risk_score": risk_score,
            "confirmed_vulns": [
                {
                    "name": v.name,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "fix": v.fix,
                }
                for v in sorted(vulns, key=lambda x: x.cvss_score, reverse=True)
            ],
            "attack_chains": self._identify_chains(vulns),
        }

    def _identify_chains(self, vulns) -> list[dict]:
        """Identify attack chains from vulnerability combinations."""
        chains = []
        vuln_names_lower = [v.name.lower() for v in vulns]

        # Chain: SQLi + Credential Exposure -> Full Compromise
        has_sqli = any("sql" in n for n in vuln_names_lower)
        has_creds = any("credential" in n or "default" in n or "password" in n
                        for n in vuln_names_lower)

        if has_sqli:
            chains.append({
                "name": "Database Compromise via SQL Injection",
                "steps": [
                    "Step 1: Exploit SQL injection to dump database",
                    "Step 2: Extract user credentials and admin passwords",
                    "Step 3: Login as admin with stolen credentials",
                    "Step 4: Full application takeover",
                ],
                "impact": "Complete data breach — all user data compromised",
            })

        # Chain: XSS + CSRF -> Account Takeover
        has_xss = any("xss" in n for n in vuln_names_lower)
        has_csrf = any("csrf" in n for n in vuln_names_lower)

        if has_xss and has_csrf:
            chains.append({
                "name": "Account Takeover via XSS + CSRF",
                "steps": [
                    "Step 1: Inject XSS payload in stored field",
                    "Step 2: Victim views page, XSS executes",
                    "Step 3: XSS forges CSRF request to change victim's password",
                    "Step 4: Attacker logs in as victim",
                ],
                "impact": "Any user account can be silently compromised",
            })

        # Chain: LFI + Exposed Credentials -> RCE
        has_lfi = any("lfi" in n or "file inclusion" in n or "traversal" in n
                      for n in vuln_names_lower)
        has_exposed = any("sensitive file" in n or "exposed" in n or ".env" in n
                          for n in vuln_names_lower)

        if has_lfi or has_exposed:
            chains.append({
                "name": "Credential Harvesting via File Access",
                "steps": [
                    "Step 1: Read .env or config files via LFI/exposure",
                    "Step 2: Extract database credentials and API keys",
                    "Step 3: Connect directly to database or cloud services",
                    "Step 4: Exfiltrate all data, pivot to cloud infrastructure",
                ],
                "impact": "Complete infrastructure compromise including cloud resources",
            })

        return chains
