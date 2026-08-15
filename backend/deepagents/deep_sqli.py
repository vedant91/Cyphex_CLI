"""DeepSQLiAgent — Oracle-guided SQL Injection with error/boolean/time-based detection."""
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import Hypothesis, HttpRequest
from backend.deepagents.payloads.sqli import SQLI_T1, SQLI_T3, SQLI_TIME, SQLI_ERRORS
import re

class DeepSQLiAgent(BaseDeepAgent):
    """
    Oracle-guided SQL Injection agent.
    Pre-seeds the Oracle plan with contextual payloads from the ASI surface,
    then hands off to the adaptive Oracle loop.
    Covers: error-based, boolean-blind, time-based, UNION extraction.
    """
    PRIMARY_VULN_CLASS = "SQL Injection"
    # Time-based probes are slow — run sequentially (batch=1)
    PARALLEL_BATCH = 2

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        has_params = any(
            p.has_numeric_params or p.has_string_params
            for p in self.asi.endpoints.values()
        )
        has_errors = bool(self.asi.error_signatures)

        if not has_params and not has_errors:
            self.console.print("[dim]DeepSQLiAgent: no parameters detected, skipping.[/dim]")
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        # ── Quick pre-flight: try Tier-1 payloads directly on known endpoints ──
        # This catches obvious vulns without waiting for Oracle planning
        await self._preflight_sqli(context)

        # ── Then run Oracle adaptive loop for deeper testing ──
        return await super().run(context)

    async def _preflight_sqli(self, context: ScanContext) -> None:
        """Rapid fire T1 payloads on all string-param endpoints."""
        from backend.deepagents.oracle_attack import HttpRequest
        for path, profile in self.asi.endpoints.items():
            if not (profile.has_string_params or profile.has_numeric_params):
                continue
            for param in list(profile.params)[:3]:  # Top 3 params per endpoint
                for payload in SQLI_T1[:4]:          # T1 fast payloads
                    full_path = f"{path}?{param}={payload}"
                    status, body, elapsed, headers = await self._http_probe(
                        HttpRequest(method="GET", path=full_path, payload=payload)
                    )
                    self.asi.ingest_response(path, "GET", "", status, body, headers)
                    lower = body.lower()
                    matched = [e for e in SQLI_ERRORS if re.search(e, lower, re.I)]
                    if matched:
                        self.console.print(
                            f"[red][DeepSQLi] Pre-flight hit: SQL error at {full_path}[/red]"
                        )
                        self.vulns.append(Vuln(
                            name="[DYNAMIC] SQL Injection — Error-Based",
                            cwe="CWE-89",
                            severity="Critical",
                            endpoint=full_path,
                            payload=payload,
                            confirmed=True,
                            evidence=matched[0],
                            fix="Use parameterised queries / prepared statements.",
                        ))
                        return  # One hit is enough — Oracle takes it from here
