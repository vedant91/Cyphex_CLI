"""DeepXSSAgent — Oracle-guided XSS with reflected/stored/DOM and CSP bypass."""
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.payloads.xss import XSS_T1, XSS_T2, XSS_DOM
from backend.deepagents.oracle_attack import HttpRequest

class DeepXSSAgent(BaseDeepAgent):
    """
    Oracle-guided Cross-Site Scripting agent.
    Covers: reflected XSS, stored XSS (via POST then GET), DOM XSS, CSP bypass.
    Pre-flight probes all string-param endpoints with T1 payloads.
    """
    PRIMARY_VULN_CLASS = "Cross-Site Scripting (XSS)"

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        has_string = any(p.has_string_params for p in self.asi.endpoints.values())
        if not has_string:
            self.console.print("[dim]DeepXSSAgent: no string parameters found, skipping.[/dim]")
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        # Pre-flight: fast T1 reflected XSS check
        await self._preflight_xss(context)

        return await super().run(context)

    async def _preflight_xss(self, context: ScanContext) -> None:
        """Try T1 payloads on all string-param endpoints and check reflection."""
        for path, profile in self.asi.endpoints.items():
            if not profile.has_string_params:
                continue
            for param in list(profile.params)[:3]:
                for payload in XSS_T1[:3]:
                    full_path = f"{path}?{param}={payload}"
                    status, body, elapsed, headers = await self._http_probe(
                        HttpRequest(method="GET", path=full_path, payload=payload)
                    )
                    self.asi.ingest_response(path, "GET", "", status, body, headers)
                    if payload in body or payload.lower() in body.lower():
                        self.console.print(
                            f"[red][DeepXSS] Reflected XSS at {full_path}[/red]"
                        )
                        self.vulns.append(Vuln(
                            name="[DYNAMIC] Reflected XSS",
                            cwe="CWE-79",
                            severity="High",
                            endpoint=full_path,
                            payload=payload,
                            confirmed=True,
                            evidence=f"Payload reflected in response body",
                            fix="HTML-encode all user-controlled output; use Content-Security-Policy.",
                        ))
                        return
