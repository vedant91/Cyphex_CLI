"""DeepSSTIAgent — Oracle-guided Server-Side Template Injection with engine identification and RCE chains."""
import re
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest
from backend.deepagents.payloads.ssti import SSTI_PROBES, SSTI_ENGINES
from backend.deepagents.payloads.cmdi import CMDI_OUTPUT_SIGS

class DeepSSTIAgent(BaseDeepAgent):
    """
    Server-Side Template Injection agent.
    Phase 1: Math probes to detect template evaluation.
    Phase 2: Engine-specific RCE chains after engine identified.
    Covers: Jinja2, Twig, ERB, Freemarker, Mako, Velocity, Pug, Smarty.
    """
    PRIMARY_VULN_CLASS = "Server-Side Template Injection (SSTI)"

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        has_string = any(p.has_string_params for p in self.asi.endpoints.values())
        if not has_string:
            self.console.print("[dim]DeepSSTIAgent: no string parameters found, skipping.[/dim]")
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        detected_engine = await self._detect_ssti(context)
        if detected_engine:
            await self._exploit_ssti(context, detected_engine)

        return await super().run(context)

    async def _detect_ssti(self, context: ScanContext) -> str | None:
        """Phase 1: Try math probes to detect template evaluation."""
        for path, profile in self.asi.endpoints.items():
            if not profile.has_string_params:
                continue
            for param in list(profile.params)[:3]:
                for payload, expected in SSTI_PROBES[:8]:
                    full_path = f"{path}?{param}={payload}"
                    req = HttpRequest(method="GET", path=full_path, payload=payload)
                    status, body, elapsed, headers = await self._http_probe(req)
                    self.asi.ingest_response(path, "GET", "", status, body, headers)

                    if expected in body:
                        self.console.print(
                            f"[red][DeepSSTI] Template evaluation detected at {full_path}! "
                            f"payload={payload!r} → response contains {expected!r}[/red]"
                        )
                        # Identify engine from payload pattern
                        engine = self._identify_engine(payload)
                        self.vulns.append(Vuln(
                            name=f"[DYNAMIC] Server-Side Template Injection — {engine or 'Unknown Engine'}",
                            cwe="CWE-94",
                            severity="Critical",
                            endpoint=full_path,
                            payload=payload,
                            confirmed=True,
                            evidence=f"Server evaluated {payload!r} → returned {expected!r}",
                            fix="Never pass user input to template render() calls; use static templates with safe context variables.",
                        ))
                        return engine
        return None

    async def _exploit_ssti(self, context: ScanContext, engine: str) -> None:
        """Phase 2: Attempt RCE via engine-specific payloads."""
        rce_payloads = SSTI_ENGINES.get(engine, [])
        if not rce_payloads:
            return

        for path, profile in self.asi.endpoints.items():
            if not profile.has_string_params:
                continue
            for param in list(profile.params)[:2]:
                for payload in rce_payloads[:3]:
                    full_path = f"{path}?{param}={payload}"
                    req = HttpRequest(method="GET", path=full_path, payload=payload)
                    status, body, elapsed, headers = await self._http_probe(req)
                    self.asi.ingest_response(path, "GET", "", status, body, headers)
                    matched = [s for s in CMDI_OUTPUT_SIGS if re.search(s, body, re.I)]
                    if matched:
                        self.console.print(f"[red][DeepSSTI] RCE via {engine} SSTI![/red]")
                        self.vulns.append(Vuln(
                            name=f"[DYNAMIC] SSTI RCE — {engine}",
                            cwe="CWE-94",
                            severity="Critical",
                            endpoint=full_path,
                            payload=payload,
                            confirmed=True,
                            rce_output=body[:400],
                            evidence=matched[0],
                            fix=f"Sandbox the template engine; sanitise all inputs before rendering.",
                        ))
                        return

    @staticmethod
    def _identify_engine(payload: str) -> str:
        if "{{" in payload:
            return "jinja2"
        if "${" in payload:
            return "freemarker"
        if "<%" in payload:
            return "erb"
        if "#{" in payload:
            return "ruby"
        if "{$" in payload:
            return "smarty"
        return "unknown"
