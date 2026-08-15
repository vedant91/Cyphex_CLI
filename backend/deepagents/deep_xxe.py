"""DeepXXEAgent — Oracle-guided XML External Entity injection."""
import re
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest
from backend.deepagents.payloads.xxe import XXE_T1
from backend.deepagents.payloads.path_traversal import LFI_SUCCESS_SIGS

class DeepXXEAgent(BaseDeepAgent):
    """
    XML External Entity injection agent.
    Detects XML-accepting endpoints from Content-Type headers and
    endpoint path patterns, then injects XXE payloads.
    """
    PRIMARY_VULN_CLASS = "XML External Entity Injection (XXE)"

    # Paths that commonly accept XML
    XML_PATH_HINTS = [
        "/api/xml", "/xml", "/soap", "/wsdl", "/api/upload",
        "/api/import", "/api/parse", "/api/convert", "/api/data",
    ]
    XML_CONTENT_TYPES = [
        "application/xml", "text/xml", "application/soap+xml",
    ]

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        # Detect XML-accepting endpoints
        xml_endpoints = self._find_xml_endpoints()
        if not xml_endpoints:
            self.console.print("[dim]DeepXXEAgent: no XML-accepting endpoints detected, skipping.[/dim]")
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        await self._probe_xxe(context, xml_endpoints)
        return await super().run(context)

    def _find_xml_endpoints(self) -> list[str]:
        """Find endpoints that likely accept XML input."""
        candidates = []
        for path in self.asi.endpoints:
            if any(hint in path.lower() for hint in self.XML_PATH_HINTS):
                candidates.append(path)
        # Always add the known XML hints themselves for direct probing
        candidates.extend(self.XML_PATH_HINTS[:5])
        return list(set(candidates))

    async def _probe_xxe(self, context: ScanContext, endpoints: list[str]) -> None:
        """Inject XXE payloads into XML-accepting endpoints."""
        for path in endpoints:
            for xxe_payload in XXE_T1:
                req = HttpRequest(
                    method="POST",
                    path=path,
                    body=xxe_payload,
                    headers={"Content-Type": "application/xml"},
                    payload="xxe_entity",
                )
                status, body, elapsed, headers = await self._http_probe(req)
                self.asi.ingest_response(path, "POST", req.body, status, body, headers)

                matched = [s for s in LFI_SUCCESS_SIGS if re.search(s, body, re.I)]
                if matched:
                    self.console.print(f"[red][DeepXXE] XXE confirmed at {path}![/red]")
                    self.vulns.append(Vuln(
                        name="[DYNAMIC] XML External Entity (XXE) Injection",
                        cwe="CWE-611",
                        severity="Critical",
                        endpoint=path,
                        payload=xxe_payload[:200],
                        confirmed=True,
                        evidence=f"File content leaked: {matched[0]}",
                        fix="Disable external entity processing in XML parser; use JSON where possible.",
                    ))
                    return
                # Check for SSRF via XXE (HTTP request made to internal)
                if status == 200 and any(k in body.lower() for k in ("ami-id", "computemetadata", "instance")):
                    self.vulns.append(Vuln(
                        name="[DYNAMIC] XXE-based SSRF",
                        cwe="CWE-611",
                        severity="Critical",
                        endpoint=path,
                        payload=xxe_payload[:200],
                        confirmed=True,
                        evidence="Internal metadata retrieved via XXE entity resolution",
                        fix="Disable external entity processing; firewall egress from app servers.",
                    ))
                    return
