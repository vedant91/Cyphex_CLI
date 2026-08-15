"""DeepSSRFAgent — Oracle-guided SSRF with cloud metadata and internal service probing."""
import re
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest
from backend.deepagents.payloads.ssrf import SSRF_CLOUD, SSRF_INTERNAL, SSRF_INTERNAL_SIGS
from backend.config.dast_constants import URL_PARAM_KEYWORDS

class DeepSSRFAgent(BaseDeepAgent):
    """
    Server-Side Request Forgery testing agent.
    Covers:
    - Cloud metadata endpoints (AWS, GCP, Azure)
    - Internal network ranges
    - Common internal services (Redis, Mongo, Elasticsearch)
    - Bypass techniques: decimal encoding, IPv6, Gopher protocol
    """
    PRIMARY_VULN_CLASS = "Server-Side Request Forgery (SSRF)"

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        has_url_params = any(p.has_file_param or p.has_format_param for p in self.asi.endpoints.values())
        url_param_endpoints = [
            (path, param)
            for path, profile in self.asi.endpoints.items()
            for param in profile.params
            if any(kw in param.lower() for kw in URL_PARAM_KEYWORDS)
        ]

        if not has_url_params and not url_param_endpoints:
            self.console.print("[dim]DeepSSRFAgent: no URL-type parameters found, skipping pre-flight.[/dim]")
        else:
            await self._preflight_ssrf(context, url_param_endpoints)

        return await super().run(context)

    async def _preflight_ssrf(self, context: ScanContext, url_param_endpoints: list) -> None:
        """Inject SSRF payloads into all discovered URL-type parameters."""
        ssrf_payloads = SSRF_CLOUD[:3] + SSRF_INTERNAL[:3]

        for path, param in url_param_endpoints[:5]:
            for ssrf_url in ssrf_payloads:
                # GET probe
                full_path = f"{path}?{param}={ssrf_url}"
                req = HttpRequest(method="GET", path=full_path, payload=ssrf_url)
                status, body, elapsed, headers = await self._http_probe(req)
                self.asi.ingest_response(path, "GET", "", status, body, headers)
                matched = [s for s in SSRF_INTERNAL_SIGS if re.search(s, body, re.I)]
                if matched and status == 200:
                    self.console.print(f"[red][DeepSSRF] SSRF confirmed at {full_path}![/red]")
                    self.vulns.append(Vuln(
                        name="[DYNAMIC] Server-Side Request Forgery (SSRF)",
                        cwe="CWE-918",
                        severity="Critical",
                        endpoint=full_path,
                        payload=ssrf_url,
                        confirmed=True,
                        evidence=f"Internal content signature detected: {matched[0]}",
                        fix="Validate/allowlist target URLs; block RFC 1918 ranges; disable unnecessary URL-fetch features.",
                    ))
                    return

                # POST probe with JSON body
                import json
                req_post = HttpRequest(
                    method="POST",
                    path=path,
                    body=json.dumps({param: ssrf_url}),
                    headers={"Content-Type": "application/json"},
                    payload=ssrf_url,
                )
                status, body, elapsed, headers = await self._http_probe(req_post)
                self.asi.ingest_response(path, "POST", req_post.body, status, body, headers)
                matched = [s for s in SSRF_INTERNAL_SIGS if re.search(s, body, re.I)]
                if matched and status == 200:
                    self.console.print(f"[red][DeepSSRF] SSRF via POST at {path}![/red]")
                    self.vulns.append(Vuln(
                        name="[DYNAMIC] Server-Side Request Forgery (SSRF)",
                        cwe="CWE-918",
                        severity="Critical",
                        endpoint=path,
                        payload=ssrf_url,
                        confirmed=True,
                        evidence=f"Internal content signature: {matched[0]}",
                        fix="Validate/allowlist target URLs; block RFC 1918 ranges.",
                    ))
                    return
