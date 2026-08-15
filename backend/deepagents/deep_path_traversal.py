"""DeepPathTraversalAgent — Oracle-guided LFI/RFI with encoding bypass variants."""
import re
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest
from backend.deepagents.payloads.path_traversal import LFI_T1, LFI_T2, LFI_WINDOWS, LFI_SUCCESS_SIGS
from backend.config.dast_constants import FILE_PARAM_KEYWORDS

class DeepPathTraversalAgent(BaseDeepAgent):
    """
    Path Traversal / LFI / RFI agent.
    Covers: direct traversal, encoding bypasses, null-byte, Windows paths.
    """
    PRIMARY_VULN_CLASS = "Path Traversal / Local File Inclusion (LFI)"

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        has_file = any(p.has_file_param for p in self.asi.endpoints.values())
        if not has_file:
            self.console.print("[dim]DeepPathTraversalAgent: no file parameters found, skipping.[/dim]")
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        await self._preflight_lfi(context)
        return await super().run(context)

    async def _preflight_lfi(self, context: ScanContext) -> None:
        """Try LFI payloads on all file-type parameters."""
        all_payloads = LFI_T1 + LFI_T2 + LFI_WINDOWS

        for path, profile in self.asi.endpoints.items():
            if not profile.has_file_param:
                continue
            for param in profile.params:
                if not any(kw in param.lower() for kw in FILE_PARAM_KEYWORDS):
                    continue
                for payload in all_payloads[:12]:
                    full_path = f"{path}?{param}={payload}"
                    req = HttpRequest(method="GET", path=full_path, payload=payload)
                    status, body, elapsed, headers = await self._http_probe(req)
                    self.asi.ingest_response(path, "GET", "", status, body, headers)
                    matched = [s for s in LFI_SUCCESS_SIGS if re.search(s, body, re.I)]
                    if matched:
                        self.console.print(
                            f"[red][DeepLFI] Path traversal at {full_path}! sig={matched[0]}[/red]"
                        )
                        self.vulns.append(Vuln(
                            name="[DYNAMIC] Path Traversal / Local File Inclusion",
                            cwe="CWE-22",
                            severity="Critical",
                            endpoint=full_path,
                            payload=payload,
                            confirmed=True,
                            evidence=f"Success signature in response: {matched[0]}",
                            fix="Resolve and validate all file paths against a strict allowlist root directory.",
                        ))
                        return
