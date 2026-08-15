"""DeepCMDiAgent — Oracle-guided Command Injection with sync/time-based/blind detection."""
import re
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.payloads.cmdi import CMDI_T1, CMDI_TIME, CMDI_OUTPUT_SIGS
from backend.deepagents.oracle_attack import HttpRequest

class DeepCMDiAgent(BaseDeepAgent):
    """
    Oracle-guided Command Injection agent.
    Covers: GET/POST CMDi, time-based blind CMDi, known API sinks (/api/ping etc).
    """
    PRIMARY_VULN_CLASS = "Command Injection"
    # Time probes are slow — limit parallelism
    PARALLEL_BATCH = 1

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        # Pre-flight on all endpoints with any params
        await self._preflight_cmdi(context)

        return await super().run(context)

    async def _preflight_cmdi(self, context: ScanContext) -> None:
        """Try Tier-1 OS command payloads on all parameterised endpoints."""
        for path, profile in self.asi.endpoints.items():
            if not (profile.has_string_params or profile.has_numeric_params):
                continue
            for param in list(profile.params)[:2]:
                for payload in CMDI_T1[:4]:
                    full_path = f"{path}?{param}={payload}"
                    status, body, elapsed, headers = await self._http_probe(
                        HttpRequest(method="GET", path=full_path, payload=payload)
                    )
                    self.asi.ingest_response(path, "GET", "", status, body, headers)
                    matched = [s for s in CMDI_OUTPUT_SIGS if re.search(s, body, re.I)]
                    if matched:
                        self.console.print(
                            f"[red][DeepCMDi] OS output at {full_path}: {matched[0]}[/red]"
                        )
                        self.vulns.append(Vuln(
                            name="[DYNAMIC] Command Injection",
                            cwe="CWE-78",
                            severity="Critical",
                            endpoint=full_path,
                            payload=payload,
                            confirmed=True,
                            rce_output=body[:300],
                            evidence=matched[0],
                            fix="Never pass user input to shell commands; use safe API alternatives.",
                        ))
                        return

        # Also probe known API sink paths
        api_sinks = [
            ("/api/ping",    "host", "POST"),
            ("/api/exec",    "cmd",  "POST"),
            ("/api/diagnose","hostname", "POST"),
            ("/ping",        "host", "GET"),
        ]
        for path, param, method in api_sinks:
            for payload in CMDI_T1[:3]:
                if method == "POST":
                    req = HttpRequest(
                        method="POST", path=path,
                        body=f"{param}=127.0.0.1{payload}",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        payload=payload,
                    )
                else:
                    req = HttpRequest(
                        method="GET", path=f"{path}?{param}=127.0.0.1{payload}",
                        payload=payload,
                    )
                status, body, elapsed, headers = await self._http_probe(req)
                self.asi.ingest_response(path, method, req.body, status, body, headers)
                matched = [s for s in CMDI_OUTPUT_SIGS if re.search(s, body, re.I)]
                if matched:
                    self.console.print(f"[red][DeepCMDi] RCE on {path}![/red]")
                    self.vulns.append(Vuln(
                        name="[DYNAMIC] Command Injection via API",
                        cwe="CWE-78",
                        severity="Critical",
                        endpoint=path,
                        payload=payload,
                        confirmed=True,
                        rce_output=body[:300],
                        evidence=matched[0],
                        fix="Use execFile/subprocess with argument arrays, never shell=True.",
                    ))
                    return
