"""DeepIDORAgent — Oracle-guided IDOR via sequential, UUID, and hash-based object traversal."""
import re
import uuid
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest

class DeepIDORAgent(BaseDeepAgent):
    """
    Insecure Direct Object Reference testing agent.
    Covers:
    - Sequential integer IDs (1, 2, 3 → check access without auth)
    - UUID enumeration (random UUIDs to find collision)
    - Hash-based IDs (predict/brute)
    - Mass assignment (PUT body with escalated role)
    - Shadow IDOR (same ID, different user data returned)
    """
    PRIMARY_VULN_CLASS = "Insecure Direct Object Reference (IDOR)"

    # Well-known IDOR-prone path patterns
    IDOR_PATH_PATTERNS = [
        r"/api/users?/\d+",
        r"/api/orders?/\d+",
        r"/api/payslips?/\d+",
        r"/api/employees?/\d+",
        r"/api/accounts?/\d+",
        r"/api/invoices?/\d+",
    ]
    IDOR_BASE_PATHS = [
        "/api/users/", "/api/orders/", "/api/employees/",
        "/api/payslips/", "/api/accounts/", "/api/invoices/",
        "/users/", "/orders/", "/account/",
    ]

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        await self._probe_sequential_ids(context)
        await self._probe_mass_assignment(context)

        return await super().run(context)

    async def _probe_sequential_ids(self, context: ScanContext) -> None:
        """Try sequential IDs 1-5 on IDOR-prone paths without authentication."""
        # Build list from ASI discovered paths + known base paths
        paths_to_test = set(self.IDOR_BASE_PATHS)
        for path in self.asi.endpoints:
            for pattern in self.IDOR_PATH_PATTERNS:
                if re.search(pattern, path):
                    # Strip the ID to get the base
                    base = re.sub(r"/\d+$", "/", path)
                    paths_to_test.add(base)
                    break

        for base_path in list(paths_to_test)[:10]:
            responses = []
            for test_id in range(1, 6):
                full = f"{base_path}{test_id}"
                req = HttpRequest(method="GET", path=full, payload=str(test_id))
                status, body, elapsed, headers = await self._http_probe(req)
                self.asi.ingest_response(full, "GET", "", status, body, headers)
                if status == 200 and len(body) > 20:
                    responses.append((test_id, body))

            if len(responses) >= 2:
                # At least 2 different IDs return data without auth → IDOR
                self.console.print(
                    f"[red][DeepIDOR] Sequential IDOR at {base_path} "
                    f"({len(responses)} IDs accessible without auth)[/red]"
                )
                self.vulns.append(Vuln(
                    name="[DYNAMIC] IDOR — Sequential ID Enumeration",
                    cwe="CWE-639",
                    severity="High",
                    endpoint=f"{base_path}*",
                    payload=f"IDs: {[r[0] for r in responses]}",
                    confirmed=True,
                    evidence=f"{len(responses)} sequential IDs returned data unauthenticated",
                    fix="Enforce object-level authorisation; use UUIDs instead of sequential IDs.",
                ))
                return

    async def _probe_mass_assignment(self, context: ScanContext) -> None:
        """Try PUT/PATCH with admin role injection on profile/account endpoints."""
        import json
        mass_paths = ["/api/users/1", "/api/profile", "/api/account", "/api/me"]
        escalation_bodies = [
            {"role": "admin"},
            {"isAdmin": True},
            {"admin": True},
            {"role": "superuser"},
        ]
        for path in mass_paths:
            for body in escalation_bodies:
                req = HttpRequest(
                    method="PUT",
                    path=path,
                    body=json.dumps(body),
                    headers={"Content-Type": "application/json"},
                    payload="mass_assignment",
                )
                status, resp_body, elapsed, headers = await self._http_probe(req)
                self.asi.ingest_response(path, "PUT", req.body, status, resp_body, headers)
                if status in (200, 201, 204):
                    # Check if response reflects the escalated role
                    if any(str(v).lower() in resp_body.lower() for v in body.values()):
                        self.vulns.append(Vuln(
                            name="[DYNAMIC] Mass Assignment / Privilege Escalation",
                            cwe="CWE-915",
                            severity="Critical",
                            endpoint=path,
                            payload=json.dumps(body),
                            confirmed=True,
                            evidence=f"Server accepted role escalation body — HTTP {status}",
                            fix="Use allowlists for accepted fields; never bind request body directly to model.",
                        ))
                        return
