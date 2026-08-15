"""
CYPHEX — Agent 08: Business Logic Agent

Tests for:
  - IDOR (Insecure Direct Object Reference)
  - Mass assignment / parameter pollution
  - SSRF (Server-Side Request Forgery)
  - CSRF (Cross-Site Request Forgery) detection
  - Missing CSRF tokens on state-changing forms
"""

import re
import shlex
from urllib.parse import quote

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class LogicAgent(BaseAgent):

    @staticmethod
    def _q(value: str) -> str:
        """Shell-quote untrusted values before embedding in terminal commands."""
        return shlex.quote(str(value))

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ BUSINESS LOGIC TESTING ═══", "info")

        # ─── 1. IDOR testing ───
        await self.log("Testing for IDOR...", "info")
        await self._test_idor(context)

        # ─── 2. Mass assignment ───
        await self.log("Testing for mass assignment...", "info")
        await self._test_mass_assignment(context)

        # ─── 3. SSRF ───
        await self.log("Testing for SSRF...", "info")
        await self._test_ssrf(context)

        # ─── 4. CSRF detection ───
        await self.log("Checking for CSRF protection...", "info")
        await self._test_csrf(context)

        # ─── 5. CORS misconfiguration ───
        await self.log("Checking CORS configuration...", "info")
        await self._test_cors(context)

        # ─── 6. HTTP method tampering ───
        await self.log("Testing HTTP method tampering...", "info")
        await self._test_method_tampering(context)

        await self.log(
            f"Logic testing complete: {len(self.vulns)} vulnerabilities found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent="LogicAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    async def _test_idor(self, context: ScanContext):
        """Test for IDOR on API endpoints."""
        # Find endpoints with numeric IDs
        id_endpoints = []

        for endpoint in context.all_endpoints:
            # Match patterns like /api/user/1 or /api/orders/42
            if re.search(r'/\d+', endpoint):
                id_endpoints.append(endpoint)

        # Also construct common IDOR targets
        common_patterns = [
            "/api/user/{id}", "/api/users/{id}",
            "/api/order/{id}", "/api/orders/{id}",
            "/api/invoice/{id}", "/api/profile/{id}",
        ]

        for pattern in common_patterns:
            for test_id in [1, 2, 3]:
                url = f"{context.target_url.rstrip('/')}" + \
                      pattern.replace("{id}", str(test_id))
                url_q = self._q(url)
                out = await self.terminal.run(
                    f"curl -s -w '\\n__STATUS__%{{http_code}}' --max-time 5 {url_q}"
                )

                body = out.stdout
                status = "000"
                if "__STATUS__" in body:
                    parts = body.rsplit("__STATUS__", 1)
                    body = parts[0]
                    status = parts[1].strip()

                if status == "200" and len(body.strip()) > 20:
                    lower = body.lower()
                    # Filter out generic error pages
                    if "cannot get" in lower or "not found" in lower:
                        continue
                    if any(kw in lower for kw in [
                        '"username"', '"email"', '"password"',
                        '"role"', '"credit_card"', '"phone"'
                    ]):
                        await self.add_vuln(Vuln(
                            name=f"IDOR -- Unauthorized Data Access",
                            severity="High",
                            cvss_score=8.1,
                            endpoint=url,
                            confirmed=True,
                            evidence=body[:300],
                            dumped_data=body[:200],
                            description=f"Accessed {url} without auth (HTTP {status}). User data exposed.",
                            fix="Implement authorization checks on all resource endpoints.",
                        ))
                        return  # Found

        # Test ID enumeration on discovered endpoints
        for endpoint in id_endpoints[:5]:
            # Extract current ID and try adjacent ones
            id_match = re.search(r'/(\d+)', endpoint)
            if id_match:
                current_id = int(id_match.group(1))
                for test_id in [current_id - 1, current_id + 1, 1]:
                    test_url = endpoint.replace(
                        f"/{current_id}", f"/{test_id}"
                    )
                    test_url_q = self._q(test_url)
                    out = await self.terminal.run(
                        f"curl -s --max-time 5 {test_url_q}"
                    )
                    if out.stdout and len(out.stdout) > 50:
                        if any(kw in out.stdout.lower() for kw in [
                            'username', 'email', 'user', 'id'
                        ]):
                            await self.add_vuln(Vuln(
                                name="IDOR — ID Enumeration",
                                severity="High",
                                cvss_score=8.1,
                                endpoint=test_url,
                                confirmed=True,
                                evidence=out.stdout[:300],
                                fix="Implement owner-based authorization checks.",
                            ))
                            return

    async def _test_mass_assignment(self, context: ScanContext):
        """Test for mass assignment vulnerabilities."""
        # Find update/create endpoints
        target_forms = [
            f for f in context.all_forms
            if any(kw in f.action.lower() for kw in [
                'update', 'edit', 'profile', 'settings', 'register', 'signup'
            ])
        ]

        # Also test common API endpoints
        for path in ["/api/user/update", "/api/profile", "/api/settings",
                     "/api/register", "/api/signup"]:
            url = f"{context.target_url.rstrip('/')}{path}"
            url_q = self._q(url)
            json_q = self._q('{"username":"test","role":"admin","is_admin":true,"admin":1,"privilege":"superuser"}')

            # Try sending privileged fields with JSON
            out = await self.terminal.run(
                f"curl -s -X POST {url_q} "
                f"-H 'Content-Type: application/json' "
                f"-d {json_q} "
                f"--max-time 10"
            )

            if out.stdout and any(kw in out.stdout.lower() for kw in [
                '"role":"admin"', '"is_admin":true', '"admin"',
                'privilege', 'superuser', 'updated'
            ]):
                await self.add_vuln(Vuln(
                    name="Mass Assignment — Privilege Escalation",
                    severity="High",
                    cvss_score=8.8,
                    endpoint=url,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    description="Server accepts unintended fields (role, is_admin, admin).",
                    fix="Whitelist allowed fields. Never bind request body directly to model.",
                ))
                return

        # Test on discovered forms
        for form in target_forms:
            data_parts = [f"{inp}=test" for inp in form.inputs]
            data_parts.extend([
                "role=admin", "is_admin=true",
                "admin=1", "privilege=superuser"
            ])
            data_str = "&".join(data_parts)
            action_q = self._q(form.action)
            data_q = self._q(data_str)

            out = await self.terminal.run(
                f"curl -s -X POST {action_q} -d {data_q} --max-time 10"
            )

            if out.stdout and "admin" in out.stdout.lower():
                await self.add_vuln(Vuln(
                    name="Mass Assignment — Privilege Escalation",
                    severity="High",
                    cvss_score=8.8,
                    endpoint=form.action,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Whitelist allowed fields on server side.",
                ))

    async def _test_ssrf(self, context: ScanContext):
        """Test for Server-Side Request Forgery."""
        url_params = [
            p for p in context.all_params
            if any(kw in p.name.lower() for kw in [
                'url', 'uri', 'href', 'src', 'redirect',
                'callback', 'next', 'destination', 'path',
                'host', 'link', 'fetch', 'proxy', 'load'
            ])
        ]
        
        # Add manual endpoints like /check-status forms
        for form in context.all_forms + context.all_endpoints:
            # endpoints are strings, forms are objects
            url = form if isinstance(form, str) else form.action
            if isinstance(form, str) and not form.startswith("http"):
                continue
                
            input_names = []
            if not isinstance(form, str):
                input_names = form.inputs
            
            for param_name in ["url", "uri", "target_url"]:
                if isinstance(form, str) or param_name in input_names:
                    from models.scan import ParamData
                    url_params.append(ParamData(url=url, name=param_name))

        ssrf_payloads = [
            ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
            ("http://metadata.google.internal/", "gcp_metadata"),
            ("http://127.0.0.1:6379/", "redis"),
            ("http://127.0.0.1:27017/", "mongodb"),
            ("http://localhost/admin", "internal_admin"),
        ]

        for param in url_params:
            for payload, target_name in ssrf_payloads:
                url = f"{param.url}?{param.name}={quote(payload)}"
                url_q = self._q(url)
                out = await self.terminal.run(
                    f"curl -s -w '\\n__STATUS__%{{http_code}}' --max-time 5 {url_q}"
                )

                body = out.stdout
                status = "000"
                if "__STATUS__" in body:
                    parts = body.rsplit("__STATUS__", 1)
                    body = parts[0]
                    status = parts[1].strip()

                # Reject 302 redirects -- that is Open Redirect, NOT SSRF
                if status in ["301", "302", "303", "307", "308"]:
                    continue

                # Only match strong SSRF indicators, NOT generic nav links
                if body and any(kw in body for kw in [
                    "ami-id", "instance-id", "computeMetadata",
                    "+PONG", "+OK", "MongoDB", "redis_version",
                    "Successfully fetched", "Mock Redis"
                ]):
                    await self.add_vuln(Vuln(
                        name=f"SSRF -- Internal Service Access ({target_name})",
                        severity="Critical",
                        cvss_score=9.3,
                        endpoint=param.url,
                        payload=f"{param.name}={payload}",
                        confirmed=True,
                        evidence=body[:500],
                        description=f"Server fetched internal resource {payload} (HTTP {status}).",
                        fix="Validate and whitelist allowed URLs. Block internal IPs.",
                    ))
                    return

    async def _test_csrf(self, context: ScanContext):
        """Check for missing CSRF tokens on state-changing forms."""
        post_forms = [
            f for f in context.all_forms if f.method.upper() == "POST"
        ]

        forms_without_csrf = []
        for form in post_forms:
            # Check if form has CSRF token input
            has_csrf = any(
                'csrf' in inp.lower() or '_token' in inp.lower()
                or 'authenticity' in inp.lower()
                for inp in form.inputs
            )

            if not has_csrf:
                forms_without_csrf.append(form)

        for form in forms_without_csrf:
            await self.add_vuln(Vuln(
                name=f"Missing CSRF Protection — {form.action}",
                severity="High",
                cvss_score=8.0,
                endpoint=form.action,
                description=f"POST form lacks CSRF token.",
                confirmed=True,
                fix="Add CSRF tokens to all forms. Set SameSite=Strict on cookies.",
            ))

    async def _test_cors(self, context: ScanContext):
        """Test for CORS misconfiguration."""
        target_q = self._q(context.target_url)
        out = await self.terminal.run(
            f"curl -s -I -H 'Origin: https://evil-cyphex.com' --max-time 5 {target_q}"
        )

        if "evil-cyphex" in out.stdout:
            await self.add_vuln(Vuln(
                name="CORS Misconfiguration — Arbitrary Origin",
                severity="High",
                cvss_score=7.5,
                endpoint=context.target_url,
                confirmed=True,
                description="Server reflects arbitrary Origin header in ACAO.",
                fix="Whitelist specific allowed origins. Don't reflect Origin header.",
            ))
        elif "Access-Control-Allow-Origin: *" in out.stdout:
            await self.add_vuln(Vuln(
                name="CORS Misconfiguration — Wildcard Origin",
                severity="Medium",
                cvss_score=5.3,
                endpoint=context.target_url,
                confirmed=True,
                description="Access-Control-Allow-Origin set to * (any origin).",
                fix="Restrict to specific trusted origins.",
            ))

    async def _test_method_tampering(self, context: ScanContext):
        """Test HTTP method tampering on restricted endpoints."""
        restricted_paths = [
            path for path in context.discovered_paths
            if any(kw in path.lower() for kw in ['admin', 'debug', 'internal'])
        ]

        for path in restricted_paths[:3]:
            url = f"{context.target_url.rstrip('/')}{path}"
            url_q = self._q(url)

            # Try different HTTP methods
            for method in ["PUT", "DELETE", "PATCH", "OPTIONS"]:
                out = await self.terminal.run(
                    f"curl -s -X {self._q(method)} -o /dev/null "
                    f"-w '%{{http_code}}' --max-time 5 {url_q}"
                )
                status = out.stdout.strip().replace("'", "")
                if status == "200":
                    await self.log(
                        f"  {method} {path} → 200 (potential method tampering)",
                        "warning",
                    )
