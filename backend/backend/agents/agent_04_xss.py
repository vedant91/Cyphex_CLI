"""
CYPHEX — Agent 04: XSS (Cross-Site Scripting) Agent

Tests for XSS vulnerabilities:
  - Reflected XSS via form submissions
  - Reflected XSS via URL parameters
  - DOM-based XSS pattern detection
  - Stored XSS via input fields
  - Various payload encodings and bypass techniques
"""

import re
import shlex
from urllib.parse import quote

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class XSSAgent(BaseAgent):

    XSS_PAYLOADS = [
        # Basic script injection
        ('<script>alert("XSS")</script>', "basic_script"),
        ("<script>alert(1)</script>", "basic_alert"),
        # Event handlers
        ('<img src=x onerror=alert(1)>', "img_onerror"),
        ('<svg onload=alert(1)>', "svg_onload"),
        ('<body onload=alert(1)>', "body_onload"),
        # Attribute escape
        ('"><script>alert(1)</script>', "attr_escape_script"),
        ("'><script>alert(1)</script>", "attr_escape_single"),
        ('"><img src=x onerror=alert(1)>', "attr_escape_img"),
        # JavaScript protocol
        ("javascript:alert(1)", "js_protocol"),
        # Encoded payloads
        ("%3Cscript%3Ealert(1)%3C/script%3E", "url_encoded"),
        ("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "html_entity"),
    ]

    # Unique canary for detection
    CANARY = "cYpH3x_X55"

    @staticmethod
    def _q(value: str) -> str:
        """Shell-quote untrusted values before embedding in terminal commands."""
        return shlex.quote(str(value))

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ XSS TESTING ═══", "info")

        # ─── 1. Test with dalfox if available ───
        has_dalfox = await self.terminal.check_tool("dalfox")
        if has_dalfox:
            await self._run_dalfox(context)

        # ─── 2. Reflected XSS on forms ───
        await self.log("Testing forms for reflected XSS...", "info")
        for form in context.all_forms:
            await self._test_reflected_form(form, context)

        # ─── 3. Reflected XSS on URL parameters ───
        await self.log("Testing URL parameters for reflected XSS...", "info")
        for param in context.all_params:
            await self._test_reflected_param(param, context)

        # ─── 4. DOM XSS detection ───
        await self.log("Scanning for DOM-based XSS patterns...", "info")
        await self._check_dom_xss(context)

        # ─── 5. Stored XSS test ───
        await self.log("Testing for stored XSS...", "info")
        await self._test_stored_xss(context)

        # ─── 6. Admin/Dashboard XSS + Broken Access Control ───
        await self.log("Testing admin endpoints for XSS & BAC...", "info")
        await self._test_admin_xss_and_bac(context)

        await self.log(
            f"XSS testing complete: {len(self.vulns)} vulnerabilities found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent="XSSAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    async def _run_dalfox(self, context: ScanContext):
        """Run dalfox XSS scanner."""
        for form in context.all_forms[:5]:
            await self.log(f"Running dalfox on {form.action}...", "info")
            action_q = self._q(form.action)
            out = await self.terminal.run(
                f'dalfox url {shlex.quote(form.action)} '
                f'--silence --no-color --timeout 10',
                timeout=60,
            )
            if "POC" in out.stdout or "Verified" in out.stdout:
                await self.add_vuln(Vuln(
                    name=f"XSS (dalfox confirmed) — {form.action}",
                    severity="High",
                    cvss_score=7.5,
                    endpoint=form.action,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Sanitize all output. Use Content-Security-Policy header.",
                ))

    async def _test_reflected_form(self, form, context: ScanContext):
        """Test a form for reflected XSS."""
        for payload, ptype in self.XSS_PAYLOADS:
            for input_field in form.inputs:
                # Build form data with one field having the payload
                data_parts = []
                for inp in form.inputs:
                    if inp == input_field:
                        data_parts.append(f"{inp}={quote(payload, safe='')}")
                    else:
                        data_parts.append(f"{inp}=test")
                data_str = "&".join(data_parts)
                action_q = self._q(form.action)
                data_q = self._q(data_str)

                if form.method.upper() == "POST":
                    out = await self.terminal.run(
                        f'curl -s -X POST {shlex.quote(form.action)} '
                        f'-d {shlex.quote(data_str)} '
                        f'--max-time 10'
                    )
                else:
                    url = f"{form.action}?{data_str}"
                    url_q = self._q(url)
                    out = await self.terminal.run(
                        f'curl -s --max-time 10 {shlex.quote(url)}'
                    )

                if not out.stdout:
                    continue

                # Check if payload is reflected unescaped
                if payload in out.stdout:
                    await self.add_vuln(Vuln(
                        name=f"Reflected XSS — {form.action}",
                        severity="High",
                        cvss_score=7.5,
                        endpoint=form.action,
                        payload=payload,
                        confirmed=True,
                        evidence=out.stdout[:300],
                        description=(
                            f"Payload reflected unescaped in response: "
                            f"{payload[:50]}"
                        ),
                        fix=(
                            "Sanitize all output with HTML entity encoding. "
                            "Use textContent instead of innerHTML. "
                            "Implement Content-Security-Policy header."
                        ),
                    ))
                    return  # Found one for this form, move on

                # Check for partial reflection (filter bypass needed)
                stripped = payload.replace("<", "").replace(">", "").replace('"', "")
                if stripped in out.stdout and len(stripped) > 5:
                    await self.log(
                        f"  Partial reflection on {form.action} field={input_field}",
                        "warning",
                    )

    async def _test_reflected_param(self, param, context: ScanContext):
        """Test a URL parameter for reflected XSS."""
        for payload, ptype in self.XSS_PAYLOADS[:5]:
            test_url = f"{param.url}?{param.name}={quote(payload, safe='')}"
            test_url_q = self._q(test_url)
            out = await self.terminal.run(
                f'curl -s --max-time 10 {shlex.quote(test_url)}'
            )

            if out.stdout and payload in out.stdout:
                await self.add_vuln(Vuln(
                    name=f"Reflected XSS — URL param {param.name}",
                    severity="High",
                    cvss_score=7.5,
                    endpoint=test_url,
                    payload=payload,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Sanitize all URL parameter output.",
                ))
                return

    async def _check_dom_xss(self, context: ScanContext):
        """Check for DOM-based XSS patterns in page source."""
        dangerous_patterns = [
            (r'\.innerHTML\s*=', "innerHTML assignment"),
            (r'document\.write\(', "document.write"),
            (r'\.outerHTML\s*=', "outerHTML assignment"),
            (r'eval\(', "eval()"),
            (r'setTimeout\(["\']', "setTimeout with string"),
            (r'setInterval\(["\']', "setInterval with string"),
        ]

        source_patterns = [
            r'location\.hash',
            r'location\.search',
            r'location\.href',
            r'document\.URL',
            r'document\.referrer',
            r'URLSearchParams',
            r'window\.name',
        ]

        for url, page_data in context.sitemap.items():
            url_q = self._q(url)
            out = await self.terminal.run(
                f'curl -sL --max-time 10 {shlex.quote(url)}'
            )
            if not out.stdout:
                continue

            found_sinks = []
            found_sources = []

            for pattern, name in dangerous_patterns:
                if re.search(pattern, out.stdout):
                    found_sinks.append(name)

            for pattern in source_patterns:
                if re.search(pattern, out.stdout):
                    found_sources.append(pattern)

            if found_sinks and found_sources:
                await self.add_vuln(Vuln(
                    name=f"DOM-based XSS — {url}",
                    severity="High",
                    cvss_score=7.1,
                    endpoint=url,
                    confirmed=True,
                    description=(
                        f"DOM XSS: user-controlled sources ({', '.join(found_sources[:3])}) "
                        f"flow into dangerous sinks ({', '.join(found_sinks[:3])})"
                    ),
                    fix="Use textContent instead of innerHTML. Sanitize all DOM inputs.",
                ))

    async def _test_stored_xss(self, context: ScanContext):
        """Test for stored XSS by submitting payloads and checking if stored."""
        # Find forms that might store data (comments, messages, etc.)
        storage_forms = [
            f for f in context.all_forms
            if any(kw in f.action.lower() for kw in [
                'comment', 'message', 'post', 'contact', 'review', 'feedback'
            ])
            or any(kw in inp.lower() for inp in f.inputs for kw in [
                'comment', 'message', 'body', 'content', 'text'
            ])
        ]

        for form in storage_forms[:3]:
            xss_payload = f'<script>alert("{self.CANARY}")</script>'

            data_parts = []
            for inp in form.inputs:
                if any(kw in inp.lower() for kw in ['comment', 'message', 'body', 'content', 'text', 'name', 'author']):
                    data_parts.append(f"{inp}={quote(xss_payload, safe='')}")
                elif any(kw in inp.lower() for kw in ['email']):
                    data_parts.append(f"{inp}=cyphex%40test.com")
                else:
                    data_parts.append(f"{inp}=test_cyphex")
            data_str = "&".join(data_parts)
            action_q = self._q(form.action)
            data_q = self._q(data_str)

            # Step 1: Submit the stored payload (don't follow redirect)
            await self.terminal.run(
                f'curl -s -X POST {shlex.quote(form.action)} '
                f'-d {shlex.quote(data_str)} '
                f'--max-time 10'
            )

            # Step 2: Fetch the display page to verify persistence
            # Determine the display page: form.page if set, or derive from action
            display_url = form.page
            if not display_url:
                # Derive: /blog/comment → /blog, /feedback → /feedback
                action_path = form.action.split('?')[0].rstrip('/')
                parts = action_path.split('/')
                # If action ends with a verb like 'comment', go up one level
                if len(parts) > 1 and parts[-1] in ['comment', 'post', 'submit', 'send', 'create', 'add']:
                    display_url = '/'.join(parts[:-1])
                else:
                    display_url = action_path

                # Make absolute
                if display_url and not display_url.startswith('http'):
                    display_url = f"{context.target_url.rstrip('/')}{display_url}"

            if display_url:
                display_url_q = self._q(display_url)
                out2 = await self.terminal.run(
                    f'curl -sL --max-time 10 {shlex.quote(display_url)}'
                )
                if out2.stdout and self.CANARY in out2.stdout:
                    await self.add_vuln(Vuln(
                        name=f"Stored XSS (confirmed persisted) — {display_url}",
                        severity="Critical",
                        cvss_score=9.0,
                        endpoint=display_url,
                        payload=xss_payload,
                        confirmed=True,
                        description=(
                            f"Stored XSS verified: payload persisted in database "
                            f"and rendered on {display_url} for all visitors."
                        ),
                        fix="Sanitize all stored user content on output.",
                    ))

    async def _test_admin_xss_and_bac(self, context: ScanContext):
        """Test admin/dashboard pages for reflected XSS and broken access control."""
        admin_paths = [
            ("/admin", ["notice", "msg", "message", "alert"]),
            ("/dashboard", ["notice", "msg", "alert"]),
            ("/panel", ["notice", "msg"]),
        ]

        for path, params in admin_paths:
            url = f"{context.target_url.rstrip('/')}{path}"

            # First check if admin page is publicly accessible (BAC)
            url_q = self._q(url)
            out = await self.terminal.run(
                f'curl -s -w "\\n__STATUS__%{{http_code}}" --max-time 5 {shlex.quote(url)}'
            )
            body = out.stdout or ""
            status = "000"
            if "__STATUS__" in body:
                parts = body.rsplit("__STATUS__", 1)
                body = parts[0]
                status = parts[1].strip()

            if status != "200" or len(body.strip()) < 50:
                continue

            lower = body.lower()
            if "cannot get" in lower or "not found" in lower:
                continue

            # Check for admin-like content (proves it's a real admin page)
            is_admin_page = any(kw in lower for kw in [
                'admin', 'dashboard', 'panel', 'moderate', 'manage',
                'settings', 'users', 'configuration'
            ])

            if is_admin_page:
                # ── Broken Access Control: admin page accessible without auth ──
                # Only flag if there's no login redirect or auth challenge
                if 'login' not in lower[:200] and '401' not in status:
                    await self.add_vuln(Vuln(
                        name=f"Broken Access Control — {path}",
                        severity="High",
                        cvss_score=8.2,
                        endpoint=url,
                        confirmed=True,
                        description=(
                            f"Admin page {path} is publicly accessible without "
                            f"authentication. Exposes administrative functionality."
                        ),
                        fix=(
                            "Implement authentication and authorization checks "
                            "on all admin endpoints. Return 401/403 for unauthenticated requests."
                        ),
                    ))

                # ── Reflected XSS on admin params ──
                for param_name in params:
                    xss_payload = '<script>alert(1)</script>'
                    test_url = f"{url}?{param_name}={quote(xss_payload, safe='')}"
                    test_url_q = self._q(test_url)
                    out2 = await self.terminal.run(
                        f'curl -s --max-time 5 {shlex.quote(test_url)}'
                    )
                    if out2.stdout and xss_payload in out2.stdout:
                        await self.add_vuln(Vuln(
                            name=f"Reflected XSS — {path}?{param_name}=",
                            severity="High",
                            cvss_score=7.5,
                            endpoint=test_url,
                            payload=xss_payload,
                            confirmed=True,
                            description=(
                                f"Payload reflected unescaped on admin page "
                                f"via ?{param_name}= parameter."
                            ),
                            fix=(
                                "Sanitize all output with HTML entity encoding. "
                                "Implement Content-Security-Policy header."
                            ),
                        ))
                        break  # Found XSS on this admin page
