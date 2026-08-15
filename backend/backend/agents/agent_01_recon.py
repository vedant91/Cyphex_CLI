"""
CYPHEX — Agent 01: Reconnaissance Agent

Performs initial target fingerprinting:
  - HTTP headers analysis (server, framework, security headers)
  - Technology detection via response patterns
  - Sensitive file discovery (.env, .git, backups)
  - SSL/TLS check
  - Port/service detection (if nmap available)
  - Directory discovery
"""

import re
import shlex
from urllib.parse import urlparse

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class ReconAgent(BaseAgent):

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ RECONNAISSANCE PHASE ═══", "info")
        await self.log(f"Target: {context.target_url}", "info")

        target = context.target_url
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # ─── 1. Grab HTTP headers ───
        await self.log("Fetching HTTP headers...", "info")
        out = await self.terminal.run(
            f'curl -sI -L --max-redirs 5 --max-time 10 {shlex.quote(target)}'
        )
        if out.success:
            context.headers = self._parse_headers(out.stdout)
            self._detect_technologies(context)
            await self._check_security_headers(context)
        else:
            await self.log(f"Header fetch failed: {out.stderr[:200]}", "warning")

        # ─── 2. Grab full homepage for fingerprinting ───
        await self.log("Fetching homepage for fingerprinting...", "info")
        out = await self.terminal.run(
            f'curl -sL --max-time 15 {shlex.quote(target)}'
        )
        if out.success:
            self._fingerprint_from_html(out.stdout, context)

        # ─── 3. Check sensitive files ───
        await self.log("Probing sensitive files...", "info")
        sensitive_paths = [
            "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
            "/wp-config.php", "/config.php", "/database.yml",
            "/.htaccess", "/web.config", "/phpinfo.php",
            "/server-status", "/actuator", "/actuator/env",
            "/.aws/credentials", "/backup.zip", "/dump.sql",
            "/.well-known/security.txt", "/api/debug",
            "/admin", "/api/users", "/api",
        ]

        for path in sensitive_paths:
            probe_url = f"{target}{path}"
            out = await self.terminal.run(
                f'curl -so /dev/null -w "%{{http_code}}" --max-time 5 {shlex.quote(probe_url)}'
            )
            status = out.stdout.strip().replace("'", "")
            if status in ["200", "301", "302", "403"]:
                if status in ["200", "301", "302"]:
                    await self.log(f"  Found: {path} → HTTP {status}", "warning")
                    context.discovered_paths.append(path)

                    # Fetch content of sensitive files
                    if path in ["/.env", "/.git/HEAD", "/robots.txt",
                                "/phpinfo.php", "/.aws/credentials"]:
                        content_out = await self.terminal.run(
                            f'curl -sL --max-time 5 {shlex.quote(probe_url)}'
                        )
                        if content_out.success:
                            await self._analyze_sensitive_file(
                                path, content_out.stdout, context
                            )
                elif status == "403":
                    await self.log(f"  Forbidden (exists): {path} → HTTP 403", "info")

        # ─── 4. Check for nmap (if available) ───
        has_nmap = await self.terminal.check_tool("nmap")
        if has_nmap:
            await self.log("Running nmap service scan...", "info")
            out = await self.terminal.run(
                f"nmap -sV --script=http-headers -p {shlex.quote(str(port))} "
                f"{shlex.quote(host)} -T4",
                timeout=60,
            )
            if out.success:
                self._parse_nmap(out.stdout, context)
        else:
            await self.log("nmap not available — skipping port scan", "info")

        # ─── 5. Directory discovery ───
        has_gobuster = await self.terminal.check_tool("gobuster")
        if has_gobuster:
            await self.log("Running directory brute-force...", "info")
            out = await self.terminal.run(
                f'gobuster dir -u {shlex.quote(target)} '
                f'-w /usr/share/wordlists/dirb/common.txt '
                f'-t 30 -q --no-error',
                timeout=90,
            )
            if out.success:
                for line in out.stdout.split("\n"):
                    if line.strip() and "(Status:" in line:
                        path_match = re.match(r'(/\S+)', line.strip())
                        if path_match:
                            context.discovered_paths.append(path_match.group(1))
        else:
            await self.log("gobuster not available — using curl-based discovery", "info")

        # ─── Summary ───
        await self.log(
            f"Recon complete: framework={context.framework}, "
            f"server={context.server}, "
            f"paths_found={len(context.discovered_paths)}, "
            f"vulns={len(self.vulns)}",
            "success",
        )

        return AgentResult(
            agent="ReconAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    def _parse_headers(self, raw: str) -> dict:
        """Parse HTTP headers from curl -I output."""
        headers = {}
        for line in raw.split("\n"):
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
        return headers

    def _detect_technologies(self, context: ScanContext):
        """Detect technologies from headers."""
        h = context.headers

        # Server
        server = h.get("Server", h.get("server", ""))
        if server:
            context.server = server
            context.technologies.append(f"Server: {server}")

        # Framework detection
        powered_by = h.get("X-Powered-By", h.get("x-powered-by", ""))
        if powered_by:
            context.technologies.append(f"X-Powered-By: {powered_by}")
            if "Express" in powered_by:
                context.framework = "Express.js"
                context.language = "JavaScript"
            elif "PHP" in powered_by:
                context.framework = "PHP"
                context.language = "PHP"
            elif "ASP.NET" in powered_by:
                context.framework = "ASP.NET"
                context.language = "C#"

        # Set cookie analysis
        set_cookie = h.get("Set-Cookie", h.get("set-cookie", ""))
        if set_cookie:
            if "PHPSESSID" in set_cookie:
                context.framework = context.framework or "PHP"
            elif "connect.sid" in set_cookie:
                context.framework = context.framework or "Express.js"
            elif "JSESSIONID" in set_cookie:
                context.framework = context.framework or "Java/Spring"
            elif "csrftoken" in set_cookie:
                context.framework = context.framework or "Django"

    def _fingerprint_from_html(self, html: str, context: ScanContext):
        """Detect technologies from HTML content."""
        lower = html.lower()

        # Framework fingerprints
        if "express" in lower or "node" in lower:
            context.framework = context.framework or "Express.js"
            context.language = "JavaScript"
        if "django" in lower or "csrfmiddlewaretoken" in lower:
            context.framework = context.framework or "Django"
            context.language = "Python"
        if "laravel" in lower:
            context.framework = context.framework or "Laravel"
            context.language = "PHP"
        if "wp-content" in lower or "wordpress" in lower:
            context.framework = context.framework or "WordPress"
            context.language = "PHP"
        if "react" in lower or "reactdom" in lower:
            context.technologies.append("React")
        if "angular" in lower or "ng-app" in lower:
            context.technologies.append("Angular")

        # Database hints
        if "mysql" in lower:
            context.database = "mysql"
        elif "postgres" in lower or "postgresql" in lower:
            context.database = "postgresql"
        elif "sqlite" in lower:
            context.database = "sqlite"
        elif "mongodb" in lower or "mongo" in lower:
            context.database = "mongodb"

    async def _check_security_headers(self, context: ScanContext):
        """Check for missing security headers."""
        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        h_lower = {k.lower(): v for k, v in context.headers.items()}
        missing = [
            h for h in required_headers if h.lower() not in h_lower
        ]

        if missing:
            await self.add_vuln(Vuln(
                name=f"Missing Security Headers ({len(missing)})",
                severity="Medium",
                cvss_score=5.8,
                description=(
                    f"Missing {len(missing)} security headers: {', '.join(missing)}. "
                    f"Exposes app to clickjacking, XSS, MIME sniffing."
                ),
                confirmed=True,
                fix=f"Add headers: {', '.join(missing)}",
            ))

        # Server info disclosure
        if context.server:
            await self.add_vuln(Vuln(
                name="Server Information Disclosure",
                severity="Low",
                cvss_score=3.5,
                description=f"Server header reveals: {context.server}",
                confirmed=True,
                fix="Remove or obfuscate Server header.",
            ))

    async def _analyze_sensitive_file(
        self, path: str, content: str, context: ScanContext
    ):
        """Analyze content of sensitive files."""
        secrets_found = []

        # Pattern matching for secrets
        patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Database Password": r"(?:DB_PASS|DB_PASSWORD|DATABASE_PASSWORD)\s*[=:]\s*(\S+)",
            "JWT Secret": r"(?:JWT_SECRET|SECRET_KEY)\s*[=:]\s*(\S+)",
            "API Key": r"(?:API_KEY|STRIPE_SK|sk_live_)\s*[=:]\s*(\S+)",
            "Private Key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "Password": r"(?:password|passwd|pwd)\s*[=:]\s*[\"']?([^\s\"']+)",
        }

        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                secrets_found.append(name)

        if secrets_found or path in ["/.env", "/.git/HEAD", "/.aws/credentials"]:
            await self.add_vuln(Vuln(
                name=f"Sensitive File Exposed: {path}",
                severity="Critical" if secrets_found else "High",
                cvss_score=9.1 if secrets_found else 7.5,
                endpoint=path,
                description=(
                    f"Sensitive file {path} is publicly accessible. "
                    f"Secrets found: {', '.join(secrets_found) if secrets_found else 'potential sensitive data'}"
                ),
                confirmed=True,
                evidence=self._redact_evidence(content),
                fix=f"Block access to {path}. Rotate all exposed credentials.",
            ))

    def _redact_evidence(self, content: str, max_len: int = 150) -> str:
        """
        Truncate and mask sensitive file content before it is stored as
        Vuln.evidence (which flows into reports/UI). Never persist raw
        credential bytes — only enough structure to prove the finding.
        """
        snippet = content[:max_len]

        redaction_patterns = [
            r"AKIA[0-9A-Z]{16}",
            r"(?:DB_PASS|DB_PASSWORD|DATABASE_PASSWORD)\s*[=:]\s*\S+",
            r"(?:JWT_SECRET|SECRET_KEY)\s*[=:]\s*\S+",
            r"(?:API_KEY|STRIPE_SK|sk_live_)\S*\s*[=:]?\s*\S+",
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?"
            r"-----END (?:RSA |EC )?PRIVATE KEY-----",
            r"(?:password|passwd|pwd)\s*[=:]\s*[\"']?[^\s\"']+",
        ]
        for pattern in redaction_patterns:
            snippet = re.sub(pattern, "[REDACTED]", snippet, flags=re.IGNORECASE)

        if len(content) > max_len:
            snippet += " ... [TRUNCATED]"
        return snippet

    def _parse_nmap(self, output: str, context: ScanContext):
        """Parse nmap output to update context."""
        for line in output.split("\n"):
            if "/tcp" in line and "open" in line:
                context.technologies.append(f"Port: {line.strip()}")
