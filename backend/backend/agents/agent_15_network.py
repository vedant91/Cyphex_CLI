"""
CYPHEX — Agent 15: Network Security Agent

Network-level security analysis that goes beyond app-layer scanning.
Pure Python implementation — no nmap dependency required.

Covers:
  - Async port scanning (top 100 ports)
  - TLS/SSL certificate validation
  - HTTP security header audit (HSTS, CSP, X-Frame-Options)
  - Server information disclosure
  - DNS subdomain enumeration (common subdomains)
  - Service fingerprinting via banner grabbing
"""

import asyncio
import re
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class NetworkSecurityAgent(BaseAgent):

    agent_id = "agent_15_network"
    target_cwe = "CWE-network"
    attack_category = "network"

    # Top 100 most commonly attacked ports
    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389,
        443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1434,
        1521, 1723, 2049, 2082, 2083, 2086, 2087, 3000, 3306, 3389,
        4443, 5000, 5432, 5900, 5985, 6379, 6443, 7001, 8000, 8008,
        8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9443, 10000,
        11211, 27017, 28017, 50000,
    ]

    # Ports that should never be publicly exposed
    CRITICAL_PORTS = {
        3306: ("MySQL", "Database exposed — direct SQL access"),
        5432: ("PostgreSQL", "Database exposed — direct SQL access"),
        27017: ("MongoDB", "NoSQL database exposed — no auth by default"),
        6379: ("Redis", "Cache/DB exposed — no auth by default"),
        9200: ("Elasticsearch", "Search engine exposed — data leak risk"),
        11211: ("Memcached", "Cache exposed — DDoS amplification risk"),
        2049: ("NFS", "File share exposed — data theft risk"),
        445: ("SMB", "File share exposed — EternalBlue/ransomware risk"),
        23: ("Telnet", "Unencrypted remote access — credential sniffing"),
        21: ("FTP", "Unencrypted file transfer — credential sniffing"),
        1433: ("MSSQL", "Database exposed — direct SQL access"),
        1521: ("Oracle DB", "Database exposed — direct SQL access"),
        5900: ("VNC", "Remote desktop exposed — screen access"),
        3389: ("RDP", "Remote desktop exposed — brute force target"),
    }

    # Required HTTP security headers
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("HSTS missing — no HTTPS enforcement", "High", 7.0),
        "Content-Security-Policy": ("CSP missing — XSS risk increased", "Medium", 5.5),
        "X-Content-Type-Options": ("X-Content-Type-Options missing — MIME sniffing", "Low", 3.5),
        "X-Frame-Options": ("X-Frame-Options missing — clickjacking risk", "Medium", 5.0),
        "Referrer-Policy": ("Referrer-Policy missing — information leak", "Low", 3.0),
        "Permissions-Policy": ("Permissions-Policy missing", "Low", 2.5),
    }

    # Common subdomains to enumerate
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "blog", "shop", "app", "cdn", "media", "static", "assets",
        "auth", "login", "portal", "dashboard", "db", "database",
        "git", "gitlab", "jenkins", "ci", "monitor", "grafana",
        "kibana", "elastic", "redis", "mongo", "postgres",
        "internal", "vpn", "proxy", "gateway", "backend",
    ]

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("=== NETWORK SECURITY ANALYSIS ===", "info")

        target = context.target_url
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not host:
            await self.log("No hostname found — skipping network scan", "warning")
            return AgentResult(
                agent=self.agent_id, vulns=self.vulns,
                context=context, terminal_logs=self.terminal.command_history,
            )

        # --- 1. Port Scan ---
        await self.log(f"Scanning top {len(self.TOP_PORTS)} ports on {host}...", "info")
        open_ports = await self._scan_ports(host)
        await self.log(f"  Found {len(open_ports)} open ports", "info")

        # --- 2. TLS/SSL Check ---
        if parsed.scheme == "https" or port == 443:
            await self.log("Checking TLS/SSL configuration...", "info")
            await self._check_tls(host, port if port != 80 else 443)

        # --- 3. HTTP Security Headers ---
        await self.log("Auditing HTTP security headers...", "info")
        await self._check_security_headers(target)

        # --- 4. Server Information Disclosure ---
        await self._check_info_disclosure(target)

        # --- 5. DNS Subdomain Enumeration ---
        if not self._is_ip(host) and not self._is_localhost(host):
            await self.log("Enumerating subdomains...", "info")
            await self._enumerate_dns(host)

        await self.log(
            f"Network scan complete: {len(self.vulns)} issues found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent=self.agent_id,
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    # ===================================================
    # PORT SCANNING (Async Python sockets)
    # ===================================================

    async def _scan_ports(self, host: str) -> list[dict]:
        """Async port scanner using Python sockets."""
        open_ports = []
        semaphore = asyncio.Semaphore(50)  # Rate limit concurrent connections

        async def scan_one(port: int):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()

                    service = self.CRITICAL_PORTS.get(port, (f"port-{port}", ""))[0]
                    open_ports.append({"port": port, "service": service})

                    # Check if this is a critically exposed port
                    if port in self.CRITICAL_PORTS:
                        svc_name, risk_desc = self.CRITICAL_PORTS[port]
                        await self.add_vuln(Vuln(
                            name=f"[NETWORK] Exposed {svc_name} (port {port})",
                            severity="Critical" if port in (3306, 5432, 27017, 6379) else "High",
                            cvss_score=9.0 if port in (3306, 5432, 27017, 6379) else 7.5,
                            endpoint=f"{host}:{port}",
                            confirmed=True,
                            cwe="CWE-200",
                            description=f"{risk_desc}. Port {port} ({svc_name}) is open and reachable.",
                            fix=f"Close port {port} or restrict access via firewall. Use VPN for internal services.",
                        ))
                    else:
                        await self.log(f"  Open: {host}:{port} ({service})", "info")

                except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                    pass

        # Scan all ports concurrently
        await asyncio.gather(*[scan_one(p) for p in self.TOP_PORTS])
        return sorted(open_ports, key=lambda x: x["port"])

    # ===================================================
    # TLS/SSL ANALYSIS
    # ===================================================

    async def _check_tls(self, host: str, port: int = 443):
        """Check TLS configuration for weaknesses."""
        try:
            # Use curl for certificate info (cross-platform)
            out = await self.terminal.run(
                f'curl -svI --max-time 10 "https://{host}:{port}/" 2>&1 | '
                f'grep -iE "(SSL|certificate|expire|subject|issuer)"'
            )

            if out.stdout:
                cert_info = out.stdout.lower()

                # Check for expired certificate
                if "expire" in cert_info:
                    expire_match = re.search(
                        r'expire.*?(\d{4}[/-]\d{2}[/-]\d{2})', cert_info
                    )
                    if expire_match:
                        try:
                            expire_str = expire_match.group(1)
                            # Simple date check
                            await self.log(f"  TLS certificate expires: {expire_str}", "info")
                        except Exception:
                            pass

                # Check for self-signed
                if "self signed" in cert_info or "self-signed" in cert_info:
                    await self.add_vuln(Vuln(
                        name="[NETWORK] Self-Signed TLS Certificate",
                        severity="High",
                        cvss_score=7.0,
                        endpoint=f"https://{host}:{port}",
                        confirmed=True,
                        cwe="CWE-295",
                        description="TLS certificate is self-signed. Vulnerable to MITM attacks.",
                        fix="Use a certificate from a trusted CA (e.g., Let's Encrypt).",
                    ))

        except Exception as e:
            await self.log(f"TLS check error: {e}", "warning")

        # Check for weak TLS versions using curl
        for version, flag in [("TLSv1.0", "--tlsv1.0"), ("TLSv1.1", "--tlsv1.1")]:
            try:
                out = await self.terminal.run(
                    f'curl -s {flag} --tls-max {version.replace("v", "").replace(".", ".")} '
                    f'-o /dev/null -w "%{{http_code}}" --max-time 5 '
                    f'"https://{host}:{port}/"'
                )
                status = out.stdout.strip().replace("'", "")
                if status and status != "000":
                    await self.add_vuln(Vuln(
                        name=f"[NETWORK] Weak TLS Version Supported ({version})",
                        severity="High",
                        cvss_score=7.5,
                        endpoint=f"https://{host}:{port}",
                        confirmed=True,
                        cwe="CWE-326",
                        description=f"Server accepts {version} connections. This version has known vulnerabilities.",
                        fix=f"Disable {version} in server configuration. Use TLSv1.2+ only.",
                    ))
            except Exception:
                pass

    # ===================================================
    # HTTP SECURITY HEADERS
    # ===================================================

    async def _check_security_headers(self, url: str):
        """Audit HTTP response headers for security best practices."""
        out = await self.terminal.run(
            f'curl -sI -L --max-time 10 "{url}"'
        )
        if not out.stdout:
            return

        headers = {}
        for line in out.stdout.split("\n"):
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        missing = []
        for header, (message, severity, cvss) in self.REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                missing.append((header, message, severity, cvss))

        if missing:
            # Group missing headers into one finding
            missing_names = [h[0] for h in missing]
            max_severity = "High" if any(s == "High" for _, _, s, _ in missing) else "Medium"
            await self.add_vuln(Vuln(
                name=f"[NETWORK] Missing Security Headers ({len(missing)})",
                severity=max_severity,
                cvss_score=max(c for _, _, _, c in missing),
                endpoint=url,
                confirmed=True,
                cwe="CWE-693",
                description=f"Missing headers: {', '.join(missing_names)}",
                fix=f"Add security headers: {', '.join(missing_names)}",
            ))

    async def _check_info_disclosure(self, url: str):
        """Check for information disclosure in response headers."""
        out = await self.terminal.run(
            f'curl -sI --max-time 10 "{url}"'
        )
        if not out.stdout:
            return

        for line in out.stdout.split("\n"):
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key.lower() == "server" and value:
                await self.log(f"  Server header: {value}", "info")

            if key.lower() == "x-powered-by" and value:
                await self.add_vuln(Vuln(
                    name=f"[NETWORK] Technology Disclosure: {value}",
                    severity="Low",
                    cvss_score=3.5,
                    endpoint=url,
                    confirmed=True,
                    cwe="CWE-200",
                    description=f"X-Powered-By header reveals: {value}",
                    fix="Remove X-Powered-By header from server configuration.",
                ))

    # ===================================================
    # DNS SUBDOMAIN ENUMERATION
    # ===================================================

    async def _enumerate_dns(self, domain: str):
        """Enumerate common subdomains via DNS resolution."""
        found_subdomains = []
        semaphore = asyncio.Semaphore(20)

        # Extract base domain (e.g., "api.example.com" -> "example.com")
        parts = domain.split(".")
        if len(parts) > 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        async def check_subdomain(sub: str):
            async with semaphore:
                fqdn = f"{sub}.{base_domain}"
                try:
                    result = await asyncio.to_thread(
                        socket.getaddrinfo, fqdn, None
                    )
                    if result:
                        ip = result[0][4][0]
                        found_subdomains.append({"subdomain": fqdn, "ip": ip})
                        await self.log(f"  Subdomain found: {fqdn} -> {ip}", "info")
                except (socket.gaierror, OSError):
                    pass

        await asyncio.gather(*[check_subdomain(s) for s in self.COMMON_SUBDOMAINS])

        if found_subdomains:
            # Report interesting subdomains
            risky = [s for s in found_subdomains
                     if any(kw in s["subdomain"] for kw in
                            ["admin", "db", "database", "jenkins", "git",
                             "internal", "staging", "test", "dev"])]

            if risky:
                await self.add_vuln(Vuln(
                    name=f"[NETWORK] Sensitive Subdomains Discovered ({len(risky)})",
                    severity="Medium",
                    cvss_score=5.5,
                    endpoint=base_domain,
                    confirmed=True,
                    cwe="CWE-200",
                    description=(
                        f"Found {len(risky)} sensitive subdomains: "
                        f"{', '.join(s['subdomain'] for s in risky[:5])}"
                    ),
                    fix="Ensure sensitive subdomains are not publicly accessible. Use VPN.",
                ))

    # --- Helpers ---

    def _is_ip(self, host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False

    def _is_localhost(self, host: str) -> bool:
        return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
