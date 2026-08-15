"""
CYPHEX — Network Vulnerability Mapper

Maps discovered open ports / services to known vulnerability patterns.
Static knowledge base — no CVE API, no internet, fully offline.
Also runs lightweight active checks (FTP anon login, Redis no-auth, etc.)
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional

from backend.network.models import NetworkMap, NetworkVuln, PortInfo, HostProfile

# ── Static vulnerability knowledge base ──────────────────────────────────────
# port → {service, risk, issues, cve_refs, remediation, mitre}
NETWORK_VULN_KB: dict[int, dict] = {
    21: {
        "service": "FTP",
        "risk": "Critical",
        "issues": ["Clear-text credentials transmitted", "Anonymous login may be enabled"],
        "cve_refs": ["CVE-2020-9054 (FTP Buffer Overflow)"],
        "remediation": "Disable FTP; use SFTP or FTPS. Disable anonymous access.",
        "mitre": "T1021.002 — Remote Services: SMB/Windows Admin Shares",
    },
    22: {
        "service": "SSH",
        "risk": "Medium",
        "issues": ["Password authentication may be enabled", "Old version may have known CVEs"],
        "cve_refs": ["CVE-2023-38408 (OpenSSH agent forwarding RCE)"],
        "remediation": "Disable password auth; use Ed25519 keys only. Pin to OpenSSH ≥ 9.x.",
        "mitre": "T1021.004 — Remote Services: SSH",
    },
    23: {
        "service": "Telnet",
        "risk": "Critical",
        "issues": ["No encryption — full session visible in plaintext", "No modern use case"],
        "cve_refs": [],
        "remediation": "Disable Telnet immediately. Replace with SSH.",
        "mitre": "T1021 — Remote Services",
    },
    25: {
        "service": "SMTP",
        "risk": "High",
        "issues": ["Open relay may allow spam/phishing pivoting", "VRFY/EXPN user enumeration"],
        "cve_refs": [],
        "remediation": "Disable open relay. Require SASL auth. Restrict VRFY/EXPN.",
        "mitre": "T1071.003 — Application Layer Protocol: Mail Protocols",
    },
    53: {
        "service": "DNS",
        "risk": "Medium",
        "issues": ["Zone transfer may leak all DNS records", "DNS amplification DDoS risk"],
        "cve_refs": ["CVE-2023-50387 (KeyTrap DNSSEC DoS)"],
        "remediation": "Restrict zone transfers to authorized IPs. Rate-limit recursive queries.",
        "mitre": "T1590.002 — Gather Victim Network Information: DNS",
    },
    80: {
        "service": "HTTP",
        "risk": "High",
        "issues": ["Unencrypted traffic — MITM trivial", "May expose admin panels"],
        "cve_refs": [],
        "remediation": "Redirect all HTTP to HTTPS (301). Enforce HSTS.",
        "mitre": "T1071.001 — Application Layer Protocol: Web Protocols",
    },
    110: {
        "service": "POP3",
        "risk": "High",
        "issues": ["Clear-text email retrieval", "User enumeration via error messages"],
        "cve_refs": [],
        "remediation": "Disable POP3; use POP3S (995) or IMAPS (993).",
        "mitre": "T1114 — Email Collection",
    },
    135: {
        "service": "MSRPC",
        "risk": "Critical",
        "issues": ["EternalBlue attack surface", "DCOM RCE vectors", "MS03-026"],
        "cve_refs": ["CVE-2003-0352", "CVE-2017-0144"],
        "remediation": "Block at firewall. Disable unnecessary DCOM endpoints.",
        "mitre": "T1021.003 — Remote Services: Distributed Component Object Model",
    },
    139: {
        "service": "NetBIOS",
        "risk": "Critical",
        "issues": ["NetBIOS Name Service poisoning", "NTLM relay", "Pass-the-hash"],
        "cve_refs": ["CVE-2017-0144 (EternalBlue)"],
        "remediation": "Disable NetBIOS over TCP/IP. Use SMB3 with signing enforced.",
        "mitre": "T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
    },
    443: {
        "service": "HTTPS",
        "risk": "Low",
        "issues": ["Check TLS version (reject TLS 1.0/1.1)", "Weak cipher suites"],
        "cve_refs": [],
        "remediation": "Enforce TLS 1.2+. Disable weak ciphers (RC4, DES, 3DES).",
        "mitre": "",
    },
    445: {
        "service": "SMB",
        "risk": "Critical",
        "issues": ["EternalBlue ransomware vector", "SMBRelay/NTLM relay", "WannaCry target"],
        "cve_refs": ["CVE-2017-0144", "CVE-2020-0796 (SMBGhost)"],
        "remediation": "Patch to latest. Enforce SMB signing. Block 445 at perimeter.",
        "mitre": "T1021.002 — Remote Services: SMB",
    },
    1433: {
        "service": "MSSQL",
        "risk": "Critical",
        "issues": ["Remote code via xp_cmdshell", "SA account brute force", "External exposure"],
        "cve_refs": [],
        "remediation": "Disable xp_cmdshell. Disable sa account. Firewall port 1433.",
        "mitre": "T1505.001 — Server Software Component: SQL Stored Procedures",
    },
    3306: {
        "service": "MySQL",
        "risk": "High",
        "issues": ["Remote root login may be enabled", "UDF exploitation for RCE"],
        "cve_refs": [],
        "remediation": "Disable remote root. Bind to 127.0.0.1 unless cross-host access needed.",
        "mitre": "T1505 — Server Software Component",
    },
    3389: {
        "service": "RDP",
        "risk": "Critical",
        "issues": ["BlueKeep pre-auth RCE", "Brute force target", "Ransomware delivery vector"],
        "cve_refs": ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1182 (DejaBlue)"],
        "remediation": "Enable NLA. Restrict to VPN only. Apply all Windows patches.",
        "mitre": "T1021.001 — Remote Services: Remote Desktop Protocol",
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "High",
        "issues": ["Remote code via COPY TO/FROM PROGRAM", "Brute force on postgres user"],
        "cve_refs": [],
        "remediation": "Bind to localhost. Use pg_hba.conf for access control.",
        "mitre": "T1505 — Server Software Component",
    },
    5900: {
        "service": "VNC",
        "risk": "Critical",
        "issues": ["No-auth mode common in default installs", "Clear-text protocol", "Brute force"],
        "cve_refs": ["CVE-2022-47952"],
        "remediation": "Require strong password. Tunnel via SSH. Restrict by IP.",
        "mitre": "T1021.005 — Remote Services: VNC",
    },
    6379: {
        "service": "Redis",
        "risk": "Critical",
        "issues": ["No authentication by default", "RCE via CONFIG SET dir/dbfilename", "Full data dump"],
        "cve_refs": ["CVE-2022-0543 (Lua sandbox escape)"],
        "remediation": "Set requirepass. Bind to 127.0.0.1. Disable CONFIG if unused.",
        "mitre": "T1505 — Server Software Component",
    },
    8080: {
        "service": "HTTP-Alt",
        "risk": "High",
        "issues": ["Admin panels often on 8080", "Dev servers with debug endpoints exposed"],
        "cve_refs": [],
        "remediation": "Firewall if not public-facing. Require auth on admin panels.",
        "mitre": "T1071.001 — Application Layer Protocol: Web Protocols",
    },
    8443: {
        "service": "HTTPS-Alt",
        "risk": "Medium",
        "issues": ["Alternative HTTPS — check TLS version and cert validity"],
        "cve_refs": [],
        "remediation": "Enforce TLS 1.2+. Use valid certificate.",
        "mitre": "",
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "Critical",
        "issues": ["No auth by default — full index read/write", "Billions of records leaked historically"],
        "cve_refs": ["CVE-2021-22145"],
        "remediation": "Enable X-Pack security. Bind to localhost. Add API key auth.",
        "mitre": "T1530 — Data from Cloud Storage",
    },
    11211: {
        "service": "Memcached",
        "risk": "Critical",
        "issues": ["No auth — full cache dump", "UDP amplification DDoS (factor 50,000x)"],
        "cve_refs": [],
        "remediation": "Bind to localhost. Disable UDP. Add SASL authentication.",
        "mitre": "T1498.002 — Network Denial of Service: Reflection Amplification",
    },
    27017: {
        "service": "MongoDB",
        "risk": "Critical",
        "issues": ["No auth in default install", "External exposure = full data access"],
        "cve_refs": [],
        "remediation": "Enable --auth. Bind to 127.0.0.1. Create admin user.",
        "mitre": "T1530 — Data from Cloud Storage",
    },
    2375: {
        "service": "Docker",
        "risk": "Critical",
        "issues": ["Unauthenticated Docker API = container escape to host root"],
        "cve_refs": ["CVE-2019-5736"],
        "remediation": "Never expose Docker socket remotely. Use TLS + client certs.",
        "mitre": "T1610 — Deploy Container",
    },
}

# Severity ordering for sorting
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


class NetworkVulnMapper:
    """
    Maps a NetworkMap to a ranked list of NetworkVuln findings.
    Combines static KB lookup with optional active verification.
    """

    async def map(self, network_map: NetworkMap,
                  active_checks: bool = True) -> list[NetworkVuln]:
        """
        Main entry point. Returns findings sorted by severity (Critical first).
        active_checks=True runs lightweight active probes (FTP anon, Redis auth, etc.)
        """
        findings: list[NetworkVuln] = []

        for host in network_map.live_hosts():
            ports = network_map.services.get(host.ip, host.open_ports)
            for port_info in ports:
                # Static KB match
                kb = NETWORK_VULN_KB.get(port_info.port)
                if kb:
                    vuln = NetworkVuln(
                        host=host.ip,
                        hostname=host.hostname,
                        port=port_info.port,
                        service=kb["service"],
                        severity=kb["risk"],
                        title=f"{kb['service']} exposed on port {port_info.port}",
                        description=port_info.banner[:200] if port_info.banner else "",
                        issues=list(kb["issues"]),
                        cve_refs=list(kb.get("cve_refs", [])),
                        mitre_technique=kb.get("mitre", ""),
                        remediation=kb.get("remediation", ""),
                    )
                    findings.append(vuln)

                # Active verification probes
                if active_checks:
                    active = await self._active_check(host.ip, port_info.port)
                    for av in active:
                        av.hostname = host.hostname
                        findings.append(av)

        # Sort: Critical → High → Medium → Low
        return sorted(
            findings,
            key=lambda f: _SEV_RANK.get(f.severity, 0),
            reverse=True,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Active checks — lightweight, non-destructive probes
    # ─────────────────────────────────────────────────────────────────────────

    async def _active_check(self, ip: str, port: int) -> list[NetworkVuln]:
        """Route to per-service active check."""
        checks = {
            21: self._check_ftp_anon,
            6379: self._check_redis_noauth,
            9200: self._check_elasticsearch_noauth,
            27017: self._check_mongodb_noauth,
            11211: self._check_memcached_noauth,
            2375: self._check_docker_api,
        }
        fn = checks.get(port)
        if fn:
            try:
                return await asyncio.wait_for(fn(ip, port), timeout=5.0)
            except Exception:
                pass
        return []

    async def _check_ftp_anon(self, ip: str, port: int = 21) -> list[NetworkVuln]:
        """Check if FTP allows anonymous login."""
        try:
            r, w = await asyncio.open_connection(ip, port)
            banner = (await asyncio.wait_for(r.read(256), 3.0)).decode(errors="replace")
            # Try anonymous login
            w.write(b"USER anonymous\r\n")
            await w.drain()
            resp = (await asyncio.wait_for(r.read(256), 3.0)).decode(errors="replace")
            w.write(b"PASS cyphex@cyphex.io\r\n")
            await w.drain()
            resp2 = (await asyncio.wait_for(r.read(256), 3.0)).decode(errors="replace")
            w.close()
            if resp2.startswith("230"):  # 230 = Login successful
                return [NetworkVuln(
                    host=ip, port=port, service="FTP",
                    severity="Critical",
                    title="FTP Anonymous Login Enabled",
                    description="Anonymous FTP login accepted — no credentials required.",
                    issues=["Anonymous read/write access to FTP directory"],
                    remediation="Disable anonymous FTP access in server config.",
                    confirmed=True,
                    evidence=f"230 response to anonymous login: {resp2[:100]}",
                )]
        except Exception:
            pass
        return []

    async def _check_redis_noauth(self, ip: str, port: int = 6379) -> list[NetworkVuln]:
        """Check if Redis responds without AUTH."""
        try:
            r, w = await asyncio.open_connection(ip, port)
            w.write(b"PING\r\n")
            await w.drain()
            resp = (await asyncio.wait_for(r.read(64), 3.0)).decode(errors="replace")
            w.close()
            if "+PONG" in resp:
                return [NetworkVuln(
                    host=ip, port=port, service="Redis",
                    severity="Critical",
                    title="Redis Running Without Authentication",
                    description="Redis PING responded without any AUTH — full keyspace accessible.",
                    issues=["RCE via CONFIG SET", "Full data dump without credentials"],
                    cve_refs=["CVE-2022-0543"],
                    remediation="Add 'requirepass <strong-password>' to redis.conf. Bind to 127.0.0.1.",
                    confirmed=True,
                    evidence=f"PING response: {resp[:50]}",
                )]
        except Exception:
            pass
        return []

    async def _check_elasticsearch_noauth(self, ip: str, port: int = 9200) -> list[NetworkVuln]:
        """Check if Elasticsearch returns cluster info without auth."""
        try:
            r, w = await asyncio.open_connection(ip, port)
            request = (
                f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: cyphex-audit\r\n\r\n"
            )
            w.write(request.encode())
            await w.drain()
            resp = b""
            for _ in range(10):
                chunk = await asyncio.wait_for(r.read(1024), 2.0)
                if not chunk:
                    break
                resp += chunk
            w.close()
            decoded = resp.decode(errors="replace")
            if '"cluster_name"' in decoded or '"version"' in decoded:
                return [NetworkVuln(
                    host=ip, port=port, service="Elasticsearch",
                    severity="Critical",
                    title="Elasticsearch Accessible Without Authentication",
                    description="Cluster metadata returned without credentials.",
                    issues=["Full index read/write", "Data exfiltration risk"],
                    remediation="Enable X-Pack Security. Set xpack.security.enabled: true.",
                    confirmed=True,
                    evidence=decoded[200:400],
                )]
        except Exception:
            pass
        return []

    async def _check_mongodb_noauth(self, ip: str, port: int = 27017) -> list[NetworkVuln]:
        """Check if MongoDB responds to isMaster without auth (banner check)."""
        try:
            r, w = await asyncio.open_connection(ip, port)
            # isMaster OP_QUERY (minimal wire protocol)
            msg = bytes.fromhex(
                "3a000000" "00000000" "00000000"
                "d4070000" "00000000" "61646d696e2e24636d6400"
                "00000000" "ffffffff"
                "130000001069734d617374657200010000000000"
            )
            w.write(msg)
            await w.drain()
            resp = await asyncio.wait_for(r.read(256), 3.0)
            w.close()
            if len(resp) > 20:  # Got a real response
                return [NetworkVuln(
                    host=ip, port=port, service="MongoDB",
                    severity="Critical",
                    title="MongoDB Accessible Without Authentication",
                    description="MongoDB wire protocol responded without credentials.",
                    issues=["Full database read/write", "Complete data exfiltration"],
                    remediation="Enable --auth flag. Create admin user. Bind to 127.0.0.1.",
                    confirmed=True,
                    evidence=f"Wire protocol response: {len(resp)} bytes received",
                )]
        except Exception:
            pass
        return []

    async def _check_memcached_noauth(self, ip: str, port: int = 11211) -> list[NetworkVuln]:
        """Check if Memcached responds to stats command."""
        try:
            r, w = await asyncio.open_connection(ip, port)
            w.write(b"stats\r\n")
            await w.drain()
            resp = (await asyncio.wait_for(r.read(512), 3.0)).decode(errors="replace")
            w.close()
            if "STAT pid" in resp or "STAT version" in resp:
                return [NetworkVuln(
                    host=ip, port=port, service="Memcached",
                    severity="Critical",
                    title="Memcached Accessible Without Authentication",
                    description="Memcached stats command succeeded — full cache accessible.",
                    issues=["Full cache dump", "UDP amplification DDoS vector"],
                    remediation="Bind to localhost. Enable SASL auth. Disable UDP (--disable-udp).",
                    confirmed=True,
                    evidence=resp[:200],
                )]
        except Exception:
            pass
        return []

    async def _check_docker_api(self, ip: str, port: int = 2375) -> list[NetworkVuln]:
        """Check if Docker API responds without TLS."""
        try:
            r, w = await asyncio.open_connection(ip, port)
            req = f"GET /version HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: cyphex-audit\r\n\r\n"
            w.write(req.encode())
            await w.drain()
            resp = (await asyncio.wait_for(r.read(512), 3.0)).decode(errors="replace")
            w.close()
            if '"Version"' in resp or '"ApiVersion"' in resp:
                return [NetworkVuln(
                    host=ip, port=port, service="Docker API",
                    severity="Critical",
                    title="Docker API Exposed Without TLS",
                    description="Unauthenticated Docker API access — container escape to host root.",
                    issues=["Full container lifecycle control", "Host filesystem access via volume mount"],
                    cve_refs=["CVE-2019-5736"],
                    remediation="Never expose TCP 2375. Use Unix socket or TLS + client certs.",
                    confirmed=True,
                    evidence=resp[100:300],
                )]
        except Exception:
            pass
        return []
