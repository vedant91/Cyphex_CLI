"""
CYPHEX — Network Discovery Engine

Discovers hosts and services on a network using whatever tools are available.
Graceful fallback chain:
  nmap (best)  →  arp-scan + socket probes  →  pure Python asyncio TCP connect

Zero external APIs. Works offline. Requires no root for the Python fallback
(though nmap/arp-scan need root for raw socket / ARP modes on macOS/Linux).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Optional

from backend.network.models import HostProfile, NetworkMap, PortInfo

# ── Top-1000 most common ports (IANA + Nmap defaults) ────────────────────────
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179,
    443, 445, 465, 587, 631, 993, 995, 1080, 1194, 1433, 1521,
    1723, 2049, 2121, 2181, 2222, 2375, 2376, 3000, 3306, 3389,
    3690, 4000, 4369, 5000, 5432, 5555, 5601, 5900, 5938, 5984,
    6379, 6443, 7001, 7077, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018,
    28017, 50070, 61616,
]

# ── Service name guessing from port number ────────────────────────────────────
_PORT_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 179: "BGP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP/Submission", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 7001: "WebLogic",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 50070: "Hadoop-HDFS",
}


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _guess_service(port: int, banner: str = "") -> str:
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "SSH"
        if "http" in banner_lower:
            return "HTTP"
        if "ftp" in banner_lower:
            return "FTP"
        if "smtp" in banner_lower:
            return "SMTP"
        if "mysql" in banner_lower:
            return "MySQL"
        if "redis" in banner_lower:
            return "Redis"
    return _PORT_SERVICES.get(port, f"port-{port}")


def _guess_device_type(host: HostProfile) -> str:
    """Classify a device from hostname, ports, vendor."""
    h = (host.hostname + " " + host.vendor + " " + host.os_guess).lower()
    ports = {p.port for p in host.open_ports}

    if any(k in h for k in ["router", "gateway", "cisco", "mikrotik", "ubnt", "unifi"]):
        return "router"
    if any(k in h for k in ["printer", "hp", "xerox", "canon", "lexmark"]):
        return "printer"
    if any(k in h for k in ["android", "iphone", "ipad", "mobile", "phone"]):
        return "mobile"
    if any(k in h for k in ["cam", "camera", "nvr", "dvr", "hikvision", "dahua"]):
        return "iot"
    if "windows" in h or 3389 in ports or 135 in ports:
        return "workstation"
    if 22 in ports and (80 in ports or 443 in ports or 3306 in ports or 5432 in ports):
        return "server"
    if any(k in h for k in ["pi", "raspberry", "arduino"]):
        return "iot"
    return "workstation"


def _compute_risk(host: HostProfile) -> float:
    """
    0.0–1.0 risk score based on open high-risk ports.
    Does NOT touch the network — pure local computation.
    """
    HIGH_RISK = {23, 21, 3389, 5900, 6379, 27017, 11211, 9200, 2375}
    MED_RISK  = {22, 80, 8080, 3306, 5432, 1521, 1433, 445, 139, 135}
    score = 0.0
    for p in host.open_ports:
        if p.port in HIGH_RISK:
            score += 0.25
        elif p.port in MED_RISK:
            score += 0.10
    return min(score, 1.0)


class NetworkDiscovery:
    """
    Multi-strategy network discovery engine.
    All methods are async so they integrate cleanly with the CYPHEX asyncio loop.
    """

    def __init__(self, timeout: float = 0.8, max_concurrent: int = 256):
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    async def discover(self, target: str = "auto") -> NetworkMap:
        """
        Full discovery pipeline: host sweep → port scan → service fingerprint.
        target: "auto" = detect local subnet, or "192.168.1.0/24" or "10.0.0.1"
        """
        t0 = time.monotonic()

        if target == "auto":
            target = self._detect_local_subnet()

        print(f"  [netmap] Target: {target}")

        # For a single IP, skip liveness sweep — treat as always-up so firewalled
        # or loopback hosts that reject our liveness probe still get port-scanned.
        _is_single = "/" not in target
        if _is_single:
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(target)[0]
            except Exception:
                pass
            hosts = [HostProfile(ip=target, hostname=hostname, is_up=True)]
        else:
            # Phase 1: Host discovery
            print("  [netmap] Phase 1: Host sweep...")
            hosts = await self._discover_hosts(target)

        live = [h for h in hosts if h.is_up]
        print(f"  [netmap] {len(live)} live hosts found")


        # Phase 2: Port + service scan
        print("  [netmap] Phase 2: Port scan...")
        services: dict[str, list[PortInfo]] = {}
        sem = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._scan_host(h, sem) for h in live]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for host, result in zip(live, results):
            if isinstance(result, list):
                host.open_ports = result
                services[host.ip] = result
            host.device_type = _guess_device_type(host)
            host.risk_score = _compute_risk(host)

        duration = time.monotonic() - t0
        print(f"  [netmap] Scan complete in {duration:.1f}s")

        return NetworkMap(
            target=target,
            hosts=hosts,
            services=services,
            scan_duration_s=duration,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 1 — Host discovery
    # ─────────────────────────────────────────────────────────────────────────

    async def _discover_hosts(self, target: str) -> list[HostProfile]:
        if _tool_available("nmap"):
            return await self._nmap_ping_sweep(target)
        return await self._python_ping_sweep(target)

    async def _nmap_ping_sweep(self, target: str) -> list[HostProfile]:
        """nmap -sn (no port scan) — fastest host discovery."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sn", "--open", "-T4", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return self._parse_nmap_ping(stdout.decode(errors="replace"))
        except Exception:
            return await self._python_ping_sweep(target)

    def _parse_nmap_ping(self, output: str) -> list[HostProfile]:
        hosts = []
        current_ip = ""
        current_hostname = ""
        for line in output.splitlines():
            m = re.search(r"Nmap scan report for (.+)", line)
            if m:
                text = m.group(1).strip()
                # "hostname (192.168.1.1)" or just "192.168.1.1"
                ip_m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", text)
                if ip_m:
                    current_ip = ip_m.group(1)
                    current_hostname = text.split("(")[0].strip()
                else:
                    current_ip = text
                    current_hostname = ""
            if "Host is up" in line and current_ip:
                hosts.append(HostProfile(
                    ip=current_ip,
                    hostname=current_hostname,
                    is_up=True,
                ))
                current_ip = ""
        return hosts

    async def _python_ping_sweep(self, target: str) -> list[HostProfile]:
        """
        Pure-Python TCP connect sweep — no root, no external tools.
        Tests port 80 or 22 as a liveness probe.
        """
        try:
            network = ipaddress.ip_network(target, strict=False)
            ips = list(network.hosts())
        except ValueError:
            # Single IP
            try:
                ips = [ipaddress.ip_address(target)]
            except ValueError:
                return []

        sem = asyncio.Semaphore(256)
        tasks = [self._probe_host(str(ip), sem) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, HostProfile) and r.is_up]

    async def _probe_host(self, ip: str, sem: asyncio.Semaphore) -> HostProfile:
        """Check if a host is up by trying to connect on common ports."""
        async with sem:
            for port in [80, 22, 443, 445, 8080]:
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=self.timeout
                    )
                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception:
                        pass
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        pass
                    return HostProfile(ip=ip, hostname=hostname, is_up=True)
                except Exception:
                    continue
        return HostProfile(ip=ip, is_up=False)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2 — Port scan
    # ─────────────────────────────────────────────────────────────────────────

    async def _scan_host(self, host: HostProfile,
                          sem: asyncio.Semaphore) -> list[PortInfo]:
        if _tool_available("nmap"):
            return await self._nmap_port_scan(host.ip)
        return await self._python_port_scan(host.ip, sem)

    async def _nmap_port_scan(self, ip: str) -> list[PortInfo]:
        """nmap with service version detection."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sV", "-T4", "--open",
                "--top-ports", "1000",
                ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return self._parse_nmap_ports(stdout.decode(errors="replace"))
        except Exception:
            return await self._python_port_scan(ip, asyncio.Semaphore(64))

    def _parse_nmap_ports(self, output: str) -> list[PortInfo]:
        ports = []
        for line in output.splitlines():
            # "22/tcp   open  ssh     OpenSSH 8.9p1"
            m = re.match(
                r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line.strip()
            )
            if m:
                port_num = int(m.group(1))
                proto = m.group(2)
                service = m.group(3)
                version = m.group(4).strip()
                ports.append(PortInfo(
                    port=port_num,
                    protocol=proto,
                    service=service,
                    version=version,
                ))
        return ports

    async def _python_port_scan(self, ip: str,
                                  sem: asyncio.Semaphore) -> list[PortInfo]:
        """Async TCP connect scan — no root, no nmap."""
        tasks = [self._tcp_probe(ip, p, sem) for p in TOP_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ports = []
        for r in results:
            if isinstance(r, PortInfo):
                ports.append(r)
        return ports

    async def _tcp_probe(self, ip: str, port: int,
                          sem: asyncio.Semaphore) -> Optional[PortInfo]:
        async with sem:
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                # Grab banner (first 512 bytes within 1s)
                banner = ""
                try:
                    data = await asyncio.wait_for(r.read(512), timeout=1.0)
                    banner = data.decode(errors="replace").strip()
                except Exception:
                    pass
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return PortInfo(
                    port=port,
                    service=_guess_service(port, banner),
                    banner=banner[:256],
                )
            except Exception:
                return None

    # ─────────────────────────────────────────────────────────────────────────
    # Subnet detection
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_local_subnet(self) -> str:
        """
        Auto-detect the local /24 subnet using the default route interface.
        Falls back to 192.168.1.0/24 if detection fails.
        """
        try:
            # Get the default gateway IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Return /24 subnet
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    # ─────────────────────────────────────────────────────────────────────────
    # ARP cache (passive, no scanning)
    # ─────────────────────────────────────────────────────────────────────────

    def read_arp_cache(self) -> list[tuple[str, str]]:
        """
        Read /proc/net/arp (Linux) or `arp -a` (macOS) for IP→MAC pairs.
        Returns list of (ip, mac) tuples. Zero network traffic.
        """
        pairs = []
        if sys.platform != "darwin":
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                            pairs.append((parts[0], parts[3]))
                return pairs
            except Exception:
                pass
        # macOS: parse `arp -a`
        try:
            out = subprocess.check_output(
                ["arp", "-a"], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                m = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line
                )
                if m:
                    pairs.append((m.group(1), m.group(2)))
        except Exception:
            pass
        return pairs
