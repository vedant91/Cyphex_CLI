"""
CYPHEX — Network Security Data Models

All dataclasses used across the network module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ─── Host / Port Models ───────────────────────────────────────────────────────

@dataclass
class PortInfo:
    """A single open port on a host."""
    port: int
    protocol: str = "tcp"          # tcp | udp
    service: str = ""              # guessed service name
    banner: str = ""               # raw banner text (first 512 bytes)
    version: str = ""              # e.g. "OpenSSH 8.9"
    state: str = "open"            # open | filtered | closed


@dataclass
class HostProfile:
    """A discovered host on the network."""
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""               # NIC vendor from MAC OUI
    os_guess: str = ""             # OS fingerprint or TTL heuristic
    ttl: int = 0
    is_up: bool = True
    open_ports: list[PortInfo] = field(default_factory=list)
    risk_score: float = 0.0        # 0.0–1.0
    device_type: str = "unknown"   # router|server|workstation|iot|printer
    discovered_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def summary(self) -> str:
        ports = ", ".join(str(p.port) for p in self.open_ports[:8])
        return f"{self.ip:16} {self.hostname:20} {self.os_guess:15} ports=[{ports}]"


@dataclass
class NetworkMap:
    """Full picture of a scanned network."""
    target: str                                # CIDR or single IP
    hosts: list[HostProfile] = field(default_factory=list)
    # host IP → list of PortInfo (same data as HostProfile.open_ports, kept
    # here for backward compat with callers that iterate by IP key)
    services: dict[str, list[PortInfo]] = field(default_factory=dict)
    flows: list[FlowObservation] = field(default_factory=list)
    scan_duration_s: float = 0.0
    scanned_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def live_hosts(self) -> list[HostProfile]:
        return [h for h in self.hosts if h.is_up]

    def hosts_by_risk(self) -> list[HostProfile]:
        return sorted(self.hosts, key=lambda h: h.risk_score, reverse=True)


# ─── Vulnerability Models ────────────────────────────────────────────────────

@dataclass
class NetworkVuln:
    """A vulnerability finding on a network host/port."""
    host: str
    port: int
    service: str
    severity: str                  # Critical | High | Medium | Low | Info
    title: str
    description: str = ""
    issues: list[str] = field(default_factory=list)
    cve_refs: list[str] = field(default_factory=list)
    mitre_technique: str = ""      # e.g. "T1046 — Network Service Discovery"
    remediation: str = ""
    confirmed: bool = False        # active probe confirmed it
    hostname: str = ""
    evidence: str = ""

    @property
    def cvss_estimate(self) -> float:
        return {"Critical": 9.5, "High": 7.5, "Medium": 5.0,
                "Low": 2.5, "Info": 0.0}.get(self.severity, 0.0)


# ─── Flow / Traffic Models ───────────────────────────────────────────────────

@dataclass
class FlowObservation:
    """
    A single traffic flow observation (from netstat/ss/tcpdump).
    One row = one active or recently closed TCP/UDP connection.
    """
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    state: str = ""                # ESTABLISHED|TIME_WAIT|SYN_SENT|...
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    pid: int = 0
    process_name: str = ""
    observed_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    @property
    def bytes_total(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def is_outbound(self) -> bool:
        """True if src is a private/local IP."""
        return _is_private_ip(self.src_ip)

    @property
    def is_inbound(self) -> bool:
        return not self.is_outbound


# ─── Anomaly Score Models ────────────────────────────────────────────────────

@dataclass
class AnomalyScore:
    """Result of scoring a device observation against its baseline."""
    device_ip: str
    score: float                   # 0.0 (normal) → 1.0 (severe anomaly)
    is_anomaly: bool
    reason: str = ""
    top_deviating_features: list[str] = field(default_factory=list)
    # Oracle enrichment (filled in later if score > threshold)
    threat_scenario: str = ""
    mitre_technique: str = ""
    confidence: float = 0.0
    false_positive_prob: float = 0.0
    containment_actions: list[str] = field(default_factory=list)
    scored_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    @property
    def severity(self) -> str:
        if self.score >= 0.85:
            return "Critical"
        if self.score >= 0.70:
            return "High"
        if self.score >= 0.55:
            return "Medium"
        return "Low"


# ─── Device Behaviour Window ─────────────────────────────────────────────────

@dataclass
class DeviceBehaviourWindow:
    """
    Aggregated network metrics for a device over a time window.
    Fed into NetworkBehavioralGenome.extract_features().
    """
    device_ip: str
    window_start: str = ""
    window_end: str = ""
    window_minutes: int = 5

    # Volume
    bytes_sent_total: int = 0
    bytes_recv_total: int = 0
    packets_sent_total: int = 0
    packets_recv_total: int = 0
    active_connections: int = 0
    new_connections: int = 0

    # Ports
    unique_remote_ports: set = field(default_factory=set)
    unique_remote_ips: set = field(default_factory=set)
    refused_connections: int = 0

    # Protocols
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    dns_queries: int = 0
    http_connections: int = 0
    cleartext_connections: int = 0   # telnet/ftp/http/pop3

    # Scan indicators
    syn_no_ack: int = 0
    arp_broadcasts: int = 0

    # Destinations
    lan_connections: int = 0
    wan_connections: int = 0
    new_destinations: int = 0       # IPs not seen in baseline


# ─── Internal helpers ────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    """True if the IP is a RFC 1918 private or loopback address."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False
