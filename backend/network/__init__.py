"""
CYPHEX — Network Security Module

Three capabilities:
  discovery.py      — Host/port/service discovery (nmap → socket fallback)
  vuln_mapper.py    — Maps open ports to known vulnerability patterns
  network_genome.py — Behavioural anomaly detection per device (no signatures)
  flow_collector.py — Parses netstat/ss/tcpdump into flow observations
  oracle_network.py — Ollama Oracle explains anomalies → MITRE ATT&CK
  topology_builder.py — networkx device graph + attack path analysis

CLI commands added to cyphex_cli.py:
  cyphex netmap   [--target CIDR]   — one-shot discovery + vuln report
  cyphex netwatch [--interval N]    — continuous behavioural monitoring
  cyphex netaudit --host IP         — deep audit of a single host
"""

from backend.network.models import (
    HostProfile,
    PortInfo,
    NetworkMap,
    NetworkVuln,
    FlowObservation,
    AnomalyScore,
)

__all__ = [
    "HostProfile",
    "PortInfo",
    "NetworkMap",
    "NetworkVuln",
    "FlowObservation",
    "AnomalyScore",
]
