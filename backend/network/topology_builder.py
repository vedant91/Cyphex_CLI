"""
CYPHEX — Network Topology Builder

Builds a device relationship graph from a NetworkMap using networkx.
Provides:
  - Visualisable device graph (nodes = devices, edges = observed connections)
  - Attack path analysis (shortest path from attacker entry → crown jewel)
  - Segment identification (LAN/DMZ/untrusted detection)
  - Critical asset ranking (most-connected + most-vulnerable devices first)

networkx is a pure-Python library — no C extensions, no GPU needed.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    nx = None  # type: ignore
    HAS_NX = False

from backend.network.models import HostProfile, NetworkMap, NetworkVuln

# Risk severity ranking
_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


class TopologyBuilder:
    """
    Builds a networkx graph from a NetworkMap.
    Handles the case where networkx is not installed gracefully.
    """

    def build(self, network_map: NetworkMap) -> Optional[object]:
        """
        Build a device graph.
        Returns None if networkx is not available.
        """
        if not HAS_NX:
            return None

        G = nx.Graph()

        for host in network_map.live_hosts():
            # Count vulnerabilities per host (from vulns list if attached)
            vuln_count = 0
            max_severity = "Low"

            G.add_node(host.ip, **{
                "hostname":    host.hostname,
                "os":          host.os_guess,
                "device_type": host.device_type,
                "open_ports":  len(host.open_ports),
                "risk_score":  host.risk_score,
                "mac":         host.mac,
                "vendor":      host.vendor,
            })

        # Add edges from observed flows
        for flow in network_map.flows:
            src = flow.src_ip
            dst = flow.dst_ip
            if src in G and dst in G:
                if G.has_edge(src, dst):
                    G[src][dst]["weight"] = G[src][dst].get("weight", 1) + 1
                    G[src][dst]["bytes"]  = G[src][dst].get("bytes", 0) + flow.bytes_total
                else:
                    G.add_edge(src, dst, **{
                        "port":     flow.dst_port,
                        "protocol": flow.protocol,
                        "bytes":    flow.bytes_total,
                        "weight":   1,
                    })

        return G

    def annotate_vulns(self, G, vulns: list[NetworkVuln]) -> None:
        """
        Attach vulnerability data to graph nodes.
        Modifies G in place.
        """
        if not HAS_NX or G is None:
            return
        for vuln in vulns:
            if vuln.host in G:
                existing = G.nodes[vuln.host].get("vuln_count", 0)
                G.nodes[vuln.host]["vuln_count"] = existing + 1
                cur_sev = G.nodes[vuln.host].get("max_severity", "Low")
                if _SEV_RANK.get(vuln.severity, 0) > _SEV_RANK.get(cur_sev, 0):
                    G.nodes[vuln.host]["max_severity"] = vuln.severity

    def find_attack_paths(
        self,
        G,
        entry_point: str,
        target_ip: str,
    ) -> list[list[str]]:
        """
        Find shortest attack paths from entry_point to target_ip.
        Returns list of paths (each path = list of IP addresses).
        """
        if not HAS_NX or G is None:
            return []
        try:
            paths = list(nx.all_shortest_paths(G, source=entry_point, target=target_ip))
            return paths
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def critical_assets(self, G, top_n: int = 5) -> list[str]:
        """
        Rank devices by: risk_score × (degree + 1).
        Most connected + most vulnerable devices listed first.
        """
        if not HAS_NX or G is None:
            return []
        scores = []
        for node in G.nodes():
            risk = G.nodes[node].get("risk_score", 0.0)
            degree = G.degree(node)
            scores.append((node, risk * (degree + 1)))
        scores.sort(key=lambda x: x[1], reverse=True)
        return [ip for ip, _ in scores[:top_n]]

    def segments(self, G) -> dict[str, list[str]]:
        """
        Identify network segments by /24 subnet grouping.
        Returns dict of "subnet_prefix" → [list of IPs].
        """
        if not HAS_NX or G is None:
            return {}
        segs: dict[str, list[str]] = {}
        for node in G.nodes():
            try:
                net = str(ipaddress.ip_network(node + "/24", strict=False).network_address)
                segs.setdefault(net, []).append(node)
            except ValueError:
                segs.setdefault("unknown", []).append(node)
        return segs

    def to_dict(self, G) -> dict:
        """
        Serialise graph to plain dict (for JSON output / report embedding).
        """
        if not HAS_NX or G is None:
            return {"nodes": [], "edges": []}
        return {
            "nodes": [
                {"id": n, **{k: v for k, v in G.nodes[n].items()}}
                for n in G.nodes()
            ],
            "edges": [
                {"source": u, "target": v, **{k: val for k, val in d.items()}}
                for u, v, d in G.edges(data=True)
            ],
        }

    def summary_text(self, G, vulns: list[NetworkVuln]) -> str:
        """Human-readable topology summary for CLI output."""
        if not HAS_NX or G is None:
            return "  (networkx not installed — topology analysis unavailable)"

        lines = [
            f"  Nodes (devices):  {G.number_of_nodes()}",
            f"  Edges (flows):    {G.number_of_edges()}",
        ]

        segs = self.segments(G)
        if segs:
            lines.append(f"  Segments (/24):   {len(segs)}")
            for subnet, ips in sorted(segs.items()):
                lines.append(f"    {subnet}/24  →  {len(ips)} devices")

        top = self.critical_assets(G)
        if top:
            lines.append("  Highest-risk devices:")
            for ip in top:
                nd = G.nodes.get(ip, {})
                hostname = nd.get("hostname", "")
                risk = nd.get("risk_score", 0.0)
                lines.append(f"    {ip:16} {hostname:20} risk={risk:.2f}")

        return "\n".join(lines)
