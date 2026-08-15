"""
CYPHEX AttackGraph — upgraded with priority chains and lateral movement logic.
Shared state across all DeepAgents in a scan session.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Set
import re


@dataclass
class AttackEdge:
    source: str
    target: str
    action: str
    priority: str  # critical | high | medium | low


@dataclass
class AttackNode:
    url: str
    known_vulns: List[str] = field(default_factory=list)
    tested_hypotheses: List[str] = field(default_factory=list)


class AttackGraph:
    """
    Shared mutable state across all DeepAgents in a scan session.
    Updated in real-time as findings emerge — drives chained exploitation.
    """

    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self.confirmed_creds: List[Tuple[str, str, str]] = []   # (user, pwd, source_url)
        self.confirmed_tokens: List[str] = []                   # JWTs / session tokens
        self.privilege_level: str = "none"                       # none → user → admin
        # Priority queue: agent class name → list of override targets
        self.priority_targets: Dict[str, List[str]] = {}

    def get_node(self, url: str) -> AttackNode:
        if url not in self.nodes:
            self.nodes[url] = AttackNode(url=url)
        return self.nodes[url]

    def _extract_token(self, evidence: str) -> str:
        match = re.search(r'"(?:token|jwt)"\s*:\s*"([^"]+)"', evidence, re.I)
        if match:
            return match.group(1)
        return ""

    def _find_auth_endpoints(self) -> List[str]:
        """Find endpoints that likely require authentication."""
        from backend.config.dast_constants import AUTH_KEYWORDS
        return [node for node in self.nodes if any(k in node for k in AUTH_KEYWORDS)]

    def update_from_finding(self, finding) -> List[AttackEdge]:
        """
        When one agent finds something, compute the follow-up attack chain.
        Returns new AttackEdges sorted by priority.
        """
        chains = []
        node = self.get_node(finding.endpoint)
        node.known_vulns.append(finding.name)

        # ── SQLi → Credential dump → Auth bypass ──────────────────────────────
        if "SQL" in finding.name:
            # If evidence contains credential patterns
            if finding.dumped_data and ":" in finding.dumped_data:
                user, pwd = finding.dumped_data.split(":", 1)
                self.confirmed_creds.append((user.strip(), pwd.strip(), finding.endpoint))
                # Tell DeepAuthAgent to hit admin endpoints with these creds
                self.priority_targets.setdefault("DeepAuthAgent", []).append("/admin")
                chains.append(AttackEdge(
                    source=finding.endpoint,
                    target="/admin",
                    action="credential_stuffing",
                    priority="critical",
                ))

            # SQL error → also try UNION extraction
            if "Error" in finding.name:
                chains.append(AttackEdge(
                    source=finding.endpoint,
                    target=finding.endpoint,
                    action="union_extraction",
                    priority="high",
                ))

        # ── Data Exposure → Token replay ───────────────────────────────────────
        if "Data Exposure" in finding.name or "Sensitive" in finding.name:
            if "token" in finding.evidence.lower():
                token = self._extract_token(finding.evidence)
                if token:
                    self.confirmed_tokens.append(token)
                    auth_targets = self._find_auth_endpoints()
                    for target in auth_targets:
                        self.priority_targets.setdefault("DeepAuthAgent", []).append(target)
                        chains.append(AttackEdge(
                            source=finding.endpoint,
                            target=target,
                            action="token_replay",
                            priority="high",
                        ))

        # ── IDOR → Mass assignment escalation ──────────────────────────────────
        if "IDOR" in finding.name:
            chains.append(AttackEdge(
                source=finding.endpoint,
                target=finding.endpoint.rstrip("/0123456789"),
                action="mass_assignment_attempt",
                priority="high",
            ))

        # ── Auth bypass → Privilege escalation ─────────────────────────────────
        if "Default" in finding.name or "Auth" in finding.name:
            self.privilege_level = "user"
            chains.append(AttackEdge(
                source=finding.endpoint,
                target="/admin",
                action="privilege_escalation",
                priority="critical",
            ))

        # ── SSTI/CMDi → Full RCE ───────────────────────────────────────────────
        if "SSTI" in finding.name or "Command Injection" in finding.name:
            self.privilege_level = "admin"
            chains.append(AttackEdge(
                source=finding.endpoint,
                target="/",
                action="rce_full_compromise",
                priority="critical",
            ))

        # Sort chains: critical first
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        chains.sort(key=lambda e: priority_order.get(e.priority, 99))
        self.edges.extend(chains)
        return chains
