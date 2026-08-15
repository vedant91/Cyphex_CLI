"""
CYPHEX — Scan Context & Vulnerability Models
ScanContext is the shared state that flows through the entire agent pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class FormData:
    """A discovered HTML form."""
    action: str
    method: str  # GET or POST
    inputs: list[str] = field(default_factory=list)
    page: str = ""
    has_file_upload: bool = False

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
            "page": self.page,
            "has_file_upload": self.has_file_upload,
        }


@dataclass
class ParamData:
    """A discovered URL parameter."""
    url: str
    name: str
    value: str = ""
    param_type: str = "query"  # query | path | header | cookie

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "name": self.name,
            "value": self.value,
            "param_type": self.param_type,
        }


@dataclass
class Evidence:
    """Raw HTTP evidence for a finding."""
    request_method: str
    request_url: str
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "request": f"{self.request_method} {self.request_url}",
            "request_body": self.request_body[:500],
            "response_status": self.response_status,
            "response_body": self.response_body[:1000],
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Vuln:
    """A confirmed vulnerability."""
    name: str
    severity: str  # Critical | High | Medium | Low
    cvss_score: float = 0.0
    description: str = ""
    endpoint: str = ""
    payload: str = ""
    confirmed: bool = False
    evidence: str = ""
    dumped_data: str = ""
    rce_output: str = ""
    cvss_vector: str = ""
    attack_chain: str = ""
    business_impact: str = ""
    fix: str = ""
    cwe: str = ""

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "confirmed": self.confirmed,
            "endpoint": self.endpoint,
        }
        if self.payload:
            d["payload"] = self.payload
        if self.description:
            d["description"] = self.description
        if self.evidence:
            d["evidence"] = self.evidence[:500]
        if self.dumped_data:
            d["dumped_data"] = self.dumped_data[:500]
        if self.rce_output:
            d["rce_output"] = self.rce_output[:500]
        if self.fix:
            d["fix"] = self.fix
        return d


@dataclass
class ScanContext:
    """
    Shared state that flows through the entire agent pipeline.
    Each agent reads from and writes to this context.
    """
    target_url: str = ""

    # Recon results
    framework: Optional[str] = None
    database: Optional[str] = None
    os_type: Optional[str] = None
    language: Optional[str] = None
    server: Optional[str] = None
    headers: dict = field(default_factory=dict)
    discovered_paths: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    # Crawler results
    sitemap: dict = field(default_factory=dict)
    all_forms: list[FormData] = field(default_factory=list)
    all_endpoints: list[str] = field(default_factory=list)
    all_params: list[ParamData] = field(default_factory=list)
    all_links: list[str] = field(default_factory=list)
    all_cookies: dict = field(default_factory=dict)
    xml_endpoints: list[str] = field(default_factory=list)
    graphql_endpoint: Optional[str] = None
    session_cookie: str = ""

    # Attack results
    confirmed_vulns: list[Vuln] = field(default_factory=list)
    raw_evidence: list[Evidence] = field(default_factory=list)

    # Terminal audit log
    terminal_logs: list = field(default_factory=list)

    def to_summary(self) -> dict:
        return {
            "target": self.target_url,
            "framework": self.framework,
            "database": self.database,
            "os_type": self.os_type,
            "forms_found": len(self.all_forms),
            "endpoints_found": len(self.all_endpoints),
            "params_found": len(self.all_params),
            "vulns_confirmed": len(self.confirmed_vulns),
            "commands_executed": len(self.terminal_logs),
        }
