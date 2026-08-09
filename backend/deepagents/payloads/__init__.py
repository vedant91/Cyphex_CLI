"""
CYPHEX DeepAgents — Payload Library
Tier 1: Fast/cheap, high signal-to-noise (always tried first)
Tier 2: WAF-bypass encoding variants (tried on failure)
Tier 3: Time-delay / blind / OOB (expensive, tried last)
"""
from .sqli import SQLI_T1, SQLI_T2, SQLI_T3, SQLI_BLIND, SQLI_TIME, SQLI_ERRORS
from .xss import XSS_T1, XSS_T2, XSS_DOM, XSS_CSP_BYPASS
from .cmdi import CMDI_T1, CMDI_T2, CMDI_TIME, CMDI_OUTPUT_SIGS
from .ssti import SSTI_PROBES, SSTI_ENGINES
from .path_traversal import LFI_T1, LFI_T2, LFI_WINDOWS, LFI_SUCCESS_SIGS
from .xxe import XXE_T1, XXE_BLIND
from .ssrf import SSRF_CLOUD, SSRF_INTERNAL, SSRF_INTERNAL_SIGS
from .auth import DEFAULT_CREDS, JWT_WEAK_SECRETS, AUTH_SUCCESS_SIGS

__all__ = [
    "SQLI_T1", "SQLI_T2", "SQLI_T3", "SQLI_BLIND", "SQLI_TIME", "SQLI_ERRORS",
    "XSS_T1", "XSS_T2", "XSS_DOM", "XSS_CSP_BYPASS",
    "CMDI_T1", "CMDI_T2", "CMDI_TIME", "CMDI_OUTPUT_SIGS",
    "SSTI_PROBES", "SSTI_ENGINES",
    "LFI_T1", "LFI_T2", "LFI_WINDOWS", "LFI_SUCCESS_SIGS",
    "XXE_T1", "XXE_BLIND",
    "SSRF_CLOUD", "SSRF_INTERNAL", "SSRF_INTERNAL_SIGS",
    "DEFAULT_CREDS", "JWT_WEAK_SECRETS", "AUTH_SUCCESS_SIGS",
]
