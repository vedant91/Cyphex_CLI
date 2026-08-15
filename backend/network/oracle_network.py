"""
CYPHEX — Network Oracle (Anomaly Reasoning)

Uses the local Ollama model (via the existing CYPHEX call chain) to explain
network anomalies detected by the NetworkBehavioralGenome and map them to
MITRE ATT&CK techniques + containment actions.

Zero external API dependency — identical to the patch Oracle pattern in
backend/council/patch_council.py but tuned for network threat analysis.
"""

from __future__ import annotations

import json
import re
from typing import Optional

import httpx

from backend.network.models import AnomalyScore

# ── System prompt ─────────────────────────────────────────────────────────────

ORACLE_NETWORK_SYSTEM = """
You are CYPHEX NetworkOracle — an elite network security analyst.

Given anomaly detection results from a device's behavioural baseline, your job is to:
1. Identify the most likely threat scenario from the deviating metrics
2. Map it to the correct MITRE ATT&CK technique (use real technique IDs)
3. Assess confidence and false-positive probability
4. Suggest specific, actionable containment steps

Common threat scenarios to consider:
- Port scanning / network reconnaissance (T1046)
- Lateral movement via SMB/RDP/SSH (T1021)
- Data exfiltration via unusual outbound (T1048)
- C2 beacon (unusual outbound rate/timing) (T1071)
- Ransomware staging (unusual file shares + encryption) (T1486)
- Credential dumping tools running (T1003)
- DNS tunneling (unusually high DNS rate) (T1071.004)
- ARP spoofing / MITM positioning (T1557)

Return ONLY valid JSON — no markdown, no explanation outside JSON:
{
  "threat_scenario": "short name, e.g. Port Scan / Data Exfiltration / C2 Beacon",
  "mitre_technique": "TXXXX — Name",
  "confidence": 0.0,
  "false_positive_probability": 0.0,
  "severity": "Critical | High | Medium | Low",
  "reasoning": "2–3 sentences explaining which metrics triggered this and why",
  "containment_actions": [
    "Isolate device from segment X",
    "Block outbound port Y at firewall",
    "Capture traffic for forensic review"
  ]
}
"""

# Fallback reasoning when Ollama is unavailable
_FALLBACK_SCENARIOS = {
    "arp_broadcast_rate": ("ARP Scanning / Host Discovery", "T1018 — Remote System Discovery"),
    "syn_without_ack_rate": ("TCP SYN Stealth Scan", "T1046 — Network Service Discovery"),
    "port_entropy": ("Port Sweep / Service Enumeration", "T1046 — Network Service Discovery"),
    "unique_remote_ports": ("Port Sweep", "T1046 — Network Service Discovery"),
    "cleartext_ratio": ("Cleartext Protocol Usage", "T1040 — Network Sniffing"),
    "new_dest_ratio": ("Lateral Movement / Unusual Outbound", "T1021 — Remote Services"),
    "dns_query_rate": ("DNS Tunneling or Exfiltration", "T1071.004 — DNS"),
    "bytes_sent_rate": ("Data Exfiltration", "T1048 — Exfiltration Over Alternative Protocol"),
    "scan_ratio": ("Port Scan / Refused Connection Spike", "T1046 — Network Service Discovery"),
}


class NetworkOracle:
    """
    Wraps Ollama with network-threat reasoning prompts.
    Falls back to heuristic reasoning if Ollama is unavailable.
    """

    def __init__(self, ollama_url: str = "http://localhost:11434",
                 model: str = "llama3.1:8b"):
        self.ollama_url = ollama_url
        self.model = model

    async def enrich(self, score: AnomalyScore) -> AnomalyScore:
        """
        Enrich an AnomalyScore with threat reasoning.
        Fills in: threat_scenario, mitre_technique, confidence,
                  false_positive_prob, containment_actions.
        Returns the same object (mutated in place).
        """
        prompt = self._build_prompt(score)
        response = await self._call_ollama(prompt)

        if response:
            parsed = self._parse_json(response)
            if parsed:
                score.threat_scenario       = parsed.get("threat_scenario", "")
                score.mitre_technique       = parsed.get("mitre_technique", "")
                score.confidence            = float(parsed.get("confidence", 0.5))
                score.false_positive_prob   = float(parsed.get("false_positive_probability", 0.3))
                score.containment_actions   = parsed.get("containment_actions", [])
                return score

        # Fallback: rule-based heuristic
        return self._heuristic_enrich(score)

    def _build_prompt(self, score: AnomalyScore) -> str:
        features_text = "\n".join(
            f"  - {f}" for f in score.top_deviating_features
        ) or "  (no specific features isolated)"

        return (
            f"Device IP: {score.device_ip}\n"
            f"Anomaly Score: {score.score:.3f} / 1.0\n"
            f"Severity assessment: {score.severity}\n\n"
            f"Top deviating behavioural features:\n{features_text}\n\n"
            f"Initial anomaly reason: {score.reason}\n\n"
            "Analyse this network anomaly and return your assessment as JSON."
        )

    async def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama model. Returns empty string on failure."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self.ollama_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": ORACLE_NETWORK_SYSTEM},
                            {"role": "user",   "content": prompt},
                        ],
                        "stream": False,
                    },
                )
                if resp.status_code == 200:
                    return resp.json().get("message", {}).get("content", "")
        except Exception:
            pass
        return ""

    def _parse_json(self, text: str) -> Optional[dict]:
        """Extract JSON from model response (handles markdown fences)."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r"\{[\s\S]*\}", text)
            if m:
                try:
                    return json.loads(m.group())
                except json.JSONDecodeError:
                    pass
        return None

    def _heuristic_enrich(self, score: AnomalyScore) -> AnomalyScore:
        """Rule-based fallback when Ollama is unavailable."""
        # Pick scenario based on top deviating feature
        scenario = "Anomalous Network Behaviour"
        mitre = "T1071 — Application Layer Protocol"

        for feature in score.top_deviating_features:
            for key, (scen, mit) in _FALLBACK_SCENARIOS.items():
                if key in feature.lower():
                    scenario = scen
                    mitre = mit
                    break

        containment = [
            f"Review outbound connections from {score.device_ip}",
            "Capture network traffic for forensic analysis",
            f"Consider isolating {score.device_ip} from sensitive segments",
        ]

        score.threat_scenario     = scenario
        score.mitre_technique     = mitre
        score.confidence          = 0.55    # heuristic, lower confidence
        score.false_positive_prob = 0.35
        score.containment_actions = containment
        return score
