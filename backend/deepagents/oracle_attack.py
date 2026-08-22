"""
CYPHEX DeepAttack Oracle — upgraded with multi-model routing, payload mutation,
and blind (time-based) vulnerability detection.

Model routing:
  plan()   → qwen2.5-coder:7b   (attack planning, security reasoning)
  decide() → llama3.1:8b         (evidence analysis, logic)
  mutate() → deepseek-coder:6.7b (payload generation/transformation)

Falls back to best single available model if any is missing.
"""
import json
import re
import asyncio
import httpx
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from backend.council.council_orchestrator import CouncilOrchestrator

# ── Model roles ────────────────────────────────────────────────────────────────
_ROLE_PLANNER  = "qwen2.5-coder:7b"
_ROLE_ANALYST  = "llama3.1:8b"
_ROLE_MUTATOR  = "deepseek-coder:6.7b"
OLLAMA_BASE    = "http://localhost:11434"


async def _get_available_models() -> list[str]:
    """Query Ollama for locally available models."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{OLLAMA_BASE}/api/tags")
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


_MODEL_CACHE: list[str] = []


async def _resolve_model(preferred: str) -> str:
    """Return preferred model if available, else best fallback."""
    global _MODEL_CACHE
    if not _MODEL_CACHE:
        _MODEL_CACHE = await _get_available_models()
    if preferred in _MODEL_CACHE:
        return preferred
    # Fallback: pick best scoring available model
    for m in _MODEL_CACHE:
        if m:
            return m
    return preferred  # Let Ollama throw its own error


# ── System prompts ─────────────────────────────────────────────────────────────

ORACLE_PLAN_SYSTEM = """\
You are CYPHEX DeepAttack Oracle — an elite offensive security reasoning engine.

Given observations about a web target, you:
1. Identify the most likely attack paths for the requested vulnerability class
2. Decompose into testable hypotheses — smallest falsifiable unit first
3. Order by: highest CVSS potential FIRST, cheapest/fastest test FIRST
4. Specify the exact HTTP request for each hypothesis
5. Define what response signals confirm vs reject each hypothesis

Rules:
- Use ONLY CWE numbers: CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (CMDi), CWE-22 (Path Traversal),
  CWE-918 (SSRF), CWE-94 (SSTI), CWE-611 (XXE), CWE-287 (Auth), CWE-639 (IDOR)
- severity: Critical | High | Medium | Low
- Output AT MOST 6 hypotheses. Never more than 6. Fewer is better — pick the
  highest-value tests only. Extra hypotheses will be discarded.
- Keep every string value short (under ~120 characters). Do not pad.
- The JSON must be COMPLETE. Emit the full closing brackets. A truncated
  response is a failed response.
- Return ONLY valid JSON. No markdown. No preamble.

JSON schema:
{
  "target_summary": "<1 sentence>",
  "primary_vulnerability_class": "<SQLi|XSS|CMDi|...>",
  "hypotheses": [
    {
      "id": "h1",
      "vuln_type": "<specific technique e.g. Time-Based SQLi>",
      "cwe": "CWE-89",
      "severity": "Critical",
      "test_request": {
        "method": "GET",
        "path": "/api/users/search?q=",
        "body": "",
        "headers": {},
        "payload": "' OR SLEEP(5)--"
      },
      "confirm_signal": "response_time > 4.5 seconds",
      "reject_signal": "response_time < 1 second AND status != 500",
      "next_if_confirmed": "h2",
      "next_if_rejected": "h3"
    }
  ]
}
"""

ORACLE_DECIDE_SYSTEM = """\
You are CYPHEX DeepAttack Oracle.
Evaluate the HTTP response to a security probe and decide the next action.

Actions:
1. "confirmed" — The response unambiguously confirms the vulnerability.
2. "abandoned" — The target is clearly not vulnerable (WAF blocked, 404, static file).
3. "adapt"     — The probe failed but vulnerability is still plausible. Provide a mutated probe.

Time-based detection rules:
- If response_time > 4.0s AND the payload contained a sleep/delay command → strong indicator.
- If response_time < 0.5s AND payload contained SLEEP(5) → likely not vulnerable.

Return ONLY valid JSON:
{
  "thinking": "<1-2 sentence reasoning>",
  "action": "confirmed|abandoned|adapt",
  "confidence": 85,
  "vuln": {
    "name": "<full vuln name>",
    "cwe": "CWE-89",
    "severity": "Critical",
    "evidence": "<exact snippet from response that confirms it>",
    "fix": "<1 sentence remediation>"
  },
  "next_probe": {
    "method": "GET",
    "path": "...",
    "body": "",
    "headers": {},
    "payload": "<mutated payload>"
  }
}
Note: 'vuln' only if action=confirmed. 'next_probe' only if action=adapt.
"""

ORACLE_MUTATE_SYSTEM = """\
You are a payload mutation engine for a penetration testing tool.
Given a payload that was blocked/failed, generate 5 semantically equivalent
bypass variants using WAF evasion techniques:
- URL/double encoding
- Null bytes, whitespace substitution
- Case variation, comment insertion
- Hex/Unicode encoding
- Alternative syntax for the same operation

Return ONLY valid JSON:
{
  "original": "<original payload>",
  "variants": [
    "<variant 1>",
    "<variant 2>",
    "<variant 3>",
    "<variant 4>",
    "<variant 5>"
  ],
  "technique": "<brief description of primary bypass technique used>"
}
"""


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class HttpRequest:
    method: str
    path: str
    body: str = ""
    headers: dict = field(default_factory=dict)
    payload: str = ""     # The specific injection string used

    def summary(self) -> str:
        return f"{self.method} {self.path}" + (f" [{self.payload[:40]}]" if self.payload else "")


@dataclass
class Hypothesis:
    id: str
    vuln_type: str
    cwe: str
    severity: str
    test_request: HttpRequest
    confirm_signal: str
    reject_signal: str
    next_if_confirmed: str = ""
    next_if_rejected: str = ""


@dataclass
class AttackPlan:
    target_summary: str
    primary_vulnerability_class: str
    hypotheses: List[Hypothesis]

    @classmethod
    def from_json(cls, data: dict) -> "AttackPlan":
        hypotheses = []
        for h in data.get("hypotheses", []):
            req = h.get("test_request", {})
            hypotheses.append(Hypothesis(
                id=h.get("id", ""),
                vuln_type=h.get("vuln_type", ""),
                cwe=h.get("cwe", ""),
                severity=h.get("severity", "Medium"),
                test_request=HttpRequest(
                    method=req.get("method", "GET"),
                    path=req.get("path", ""),
                    body=req.get("body", ""),
                    headers=req.get("headers", {}),
                    payload=req.get("payload", ""),
                ),
                confirm_signal=h.get("confirm_signal", ""),
                reject_signal=h.get("reject_signal", ""),
                next_if_confirmed=h.get("next_if_confirmed", ""),
                next_if_rejected=h.get("next_if_rejected", ""),
            ))
        return cls(
            target_summary=data.get("target_summary", ""),
            primary_vulnerability_class=data.get("primary_vulnerability_class", ""),
            hypotheses=hypotheses,
        )


@dataclass
class Decision:
    action: str           # confirmed | abandoned | adapt
    thinking: str
    confidence: int = 0   # 0-100
    vuln: dict = None
    next_probe: Optional[HttpRequest] = None

    @classmethod
    def from_json(cls, data: dict) -> "Decision":
        next_probe = None
        if data.get("next_probe"):
            req = data["next_probe"]
            next_probe = HttpRequest(
                method=req.get("method", "GET"),
                path=req.get("path", ""),
                body=req.get("body", ""),
                headers=req.get("headers", {}),
                payload=req.get("payload", ""),
            )
        return cls(
            action=data.get("action", "abandoned"),
            thinking=data.get("thinking", ""),
            confidence=int(data.get("confidence", 0)),
            vuln=data.get("vuln"),
            next_probe=next_probe,
        )


# ── Oracle ─────────────────────────────────────────────────────────────────────

class AttackOracle:
    """
    Multi-model oracle for DeepAgent attack reasoning.
    Routes tasks to the most capable available local model.
    """

    def __init__(self, orchestrator: CouncilOrchestrator):
        self.orchestrator = orchestrator

    async def plan(self, target: str, surface_summary: str,
                   vuln_class: str) -> AttackPlan:
        """Generate an ordered attack plan via the planner model."""
        model = await _resolve_model(_ROLE_PLANNER)
        prompt = (
            f"Target: {target}\n\n"
            f"Vulnerability class to test: {vuln_class}\n\n"
            f"Observed attack surface:\n{surface_summary}\n\n"
            "Generate a prioritised, hypothesis-driven attack plan with 4-6 "
            "hypotheses (never more than 6). Return complete, compact JSON."
        )
        response = await self.orchestrator._call(
            model=model,
            system=ORACLE_PLAN_SYSTEM,
            prompt=prompt,
            task_name="Reasoning",
        )
        return AttackPlan.from_json(response)

    async def decide(self, hypothesis: Hypothesis, response_status: int,
                     response_body: str, response_time: float,
                     attempt: int, baseline_time: float = 0.0) -> Decision:
        """Evaluate a probe response and decide the next action."""
        model = await _resolve_model(_ROLE_ANALYST)
        time_analysis = ""
        if baseline_time > 0:
            delta = response_time - baseline_time
            time_analysis = (
                f"Baseline response time: {baseline_time:.2f}s\n"
                f"Probe response time: {response_time:.2f}s\n"
                f"Delta: {delta:+.2f}s (significant if >3.0s for sleep payloads)\n"
            )

        prompt = (
            f"Hypothesis: {hypothesis.vuln_type} at {hypothesis.test_request.path}\n"
            f"Attempt: {attempt + 1}\n"
            f"Test sent: {hypothesis.test_request.summary()}\n"
            f"Payload used: {hypothesis.test_request.payload}\n"
            f"Response: HTTP {response_status}, {len(response_body)} bytes, {response_time:.2f}s\n"
            f"{time_analysis}"
            f"Response body (first 800 chars):\n{response_body[:800]}\n\n"
            f"Confirmation signal: {hypothesis.confirm_signal}\n"
            f"Rejection signal: {hypothesis.reject_signal}\n\n"
            "Decide: confirmed / adapt (provide next probe) / abandoned"
        )
        response = await self.orchestrator._call(
            model=model,
            system=ORACLE_DECIDE_SYSTEM,
            prompt=prompt,
            task_name="Reasoning",
        )
        return Decision.from_json(response)

    async def mutate(self, payload: str, vuln_class: str,
                     reason: str = "blocked") -> list[str]:
        """Generate WAF-bypass variants of a failed payload."""
        model = await _resolve_model(_ROLE_MUTATOR)
        prompt = (
            f"Vulnerability class: {vuln_class}\n"
            f"Failed payload: {payload}\n"
            f"Failure reason: {reason}\n\n"
            "Generate 5 bypass variants of this payload."
        )
        try:
            response = await self.orchestrator._call(
                model=model,
                system=ORACLE_MUTATE_SYSTEM,
                prompt=prompt,
                task_name="Generating",
            )
            return response.get("variants", [])
        except Exception:
            return []
