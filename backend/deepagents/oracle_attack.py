"""
CYPHEX DeepAttack Oracle — Powered by agent-reasoning cognitive architectures.

Uses CyphexReasoner (wrapping Oracle's agent-reasoning ReasoningInterceptor)
to enhance local Ollama models with structured thinking strategies:

  plan()   → decomposed strategy  (break attack surface into testable hypotheses)
  decide() → cot strategy         (step-by-step evidence analysis)
  mutate() → cot strategy         (payload bypass reasoning)

Model selection: auto-resolves to best available chat model from Ollama.
Falls back to deterministic pre-flight probes if LLM is unavailable.

Zero external API cost — runs entirely local through Ollama + agent-reasoning.
"""
import json
import re
import asyncio
import httpx
from dataclasses import dataclass, field
from typing import List, Optional

# ── Model preferences (ordered by capability for security reasoning) ──
# We prefer code-tuned models for attack planning, but any chat model works.
_PREFERRED_MODELS = [
    "qwen2.5-coder:7b",
    "deepseek-coder:6.7b",
    "llama3.1:8b",
    "llama3.2:3b",
    "deepseek-coder:1.3b",
    "mistral:7b",
    "codellama:7b",
    "phi3:mini",
]

# Embedding-only models — cannot do chat, never pick these
_EMBEDDING_MODELS = {
    "nomic-embed-text", "mxbai-embed-large", "all-minilm",
    "bge-large", "bge-m3", "snowflake-arctic-embed",
}

OLLAMA_BASE = "http://localhost:11434"

_MODEL_CACHE: list[str] = []
_SELECTED_MODEL: str = ""


async def _get_available_models() -> list[str]:
    """Query Ollama for locally available models."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{OLLAMA_BASE}/api/tags")
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


def _is_embedding_model(name: str) -> bool:
    """Return True if the model is embedding-only (cannot do chat)."""
    base = name.split(":")[0].lower()
    return any(e in base for e in _EMBEDDING_MODELS)


async def _resolve_best_model() -> str:
    """
    Pick the best available chat model for security reasoning.
    Skips embedding-only models. Prefers code-tuned models.
    Caches result for the scan lifetime.
    """
    global _MODEL_CACHE, _SELECTED_MODEL
    if _SELECTED_MODEL:
        return _SELECTED_MODEL

    if not _MODEL_CACHE:
        _MODEL_CACHE = await _get_available_models()

    # Try preferred order first
    for preferred in _PREFERRED_MODELS:
        for available in _MODEL_CACHE:
            if available == preferred or available.startswith(preferred.split(":")[0] + ":"):
                if not _is_embedding_model(available):
                    _SELECTED_MODEL = available
                    return available

    # Fall back to any non-embedding model
    for available in _MODEL_CACHE:
        if not _is_embedding_model(available):
            _SELECTED_MODEL = available
            return available

    return "llama3.2:3b"  # Last resort


# ── System prompts ─────────────────────────────────────────────────────────────

ORACLE_PLAN_SYSTEM = """\
You are an elite offensive security researcher.
Given observations about a web target, generate a prioritised attack plan.

For the requested vulnerability class:
1. Identify the most likely attack paths from the observed surface
2. Decompose into testable hypotheses — smallest falsifiable unit first
3. Order by: highest CVSS potential FIRST, cheapest/fastest test FIRST
4. Specify the exact HTTP request for each hypothesis
5. Define what response signals confirm vs reject each hypothesis

Rules:
- Use ONLY these CWE numbers: CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (CMDi),
  CWE-22 (Path Traversal), CWE-918 (SSRF), CWE-94 (SSTI), CWE-611 (XXE),
  CWE-287 (Auth), CWE-639 (IDOR), CWE-915 (Mass Assignment)
- severity: Critical | High | Medium | Low
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
        "path": "/api/orders/lookup?email=",
        "body": "",
        "headers": {},
        "payload": "' OR SLEEP(5)--"
      },
      "confirm_signal": "response_time > 4.5 seconds OR sql error in body",
      "reject_signal": "response_time < 1 second AND status != 500",
      "next_if_confirmed": "h2",
      "next_if_rejected": "h3"
    }
  ]
}
"""

ORACLE_DECIDE_SYSTEM = """\
You are an offensive security analyst evaluating a probe response.
Decide whether the HTTP response confirms a vulnerability.

Actions:
1. "confirmed" — The response unambiguously confirms the vulnerability.
2. "abandoned" — The target is clearly not vulnerable (blocked, 404, static).
3. "adapt"     — Probe failed but vulnerability is still plausible. Provide mutated probe.

Time-based detection rules:
- response_time > 4.0s AND payload contained a sleep/delay → strong indicator
- response_time < 0.5s AND payload contained SLEEP(5) → likely not vulnerable

Return ONLY valid JSON:
{
  "thinking": "<1-2 sentence reasoning based on the evidence>",
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
You are a payload mutation engine for penetration testing.
Given a payload that was blocked/failed, generate 5 bypass variants using:
- URL/double encoding
- Null bytes, whitespace substitution
- Case variation, comment insertion (/**/, --, #)
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


def _extract_json(text: str) -> Optional[dict]:
    """Extract the outermost {...} JSON object from a string."""
    # Strip markdown fences
    clean = re.sub(r"```(?:json)?|```", "", text).strip()
    start = clean.find("{")
    if start == -1:
        return None
    depth, in_str = 0, False
    i = start
    while i < len(clean):
        ch = clean[i]
        if ch == "\\" and in_str:
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(clean[start:i + 1])
                    except json.JSONDecodeError:
                        return None
        i += 1
    return None


# ── Oracle ─────────────────────────────────────────────────────────────────────

class AttackOracle:
    """
    DeepAgent reasoning engine powered by agent-reasoning cognitive architectures.

    Uses CyphexReasoner directly — no CouncilOrchestrator/VRAMManager overhead.
    The agent-reasoning interceptor wraps each call with a cognitive strategy:
      plan()   → decomposed  (break surface into falsifiable hypotheses)
      decide() → cot         (step-by-step evidence evaluation)
      mutate() → cot         (bypass payload reasoning)

    Falls back gracefully to empty plan / abandoned decision if LLM unavailable.
    """

    def __init__(self, orchestrator=None):
        # Keep orchestrator param for backward compatibility — not used anymore
        from backend.reasoning.oracle_adapter import get_reasoner
        self.reasoner = get_reasoner()
        self._model: str = ""  # resolved lazily on first call

    async def _get_model(self) -> str:
        """Resolve and cache the best available chat model."""
        if not self._model:
            self._model = await asyncio.wait_for(_resolve_best_model(), timeout=10.0)
        return self._model

    async def _call_reasoner(
        self,
        system: str,
        prompt: str,
        task_type: str,
        cwe: str = "",
        severity: str = "",
        timeout: float = 90.0,
    ) -> Optional[dict]:
        """
        Call CyphexReasoner with the right cognitive strategy.
        Returns parsed JSON dict or None on failure/timeout.
        """
        model = await self._get_model()
        print(f"  [DeepAgent] Thinking with {model} ({task_type} strategy)...")

        async def _run():
            # CyphexReasoner.generate() is synchronous — run in thread
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.reasoner.generate(
                    model=model,
                    prompt=f"SYSTEM: {system}\n\nUSER: {prompt}\nASSISTANT:",
                    task_type=task_type,
                    severity=severity,
                    cwe=cwe,
                )
            )
            return result

        try:
            result = await asyncio.wait_for(_run(), timeout=timeout)
        except asyncio.TimeoutError:
            print(f"  [DeepAgent] Reasoning timed out ({timeout}s) — skipping LLM planning")
            return None

        if not result or not result.response:
            return None

        parsed = _extract_json(result.response)
        if parsed:
            strat = result.strategy_name or result.strategy
            print(f"  [DeepAgent] ◈ {strat} ({result.duration_ms:.0f}ms) → {len(result.response)} chars")
        return parsed

    async def plan(self, target: str, surface_summary: str, vuln_class: str) -> AttackPlan:
        """
        Generate an ordered, hypothesis-driven attack plan.
        Uses 'decomposed' reasoning: breaks the attack surface into
        sub-problems and solves each independently.
        """
        prompt = (
            f"Target: {target}\n\n"
            f"Vulnerability class to test: {vuln_class}\n\n"
            f"Observed attack surface:\n{surface_summary}\n\n"
            "Generate a prioritised, hypothesis-driven attack plan with 5-8 hypotheses. "
            "Focus ONLY on endpoints and parameters that actually exist in the surface above. "
            "Think like a real attacker — adaptive, evidence-driven, no guessing."
        )
        data = await self._call_reasoner(
            system=ORACLE_PLAN_SYSTEM,
            prompt=prompt,
            task_type="vuln_analysis",
            timeout=90.0,
        )
        if not data:
            return AttackPlan(
                target_summary=f"{target} — LLM planning skipped",
                primary_vulnerability_class=vuln_class,
                hypotheses=[],
            )
        return AttackPlan.from_json(data)

    async def decide(
        self,
        hypothesis: Hypothesis,
        response_status: int,
        response_body: str,
        response_time: float,
        attempt: int,
        baseline_time: float = 0.0,
    ) -> Decision:
        """
        Evaluate a probe response using CoT reasoning.
        Decides: confirmed / adapt / abandoned.
        """
        time_note = ""
        if baseline_time > 0:
            delta = response_time - baseline_time
            time_note = (
                f"Baseline: {baseline_time:.2f}s | Probe: {response_time:.2f}s | "
                f"Delta: {delta:+.2f}s (significant if >3.0s for SLEEP payloads)\n"
            )

        prompt = (
            f"Hypothesis: {hypothesis.vuln_type} at {hypothesis.test_request.path}\n"
            f"Attempt: {attempt + 1}\n"
            f"Sent: {hypothesis.test_request.summary()}\n"
            f"Payload: {hypothesis.test_request.payload}\n"
            f"Response: HTTP {response_status}, {len(response_body)} bytes, {response_time:.2f}s\n"
            f"{time_note}"
            f"Body (first 800 chars):\n{response_body[:800]}\n\n"
            f"Confirm signal: {hypothesis.confirm_signal}\n"
            f"Reject signal:  {hypothesis.reject_signal}\n\n"
            "Decide: confirmed / adapt (provide next probe) / abandoned"
        )
        data = await self._call_reasoner(
            system=ORACLE_DECIDE_SYSTEM,
            prompt=prompt,
            task_type="vuln_analysis",
            cwe=hypothesis.cwe,
            severity=hypothesis.severity,
            timeout=60.0,
        )
        if not data:
            return Decision(action="abandoned", thinking="LLM unavailable", confidence=0)
        return Decision.from_json(data)

    async def mutate(self, payload: str, vuln_class: str, reason: str = "blocked") -> list[str]:
        """
        Generate WAF-bypass variants of a failed payload using CoT reasoning.
        Thinks step-by-step about encoding/obfuscation techniques.
        """
        prompt = (
            f"Vulnerability class: {vuln_class}\n"
            f"Failed payload: {payload}\n"
            f"Failure reason: {reason}\n\n"
            "Generate 5 bypass variants. Think about what defence blocked it "
            "and what encoding or syntax change would evade it."
        )
        data = await self._call_reasoner(
            system=ORACLE_MUTATE_SYSTEM,
            prompt=prompt,
            task_type="patch_generate",  # CoT — step-by-step mutation reasoning
            timeout=60.0,
        )
        if not data:
            return []
        return data.get("variants", [])
