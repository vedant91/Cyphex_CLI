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

# ── Multi-model role assignments ──────────────────────────────────────────────
# Each role has a preference list ordered by fitness for the task.
# Fallback chain ensures we always get a working model.
#
#  PLANNER  — complex attack surface decomposition, hypothesis generation
#             Needs: code understanding, security domain, structured JSON output
#  ANALYST  — evidence evaluation, HTTP response analysis, logic reasoning
#             Needs: general reasoning, instruction following
#  MUTATOR  — payload generation, WAF bypass variants, fast turnaround
#             Needs: code/string manipulation, fast inference (smallest usable)

_ROLE_PREFERENCES = {
    "planner": [
        "qwen2.5-coder:7b",
        "qwen2.5-coder:3b",
        "deepseek-coder:6.7b",
        "codellama:7b",
        "llama3.1:8b",
        "mistral:7b",
        "llama3.2:3b",
    ],
    "analyst": [
        "llama3.1:8b",
        "mistral:7b",
        "qwen2.5-coder:7b",
        "llama3.2:3b",
        "deepseek-coder:6.7b",
    ],
    "mutator": [
        "deepseek-coder:1.3b",
        "deepseek-coder:6.7b",
        "qwen2.5-coder:3b",
        "llama3.2:3b",
        "qwen2.5-coder:7b",
        "llama3.1:8b",
    ],
}

# Roles map to agent-reasoning cognitive strategies
_ROLE_STRATEGY = {
    "planner": "decomposed",   # Break attack surface into falsifiable hypotheses
    "analyst": "cot",          # Step-by-step evidence evaluation
    "mutator": "cot",          # Payload mutation reasoning
}

# Embedding-only models — cannot do chat completion, never route to these
_EMBEDDING_MODELS = {
    "nomic-embed-text", "mxbai-embed-large", "all-minilm",
    "bge-large", "bge-m3", "snowflake-arctic-embed",
}

OLLAMA_BASE = "http://localhost:11434"

_MODEL_CACHE: list[str] = []  # All available Ollama models (fetched once)
_ROLE_CACHE: dict[str, str] = {}  # role -> resolved model (cached per scan)


async def _get_available_models() -> list[str]:
    """Query Ollama for locally available models (5s timeout)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{OLLAMA_BASE}/api/tags")
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


def _is_embedding_model(name: str) -> bool:
    """Return True if model is embedding-only (cannot do chat)."""
    base = name.split(":")[0].lower().replace("-", "_")
    return any(e.replace("-", "_") in base for e in _EMBEDDING_MODELS)


async def _resolve_model_for_role(role: str) -> str:
    """
    Resolve the best available model for a given role.
    Checks Ollama's installed models against the role's preference list.
    Skips embedding-only models. Caches per role for the scan lifetime.
    """
    global _MODEL_CACHE, _ROLE_CACHE

    if role in _ROLE_CACHE:
        return _ROLE_CACHE[role]

    if not _MODEL_CACHE:
        try:
            _MODEL_CACHE = await asyncio.wait_for(_get_available_models(), timeout=8.0)
        except asyncio.TimeoutError:
            _MODEL_CACHE = []

    preferences = _ROLE_PREFERENCES.get(role, _ROLE_PREFERENCES["analyst"])

    # Walk preference list — first match wins
    for preferred in preferences:
        for available in _MODEL_CACHE:
            # Match exact name OR same base (e.g. 'qwen2.5-coder' matches 'qwen2.5-coder:7b')
            pbase = preferred.split(":")[0].lower()
            abase = available.split(":")[0].lower()
            if (available == preferred or abase == pbase) and not _is_embedding_model(available):
                _ROLE_CACHE[role] = available
                return available

    # Last resort: any non-embedding model
    for available in _MODEL_CACHE:
        if not _is_embedding_model(available):
            _ROLE_CACHE[role] = available
            return available

    # Absolute fallback — let Ollama error surface naturally
    fallback = preferences[0]
    _ROLE_CACHE[role] = fallback
    return fallback


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
    DeepAgent reasoning engine — multi-model, role-routed, agent-reasoning enhanced.

    Three specialised models, each enhanced by Oracle's agent-reasoning cognitive
    architectures, work together on the Observe-Think-Attack loop:

      PLANNER  (qwen2.5-coder:7b  + decomposed strategy)
        → Analyses the attack surface and generates prioritised hypotheses.
          'decomposed' breaks the surface into sub-problems then synthesises.

      ANALYST  (llama3.1:8b       + cot strategy)
        → Evaluates HTTP probe responses and decides confirmed/adapt/abandon.
          'cot' forces step-by-step evidence reasoning, reducing false positives.

      MUTATOR  (deepseek-coder:1.3b + cot strategy)
        → Generates WAF-bypass payload variants quickly.
          Smallest usable model for fast turnaround on each blocked attempt.

    All roles auto-resolve to the best available Ollama model if the preferred
    one is not installed — no hardcoded model names in the hot path.
    Falls back to empty plan / abandoned decision if LLM is unavailable.
    """

    def __init__(self, orchestrator=None):
        # Keep orchestrator param for backward compatibility — not used
        # Try both import paths: project root context and backend/ context
        try:
            from backend.reasoning.oracle_adapter import get_reasoner
        except ImportError:
            from reasoning.oracle_adapter import get_reasoner
        self.reasoner = get_reasoner()


    async def _call_reasoner(
        self,
        role: str,
        system: str,
        prompt: str,
        cwe: str = "",
        severity: str = "",
        timeout: float = 90.0,
    ) -> Optional[dict]:
        """
        Call CyphexReasoner with the model and cognitive strategy for `role`.
        Returns parsed JSON dict, or None on timeout/failure.
        """
        model = await _resolve_model_for_role(role)
        strategy = _ROLE_STRATEGY.get(role, "cot")
        print(f"  [DeepAgent:{role}] {model} + {strategy} strategy")

        async def _run():
            # CyphexReasoner.generate() is synchronous — run in a thread
            # so it doesn't block the asyncio event loop
            return await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.reasoner.generate(
                    model=model,
                    prompt=f"SYSTEM: {system}\n\nUSER: {prompt}\nASSISTANT:",
                    task_type={
                        "planner": "vuln_analysis",
                        "analyst": "vuln_analysis",
                        "mutator": "patch_generate",
                    }.get(role, "default"),
                    severity=severity,
                    cwe=cwe,
                )
            )

        try:
            result = await asyncio.wait_for(_run(), timeout=timeout)
        except asyncio.TimeoutError:
            print(f"  [DeepAgent:{role}] timed out after {timeout}s — skipping")
            return None

        if not result or not result.response:
            return None

        parsed = _extract_json(result.response)
        if parsed:
            strat_name = result.strategy_name or result.strategy
            print(f"  [DeepAgent:{role}] ◈ {strat_name} ({result.duration_ms:.0f}ms)")
        return parsed

    async def plan(self, target: str, surface_summary: str, vuln_class: str) -> AttackPlan:
        """
        PLANNER role — qwen2.5-coder:7b + decomposed strategy.
        Generates an ordered, hypothesis-driven attack plan by decomposing
        the observed attack surface into falsifiable sub-problems.
        """
        prompt = (
            f"Target: {target}\n\n"
            f"Vulnerability class to test: {vuln_class}\n\n"
            f"Observed attack surface:\n{surface_summary}\n\n"
            "Generate a prioritised, hypothesis-driven attack plan with 5-8 hypotheses. "
            "Focus ONLY on endpoints and parameters that actually exist in the surface above. "
            "Think like a real attacker — adaptive, evidence-driven, not guessing."
        )
        data = await self._call_reasoner(
            role="planner",
            system=ORACLE_PLAN_SYSTEM,
            prompt=prompt,
            timeout=90.0,
        )
        if not data:
            return AttackPlan(
                target_summary=f"{target} — LLM planning unavailable",
                primary_vulnerability_class=vuln_class,
                hypotheses=[],  # Falls through to deterministic pre-flight probes
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
        ANALYST role — llama3.1:8b + cot strategy.
        Evaluates HTTP probe response with step-by-step reasoning.
        Decides: confirmed / adapt (with mutated probe) / abandoned.
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
            role="analyst",
            system=ORACLE_DECIDE_SYSTEM,
            prompt=prompt,
            cwe=hypothesis.cwe,
            severity=hypothesis.severity,
            timeout=60.0,
        )
        if not data:
            return Decision(action="abandoned", thinking="ANALYST LLM unavailable", confidence=0)
        return Decision.from_json(data)

    async def mutate(self, payload: str, vuln_class: str, reason: str = "blocked") -> list[str]:
        """
        MUTATOR role — deepseek-coder:1.3b + cot strategy.
        Smallest, fastest model — generates 5 WAF-bypass payload variants
        quickly so the agent can retry without slowing the whole swarm.
        """
        prompt = (
            f"Vulnerability class: {vuln_class}\n"
            f"Failed payload: {payload}\n"
            f"Failure reason: {reason}\n\n"
            "Generate 5 bypass variants. Think step-by-step about "
            "what defence blocked this and what encoding or syntax change evades it."
        )
        data = await self._call_reasoner(
            role="mutator",
            system=ORACLE_MUTATE_SYSTEM,
            prompt=prompt,
            timeout=45.0,  # Mutator should be fast — 45s cap
        )
        if not data:
            return []
        return data.get("variants", [])


