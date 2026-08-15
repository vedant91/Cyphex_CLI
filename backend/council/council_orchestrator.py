import httpx
import json
import re
import asyncio
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from backend.council.council_errors import CouncilCallError, ModelNotFoundError

# Oracle agent-reasoning integration
try:
    from backend.reasoning.oracle_adapter import get_reasoner, AGENT_REASONING_AVAILABLE
except ImportError:
    AGENT_REASONING_AVAILABLE = False
    def get_reasoner(**kwargs): return None

OLLAMA_BASE = "http://localhost:11434"
console = Console()

# Tier → context window size. Cached after first detection to avoid repeated
# GPU probing. Small/low-end hardware stays at 4096 (also the cyphex-patch
# Modelfile pin); mid gets 6144; high/ultra get 8192 for the non-pinned
# reasoning/review models.
_TIER_CTX = {
    "minimal": 4096,
    "low":     4096,
    "cloud":   4096,
    "mid":     6144,
    "high":    8192,
    "ultra":   8192,
}
_CTX_CACHE: Optional[int] = None


def ctx_for_tier() -> int:
    """Return the num_ctx to use, based on detected hardware tier (cached)."""
    global _CTX_CACHE
    if _CTX_CACHE is None:
        try:
            from cyphex.hardware import detect_mode
            _CTX_CACHE = _TIER_CTX.get(detect_mode(), 4096)
        except Exception:
            _CTX_CACHE = 4096
    return _CTX_CACHE


def is_approved_vote(value) -> bool:
    """
    Strictly interpret a council vote's "approved"/"confirmed" field.

    Only Python's real `True`, or unambiguous string spellings of true
    ("true"/"yes", case-insensitive), count as approved. Everything else —
    `False`, `None`, a missing key, or ANY other string (including the
    literal string "false", which some small local models emit despite
    JSON-mode prompting) — counts as NOT approved.

    This guards against `bool("false") == True` style bugs when tallying
    votes returned by LLMs that don't reliably emit JSON booleans.
    """
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes")
    return False


def ctx_for_tier() -> dict:
    """
    Return tier-appropriate num_ctx and num_predict based on detected hardware.
    Respects the cyphex-patch fine-tuned model's training context (4096).
    """
    try:
        from cyphex.hardware import detect_mode
        mode = detect_mode()
    except Exception:
        mode = "mid"  # safe fallback

    tier_config = {
        "ultra":   {"num_ctx": 8192, "num_predict": 4096},
        "high":    {"num_ctx": 6144, "num_predict": 2048},
        "mid":     {"num_ctx": 4096, "num_predict": 2048},
        "low":     {"num_ctx": 4096, "num_predict": 1536},
        "minimal": {"num_ctx": 4096, "num_predict": 1024},
        "cloud":   {"num_ctx": 4096, "num_predict": 2048},
    }
    return tier_config.get(mode, tier_config["mid"])


def _detect_vram_limit() -> float:
    """
    Detect actual VRAM/unified memory and set a safe limit.
    Leaves 2GB headroom for OS + other apps.
    """
    try:
        from cyphex.hardware import get_gpu_info
        info = get_gpu_info()
        vram = info.get("vram_gb", 0)
        if vram > 0:
            # Leave 2GB for OS overhead, min 4GB usable
            return max(vram - 2.0, 4.0)
    except Exception:
        pass
    return 5.5  # safe fallback


class VRAMManager:
    """
    Tracks which models are currently loaded and enforces VRAM budget.
    
    The VRAM limit is detected dynamically from hardware:
      - M1 Pro 16GB → 12GB usable → 10GB budget (2GB headroom)
      - RTX 3060 12GB → 10GB budget
      - No GPU → 5.5GB fallback
    
    This allows loading 2 models simultaneously for parallel reviews
    (e.g., qwen2.5-coder:7b ~4.5GB + deepseek-coder:6.7b ~4GB = ~8.5GB).
    """

    # Seed costs for known models (overridden by ModelSelector at runtime)
    VRAM_COST = {
        "deepseek-coder:1.3b": 1.0,
        "phi3:mini":            2.2,
        "llama3.2:1b":          1.0,
        "cyphex-patch":         4.5,
        "qwen2.5-coder:7b":    4.5,
        "deepseek-coder:6.7b":  4.0,
        "llama3.1:8b":          5.0,
        "qwen2.5-coder:3b":    2.0,
        "mistral:7b":          4.5,
        "codellama:7b":        4.5,
    }

    def __init__(self):
        self.loaded: dict[str, float] = {}  # model → VRAM cost
        self.VRAM_LIMIT = _detect_vram_limit()
        self._parallel_capable = self.VRAM_LIMIT >= 8.0  # Can fit 2 × 7B models

    @property
    def parallel_capable(self) -> bool:
        """True if hardware can run 2 models simultaneously."""
        return self._parallel_capable

    def update_costs(self, dynamic_costs: dict[str, float]):
        """Merge dynamically discovered VRAM costs (from ModelSelector)."""
        self.VRAM_COST.update(dynamic_costs)

    def can_load(self, model: str) -> bool:
        cost = self.VRAM_COST.get(model, 2.0)
        return sum(self.loaded.values()) + cost <= self.VRAM_LIMIT

    def can_load_together(self, models: list[str]) -> bool:
        """Check if all given models can be loaded simultaneously."""
        total = sum(self.VRAM_COST.get(m, 2.0) for m in models)
        return total <= self.VRAM_LIMIT

    def get_parallel_batches(self, models: list[str]) -> list[list[str]]:
        """
        Dynamically chunks a list of models into batches that fit within the VRAM budget.
        For an A100 (80GB), this might fit 10 models. For an M1 Pro (12GB), maybe 2-3.
        """
        batches = []
        current_batch = []
        current_cost = 0.0

        for model in models:
            cost = self.VRAM_COST.get(model, 2.0)
            if current_cost + cost > self.VRAM_LIMIT and current_batch:
                batches.append(current_batch)
                current_batch = [model]
                current_cost = cost
            else:
                current_batch.append(model)
                current_cost += cost
        
        if current_batch:
            batches.append(current_batch)
        
        return batches

    async def ensure_loaded(self, model: str):
        if model in self.loaded:
            return
        # If adding this model would exceed budget, unload least-recently-used
        cost = self.VRAM_COST.get(model, 2.0)
        while sum(self.loaded.values()) + cost > self.VRAM_LIMIT and self.loaded:
            evict = next(iter(self.loaded))
            await self.unload(evict)
        # Warm up the model with a no-op prompt
        try:
            await self._raw_call(model, "ready", stream=False)
            self.loaded[model] = cost
        except Exception as e:
            raise ModelNotFoundError(f"Could not load model {model}: {e}")

    async def ensure_loaded_together(self, models: list[str]):
        """Load multiple models simultaneously for parallel execution."""
        # First check if they all fit
        models_to_load = [m for m in models if m not in self.loaded]
        if not models_to_load:
            return  # All already loaded

        needed = sum(self.VRAM_COST.get(m, 2.0) for m in models_to_load)
        current = sum(self.loaded.values())

        # Evict until we have room
        while current + needed > self.VRAM_LIMIT and self.loaded:
            evict = next(iter(self.loaded))
            if evict not in models:  # Don't evict a model we're trying to keep
                current -= self.loaded.get(evict, 0)
                await self.unload(evict)
            else:
                break

        # Load all needed models
        for model in models_to_load:
            try:
                await self._raw_call(model, "ready", stream=False)
                cost = self.VRAM_COST.get(model, 2.0)
                self.loaded[model] = cost
            except Exception as e:
                console.print(f"[yellow]⚠ Could not load {model} for parallel execution: {e}[/yellow]")

    async def unload(self, model: str):
        """Force Ollama to release VRAM for this model immediately."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"{OLLAMA_BASE}/api/generate",
                    json={"model": model, "prompt": "", "keep_alive": 0}
                )
        except Exception:
            pass
        self.loaded.pop(model, None)

    async def _raw_call(self, model: str, prompt: str, stream: bool = False) -> str:
        # Bounded timeout (consistent with the main call path's ~90s budget) —
        # an unbounded timeout here let a hung Ollama warm-up call block the
        # entire pipeline indefinitely.
        warmup_timeout = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)
        async with httpx.AsyncClient(timeout=warmup_timeout) as client:
            r = await client.post(
                f"{OLLAMA_BASE}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": stream,
                    "keep_alive": "10m",
                    "options": {"temperature": 0.1, "top_p": 0.9, **ctx_for_tier()}
                }
            )
            return r.json()["response"]


class CouncilOrchestrator:

    UNIVERSAL_ANTI_HALLUCINATION_RULES = """
ANTI-HALLUCINATION RULES — apply on every response:
1. Never invent CVE IDs. Never write "CVE-" followed by any number.
   If asked about CVE, respond: "I cannot assign a CVE without NVD verification."
2. Use only these CWE numbers (hardcoded):
   CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (CMDi), CWE-22 (Path Traversal/LFI),
   CWE-798 (Hardcoded Secret), CWE-306 (Missing Auth), CWE-942 (CORS),
   CWE-614 (Insecure Cookie), CWE-693 (Missing Header), CWE-1104 (Supply Chain)
   If the vulnerability type is not in this list, use "CWE-unknown".
3. Never use phrases like "might be", "could potentially", "appears to be",
   "seems vulnerable". Every finding statement must be backed by evidence.
4. If you are uncertain, set confirmed=false or approved=false. Never guess true.
5. You MUST provide your reasoning in a "thinking" key inside the final JSON object BEFORE the decision keys. Keep it to 1-2 SHORT sentences only. Do NOT write long explanations.
6. Return ONLY valid JSON. No preamble, no markdown, no extra text.
"""

    def __init__(self, thread_id: str = ""):
        self.vram = VRAMManager()
        self.thread_id = thread_id
        self.reasoner = get_reasoner() if AGENT_REASONING_AVAILABLE else None
        self._reasoning_calls = 0

    async def _call(self, model: str, system: str, prompt: str, task_name: str = "Reasoning",
                    severity: str = "", cwe: str = "", temperature: float = 0.1) -> dict:
        """
        Call a model and return parsed JSON.
        Routes through Oracle agent-reasoning when available (adds CoT/reflection).
        Handles: model loading, JSON extraction from markdown fences, retries.
        Raises CouncilCallError if model returns non-JSON after 2 retries.

        temperature: sampling temperature (default 0.1 for deterministic reasoning).
        Self-consistency uses a higher value to diversify candidate patches.
        """
        console.print(f"[dim]VRAM Manager: Loading {model}...[/dim]")
        await self.vram.ensure_loaded(model)

        # Determine reasoning task type from task_name
        task_type_map = {
            "Reasoning": "vuln_analysis",
            "Generating": "patch_generate",
            "Reviewing": "patch_review",
        }
        task_type = task_type_map.get(task_name, "default")

        full_system = f"{system}\n\n{self.UNIVERSAL_ANTI_HALLUCINATION_RULES}"

        # ── Try Oracle agent-reasoning first (adds CoT/reflection layer) ──
        if self.reasoner and self.reasoner.is_enhanced:
            try:
                strategy = self.reasoner.select_strategy(task_type, severity, cwe)
                console.print(f"[dim]  ◈ Agent-Reasoning: {strategy} strategy[/dim]")
                result = self.reasoner.generate(
                    model=model,
                    prompt=prompt,
                    task_type=task_type,
                    severity=severity,
                    cwe=cwe,
                    system=full_system,
                )
                if result.response:
                    self._reasoning_calls += 1
                    # Parse JSON from reasoning output
                    clean = re.sub(r"```(?:json)?|```", "", result.response).strip()
                    try:
                        parsed = json.loads(clean)
                    except json.JSONDecodeError:
                        parsed = self._extract_json_robust(clean)
                    if parsed and isinstance(parsed, dict):
                        console.print(f"[dim]  ◈ Reasoning complete ({result.strategy}, {result.duration_ms:.0f}ms)[/dim]")
                        return parsed
            except Exception as e:
                console.print(f"[dim]  ◈ Agent-reasoning fallback: {str(e)[:60]}[/dim]")

        # ── Fallback: direct Ollama httpx call ──
        for attempt in range(2):
            try:

                # Use Live to show thinking process — 90s timeout prevents infinite hangs
                with Live(Panel(f"[cyan bold]Evaluating[/cyan bold]\n[dim]Model: {model}[/dim]\n[yellow]Status: Thinking...[/yellow]", border_style="cyan"), refresh_per_second=2, console=console, transient=True) as live:
                    async with httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
                        r = await client.post(
                            f"{OLLAMA_BASE}/api/chat",
                            json={
                                "model": model,
                                "messages": [
                                    {"role": "system", "content": full_system},
                                    {"role": "user", "content": prompt},
                                ],
                                "stream": False,
                                "format": "json",
                                "keep_alive": "10m",
                                "options": {
                                    "temperature": temperature,
                                    "top_p": 0.9,
                                    **ctx_for_tier(),     # Tier-aware: 4096 (low) → 8192 (ultra)
                                }
                            }
                        )
                    raw = r.json()["message"]["content"]
                    live.update(Panel(f"[green bold]✓ Done[/green bold] [dim]({model})[/dim]", border_style="green"))

                # Strip markdown code fences just in case
                clean = re.sub(r"```(?:json)?|```", "", raw).strip()
                
                try:
                    parsed = json.loads(clean)
                except json.JSONDecodeError:
                    # Fallback: bracket-balanced extraction (handles nested braces in strings)
                    parsed = self._extract_json_robust(clean)
                    if parsed is None:
                        raise json.JSONDecodeError("No JSON structure found", clean, 0)
                
                # CYPHEX GLOBAL FIX: Recursively flatten lists of strings into multiline strings
                # to prevent AttributeError: 'list' object has no attribute 'strip' downstream
                def _sanitize(obj):
                    if isinstance(obj, dict):
                        return {k: _sanitize(v) for k, v in obj.items()}
                    if isinstance(obj, list) and len(obj) > 0 and all(isinstance(x, str) for x in obj):
                        return "\n".join(obj)
                    return obj
                parsed = _sanitize(parsed)
                
                # Extract and display thinking from the JSON
                if isinstance(parsed, dict) and "thinking" in parsed:
                    thinking_content = str(parsed["thinking"]).strip()
                    if thinking_content:
                        console.print(Panel(thinking_content, title=f"[{model}] Thinking Process", border_style="blue"))
                    
                # Display the decision if applicable
                if isinstance(parsed, dict):
                    if "confirmed" in parsed:
                        vote_ok = is_approved_vote(parsed["confirmed"])
                        c = "green" if vote_ok else "red"
                        console.print(f"  └─ [{c}]{model} vote: {parsed['confirmed']}[/{c}] - {parsed.get('reason', '')}")
                    elif "approved" in parsed:
                        vote_ok = is_approved_vote(parsed["approved"])
                        c = "green" if vote_ok else "red"
                        console.print(f"  └─ [{c}]{model} review: {parsed['approved']}[/{c}] - {parsed.get('reason', '')}")
                
                return parsed
            except json.JSONDecodeError:
                if attempt == 1:
                    raise CouncilCallError(f"{model} returned non-JSON after 2 attempts: {raw[:200]}")
                console.print(f"[yellow]⚠ {model} returned invalid JSON, retrying...[/yellow]")
                continue
            except Exception as e:
                # str() is empty for httpx.ReadTimeout and many KeyErrors — fall back
                # to the type name so the message is never a bare "model API error:".
                detail = str(e) or type(e).__name__
                raise CouncilCallError(f"{model} API error: {detail}")

        raise CouncilCallError(f"{model} failed after 2 attempts")

    @staticmethod
    def _extract_json_robust(text: str):
        """
        Find the outermost balanced {...} using bracket counting.
        Handles nested braces inside JSON string values correctly.
        Returns parsed dict or None.
        """
        start = text.find('{')
        if start == -1:
            return None
        depth = 0
        in_string = False
        i = start
        while i < len(text):
            ch = text[i]
            if ch == '\\' and in_string:
                i += 2
                continue
            if ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            return None
            i += 1
        return None
