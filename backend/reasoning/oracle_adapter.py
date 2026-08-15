"""
CYPHEX — Oracle Agent-Reasoning Adapter (Full 16-Strategy Edition)

Drop-in integration with Oracle's agent-reasoning package.
Wraps all Ollama calls through the ReasoningInterceptor to add
ALL 16 cognitive architectures transparently:

  Standard      — Direct generation (baseline)
  CoT           — Chain-of-Thought (step-by-step reasoning)
  Self-Reflection — Draft → Critique → Improve loop
  ToT           — Tree of Thoughts (BFS multi-path exploration)
  ReAct         — Reason + Act (tool-use loop)
  Decomposed    — Break complex problems into sub-tasks
  Least-to-Most — Solve easy sub-problems first, build up
  Consistency   — Majority voting across K candidates
  Recursive     — Code REPL agent (self-executing code)
  Refinement    — Score-based iterative improvement
  Complex Ref.  — 5-stage optimization pipeline
  Debate        — Adversarial multi-agent debate
  MCTS          — Monte Carlo Tree Search
  Analogical    — Analogy-based reasoning
  Socratic      — Guided questioning
  Meta          — Auto-select best strategy for the task

When agent-reasoning is installed:
  model="qwen2.5-coder:7b" + task_type="patch_generate"
  → internally calls model="qwen2.5-coder:7b+cot"

When NOT installed: Falls back to direct Ollama calls (no reasoning layer).

Zero API cost — runs entirely local through Ollama.
"""

import os
import time
import logging
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger("cyphex.reasoning")

# ── Try importing Oracle's agent-reasoning ──
AGENT_REASONING_AVAILABLE = False
_ReasoningInterceptor = None
ORACLE_AGENT_MAP = {}

try:
    from agent_reasoning import ReasoningInterceptor as _RI
    from agent_reasoning import AGENT_MAP
    _ReasoningInterceptor = _RI
    ORACLE_AGENT_MAP = AGENT_MAP
    AGENT_REASONING_AVAILABLE = True
    logger.info(f"Oracle agent-reasoning loaded ({len(AGENT_MAP)} cognitive architectures)")
except ImportError:
    logger.info("agent-reasoning not installed — using direct Ollama (pip install agent-reasoning)")


# ══════════════════════════════════════════════════════════════════════════
# ALL 16 STRATEGIES — Mapped to CYPHEX security patching tasks
# ══════════════════════════════════════════════════════════════════════════

# Full catalog of Oracle agent-reasoning strategies
ALL_STRATEGIES = {
    "standard":           {"name": "Standard",            "icon": "📝", "desc": "Direct generation (baseline, fastest)", "calls": 1},
    "cot":                {"name": "Chain-of-Thought",    "icon": "🔗", "desc": "Step-by-step logical reasoning", "calls": 1},
    "self_reflection":    {"name": "Self-Reflection",     "icon": "🪞", "desc": "Draft → Critique → Improve loop", "calls": 3},
    "tot":                {"name": "Tree of Thoughts",    "icon": "🌳", "desc": "BFS multi-path exploration with pruning", "calls": 5},
    "react":              {"name": "ReAct",               "icon": "🛠️", "desc": "Reason + Act (tool-use reasoning loop)", "calls": 3},
    "decomposed":         {"name": "Decomposition",       "icon": "🧩", "desc": "Break complex problems into sub-tasks", "calls": 3},
    "least_to_most":      {"name": "Least-to-Most",       "icon": "📶", "desc": "Solve easy sub-problems first, build up", "calls": 3},
    "consistency":        {"name": "Self-Consistency",     "icon": "🗳️", "desc": "Majority voting across K candidates", "calls": 3},
    "recursive":          {"name": "Recursive (RLM)",      "icon": "🔄", "desc": "Code REPL agent (self-executing code)", "calls": 3},
    "refinement":         {"name": "Refinement Loop",      "icon": "🔧", "desc": "Score-based iterative improvement", "calls": 4},
    "complex_refinement": {"name": "Complex Pipeline",     "icon": "📊", "desc": "5-stage optimization (accuracy→structure→depth→examples→polish)", "calls": 6},
    "debate":             {"name": "Adversarial Debate",   "icon": "⚔️", "desc": "Multi-perspective adversarial challenge", "calls": 4},
    "mcts":               {"name": "Monte Carlo Search",   "icon": "🎲", "desc": "MCTS tree search with UCB1 scoring", "calls": 5},
    "analogical":         {"name": "Analogical",           "icon": "🔀", "desc": "Analogy-based reasoning from known patterns", "calls": 2},
    "socratic":           {"name": "Socratic",             "icon": "❓", "desc": "Guided questioning to find the root cause", "calls": 3},
    "meta":               {"name": "Meta-Reasoning",       "icon": "🧠", "desc": "Auto-select best strategy for the task", "calls": 2},
}


# ── Task → Strategy mapping (which strategy for which CYPHEX task) ──
STRATEGY_MAP = {
    # Patch generation: step-by-step fix reasoning
    "patch_generate":   "cot",
    # Patch review: draft → critique → improve
    "patch_review":     "self_reflection",
    # Vulnerability analysis: break down complex vulns
    "vuln_analysis":    "decomposed",
    # Complex fixes (CMDi, SSRF, auth bypass): explore multiple approaches
    "complex_fix":      "tot",
    # Critical severity: majority vote across K candidates
    "high_severity":    "consistency",
    # Council debate: adversarial review
    "council_debate":   "debate",
    # Code understanding: guided questioning
    "code_analysis":    "socratic",
    # Pattern matching from past fixes
    "pattern_match":    "analogical",
    # Iterative code refinement
    "code_refine":      "refinement",
    # Multi-stage pipeline for production patches
    "production_patch": "complex_refinement",
    # Search-based exploration of fix space
    "fix_search":       "mcts",
    # Tool-augmented reasoning
    "tool_augmented":   "react",
    # Progressive complexity resolution
    "progressive":      "least_to_most",
    # Auto-select best strategy
    "auto":             "meta",
    # Default fallback
    "default":          "cot",
}

# ── Severity → strategy escalation ──
SEVERITY_STRATEGY = {
    "Critical": "consistency",     # K=3 majority vote (most expensive, best quality)
    "High":     "self_reflection", # Draft → critique → improve
    "Medium":   "cot",            # Step-by-step reasoning
    "Low":      "cot",            # Lightweight
    "Info":     "standard",       # Direct generation
}

# ── CWE → strategy override for complex vuln types ──
CWE_STRATEGY = {
    "CWE-78":  "tot",            # Command injection — multiple escape approaches
    "CWE-918": "tot",            # SSRF — URL validation strategies
    "CWE-287": "decomposed",     # Auth bypass — multi-step auth decomposition
    "CWE-284": "decomposed",     # IDOR — auth + validation chain
    "CWE-89":  "cot",            # SQLi — well-understood, CoT sufficient
    "CWE-79":  "cot",            # XSS — well-understood, CoT sufficient
    "CWE-798": "standard",       # Hardcoded secrets — deterministic fix
    "CWE-942": "standard",       # CORS — deterministic fix
    "CWE-306": "self_reflection",  # Missing auth — needs careful review
    "CWE-22":  "least_to_most",  # Path traversal — build up from simple to complex
}

# ── VRAM tier → allowed strategies (avoid expensive strategies on low VRAM) ──
TIER_ALLOWED = {
    "ultra":   list(ALL_STRATEGIES.keys()),  # All 16 strategies
    "high":    ["standard", "cot", "self_reflection", "tot", "decomposed",
                "consistency", "refinement", "debate", "analogical", "meta",
                "least_to_most", "react", "socratic"],
    "mid":     ["standard", "cot", "self_reflection", "decomposed",
                "consistency", "analogical", "refinement", "meta"],
    "low":     ["standard", "cot", "self_reflection", "analogical"],
    "minimal": ["standard", "cot"],
    "cloud":   list(ALL_STRATEGIES.keys()),  # All 16 for cloud
}


@dataclass
class ReasoningResult:
    """Result from a reasoning-enhanced model call."""
    response: str
    strategy: str
    strategy_name: str         # Human-readable name
    strategy_icon: str         # Emoji icon
    model: str
    duration_ms: float
    reasoning_available: bool
    estimated_calls: int = 1   # How many LLM calls this strategy used


class CyphexReasoner:
    """
    Central reasoning adapter for CYPHEX.
    
    Wraps Oracle's ReasoningInterceptor for enhanced model reasoning.
    Uses ALL 16 cognitive architectures, selecting the optimal one
    based on task type, vulnerability severity, CWE, and hardware tier.
    
    Falls back to direct Ollama calls if agent-reasoning isn't installed.
    """

    def __init__(self, host: str = "http://localhost:11434", tier: str = "mid"):
        self.host = host
        self.tier = tier
        self.interceptor = None
        self._call_count = 0
        self._total_time_ms = 0.0
        self._strategy_usage = {}  # Track which strategies were used

        if AGENT_REASONING_AVAILABLE:
            try:
                self.interceptor = _ReasoningInterceptor(host=host)
                logger.info(f"CyphexReasoner initialized with agent-reasoning (host={host})")
            except Exception as e:
                logger.warning(f"Failed to init ReasoningInterceptor: {e}")
                self.interceptor = None

    @property
    def is_enhanced(self) -> bool:
        """True if Oracle agent-reasoning is active."""
        return self.interceptor is not None

    @property
    def available_strategies(self) -> list:
        """Get strategies available for current VRAM tier."""
        allowed = TIER_ALLOWED.get(self.tier, TIER_ALLOWED["mid"])
        return [s for s in allowed if s in ALL_STRATEGIES]

    def select_strategy(
        self,
        task_type: str = "default",
        severity: str = "",
        cwe: str = "",
    ) -> str:
        """
        Select the optimal reasoning strategy based on task, severity, and CWE.
        
        Priority: CWE override > Severity escalation > Task default
        Falls back to allowed strategies for the current tier.
        """
        allowed = TIER_ALLOWED.get(self.tier, TIER_ALLOWED["mid"])

        # CWE-specific override (e.g., CMDi always gets ToT)
        if cwe in CWE_STRATEGY:
            candidate = CWE_STRATEGY[cwe]
            if candidate in allowed:
                return candidate

        # Severity escalation for critical vulns
        if severity in SEVERITY_STRATEGY:
            candidate = SEVERITY_STRATEGY[severity]
            if severity in ("Critical", "High") and candidate in allowed:
                return candidate

        # Task-based strategy
        candidate = STRATEGY_MAP.get(task_type, STRATEGY_MAP["default"])
        if candidate in allowed:
            return candidate

        # Fallback to CoT (always available) or standard
        return "cot" if "cot" in allowed else "standard"

    def generate(
        self,
        model: str,
        prompt: str,
        task_type: str = "default",
        severity: str = "",
        cwe: str = "",
        system: str = "",
        **kwargs,
    ) -> ReasoningResult:
        """
        Generate a response using the optimal reasoning strategy.
        
        Routes through Oracle's ReasoningInterceptor with the selected
        cognitive architecture. Falls back to empty response if not installed.
        """
        strategy = self.select_strategy(task_type, severity, cwe)
        strategy_info = ALL_STRATEGIES.get(strategy, ALL_STRATEGIES["standard"])
        start = time.time()

        if self.interceptor:
            try:
                # Combine system + prompt for the interceptor
                full_prompt = prompt
                if system:
                    full_prompt = f"SYSTEM: {system}\n\nUSER: {prompt}\nASSISTANT: "

                model_with_strategy = f"{model}+{strategy}"
                result = self.interceptor.generate(
                    model=model_with_strategy,
                    prompt=full_prompt,
                    stream=False,
                    **kwargs,
                )
                response_text = result.get("response", "") if isinstance(result, dict) else str(result)
                elapsed = (time.time() - start) * 1000

                self._call_count += 1
                self._total_time_ms += elapsed
                self._strategy_usage[strategy] = self._strategy_usage.get(strategy, 0) + 1

                return ReasoningResult(
                    response=response_text,
                    strategy=strategy,
                    strategy_name=strategy_info["name"],
                    strategy_icon=strategy_info["icon"],
                    model=model,
                    duration_ms=elapsed,
                    reasoning_available=True,
                    estimated_calls=strategy_info["calls"],
                )
            except Exception as e:
                logger.warning(f"Agent-reasoning call failed ({strategy}): {e}. Falling back.")

        # Fallback: no enhanced reasoning
        elapsed = (time.time() - start) * 1000
        return ReasoningResult(
            response="",
            strategy="direct",
            strategy_name="Direct (no reasoning)",
            strategy_icon="⚡",
            model=model,
            duration_ms=elapsed,
            reasoning_available=False,
            estimated_calls=1,
        )

    def get_stats(self) -> dict:
        """Return reasoning call statistics."""
        return {
            "calls": self._call_count,
            "total_time_ms": round(self._total_time_ms, 1),
            "avg_time_ms": round(self._total_time_ms / max(1, self._call_count), 1),
            "enhanced": self.is_enhanced,
            "tier": self.tier,
            "available_strategies": self.available_strategies,
            "strategy_usage": dict(self._strategy_usage),
        }

    def get_strategy_display(self) -> str:
        """Get a rich-formatted display of all available strategies."""
        allowed = self.available_strategies
        lines = []
        for key, info in ALL_STRATEGIES.items():
            active = "✓" if key in allowed else "✗"
            color = "green" if key in allowed else "dim"
            lines.append(
                f"  [{color}]{active} {info['icon']} {info['name']:22s} "
                f"({info['calls']} call{'s' if info['calls'] > 1 else ''}) — "
                f"{info['desc']}[/{color}]"
            )
        return "\n".join(lines)


# ── Singleton ──
_reasoner_instance: Optional[CyphexReasoner] = None


def get_reasoner(host: str = "http://localhost:11434", tier: str = "mid") -> CyphexReasoner:
    """Get or create the global CyphexReasoner instance."""
    global _reasoner_instance
    if _reasoner_instance is None:
        _reasoner_instance = CyphexReasoner(host=host, tier=tier)
    return _reasoner_instance


def get_strategy_info() -> dict:
    """Return human-readable info about available strategies."""
    return {
        "agent_reasoning_installed": AGENT_REASONING_AVAILABLE,
        "total_strategies": len(ALL_STRATEGIES),
        "strategies": {k: v["desc"] for k, v in ALL_STRATEGIES.items()},
        "task_map": STRATEGY_MAP,
        "severity_map": SEVERITY_STRATEGY,
        "cwe_overrides": CWE_STRATEGY,
        "tier_limits": {k: len(v) for k, v in TIER_ALLOWED.items()},
    }
