"""
reasoning_strategy.py — CYPHEX Meta-Reasoning Strategy Engine.

A real, selectable reasoning registry (parity with the named "cognitive
architecture" frameworks) — but every ACTIVE strategy here maps to a mechanism
CYPHEX genuinely runs, not a marketing label. The Meta-Reasoner routes each
vulnerability to the cheapest strategy that fits its difficulty, so a small
6-8B local model spends extra compute only where it pays off.

Routing (per vulnerability):
  • Critical severity, or injection/SSRF/CMDi CWEs → Self-Consistency
    (generate K candidate patches, majority-vote the winner).
  • High severity                                  → Chain-of-Thought
    (single Oracle decomposition pass).
  • Everything else                                → Standard / CoT.

Patch review is always Adversarial Debate (the dual-reviewer council) and
failed patches are retried via Self-Reflection (grounded reflexion) downstream.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Strategy:
    key: str
    icon: str
    name: str
    calls: str
    desc: str
    active: bool
    candidates: int = 1  # number of patch candidates this strategy generates


# ── The registry ─────────────────────────────────────────────────────────────
# `active` = wired into the CYPHEX pipeline today. Inactive entries are declared
# for transparency (and future work) but are NOT silently claimed as working.
STRATEGIES: dict[str, Strategy] = {
    "standard":        Strategy("standard",        "📝", "Standard",          "1 call",  "Direct generation (baseline, fastest)",                 True,  1),
    "chain_of_thought":Strategy("chain_of_thought","🔗", "Chain-of-Thought",  "1 call",  "Oracle step-by-step reasoning before the fix",          True,  1),
    "self_reflection": Strategy("self_reflection", "🪞", "Self-Reflection",   "≤3 calls","Grounded reflexion: draft → verify → improve",          True,  1),
    "tree_of_thoughts":Strategy("tree_of_thoughts","🌳", "Tree of Thoughts",  "5 calls", "BFS multi-path exploration with pruning",               False, 1),
    "react":           Strategy("react",           "🛠️", "ReAct",             "3 calls", "Reason + Act tool-use loop",                            False, 1),
    "decomposition":   Strategy("decomposition",   "🧩", "Decomposition",     "1 call",  "Oracle splits attack-vector / data-flow / fix",         True,  1),
    "least_to_most":   Strategy("least_to_most",   "📶", "Least-to-Most",     "3 calls", "Solve easy sub-problems first, build up",               False, 1),
    "self_consistency":Strategy("self_consistency","🗳️", "Self-Consistency",  "K calls", "Generate K candidate patches, majority-vote winner",    True,  3),
    "recursive_rlm":   Strategy("recursive_rlm",   "🔄", "Recursive (RLM)",   "3 calls", "Self-executing code REPL agent",                        False, 1),
    "refinement_loop": Strategy("refinement_loop", "🔧", "Refinement Loop",   "≤4 calls","Score-based iterative improvement (reflexion)",         True,  1),
    "complex_pipeline":Strategy("complex_pipeline","📊", "Complex Pipeline",  "6 calls", "5-stage optimisation pipeline",                         False, 1),
    "adversarial":     Strategy("adversarial",     "⚔️", "Adversarial Debate","≤4 calls","Dual-reviewer council challenges the patch",            True,  1),
    "monte_carlo":     Strategy("monte_carlo",     "🎲", "Monte Carlo Search","5 calls", "MCTS tree search with UCB1 scoring",                    False, 1),
    "analogical":      Strategy("analogical",      "🔀", "Analogical",        "1 call",  "RAG injects in-repo secure references + KB patterns",   True,  1),
    "socratic":        Strategy("socratic",        "❓", "Socratic",          "3 calls", "Guided questioning to find the root cause",             False, 1),
    "meta_reasoning":  Strategy("meta_reasoning",  "🧠", "Meta-Reasoning",    "router",  "Auto-routes each vuln to the best strategy",            True,  1),
}

# CWEs that justify the extra cost of multi-candidate self-consistency.
_HARD_CWES = {"CWE-78", "CWE-918", "CWE-89", "CWE-94", "CWE-77", "CWE-22"}


def active_count() -> int:
    return sum(1 for s in STRATEGIES.values() if s.active)


def select_strategy(cwe: str, severity: str) -> Strategy:
    """Meta-Reasoner: route a single vulnerability to a generation strategy."""
    cwe_u = (cwe or "").strip().upper()
    sev = (severity or "").strip().lower()

    if sev == "critical" or cwe_u in _HARD_CWES:
        return STRATEGIES["self_consistency"]
    if sev == "high":
        return STRATEGIES["chain_of_thought"]
    return STRATEGIES["standard"]


def render_engine_banner(console) -> None:
    """Print the reasoning-engine capability panel (called once per patch run)."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.box import SIMPLE

    t = Table(box=SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("flag", no_wrap=True)
    t.add_column("name", no_wrap=True)
    t.add_column("calls", style="dim", no_wrap=True)
    t.add_column("desc", style="white")
    for s in STRATEGIES.values():
        if s.active:
            flag = "[bold green]✓[/bold green]"
            name = f"[cyan]{s.icon} {s.name}[/cyan]"
        else:
            flag = "[red]✗[/red]"
            name = f"[dim]{s.icon} {s.name}[/dim]"
        t.add_row(flag, name, f"({s.calls})", s.desc)

    routing = (
        "\n[bold]Meta-Reasoner routing:[/bold]\n"
        "  • Critical / CMDi / SSRF / SQLi  → 🗳️ [cyan]Self-Consistency[/cyan] (K-candidate vote)\n"
        "  • High severity                  → 🔗 [cyan]Chain-of-Thought[/cyan] (Oracle decomposition)\n"
        "  • Standard                       → 📝 [cyan]Standard[/cyan]\n"
        "  • Every patch review             → ⚔️ [cyan]Adversarial Debate[/cyan] (dual council)\n"
        "  • Failed patches                 → 🪞 [cyan]Self-Reflection[/cyan] (grounded reflexion)"
    )

    n_active = active_count()
    console.print(Panel(
        t,
        title=f"[bold yellow]◈ CYPHEX Meta-Reasoning Engine[/bold yellow]  [dim]{n_active}/{len(STRATEGIES)} strategies active[/dim]",
        subtitle=routing,
        border_style="yellow",
        padding=(1, 2),
    ))
