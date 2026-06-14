"""
CYPHEX SOC Terminal UI — Cyber Command Center
Premium Rich-based terminal interface for the Cyphex security pipeline.
"""
import sys, os
# Force UTF-8 output on Windows to avoid encoding errors with Unicode chars
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.columns import Columns
from rich.align import Align
from rich.box import HEAVY, ROUNDED, DOUBLE, SIMPLE_HEAVY, MINIMAL
from rich.theme import Theme
from rich.style import Style
from rich.layout import Layout
import math, time

# ══════════════════════════════════════════════════════════════
#  CYBER COMMAND CENTER — Color Token System
# ══════════════════════════════════════════════════════════════
CYBER_THEME = Theme({
    "cy.primary":   "bold #00E5FF",
    "cy.secondary": "bold #7C4DFF",
    "cy.success":   "bold #00E676",
    "cy.warning":   "#FFD43B",
    "cy.high":      "bold #FF8A00",
    "cy.critical":  "bold #FF3B5C",
    "cy.muted":     "#6B7280",
    "cy.border":    "#1E293B",
    "cy.dim":       "dim #4A5568",
    "cy.text":      "#E2E8F0",
    "cy.cyan":      "#00E5FF",
    "cy.purple":    "#7C4DFF",
    "cy.green":     "#00E676",
    "cy.red":       "#FF3B5C",
})

soc = Console(theme=CYBER_THEME, highlight=False)

# Severity styling
SEV = {
    "Critical": ("cy.critical", "▲", "🔴"),
    "High":     ("cy.high",     "●", "🟠"),
    "Medium":   ("cy.warning",  "◆", "🟡"),
    "Low":      ("cy.muted",    "○", "🟢"),
    "Info":     ("cy.muted",    "○", "🟢"),
}

STEP_META = {
    1: ("📡", "RECONNAISSANCE"),
    2: ("🔬", "STATIC ANALYSIS"),
    3: ("🚀", "SANDBOX DEPLOY"),
    4: ("⚡", "DYNAMIC SCAN"),
    5: ("🧬", "GENOME EVOLUTION"),
    6: ("⚔️",  "ATTACK SIMULATION"),
    7: ("📊", "SECURITY REPORT"),
    8: ("🔧", "PATCH & VERIFY"),
}


def _gradient_bar(value, max_val, width=30):
    """Colored progress bar based on value. Returns a Text object."""
    ratio = min(value / max_val, 1.0) if max_val else 0
    filled = int(ratio * width)
    if value >= 80:   color = "#00E676"
    elif value >= 60: color = "#00E5FF"
    elif value >= 40: color = "#FFD43B"
    elif value >= 20: color = "#FF3B5C"
    else:             color = "bold #FF3B5C"
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="#2D3748")
    return bar


def _sev_style(sev):
    return SEV.get(sev, SEV["Low"])


# ══════════════════════════════════════════════════════════════
#  1. HERO DASHBOARD — Splash + Scan Info
# ══════════════════════════════════════════════════════════════
def render_hero(scan_id, target="", score=None):
    logo = Text()
    lines = [
        "  ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗",
        "  ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝",
        "  ██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝ ",
        "  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗ ",
        "  ╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗",
        "   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
    ]
    colors = ["#00E5FF", "#00D4EE", "#00C3DD", "#5B4DCC", "#7C4DFF", "#7C4DFF"]
    for i, line in enumerate(lines):
        logo.append(line + "\n", style=colors[i])
    logo.append("\n  Autonomous Cyber Defence Engine", style="#6B7280")
    logo.append("  │  ", style="#2D3748")
    logo.append("v4.3", style="#00E5FF")
    logo.append("  │  ", style="#2D3748")
    logo.append("AI-Powered\n", style="#7C4DFF")
    logo.append(f"  Scan ID: ", style="#6B7280")
    logo.append(f"{scan_id}\n", style="#00E5FF")
    if target:
        logo.append(f"  Target:  ", style="#6B7280")
        logo.append(f"{target}\n", style="#E2E8F0")
    soc.print(Panel(logo, border_style="#1E293B", box=HEAVY, padding=(0, 1)))


# ══════════════════════════════════════════════════════════════
#  2. SCAN TIMELINE — Step Transitions
# ══════════════════════════════════════════════════════════════
def render_step(step_num, total, title, elapsed=0.0, mode="SCAN"):
    icon, label = STEP_META.get(step_num, ("◆", title))
    filled = int(step_num / total * 30)
    bar = f"[#00E5FF]{'━' * filled}[/][#1E293B]{'━' * (30 - filled)}[/]"
    header = Text()
    header.append(f" {icon} ", style="bold")
    header.append(f"STEP {step_num}/{total}", style="bold #00E5FF")
    header.append(f"  {title}", style="bold white")
    header.append(f"  [{mode} t={elapsed:.1f}s]", style="#6B7280")
    soc.print()
    soc.print(Panel(
        header,
        subtitle=f"{bar}  {step_num}/{total}",
        border_style="#7C4DFF" if step_num <= total // 2 else "#00E5FF",
        box=HEAVY, padding=(0, 1),
    ))


# ══════════════════════════════════════════════════════════════
#  3. TOOL READINESS
# ══════════════════════════════════════════════════════════════
def render_tools(tools):
    """tools: list of (name, ok, hint)"""
    active = sum(1 for _, ok, _ in tools if ok)
    t = Table(box=ROUNDED, border_style="#1E293B", show_header=False,
              title=f"[bold #00E5FF]Tool Readiness[/] [#6B7280]({active}/{len(tools)} active)[/]",
              padding=(0, 1))
    t.add_column(width=3)
    t.add_column(width=14)
    t.add_column()
    for name, ok, hint in tools:
        icon = "[#00E676]✓[/]" if ok else "[#FFD43B]○[/]"
        detail = f"[#6B7280]{hint}[/]" if hint else ""
        t.add_row(icon, name, detail)
    soc.print(t)


# ══════════════════════════════════════════════════════════════
#  4. AGENT COMMAND CENTER
# ══════════════════════════════════════════════════════════════
def render_agent_header(agent_id, name, objective):
    header = Text()
    header.append(f"  ▸ ", style="#00E5FF")
    header.append(f"[{agent_id}]", style="bold #00E5FF")
    header.append(f" {name}", style="bold #7C4DFF")
    header.append(f"\n  {objective}", style="#6B7280")
    soc.print(Panel(header, border_style="#1E293B", box=ROUNDED, padding=(0, 0)))


def render_agent_result(agent, status, detail=""):
    if status == "ok":
        soc.print(f"  [#00E676]✓[/] [{agent}] {detail}")
    elif status == "warn":
        soc.print(f"  [#FFD43B]⚠[/] [{agent}] {detail}")
    else:
        soc.print(f"  [#FF3B5C]✗[/] [{agent}] {detail}")


# ══════════════════════════════════════════════════════════════
#  5. SOURCE ROUTE DISCOVERY
# ══════════════════════════════════════════════════════════════
def render_routes(routes, count=None):
    t = Table(box=ROUNDED, border_style="#1E293B",
              title=f"[bold #00E5FF]📂 Source-Code Route Discovery[/] [#6B7280]— {count or len(routes)} routes[/]",
              padding=(0, 1))
    t.add_column("Method", style="bold #00E5FF", width=8)
    t.add_column("Path", style="#E2E8F0", min_width=30)
    t.add_column("Source", style="#6B7280")
    t.add_column("Params", style="#7C4DFF")
    for r in routes[:18]:
        params = ", ".join(r.get("params", [])[:3])
        t.add_row(r["method"], r["path"], r.get("source", ""), params or "—")
    soc.print(t)


# ══════════════════════════════════════════════════════════════
#  6. VULNERABILITY COMMAND CENTER
# ══════════════════════════════════════════════════════════════
def render_vulns(vulns, duration=0):
    crit = sum(1 for v in vulns if v.severity == "Critical")
    high = sum(1 for v in vulns if v.severity == "High")
    med  = sum(1 for v in vulns if v.severity == "Medium")
    low  = sum(1 for v in vulns if v.severity in ("Low", "Info"))
    total = len(vulns)
    penalty = 0
    if crit: penalty += 20 + 10 * math.log2(1 + crit)
    if high: penalty += 10 + 8 * math.log2(1 + high)
    if med:  penalty += 3 + 4 * math.log2(1 + med)
    if low:  penalty += 1 + 2 * math.log2(1 + low)
    score = max(0, min(100, round(100 - penalty)))

    # Score badge
    if score >= 80:   label, color = "SECURE",   "#00E676"
    elif score >= 60: label, color = "FAIR",     "#00E5FF"
    elif score >= 40: label, color = "AT RISK",  "#FFD43B"
    elif score >= 20: label, color = "POOR",     "#FF8A00"
    else:             label, color = "CRITICAL", "#FF3B5C"

    score_text = Text()
    score_text.append("\n  ")
    score_text.append_text(_gradient_bar(score, 100))
    score_text.append("  ")
    score_text.append(f"{score}/100 ", style=f"bold {color}")
    score_text.append(f"{label}\n\n", style=f"bold {color}")
    score_text.append(f"  🔴 Critical: {crit}", style="#FF3B5C")
    score_text.append(f"    🟠 High: {high}", style="#FF8A00")
    score_text.append(f"    🟡 Medium: {med}", style="#FFD43B")
    score_text.append(f"    🟢 Low: {low}", style="#6B7280")
    score_text.append(f"    │  Total: {total}\n", style="#6B7280")

    soc.print(Panel(score_text,
        title="[bold #00E5FF]◈ SECURITY ASSESSMENT ◈[/]",
        border_style=color, box=HEAVY, padding=(0, 1)))

    # Vulnerability table
    if not vulns:
        return score
    t = Table(box=ROUNDED, border_style="#1E293B",
              title=f"[bold #00E5FF]Confirmed Vulnerabilities ({total})[/]",
              padding=(0, 1))
    t.add_column("#", style="#6B7280", width=4)
    t.add_column("Sev", width=10)
    t.add_column("Vulnerability", min_width=30)
    t.add_column("CWE", style="#7C4DFF", width=10)
    t.add_column("Location", style="#6B7280")
    for i, v in enumerate(vulns, 1):
        style, icon, _ = _sev_style(v.severity)
        sev_cell = f"[{style}]{icon} {v.severity}[/]"
        t.add_row(str(i), sev_cell, v.title or v.vuln_type, v.cwe or "—", v.endpoint or "")
    soc.print(t)
    return score


# ══════════════════════════════════════════════════════════════
#  7. AI SECURITY COUNCIL
# ══════════════════════════════════════════════════════════════
def render_council_vote(finding, votes):
    """votes: list of (model_name, approved:bool, reason)"""
    cards = []
    for model, approved, reason in votes:
        verdict = "[#00E676]✅ APPROVED[/]" if approved else "[#FF3B5C]❌ REJECTED[/]"
        short = (reason or "")[:60]
        card = Panel(
            f"{verdict}\n[#6B7280]{short}[/]",
            title=f"[bold #7C4DFF]{model}[/]",
            border_style="#1E293B", box=ROUNDED, width=28, padding=(0, 1))
        cards.append(card)
    confirmed = sum(1 for _, a, _ in votes if a)
    total = len(votes)
    soc.print(Columns(cards, padding=(0, 1)))
    bar_w = 20
    filled = int(confirmed / total * bar_w) if total else 0
    color = "#00E676" if confirmed > total // 2 else "#FF3B5C"
    soc.print(f"  [{color}]CONSENSUS: {confirmed}/{total}[/]  "
              f"[{color}]{'█' * filled}[/][#2D3748]{'░' * (bar_w - filled)}[/]  "
              f"[#6B7280]{confirmed/total*100:.0f}%[/]")


# ══════════════════════════════════════════════════════════════
#  8. BEHAVIORAL GENOME
# ══════════════════════════════════════════════════════════════
def render_genome(gen_count, block_history, endpoints=0, converged=False):
    content = Text()
    content.append("  Generation: ", style="#6B7280")
    content.append(f"{gen_count}", style="bold #00E5FF")
    content.append("    Status: ", style="#6B7280")
    if converged:
        content.append("CONVERGED ✅", style="bold #00E676")
    else:
        content.append("EVOLVING ⟳", style="#FFD43B")
    content.append(f"    Endpoints: ", style="#6B7280")
    content.append(f"{endpoints}\n\n", style="#E2E8F0")
    # Mini chart
    if block_history:
        content.append("  Block Rate: ", style="#6B7280")
        first = block_history[0] if block_history else 0
        last = block_history[-1] if block_history else 0
        content.append(f"{first:.0f}%", style="#FF8A00")
        content.append(" → ", style="#6B7280")
        content.append(f"{last:.0f}%\n", style="bold #00E676")
        # Sparkline
        content.append("  ", style="")
        for val in block_history:
            if val >= 95:   ch, c = "█", "#00E676"
            elif val >= 80: ch, c = "▆", "#00E5FF"
            elif val >= 60: ch, c = "▄", "#FFD43B"
            else:           ch, c = "▂", "#FF8A00"
            content.append(ch, style=c)
        content.append("\n", style="")

    soc.print(Panel(content,
        title="[bold #00E5FF]🧬 BEHAVIORAL GENOME[/]",
        border_style="#1E293B", box=HEAVY, padding=(0, 1)))


# ══════════════════════════════════════════════════════════════
#  9. ATTACK SIMULATION ARENA
# ══════════════════════════════════════════════════════════════
def render_attacks(attacks_data, blocked=0, total_mal=0, fp=0):
    t = Table(box=ROUNDED, border_style="#1E293B",
              title="[bold #00E5FF]⚔️  ATTACK SIMULATION ARENA[/]",
              padding=(0, 1))
    t.add_column("Attack", style="#E2E8F0", min_width=18)
    t.add_column("Payload", max_width=24, style="#6B7280")
    t.add_column("Type", justify="center", width=8)
    t.add_column("Before", justify="center", width=10)
    t.add_column("After", justify="center", width=10)
    t.add_column("Score", justify="right", width=6)
    for row in attacks_data:
        name, payload, ptype, before, after, score_val = row
        type_colors = {"sqli":"#FF3B5C","xss":"#FF8A00","cmdi":"#FFD43B","lfi":"#7C4DFF","ssrf":"#00E5FF","benign":"#00E676"}
        tc = type_colors.get(ptype, "#6B7280")
        t.add_row(name, payload[:22], f"[{tc}]{ptype}[/]", before, after, f"{score_val:.3f}")
    soc.print(t)
    rate = (blocked / total_mal * 100) if total_mal else 0
    color = "#00E676" if rate >= 80 else "#FFD43B" if rate >= 50 else "#FF3B5C"
    soc.print(f"\n  [{color}]Defense Rate: {blocked}/{total_mal} ({rate:.0f}%)[/]  │  "
              f"[{'#FF3B5C' if fp else '#00E676'}]False Positives: {fp}[/]")


# ══════════════════════════════════════════════════════════════
# 10. ENDPOINT INTELLIGENCE MAP
# ══════════════════════════════════════════════════════════════
def render_endpoint_tree(target_url, endpoints, vuln_paths=None):
    vuln_paths = vuln_paths or set()
    tree = Tree(f"[bold #00E5FF]🌐 {target_url}[/]", guide_style="#1E293B")
    groups = {}
    for ep in endpoints:
        path = ep.replace(target_url, "")
        parts = [p for p in path.split("/") if p]
        prefix = f"/{parts[0]}" if parts else "/"
        groups.setdefault(prefix, []).append(path)
    for prefix, paths in sorted(groups.items()):
        branch = tree.add(f"[bold #7C4DFF]{prefix}[/]")
        for p in sorted(paths):
            sub = p.replace(prefix, "", 1).lstrip("/")
            if not sub: sub = "/"
            risk = "[#FF3B5C]🔴[/]" if p in vuln_paths else "[#00E676]●[/]"
            branch.add(f"{risk} [#E2E8F0]{sub}[/]")
    soc.print(Panel(tree, title="[bold #00E5FF]ENDPOINT MAP[/]",
                    border_style="#1E293B", box=ROUNDED, padding=(0, 1)))


# ══════════════════════════════════════════════════════════════
# 11. PATCH OPERATIONS CENTER
# ══════════════════════════════════════════════════════════════
def render_patch_pipeline(generated, reviewed, approved, applied, verified):
    stages = [("GENERATED", generated), ("REVIEWED", reviewed),
              ("APPROVED", approved), ("APPLIED", applied), ("VERIFIED", verified)]
    parts = []
    for name, count in stages:
        c = "#00E676" if count > 0 else "#6B7280"
        parts.append(f"[{c}]{name}[/]\n[bold {c}]{count}[/]")
    soc.print(Panel(
        Columns([Panel(p, border_style="#1E293B", box=ROUNDED, width=16) for p in parts]),
        title="[bold #00E5FF]🔧 PATCH PIPELINE[/]",
        border_style="#1E293B", box=HEAVY, padding=(0, 1)))


def render_patch_table(patches):
    """patches: list of (vuln_name, cwe, file, method, verdict, status)"""
    t = Table(box=ROUNDED, border_style="#1E293B",
              title="[bold #00E5FF]Patch Results[/]", padding=(0, 1))
    t.add_column("#", width=3, style="#6B7280")
    t.add_column("Vulnerability", min_width=24)
    t.add_column("CWE", width=8, style="#7C4DFF")
    t.add_column("Method", width=10)
    t.add_column("Status", width=10, justify="center")
    for i, (name, cwe, f, method, status) in enumerate(patches, 1):
        m_color = "#00E5FF" if method == "TEMPLATE" else "#7C4DFF"
        s_color = "#00E676" if status == "APPLIED" else "#FF3B5C"
        t.add_row(str(i), name, cwe, f"[{m_color}]{method}[/]", f"[{s_color}]{status}[/]")
    soc.print(t)


# ══════════════════════════════════════════════════════════════
# 12. EXECUTIVE REPORT (FINAL)
# ══════════════════════════════════════════════════════════════
def render_final_banner(score, crit, high, med, low, elapsed, scan_id,
                        patches_applied=0, patches_total=0, endpoints=0):
    if score >= 80:   label, color = "SECURE",   "#00E676"
    elif score >= 60: label, color = "FAIR",     "#00E5FF"
    elif score >= 40: label, color = "AT RISK",  "#FFD43B"
    elif score >= 20: label, color = "POOR",     "#FF8A00"
    else:             label, color = "CRITICAL", "#FF3B5C"
    total = crit + high + med + low

    score_box = Text(justify="center")
    score_box.append("\n")
    score_box.append("╔═══════════════════╗\n", style=color)
    score_box.append("║  ", style=color)
    score_box.append("SECURITY SCORE", style=f"bold {color}")
    score_box.append("   ║\n", style=color)
    score_box.append("║                   ║\n", style=color)
    score_box.append("║      ", style=color)
    score_box.append(f"{score:3d}", style=f"bold {color}")
    score_box.append(" / 100", style=color)
    score_box.append("      ║\n", style=color)
    score_box.append("║      ", style=color)
    score_box.append(f"{label:^13s}", style=f"bold {color}")
    score_box.append("║\n", style=color)
    score_box.append("║                   ║\n", style=color)
    score_box.append("╚═══════════════════╝\n\n", style=color)
    score_box.append("  ")
    score_box.append_text(_gradient_bar(score, 100))
    score_box.append("\n\n")
    score_box.append(f"  🔴 Critical: {crit}", style="#FF3B5C")
    score_box.append(f"   🟠 High: {high}", style="#FF8A00")
    score_box.append(f"   🟡 Medium: {med}", style="#FFD43B")
    score_box.append(f"   🟢 Low: {low}\n", style="#6B7280")

    soc.print(Panel(
        Align.center(score_box),
        title="[bold #00E5FF]✓ CYPHEX SCAN COMPLETE[/]",
        border_style=color, box=HEAVY, padding=(0, 2)))

    # Metrics
    t = Table(box=ROUNDED, border_style="#1E293B", show_header=False, padding=(0, 2))
    t.add_column(style="#6B7280", width=14)
    t.add_column(style="#E2E8F0")
    t.add_row("Duration", f"[#00E5FF]{elapsed:.1f}s[/]")
    t.add_row("Scan ID", f"[#00E5FF]{scan_id}[/]")
    t.add_row("Agents", "[#E2E8F0]13 deployed[/]")
    t.add_row("Endpoints", f"[#E2E8F0]{endpoints}[/]")
    t.add_row("Patches", f"[#00E676]{patches_applied}[/][#6B7280]/{patches_total}[/]")
    t.add_row("Pipeline", "[#7C4DFF]RAG + Council + Reasoning + Genome[/]")
    soc.print(t)

    soc.print(f"\n  [#7C4DFF]cyphex[/] [#6B7280]— Multi-Agent Security Pipeline v4.3[/]\n")
