"""
CYPHEX Immune System — Full Visual Demo
========================================
Shows EVERY step of the adversarial co-evolution engine:
  1. How the Behavioral Genome is built
  2. How payloads are generated & scored
  3. How the red team mutates blocked payloads
  4. How the blue team retrains after bypasses
  5. The full evolution loop with real-time visualization

Run: python demo_immune_system.py
"""

import asyncio
import sys
import os
import time

# Ensure UTF-8 output on Windows
os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend", "backend"))

from models.scan import ScanContext, FormData, ParamData, Vuln
from models.genome import EndpointProfile, GenomeState, EvolutionResult
from immune.behavioral_genome import BehavioralGenome
from immune.mutation_engine import MutationEngine
from immune.evolution_controller import EvolutionController

# ═══════════════════════════════════════════════════════════════
# COLORS FOR TERMINAL OUTPUT
# ═══════════════════════════════════════════════════════════════
class C:
    # MONO SIGNAL RED — names kept, values mirror terminal_ui.py's ramp.
    RED = "\033[38;2;225;142;145m"      # bright — error / high
    GREEN = "\033[38;2;217;94;98m"      # PRIMARY — success / engaged
    YELLOW = "\033[38;2;193;78;91m"     # mid — warning / medium
    BLUE = "\033[38;2;142;113;116m"     # muted — info / low
    MAGENTA = "\033[38;2;225;142;145m"  # bright (legacy alias)
    CYAN = "\033[38;2;217;94;98m"       # PRIMARY (legacy alias)
    WHITE = "\033[38;2;225;208;210m"    # readout — primary prose
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def header(title: str, emoji: str = ""):
    print(f"\n{C.BOLD}{C.CYAN}{'='*70}{C.RESET}")
    print(f"  {emoji}  {C.BOLD}{C.WHITE}{title}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'='*70}{C.RESET}\n")


def section(title: str, emoji: str = ""):
    print(f"\n  {emoji}  {C.BOLD}{C.YELLOW}{title}{C.RESET}")
    print(f"  {C.DIM}{'─'*50}{C.RESET}")


def info(msg: str):
    print(f"  {C.DIM}>{C.RESET} {msg}")


def success(msg: str):
    print(f"  {C.GREEN}[OK]{C.RESET} {msg}")


def danger(msg: str):
    print(f"  {C.RED}[!!]{C.RESET} {msg}")


def blocked(msg: str):
    print(f"  {C.GREEN}[BLOCKED]{C.RESET}  {msg}")


def bypassed(msg: str):
    print(f"  {C.RED}[BYPASSED]{C.RESET} {msg}")


def pause(msg: str = ""):
    print(f"\n  {C.DIM}───────────────────────────────────────{C.RESET}")
    time.sleep(0.3)


# ═══════════════════════════════════════════════════════════════
# PHASE 1: SIMULATED SCAN (What agents would discover)
# ═══════════════════════════════════════════════════════════════
def create_scan_context() -> ScanContext:
    """Simulate what Agent 01 (Recon) and Agent 02 (Crawler) would discover."""

    header("PHASE 1: SIMULATED SCAN RESULTS", "1")
    info("Simulating what CYPHEX agents would discover on a target...")
    time.sleep(0.5)

    context = ScanContext(
        target_url="http://vulncorp.local:5000",
        framework="Flask 2.3.1",
        database="SQLite 3.39",
        os_type="Linux (Ubuntu 22.04)",
        language="Python 3.11",
        server="Werkzeug/2.3.1",
        headers={
            "Server": "Werkzeug/2.3.1",
            "Content-Type": "text/html; charset=utf-8",
            "X-Powered-By": "Flask",
        },
        discovered_paths=[
            "/", "/login", "/search", "/api/users", "/api/profile",
            "/admin", "/static", "/.env", "/api/products",
        ],
        all_endpoints=[
            "http://vulncorp.local:5000/api/search",
            "http://vulncorp.local:5000/api/login",
            "http://vulncorp.local:5000/api/users",
            "http://vulncorp.local:5000/api/profile",
            "http://vulncorp.local:5000/api/products",
        ],
        all_forms=[
            FormData(
                action="http://vulncorp.local:5000/api/login",
                method="POST",
                inputs=["username", "password"],
                page="/login",
            ),
            FormData(
                action="http://vulncorp.local:5000/api/search",
                method="GET",
                inputs=["q"],
                page="/search",
            ),
            FormData(
                action="http://vulncorp.local:5000/api/profile",
                method="PUT",
                inputs=["name", "email", "bio"],
                page="/profile",
            ),
        ],
        all_params=[
            ParamData(url="http://vulncorp.local:5000/api/search", name="q", value="laptop"),
            ParamData(url="http://vulncorp.local:5000/api/users", name="id", value="1"),
            ParamData(url="http://vulncorp.local:5000/api/products", name="category", value="electronics"),
        ],
        confirmed_vulns=[
            Vuln(name="SQL Injection", severity="Critical", endpoint="/api/search?q=", confirmed=True),
            Vuln(name="Reflected XSS", severity="High", endpoint="/api/search?q=", confirmed=True),
            Vuln(name="Missing Security Headers", severity="Medium", confirmed=True),
        ],
    )

    print(f"\n  {C.BOLD}Target:{C.RESET}       {context.target_url}")
    print(f"  {C.BOLD}Framework:{C.RESET}    {context.framework}")
    print(f"  {C.BOLD}Database:{C.RESET}     {context.database}")
    print(f"  {C.BOLD}OS:{C.RESET}           {context.os_type}")
    print(f"  {C.BOLD}Endpoints:{C.RESET}    {len(context.all_endpoints)}")
    print(f"  {C.BOLD}Forms:{C.RESET}        {len(context.all_forms)}")
    print(f"  {C.BOLD}Parameters:{C.RESET}   {len(context.all_params)}")
    print(f"  {C.BOLD}Vulns Found:{C.RESET}  {len(context.confirmed_vulns)}")

    for v in context.confirmed_vulns:
        severity_color = {
            "Critical": C.RED, "High": C.YELLOW,
            "Medium": C.CYAN, "Low": C.DIM,
        }.get(v.severity, C.WHITE)
        print(f"    {severity_color}[{v.severity}]{C.RESET} {v.name} at {v.endpoint}")

    return context


# ═══════════════════════════════════════════════════════════════
# PHASE 2: BUILD THE BEHAVIORAL GENOME
# ═══════════════════════════════════════════════════════════════
def build_genome(context: ScanContext) -> BehavioralGenome:
    """Build the behavioral genome from scan results."""

    header("PHASE 2: BUILDING BEHAVIORAL GENOME", "2")

    info("The genome learns what NORMAL looks like for each endpoint.")
    info("It doesn't know what attacks look like - it just knows YOUR app.\n")

    genome = BehavioralGenome()

    # Show the process step by step
    section("Step 2a: Profile each endpoint", "")
    time.sleep(0.3)

    state = genome.build_from_scan(context)

    for key, profile in genome.endpoint_profiles.items():
        print(f"    Endpoint: {C.CYAN}{profile.endpoint}{C.RESET}")
        print(f"      Method:        {profile.method}")
        print(f"      Input fields:  {profile.input_fields or ['(auto-detected)']}")
        print(f"      Avg length:    {profile.input_length_mean}")
        print(f"      Avg entropy:   {profile.input_entropy_mean}")
        print(f"      ML model:      {'Trained' if key in genome.endpoint_models else 'Heuristic'}")
        print()

    success(f"Genome built with {len(genome.endpoint_profiles)} endpoint profiles")
    success(f"Isolation Forest models trained for {len(genome.endpoint_models)} endpoints")

    # Demo: Score some normal vs attack inputs
    section("Step 2b: Demo scoring (normal vs attack)", "")
    time.sleep(0.3)

    test_cases = [
        ("Normal search", "laptop case"),
        ("Normal search", "blue wireless mouse"),
        ("Normal login", "john_doe"),
        ("SQLi attack", "' OR 1=1--"),
        ("SQLi attack", "admin'; DROP TABLE users;--"),
        ("XSS attack", "<script>alert(document.cookie)</script>"),
        ("XSS attack", "<img src=x onerror=alert(1)>"),
        ("CMDi attack", "; cat /etc/passwd"),
        ("Obfuscated SQLi", "%27%20OR%201%3D1--"),
        ("Encoded XSS", "<svg/onload=alert(1)>"),
    ]

    ep = list(genome.endpoint_profiles.keys())[0]
    print(f"    Testing against endpoint: {C.CYAN}{ep}{C.RESET}\n")

    for label, payload in test_cases:
        score = genome.score_request(ep, payload)
        is_attack = "attack" in label.lower()

        if score >= 0.7:
            status = f"{C.GREEN}BLOCKED{C.RESET}"
        elif score >= 0.4:
            status = f"{C.YELLOW}SUSPICIOUS{C.RESET}"
        else:
            status = f"{C.RED}ALLOWED{C.RESET}" if is_attack else f"{C.DIM}ALLOWED{C.RESET}"

        bar_len = int(score * 20)
        bar = f"{C.RED}{'█' * bar_len}{C.DIM}{'░' * (20 - bar_len)}{C.RESET}"

        correct = (score >= 0.7 and is_attack) or (score < 0.7 and not is_attack)
        check = f"{C.GREEN}✓{C.RESET}" if correct else f"{C.RED}✗{C.RESET}"

        print(f"    {check} [{bar}] {score:.2f}  {status}  {C.DIM}{label}:{C.RESET} {payload[:40]}")

    return genome


# ═══════════════════════════════════════════════════════════════
# PHASE 3: RED TEAM PAYLOAD GENERATION
# ═══════════════════════════════════════════════════════════════
def demo_red_team(genome: BehavioralGenome) -> MutationEngine:
    """Show how the red team generates and mutates payloads."""

    header("PHASE 3: RED TEAM PAYLOAD GENERATION", "3")

    mutation = MutationEngine()

    # Show initial payload generation
    section("Step 3a: Generate initial attack payloads", "")
    time.sleep(0.3)

    for attack_type in ["sqli", "xss", "cmdi"]:
        payloads = mutation.generate_initial_payloads(attack_type=attack_type, count=5)
        print(f"\n    {C.BOLD}{attack_type.upper()} Payloads:{C.RESET}")
        for p in payloads[:5]:
            print(f"      [{p['technique'][:15]:>15}]  {p['payload'][:60]}")

    # Show mutation techniques
    section("Step 3b: Demonstrate obfuscation techniques", "")
    time.sleep(0.3)

    base = "' OR 1=1--"
    print(f"\n    Base payload: {C.RED}{base}{C.RESET}\n")

    techniques = [
        ("URL Encode", mutation.url_encode(base)),
        ("Double Encode", mutation.double_url_encode(base)),
        ("Unicode", mutation.unicode_escape(base)),
        ("Case Mutation", mutation.case_mutation(base)),
        ("Whitespace Sub", mutation.whitespace_substitution(base)),
        ("Comment Inject", mutation.comment_injection(base)),
    ]

    ep = list(genome.endpoint_profiles.keys())[0]
    for name, mutated in techniques:
        score = genome.score_request(ep, mutated)
        status = f"{C.GREEN}BLOCKED{C.RESET}" if score >= 0.7 else f"{C.RED}BYPASSED{C.RESET}"
        print(f"    {name:>16}: {C.YELLOW}{mutated[:50]:<50}{C.RESET}  score={score:.2f}  {status}")

    return mutation


# ═══════════════════════════════════════════════════════════════
# PHASE 4: FULL EVOLUTION LOOP
# ═══════════════════════════════════════════════════════════════
async def run_evolution(context: ScanContext):
    """Run the full adversarial co-evolution and show every generation."""

    header("PHASE 4: ADVERSARIAL CO-EVOLUTION LOOP", "4")

    info("Red Team (attacker) vs Blue Team (genome) — 10 generations")
    info("Watch the block rate climb as the genome learns!\n")
    time.sleep(0.5)

    controller = EvolutionController()

    # Custom callback to show detailed per-generation info
    gen_details = []

    async def on_gen_complete(result: EvolutionResult):
        gen_details.append(result)

    results = await controller.run_evolution(
        context,
        generations=10,
        payloads_per_gen=30,
        on_generation_complete=on_gen_complete,
    )

    # Show detailed evolution visualization
    section("Evolution Timeline", "")

    for r in results:
        # Visual bar
        bar_len = int(r.block_rate * 40)
        bar_blocked = f"{C.GREEN}{'█' * bar_len}{C.RESET}"
        bar_bypassed = f"{C.RED}{'█' * (40 - bar_len)}{C.RESET}"

        status_icon = "🟢" if r.block_rate > 0.8 else "🟡" if r.block_rate > 0.5 else "🔴"

        print(f"    Gen {r.generation:2d} {status_icon} [{bar_blocked}{bar_bypassed}] "
              f"{r.block_rate:6.1%}  "
              f"{C.GREEN}blocked={r.payloads_blocked}{C.RESET}  "
              f"{C.RED}bypassed={r.payloads_bypassed}{C.RESET}  "
              f"{C.DIM}{r.duration_seconds:.1f}s{C.RESET}")

    # Summary
    summary = controller.get_evolution_summary()

    section("Final Results", "")

    initial = summary["initial_block_rate"]
    final = summary["final_block_rate"]
    improvement = final - initial

    print(f"    Initial Block Rate:  {C.RED}{initial:.1%}{C.RESET}")
    print(f"    Final Block Rate:    {C.GREEN}{final:.1%}{C.RESET}")
    print(f"    Improvement:         {C.BOLD}+{improvement:.1%}{C.RESET}")
    print(f"    Total Attacks Tested: {summary['total_attacks_tested']}")
    print(f"    Total Blocked:       {summary['total_attacks_blocked']}")
    print(f"    Endpoints Protected: {summary['genome_endpoints']}")

    return controller


# ═══════════════════════════════════════════════════════════════
# PHASE 5: FINAL GENOME STATUS
# ═══════════════════════════════════════════════════════════════
def show_final_genome(controller: EvolutionController):
    """Show the final hardened genome state."""

    header("PHASE 5: HARDENED GENOME STATUS", "5")

    genome = controller.genome

    section("Endpoint Protection Status", "")

    for key, profile in genome.endpoint_profiles.items():
        has_model = key in genome.endpoint_models
        attack_count = len(genome._attack_history.get(key, []))

        status = f"{C.GREEN}PROTECTED{C.RESET}" if has_model else f"{C.YELLOW}HEURISTIC{C.RESET}"
        print(f"    {status}  {C.CYAN}{profile.endpoint}{C.RESET}")
        print(f"              ML Model: {'Isolation Forest (trained)' if has_model else 'Heuristic fallback'}")
        print(f"              Attacks learned: {attack_count}")
        print()

    # Final test: score some attacks against the hardened genome
    section("Final Defense Test (Hardened Genome)", "")

    attacks = [
        ("' OR 1=1--", "Basic SQLi"),
        ("' UNION SELECT NULL,NULL,NULL--", "Union SQLi"),
        ("<script>alert(1)</script>", "Basic XSS"),
        ("%27%20OR%201%3D1--", "URL-encoded SQLi"),
        ("admin'/**/OR/**/1=1--", "Comment-obfuscated SQLi"),
        ("; cat /etc/passwd", "Command injection"),
        ("laptop case", "Normal search (should pass)"),
        ("wireless mouse", "Normal search (should pass)"),
    ]

    ep = list(genome.endpoint_profiles.keys())[0]
    blocked_count = 0
    correct_count = 0

    for payload, label in attacks:
        score = genome.score_request(ep, payload)
        is_normal = "Normal" in label
        is_blocked = score >= 0.7

        if is_blocked:
            blocked_count += 1

        correct = (is_blocked and not is_normal) or (not is_blocked and is_normal)
        if correct:
            correct_count += 1

        if is_blocked:
            print(f"    {C.GREEN}[BLOCKED]  {C.RESET} score={score:.2f}  {label}: {C.DIM}{payload[:40]}{C.RESET}")
        else:
            color = C.DIM if is_normal else C.RED
            status = "ALLOWED" if is_normal else "BYPASSED"
            print(f"    {color}[{status}] {C.RESET} score={score:.2f}  {label}: {C.DIM}{payload[:40]}{C.RESET}")

    print(f"\n    Accuracy: {correct_count}/{len(attacks)} ({100*correct_count/len(attacks):.0f}%)")
    print(f"    Attacks blocked: {blocked_count}/{len(attacks) - 2}")


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
async def main():
    os.system("cls" if os.name == "nt" else "clear")

    print(f"""
{C.CYAN}
    ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗
   ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝
   ██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝
   ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗
   ╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗
    ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{C.RESET}
   {C.BOLD}{C.WHITE}ADVERSARIAL CO-EVOLUTION ENGINE{C.RESET}
   {C.DIM}Self-Evolving Cyber Immune System{C.RESET}
   {C.DIM}No API keys. No cloud. Pure local AI defense.{C.RESET}
""")

    time.sleep(0.5)

    # Phase 1: Simulated scan
    context = create_scan_context()
    pause()

    # Phase 2: Build genome
    genome = build_genome(context)
    pause()

    # Phase 3: Red team demo
    mutation = demo_red_team(genome)
    pause()

    # Phase 4: Full evolution
    controller = await run_evolution(context)
    pause()

    # Phase 5: Final genome
    show_final_genome(controller)

    # Done
    header("DEMO COMPLETE", "")
    print(f"  {C.GREEN}The CYPHEX Immune System is fully operational.{C.RESET}")
    print(f"  {C.DIM}No LLM was used for genome creation or scoring.{C.RESET}")
    print(f"  {C.DIM}Everything ran on your local machine with scikit-learn.{C.RESET}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
