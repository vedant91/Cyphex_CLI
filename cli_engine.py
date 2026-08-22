"""
CYPHEX CLI Engine - Core logic for scan, patch, push workflow.
"""
import asyncio
import os
import sys
import shutil
import subprocess
import time
import uuid
import json
import hashlib
import re
import glob
import math
import random
from types import SimpleNamespace
from datetime import datetime, timezone
from typing import Any, Optional
import httpx
import logging
# Suppress httpx INFO logs (e.g., "HTTP Request: GET ... 200 OK") globally.
# These flood the CLI output during DAST scans and confuse users.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.box import ROUNDED, DOUBLE

console = Console()

# Security posture scoring — zero-dependency module, always importable
# regardless of whether the rich-based SOC UI below is available. This is
# the ONLY place the score formula and its 20/40/60/80 presentation bands
# are defined; do not hand-copy them here or anywhere else — that hand-
# copying previously let this exact fallback silently diverge from
# terminal_ui's copy (this one was missing the severity-band cap the other
# one had), producing wrong scores whenever SOC_UI was False.
from scoring import score_from_counts as security_score, score_band as _score_band

# SOC Terminal UI
try:
    import terminal_ui as ui
    SOC_UI = True
except ImportError:
    SOC_UI = False

# Terminal mascot — animated companion for otherwise-silent waits (Docker
# boot, model calls). No-ops itself on non-tty/NO_COLOR, so it's always
# safe to import and call even when SOC_UI above is False.
try:
    import mascot
    MASCOT = True
except ImportError:
    MASCOT = False
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend", "backend"))
sys.path.insert(0, os.path.dirname(__file__))

from sandbox_manager import (
    deploy_sandbox,
    stop_sandbox,
    restart_sandbox,
    sync_file_to_sandbox,
    _find_free_port,
    _get_node_env,
)
from immune.behavioral_genome import BehavioralGenome
from immune.mutation_engine import MutationEngine
from immune.evolution_controller import EvolutionController
from models.scan import ScanContext, FormData, ParamData, Vuln
from config import config as cyphex_config

try:
    from backend.observability.events import emit as _obs_emit
except Exception:
    def _obs_emit(*a, **kw):
        pass

# Council system imports
sys.path.insert(0, os.path.dirname(__file__))
try:
    from backend.council.patch_council import PatchCouncil
    from backend.council.debate_protocol import DebateProtocol
    from backend.council.analysis_council import AnalysisCouncil
    from backend.council.route_tracer import RouteTracer
    from backend.council.council_orchestrator import is_approved_vote
    COUNCIL_AVAILABLE = True
except ImportError as e:
    COUNCIL_AVAILABLE = False
    # All-or-nothing gate: a single missing transitive dep (e.g. httpx) or a
    # broken import inside any council module disables every council feature.
    # Surface the reason instead of silently showing "Council: OFF".
    console.print(f"[yellow]⚠ AI Council disabled (import failed): {e}[/yellow]")

# ── New Patching Infrastructure (vectorless RAG + grounded reasoning) ──
try:
    from backend.patch.resolver import resolve as resolve_location, is_patchable
    from backend.patch.context import extract_function, extract_function_span, extract_imports, detect_language
    from backend.patch.applier import apply_patch, rollback
    from backend.patch.verifier import verify_static, VerifyResult
    from backend.patch.manifest import PatchManifest
    from backend.patch.templates import apply_template
    from backend.patch.regression import generate_regression_test
    from backend.rag.code_indexer import CodeIndexer
    from backend.rag.security_kb import format_for_prompt, detect_framework, get_fix_strategies, load_security_kb
    from backend.rag.patch_memory import PatchMemory
    PATCH_V2_AVAILABLE = True
except ImportError as _e:
    PATCH_V2_AVAILABLE = False

# ── Cross-project patch memory (cognee, optional) ──
try:
    from backend.rag import cognee_memory
    COGNEE_AVAILABLE = cognee_memory.is_available()
except ImportError:
    COGNEE_AVAILABLE = False

# ── Oracle Agent-Reasoning + Session Memory ──
try:
    from backend.reasoning.oracle_adapter import get_reasoner, get_strategy_info, AGENT_REASONING_AVAILABLE
    from backend.reasoning.session_memory import (
        SessionMemory, create_session, save_session, load_session, ReasoningEntry
    )
    from backend.reasoning.reasoning_tree import (
        ReasoningTree, create_tree, save_tree
    )
    REASONING_AVAILABLE = True
except ImportError:
    AGENT_REASONING_AVAILABLE = False
    REASONING_AVAILABLE = False

# Backwards-compat alias — some code paths use PATCH_PIPELINE_AVAILABLE,
# others use PATCH_V2_AVAILABLE; both should reflect the same flag.
PATCH_PIPELINE_AVAILABLE = PATCH_V2_AVAILABLE

class C:
    """Premium cyber-themed color palette — turquoise/purple/black."""
    # ── Core palette ──
    RST    = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    ITALIC = "\033[3m"
    ULINE  = "\033[4m"
    # Standard colors
    R  = "\033[91m"
    G  = "\033[92m"
    Y  = "\033[93m"
    B  = "\033[94m"
    M  = "\033[95m"
    CY = "\033[96m"
    W  = "\033[97m"
    # ── True-color cyber palette ──
    CYAN   = "\033[38;2;0;255;255m"      # Turquoise/cyan primary
    CYAN2  = "\033[38;2;72;209;204m"     # Muted teal
    PURPLE = "\033[38;2;138;43;226m"     # Vivid purple
    PURP2  = "\033[38;2;161;100;255m"    # Soft purple
    NEON   = "\033[38;2;57;255;20m"      # Neon green (success)
    FLAME  = "\033[38;2;255;69;0m"       # Orange-red (critical)
    GHOST  = "\033[38;2;100;100;120m"    # Ghost gray (dim text)
    SLATE  = "\033[38;2;140;150;170m"    # Slate (secondary text)
    # Backgrounds
    BG_DARK   = "\033[48;2;15;15;25m"    # Near-black bg
    BG_PURPLE = "\033[48;2;30;20;50m"    # Dark purple bg
    BG_CYAN   = "\033[48;2;0;50;60m"     # Dark cyan bg
    BG_RED    = "\033[48;2;60;10;10m"    # Dark red bg

    @staticmethod
    def gradient(text, r1, g1, b1, r2, g2, b2):
        """Apply a horizontal gradient across text."""
        result = []
        n = max(len(text) - 1, 1)
        for i, ch in enumerate(text):
            r = int(r1 + (r2 - r1) * i / n)
            g = int(g1 + (g2 - g1) * i / n)
            b = int(b1 + (b2 - b1) * i / n)
            result.append(f"\033[38;2;{r};{g};{b}m{ch}")
        result.append("\033[0m")
        return "".join(result)

WORK_DIR = os.path.join(os.path.dirname(__file__), "backend", "sandboxes")
os.makedirs(WORK_DIR, exist_ok=True)


class CyphexEngine:
    def __init__(self):
        self.scan_id = f"cli_{uuid.uuid4().hex[:8]}"
        self.source_dir = None
        self.sandbox_info = None
        self.context = None
        self.vulns = []
        self.genome = None
        self.repo_url = None
        self._static_proc = None
        self.judge_mode = False
        self.non_interactive = False
        self.verbose = False
        self.start_ts = 0.0
        try:
            from cyphex.hardware import detect_mode
            self._hw_tier = detect_mode()
        except Exception:
            self._hw_tier = "mid"

    async def run(self, repo_url=None, local_path=None, source_path=None,
                  target_url=None, branch="main",
                  generations=10, output_file=None, auto_patch=True,
                  judge_mode=False, judge=False, non_interactive=False,
                  network_scan=False, use_deepagents=False, verbose: bool = False):
        self.start_ts = time.time()
        self._emit("scan_start", repo_url=repo_url, local_path=local_path, judge_mode=judge_mode or judge)
        self.repo_url = repo_url
        self.local_path = local_path
        self.judge_mode = judge_mode or judge
        self.non_interactive = non_interactive
        self.verbose = verbose

        # Show premium splash banner
        self._splash_banner()

        # Normalize: source_path is an alias for local_path
        if source_path and not local_path:
            local_path = source_path
        # Keep self.local_path as the ORIGINAL user-supplied path (post-alias).
        # Cross-scan memory (session + patch cache) keys on this stable path, not
        # on the per-scan sandbox copy under WORK_DIR/<random scan_id> — otherwise
        # every scan looks like a brand-new project and no memory is ever reused.
        self.local_path = local_path

        if self.judge_mode:
            random.seed(1337)
            generations = min(generations, 4)
            auto_patch = False

        # ── Direct URL scan (no source code needed) ──
        if target_url and not local_path and not repo_url:
            self._step("1/8", "TARGET: LIVE URL")
            print(f"  Scanning live target: {target_url}")
            self.source_dir = None

            # Skip steps 2-3, go directly to dynamic scan
            self._step("4/8", "DYNAMIC VULNERABILITY SCAN")
            self.context = await self._dynamic_scan(target_url, use_deepagents=use_deepagents)

            # Continue with remaining steps (immune system, patching, report)
            self._step("5/8", "AI IMMUNE SYSTEM")
            try:
                await self._build_and_evolve(self.context, generations)
            except Exception as e:
                print(f"  {C.Y}[SKIP]{C.RST} Immune system requires Ollama: {str(e)[:60]}")

            self._step("6/8", "VULNERABILITY REPORT")
            duration = time.time() - self.start_ts
            await self._print_report(duration)

            if auto_patch and self.context.confirmed_vulns:
                self._step("7/8", "PATCH GENERATION")
                try:
                    await self._patch_workflow()
                except Exception as e:
                    print(f"  {C.Y}[SKIP]{C.RST} Patch generation requires Ollama: {str(e)[:60]}")

            self._step("8/8", "COMPLETE")
            self._final_banner()
            return

        # Step 1: Get source code
        self._step("1/9", "GETTING SOURCE CODE")
        self.source_dir = await self._get_source(repo_url, local_path, branch)
        if not self.source_dir:
            return

        # Step 2: Analyze code files
        self._step("2/9", "STATIC CODE ANALYSIS")
        file_vulns = self._analyze_code_files(self.source_dir)

        # Augment with multi-language scanner (Semgrep + 20-language fallback)
        try:
            from cyphex.scanner import run_static_analysis, semgrep_available
            tool_name = "Semgrep" if semgrep_available() else "Built-in (20 languages)"
            print(f"  {C.DIM}Running {tool_name} scanner...{C.RST}")
            extra_findings = run_static_analysis(self.source_dir)
            if extra_findings:
                seen = {(v.endpoint, v.name) for v in file_vulns}
                added = 0
                for ef in extra_findings:
                    key = (f"{ef.file_path}:{ef.line_number}", f"[STATIC] {ef.name}")
                    if key not in seen:
                        seen.add(key)
                        sev = ef.severity if ef.severity in ("Critical", "High", "Medium", "Low") else "Medium"
                        file_vulns.append(Vuln(
                            name=f"[STATIC] {ef.name}",
                            severity=sev,
                            endpoint=f"{ef.file_path}:{ef.line_number}",
                            confirmed=False,
                            cwe=ef.cwe,
                        ))
                        c = "red" if sev == "Critical" else "magenta" if sev == "High" else "yellow"
                        console.print(f"  [[{c}]{sev}[/{c}]] {ef.name} ({ef.cwe})")
                        console.print(f"       {ef.file_path}:{ef.line_number}")
                        console.print(f"       [dim]{ef.code_snippet[:100]}[/dim]")
                        added += 1
                if added:
                    print(f"  {C.G}[OK]{C.RST} {tool_name}: +{added} additional findings")
        except ImportError:
            pass  # cyphex package not installed

        # Step 3: Deploy sandbox
        self._step("3/9", "DEPLOYING SANDBOX")
        target_url = await self._deploy(self.source_dir)
        if not target_url:
            return

        # Step 3b: Network Security Scan (optional, --network flag)
        # Runs AFTER the Docker sandbox is deployed so the container's freshly
        # published app+DB ports are live on the host when the subnet sweep runs.
        # (Running it before deploy would sweep a network where the target's
        # ports are still closed — the scan would miss the very thing we deploy.)
        if network_scan:
            self._step("3b/9", "NETWORK SECURITY SCAN")
            await self._run_network_scan()

        # Step 4: Dynamic scan (crawl + attack)
        self._step("4/9", "DYNAMIC VULNERABILITY SCAN")
        if target_url == "offline_mode":
            print(f"  {C.Y}[WARN] Sandbox deployment failed. Skipping dynamic scan. Proceeding with static vulnerabilities.{C.RST}")
            self.context = ScanContext(target_url="http://offline.local")
            # Inject static endpoints so the Genome can still train profiles
            for v in file_vulns:
                ep_path = v.endpoint.split(":")[0]
                if ep_path not in self.context.all_endpoints:
                    self.context.all_endpoints.append(ep_path)
        else:
            self.context = await self._dynamic_scan(target_url, use_deepagents=use_deepagents)
        self.context.confirmed_vulns.extend(file_vulns)

        # Merge network findings (if netmap ran in step 3b)
        if hasattr(self, "_network_vulns") and self._network_vulns:
            self.context.confirmed_vulns.extend(self._network_vulns)
            print(f"  {C.G}[OK]{C.RST} +{len(self._network_vulns)} network vulnerability findings merged")

        # Step 5: Build genome + evolve
        self._step("5/9", "IMMUNE SYSTEM - BUILD GENOME")
        self.genome = await self._build_and_evolve(self.context, generations)

        # Step 6: AI Attack Simulation
        self._step("6/9", "AI ATTACK SIMULATION - GENOME DEFENSE")
        self._simulate_attacks()

        # Step 7: Report
        self._step("7/9", "SECURITY REPORT")
        report = await self._print_report(time.time() - self.start_ts)
        if output_file:
            self._save_report(report, output_file)
        if self.judge_mode:
            self._save_judge_artifacts(report)

        # Step 8: Patch workflow
        if auto_patch and self.context.confirmed_vulns:
            self._step("8/9", "AI PATCH + VERIFY  (RAG · Council · Reflexion · Memory)")
            await self._patch_workflow()

        # Cleanup
        if hasattr(self, "_docker_compose_dir") and self._docker_compose_dir:
            try:
                subprocess.run(["docker", "compose", "down", "-v"], cwd=self._docker_compose_dir, capture_output=True, timeout=30)
                print(f"\n  {C.G}[OK]{C.RST} Docker stack stopped.")
            except Exception:
                pass
                
        if self._static_proc:
            self._static_proc.terminate()
            print(f"\n  {C.G}[OK]{C.RST} Static server stopped.")
        elif self.sandbox_info and self.sandbox_info.get("container_name"):
            # A real Docker container (Priority 2) — the native stop_sandbox() can't
            # touch it; route to stop_docker_sandbox so it doesn't leak.
            try:
                from cyphex.docker_sandbox import stop_docker_sandbox
                stop_docker_sandbox(self.sandbox_info["container_name"])
                print(f"\n  {C.G}[OK]{C.RST} Sandbox container stopped.")
            except Exception:
                pass
        elif self.sandbox_info and self.sandbox_info.get("type") != "docker-compose":
            stop_sandbox(self.sandbox_info.get("sandbox_id", ""))
            print(f"\n  {C.G}[OK]{C.RST} Sandbox stopped.")

        self._final_banner()

    def doctor(self) -> bool:
        """
        Local readiness check for judge/demo environments.
        Returns True when all required checks pass.
        """
        checks = []
        checks.append(("python", sys.version.split()[0], True))
        checks.append(("platform", os.name, True))

        def _cmd_ok(cmd: list[str]) -> tuple[bool, str]:
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                if p.returncode == 0:
                    return True, (p.stdout.strip() or p.stderr.strip() or "ok")
                return False, (p.stderr.strip() or p.stdout.strip() or "failed")
            except Exception as exc:
                return False, str(exc)

        npm_bin = shutil.which("npm") or ("npm.cmd" if os.name == "nt" else "npm")
        tool_cmds = [
            ("git", ["git", "--version"]),
            ("node", ["node", "--version"]),
            ("npm", [npm_bin, "--version"]),
            ("curl", ["curl", "--version"]),
            ("ollama", ["ollama", "--version"]),
        ]
        for name, cmd in tool_cmds:
            ok, detail = _cmd_ok(cmd)
            checks.append((name, detail.splitlines()[0][:80], ok))

        ollama_ok = False
        ollama_detail = "not checked"
        try:
            r = httpx.get("http://localhost:11434/api/tags", timeout=4.0)
            ollama_ok = r.status_code == 200
            if ollama_ok:
                models = [m.get("name", "") for m in r.json().get("models", [])]
                ollama_detail = ", ".join(models[:3]) if models else "no models pulled"
            else:
                ollama_detail = f"status={r.status_code}"
        except Exception as exc:
            ollama_detail = str(exc)[:80]
        checks.append(("ollama-api", ollama_detail, ollama_ok))

        print(f"{C.CY}{'='*60}{C.RST}")
        print(f"  {C.BOLD}CYPHEX Doctor - Local Readiness{C.RST}")
        print(f"{C.CY}{'='*60}{C.RST}")
        all_ok = True
        for name, detail, ok in checks:
            mark = f"{C.G}[OK]{C.RST}" if ok else f"{C.R}[!!]{C.RST}"
            print(f"  {mark} {name:<12} {detail}")
            all_ok = all_ok and ok

        if all_ok:
            print(f"\n  Result: {C.G}READY{C.RST}")
        else:
            print(f"\n  Result: {C.Y}PARTIAL - fix failed checks before demo{C.RST}")
        return all_ok

    def _vprint(self, *args, **kwargs):
        """Verbose-only print — pipeline chatter (per-payload DAST narration,
        per-file SAST hits, docker retry noise, patch-loop internals) that
        floods the terminal on a normal run. Gated behind --verbose so the
        default CLI output stays phase-banner + final-result focused."""
        if self.verbose:
            print(*args, **kwargs)

    def _vconsole(self, *args, **kwargs):
        """Same as _vprint but for rich `console.print(...)` call sites."""
        if self.verbose:
            console.print(*args, **kwargs)

    def _emit(self, event: str, **fields):
        """Best-effort observability event — never raises, never blocks the pipeline."""
        try:
            _obs_emit(os.path.join(WORK_DIR, self.scan_id), event, scan_id=self.scan_id, **fields)
        except Exception:
            pass

    def _step(self, num, title):
        self._emit("phase_start", num=str(num), title=str(title))
        elapsed = time.time() - self.start_ts if self.start_ts else 0.0
        mode = "JUDGE" if self.judge_mode else "SCAN"
        step_num, step_total = num.split("/")
        # step_num may be '2b', '3', etc — strip non-digit suffix for progress bar
        import re as _re
        done = int(_re.sub(r"[^0-9]", "", step_num) or "0")
        total = int(step_total)

        # Mascot cameo announcing the phase transition — brief, self-cleaning,
        # never held open (each phase's own work handles its own feedback).
        if MASCOT:
            mascot.thinking(label=title, flourish=True)

        if SOC_UI:
            ui.render_step(done, total, title, elapsed, mode)
            return

        # Fallback: original ANSI rendering
        step_icons = {
            "1": "📥", "2": "🔍", "3": "📦", "3b": "🌐", "4": "⚡",
            "5": "🧬", "6": "⚔️", "7": "📊", "8": "🔧",
        }
        icon = step_icons.get(step_num, "◆")
        filled = int(done / total * 20)
        progress = f"{'█' * filled}{'░' * (20 - filled)}"
        border = C.gradient("━" * 72, 0, 255, 255, 138, 43, 226)
        print(f"\n{border}")
        pill = f"{C.BG_CYAN}{C.BOLD} {icon} STEP {step_num}/{step_total} {C.RST}"
        title_text = f"{C.CYAN}{C.BOLD}{title}{C.RST}"
        meta = f"{C.GHOST}[{mode} t={elapsed:.1f}s]{C.RST}"
        print(f"  {pill}  {title_text}  {meta}")
        print(f"  {C.GHOST}{progress} {done}/{total}{C.RST}")
        print(f"{border}\n")

    def _splash_banner(self):
        """Premium cyber-themed splash screen."""
        if SOC_UI:
            target = self.repo_url or getattr(self, 'local_path', '') or ''
            ui.render_hero(self.scan_id, target=str(target))
            self._tool_availability_summary()
            return

        # Fallback: original ANSI rendering
        banner = f"""
{C.CYAN}  ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗{C.RST}
{C.CYAN}  ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝{C.RST}
{C.CYAN2}  ██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝{C.RST}
{C.PURP2}  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗{C.RST}
{C.PURPLE}  ╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗{C.RST}
{C.PURPLE}   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{C.RST}
"""
        divider = C.gradient("━" * 60, 0, 255, 255, 138, 43, 226)
        print(banner)
        print(f"  {divider}")
        print(f"  {C.SLATE}Multi-Agent Security Pipeline{C.RST}  {C.GHOST}│{C.RST}  {C.CYAN}v2.0{C.RST}  {C.GHOST}│{C.RST}  {C.PURP2}AI-Powered  │  OFFLINE-FIRST{C.RST}")
        print(f"  {divider}")
        print(f"  {C.GHOST}Scan ID: {C.CYAN2}{self.scan_id}{C.RST}   {C.GHOST}Hardware tier: {C.PURP2}{self._hw_tier.upper()}{C.RST}")
        print()

        # ── Active capability flags ──
        rag_ok  = RAG_AVAILABLE
        pipe_ok = PATCH_PIPELINE_AVAILABLE
        council = COUNCIL_AVAILABLE

        def _flag(on: bool) -> str:
            return f"{C.NEON}✓{C.RST}" if on else f"{C.R}○{C.RST}"

        def _label(on: bool, text_on: str, text_off: str, col_on: str = C.NEON) -> str:
            return (f"{col_on}{C.BOLD}{text_on}{C.RST}" if on else f"{C.R}{text_off}{C.RST}")

        B = C.GHOST  # box border shorthand
        print(f"  {B}┌─ Active Pipeline Capabilities ──────────────────────────────┐{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(True)}  {C.CYAN}{C.BOLD}SAST{C.RST}          {C.SLATE}Semgrep + built-in 20-lang scanner + Nuclei{C.RST}   {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(True)}  {C.CYAN}{C.BOLD}DAST{C.RST}          {C.SLATE}multi-agent exploit replay (SQLi/XSS/CMDi/LFI/SSRF){C.RST} {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(True)}  {C.PURP2}{C.BOLD}Immune System{C.RST} {C.SLATE}adversarial co-evolution genome{C.RST}              {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(council)}  {_label(council,'AI Council','AI Council — offline',C.PURP2)}  {C.SLATE}batch patch + dual-specialist review{C.RST}       {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(rag_ok)}  {_label(rag_ok,'Vectorless RAG','RAG disabled',C.CYAN2)}  {C.SLATE}function-extract + CWE-KB + repo examples{C.RST}  {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(pipe_ok)}  {_label(pipe_ok,'Verification Gate','Verify — off',C.NEON)}  {C.SLATE}re-scan + exploit-replay + rollback{C.RST}       {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(pipe_ok)}  {_label(pipe_ok,'Patch Manifest','Manifest — off',C.NEON)}   {C.SLATE}.cyphex/patches.json durability tracking{C.RST}  {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(pipe_ok)}  {_label(pipe_ok,'Patch Memory','Memory — off',C.CYAN2)}    {C.SLATE}semantic-hash recall + pattern library{C.RST}    {B}│{C.RST}")
        _refl_rounds = {"minimal": 1, "low": 1, "mid": 2, "high": 3, "ultra": 3, "cloud": 3}.get(self._hw_tier, 2)
        print(f"  {B}│{C.RST}  {_flag(pipe_ok)}  {_label(pipe_ok,'Reflexion Loop','Reflexion — off',C.CYAN2)}  {C.SLATE}evidence-fed retry ({self._hw_tier}: up to {_refl_rounds} round(s)){C.RST}  {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(pipe_ok)}  {_label(pipe_ok,'Regression Tests','Regression — off',C.PURP2)} {C.SLATE}auto-emitted per verified fix{C.RST}          {B}│{C.RST}")
        print(f"  {B}│{C.RST}  {_flag(True)}  {C.Y}{C.BOLD}Autonomy Ladder{C.RST}  {C.SLATE}L1–L4 degradation honesty{C.RST}                {B}│{C.RST}")
        print(f"  {B}└──────────────────────────────────────────────────────────────┘{C.RST}")
        print()
        self._tool_availability_summary()

    def _tool_availability_summary(self):
        """Show what tools are available before scanning starts."""
        is_windows = os.name == "nt"

        # ── Check each tool ──
        tools = []

        # Git
        git_ok = shutil.which("git") is not None
        tools.append(("Git", git_ok, "git-scm.com" if not git_ok else None))

        # Docker
        docker_ok = shutil.which("docker") is not None
        if docker_ok:
            try:
                r = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
                if r.returncode != 0:
                    if sys.platform == "darwin":
                        print(f"  {C.GHOST}│{C.RST}  {C.Y}⚠ Docker Desktop offline — auto-starting...{C.RST}")
                        subprocess.run(["open", "-a", "Docker"], capture_output=True)
                        time.sleep(3)
                    elif sys.platform == "win32":
                        # A single hardcoded path missed non-default installs
                        # (per-user %LOCALAPPDATA% installs, a non-C: drive,
                        # Program Files (x86)) — check the common locations
                        # before giving up on auto-start. Fails silently
                        # either way (os.path.exists guard), same as before.
                        _candidates = [
                            r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
                            r"C:\Program Files (x86)\Docker\Docker\Docker Desktop.exe",
                            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe"),
                        ]
                        docker_exe = next((p for p in _candidates if os.path.exists(p)), None)
                        if docker_exe:
                            print(f"  {C.GHOST}│{C.RST}  {C.Y}⚠ Docker Desktop offline — auto-starting...{C.RST}")
                            subprocess.Popen([docker_exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            time.sleep(5)
                r = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
                docker_ok = r.returncode == 0
                docker_hint = None if docker_ok else "Docker daemon waking up (may take a minute)"
            except Exception:
                docker_ok = False
                docker_hint = "Docker daemon waking up (may take a minute)"
        else:
            docker_hint = "docker.com/products/docker-desktop"
        tools.append(("Docker", docker_ok, docker_hint))

        # Ollama
        ollama_ok = False
        ollama_models = []
        try:
            r = httpx.get("http://localhost:11434/api/tags", timeout=1.0)
            if r.status_code == 200:
                ollama_ok = True
        except Exception:
            pass

        if not ollama_ok and shutil.which("ollama"):
            print(f"  {C.GHOST}│{C.RST}  {C.Y}⚠ Ollama server offline — auto-starting...{C.RST}")
            if sys.platform == "darwin":
                subprocess.run(["open", "-a", "Ollama"], capture_output=True)
            elif sys.platform == "win32":
                # CREATE_NO_WINDOW (0x08000000) alone hides the console but
                # doesn't stop Ctrl+C from reaching this child — need
                # CREATE_NEW_PROCESS_GROUP (0x00000200) too so
                # GenerateConsoleCtrlEvent from a Ctrl+C during the scan
                # doesn't kill the Ollama server this just launched.
                subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  creationflags=0x08000000 | 0x00000200)
            else:
                # start_new_session=True (== os.setsid()) takes this process
                # out of the terminal's foreground process group — without
                # it, Ctrl+C during the scan sends SIGINT to this freshly
                # launched Ollama server too, defeating the point of having
                # auto-started a persistent local model server.
                subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
            time.sleep(3)  # Give server a moment to bind to port
            
        try:
            r = httpx.get("http://localhost:11434/api/tags", timeout=3.0)
            if r.status_code == 200:
                ollama_ok = True
                ollama_models = [m.get("name", "") for m in r.json().get("models", [])]
        except Exception:
            pass
            
        if not ollama_ok:
            tools.append(("Ollama", False, "ollama.com (AI council + patching)"))
        else:
            model_str = f"{len(ollama_models)} model(s)" if ollama_models else "no models"
            tools.append(("Ollama", True, model_str))

        # Semgrep
        from cyphex.scanner import semgrep_available
        semgrep_ok = semgrep_available()
        
        if is_windows and semgrep_ok:
            tools.append(("Semgrep", True, "via WSL"))
        elif is_windows and not semgrep_ok:
            tools.append(("Semgrep", False, "Requires WSL on Windows (optional)"))
        else:
            tools.append(("Semgrep", semgrep_ok, "pip install semgrep" if not semgrep_ok else None))

        # Nuclei
        nuclei_ok = shutil.which("nuclei") is not None
        tools.append(("Nuclei", nuclei_ok, "run: cyphex doctor" if not nuclei_ok else None))

        # ── Display ──
        active = sum(1 for _, ok, _ in tools if ok)
        total = len(tools)

        print(f"  {C.GHOST}┌─ Tool Readiness {C.NEON}({active}/{total} active){C.GHOST} ─────────────────────┐{C.RST}")
        for name, ok, hint in tools:
            if ok:
                icon = f"{C.NEON}✓{C.RST}"
                detail = f"{C.CYAN2}{hint}{C.RST}" if hint else ""
                print(f"  {C.GHOST}│{C.RST}  {icon} {C.NEON}{name:12s}{C.RST} {detail}")
            else:
                icon = f"{C.R}✗{C.RST}"
                hint_str = f"{C.Y}→ {hint}{C.RST}" if hint else ""
                print(f"  {C.GHOST}│{C.RST}  {icon} {C.R}{name:12s}{C.RST} {hint_str}")
        print(f"  {C.GHOST}└──────────────────────────────────────────────────┘{C.RST}")

        # Show Ollama model assignments if available
        if ollama_ok and ollama_models:
            try:
                import asyncio
                from backend.council.model_selector import ModelSelector
                s = ModelSelector()
                # Run discovery synchronously
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # We're inside async context, just show model count
                    print(f"  {C.GHOST}  Models: {', '.join(ollama_models[:4])}{C.RST}")
                else:
                    asyncio.run(s.discover(quiet=True))
                    roles = {r: s.get(r) for r in s.ROLES}
                    unique = set(roles.values())
                    print(f"  {C.GHOST}  AI: {', '.join(unique)} → auto-assigned to {len(s.ROLES)} roles{C.RST}")
            except Exception:
                if ollama_models:
                    print(f"  {C.GHOST}  Models: {', '.join(ollama_models[:4])}{C.RST}")

        print()

    # Step 1: Clone or copy source
    async def _get_source(self, repo_url, local_path, branch):
        dest = os.path.join(WORK_DIR, self.scan_id)
        os.makedirs(dest, exist_ok=True)

        if repo_url:
            print(f"  Cloning {C.CY}{repo_url}{C.RST} (branch: {branch})")

            # --- Security: validate repo_url/branch before touching subprocess ---
            # Reject dangerous git transports (e.g. `ext::`, `fd::`, `file://`) that
            # can be abused for command execution or local file disclosure, and
            # reject leading-dash values that git would otherwise parse as options
            # instead of positional arguments (argument injection).
            if repo_url.startswith("-") or (branch and branch.startswith("-")):
                print(f"  {C.R}[ERR]{C.RST} Invalid repo URL or branch: values starting with '-' are not allowed.")
                return None
            if not (repo_url.startswith("https://") or repo_url.startswith("git@") or repo_url.startswith("ssh://")):
                print(f"  {C.R}[ERR]{C.RST} Unsupported repo URL scheme. Only https://, git@, and ssh:// URLs are allowed.")
                return None

            # Defense-in-depth: even if a disallowed transport slips through,
            # tell git itself to refuse anything but the protocols we support.
            git_env = {**os.environ, "GIT_ALLOW_PROTOCOL": "https:ssh:git"}
            try:
                proc = subprocess.run(
                    ["git", "clone", "--depth", "1", "-b", branch, "--", repo_url, dest],
                    capture_output=True, text=True, timeout=120, env=git_env
                )
                if proc.returncode != 0:
                    # Try without branch
                    proc = subprocess.run(
                        ["git", "clone", "--depth", "1", "--", repo_url, dest],
                        capture_output=True, text=True, timeout=120, env=git_env
                    )
                if proc.returncode != 0:
                    print(f"  {C.R}[ERR]{C.RST} Git clone failed: {proc.stderr[:200]}")
                    return None
                print(f"  {C.G}[OK]{C.RST} Cloned to {dest}")
            except FileNotFoundError:
                print(f"  {C.R}[ERR]{C.RST} Git not found. Install git first.")
                return None
        elif local_path:
            src = os.path.abspath(local_path)
            print(f"  Copying {C.CY}{src}{C.RST}")
            if not os.path.isdir(src):
                print(f"  {C.R}[ERR]{C.RST} Path not found: {src}")
                return None
            shutil.copytree(src, dest, dirs_exist_ok=True)
            print(f"  {C.G}[OK]{C.RST} Copied to {dest}")

        # Detect framework
        fw = self._detect_framework(dest)
        print(f"  {C.GHOST}Framework{C.RST}   {C.CYAN}{fw['name']}{C.RST}")
        print(f"  {C.GHOST}Entry{C.RST}       {C.SLATE}{fw['entry'] or 'auto-detect'}{C.RST}")
        print(f"  {C.GHOST}Files{C.RST}       {C.SLATE}{fw['file_count']} code files{C.RST}")
        return dest

    def _detect_framework(self, path):
        info = {"name": "Unknown", "entry": None, "file_count": 0}
        code_exts = {'.js','.ts','.py','.php','.go','.java','.rb','.html','.css'}
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in {'node_modules','.git','__pycache__','.venv','venv'}]
            for f in files:
                if os.path.splitext(f)[1] in code_exts:
                    info["file_count"] += 1

        if os.path.exists(os.path.join(path, "package.json")):
            try:
                with open(os.path.join(path, "package.json"), encoding="utf-8") as f:
                    pkg = json.load(f)
                deps = {**pkg.get("dependencies",{}), **pkg.get("devDependencies",{})}
                if "express" in deps: info["name"] = "Node.js (Express)"
                elif "next" in deps: info["name"] = "Node.js (Next.js)"
                elif "fastify" in deps: info["name"] = "Node.js (Fastify)"
                else: info["name"] = "Node.js"
                info["entry"] = pkg.get("main", "")
            except: pass
        elif os.path.exists(os.path.join(path, "requirements.txt")):
            info["name"] = "Python (Flask/Django)"
        elif os.path.exists(os.path.join(path, "go.mod")):
            info["name"] = "Go"
        elif os.path.exists(os.path.join(path, "composer.json")):
            info["name"] = "PHP"
        return info

    # Step 2: Static code analysis
    def _analyze_code_files(self, source_dir):
        vulns = []
        patterns = {
            "SQL Injection": [
                (r'f"[^"]*\{[^}]*\}[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)', "Python f-string SQL"),
                (r'f"SELECT.*\{', "Python f-string query"),
                (r"execute\s*\(\s*f['\"]", "execute() with f-string"),
                (r'(?:query|execute|raw)\s*\(\s*[`\'"].*\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)', "JS template SQL with user input"),
                (r"query\s*\(\s*[`'\"].*\+", "String concat in query"),
                (r"db\.execute\s*\(.*%s.*%.*\)", "% format SQL"),
            ],
            "XSS (Cross-Site Scripting)": [
                (r'innerHTML\s*=\s*(?![\'"\s]*$)', "innerHTML assignment with dynamic content"),
                (r'document\.write\s*\(', "document.write()"),
                (r'res\.send\s*\(.*\$\{.*req\.(query|body|params)', "Express res.send with user input"),
                (r'\.html\s*\(.*req\.(query|body|params)', "Express .html() with user input"),
                (r'render.*\$\{.*req\.(query|body|params)', "Render with unescaped input"),
            ],
            "Command Injection": [
                (r'exec\s*\(.*req\.(query|body|params)', "exec() with user input"),
                (r'child_process.*exec\s*\(.*\+', "child_process with concat"),
                (r'os\.system\s*\(.*\+', "os.system with concat"),
                (r'subprocess\.\w+\s*\(.*shell\s*=\s*True', "subprocess shell=True"),
            ],
            "Path Traversal": [
                (r'readFile.*req\.(query|body|params)', "readFile with user input"),
                (r'open\s*\(.*req\.(query|body|params)', "open() with user input"),
                (r'(?:readFile|createReadStream|access)\s*\(.*\+.*(?:req|params|query)', "File access with user input"),
            ],
            "Hardcoded Secrets": [
                (r'(?:password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}', "Hardcoded credential"),
                (r'(?:MYSQL_ROOT_PASSWORD|DB_PASS)\s*[:=]\s*\S+', "Hardcoded DB password"),
            ],
            "Missing Auth": [
                (r'app\.(get|post|put|delete)\s*\(\s*["\']\/admin', "Admin route without auth middleware"),
            ],
            "JWT Weak Secret": [
                (r'jwt\.sign\s*\(.*["\'](?:secret|password|123|test|dev|key)["\']', "Hardcoded weak JWT secret"),
                (r'(?:JWT_SECRET|SECRET_KEY)\s*[:=]\s*["\'][^"\']{1,15}["\']', "Short/weak JWT secret in config"),
            ],
            "IDOR (Insecure Direct Object Reference)": [
                (r'(?:findById|findOne)\s*\(\s*req\.(params|query)\.\w+\s*\)', "DB lookup with unsanitized user ID"),
                (r'WHERE\s+id\s*=\s*[\$`]?\{?\s*req\.(params|query)', "SQL WHERE id from user input without authz"),
            ],
            "SSRF (Server-Side Request Forgery)": [
                (r'(?:fetch|axios\.get|axios\.post|http\.get|got)\s*\(\s*(?:req\.(?:body|query)|url|target)', "HTTP request with user-controlled URL"),
                (r'(?:url|endpoint|target)\s*=\s*req\.(body|query)', "URL variable from user input"),
            ],
            "Sensitive Data Exposure": [
                (r'res\.json\s*\(\s*process\.env', "process.env returned in API response"),
                (r'(?:\/debug|\/env|\/config)\s*[\'"]', "Debug/env/config endpoint exposed"),
            ],
        }

        scanned = 0
        code_exts = {'.js','.ts','.py','.php','.go','.java','.rb','.jsx','.tsx'}

        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in {'node_modules','.git','__pycache__','.venv','dist','build'}]
            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext not in code_exts:
                    continue
                filepath = os.path.join(root, fname)
                rel_path = os.path.relpath(filepath, source_dir)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    lines = content.split('\n')
                except:
                    continue

                scanned += 1
                for vuln_type, pats in patterns.items():
                    for pat, desc in pats:
                        for i, line in enumerate(lines, 1):
                            if re.search(pat, line, re.IGNORECASE):
                                severity = "Critical" if "Injection" in vuln_type else "High"
                                v = Vuln(
                                    name=f"[STATIC] {vuln_type}",
                                    severity=severity,
                                    endpoint=f"{rel_path}:{i}",
                                    confirmed=False,
                                )
                                vulns.append(v)
                                sev_icon = {"Critical": f"{C.FLAME}▲", "High": f"{C.R}●", "Medium": f"{C.Y}◆", "Low": f"{C.SLATE}○"}
                                icon = sev_icon.get(severity, f"{C.SLATE}○")
                                self._vprint(f"  {icon} {C.BOLD}[{severity}]{C.RST} {C.CYAN}{vuln_type}{C.RST}")
                                self._vprint(f"       {C.SLATE}{rel_path}:{i}{C.RST}")
                                self._vprint(f"       {C.GHOST}{line.strip()[:100]}{C.RST}")
                                break  # One per pattern per file

        print(f"\n  {C.CYAN}SAST:{C.RST} {C.SLATE}{scanned} files scanned, {C.BOLD}{C.CYAN}{len(vulns)} issues{C.RST}")
        return vulns

    # Step 3: Deploy sandbox
    async def _deploy(self, source_dir):
        import zipfile, tempfile
        from cyphex.docker_sandbox import docker_available

        # Docker being down must NOT kill the whole dynamic phase. When the
        # daemon is unavailable we skip the container sandboxes (Priority 1 & 2)
        # and fall through to the NATIVE process runner (Priority 3: npm
        # install + node), which needs no Docker. That keeps the crawl + DAST +
        # DeepAgents/Oracle phase alive on dev machines without Docker — the
        # previous early `return "offline_mode"` here is exactly why "the deep
        # agents don't run" when Docker isn't up.
        docker_ok = docker_available()
        if not docker_ok:
            print(f"  {C.Y}[WARN] Docker not found or not running.{C.RST}")
            print(f"  {C.SLATE}  → Skipping container sandbox; deploying the target as a NATIVE process (npm/node).{C.RST}")
            print(f"  {C.SLATE}  → The full dynamic + DeepAgents phase still runs against the live native app.{C.RST}")


        # ── Priority 1: Docker Compose (full stack with DB) ──
        compose_file = os.path.join(source_dir, "docker-compose.yml")
        if not os.path.exists(compose_file):
            compose_file = os.path.join(source_dir, "docker-compose.yaml")

        if docker_ok and os.path.exists(compose_file) and shutil.which("docker"):
            print(f"  {C.CYAN}▸ [DOCKER]{C.RST} {C.SLATE}Found docker-compose.yml — deploying full stack (app + DB)...{C.RST}")
            try:
                # Strip obsolete 'version' key to prevent warnings
                self._strip_compose_version(compose_file)

                # ── Pre-flight: tear down any stale containers from a previous
                #    scan so we never hit "container name already in use" conflicts.
                self._vprint(f"  {C.GHOST}[DOCKER] Cleaning up any stale containers...{C.RST}")
                await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "compose", "-f", compose_file, "down", "--remove-orphans"],
                    cwd=source_dir, capture_output=True, text=True, timeout=60
                )

                # Build and start containers
                proc = await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "compose", "-f", compose_file, "up", "-d", "--build"],
                    cwd=source_dir, capture_output=True, text=True, timeout=300
                )

                if proc.returncode != 0:
                    stderr_text = proc.stderr or ""
                    # Conflict: container name already in use → force-remove and retry once
                    if "conflict" in stderr_text.lower() or "already in use" in stderr_text.lower():
                        self._vprint(f"  {C.Y}[DOCKER]{C.RST} Container conflict detected — force-removing and retrying...")
                        await asyncio.to_thread(
                            subprocess.run,
                            ["docker", "compose", "-f", compose_file, "down", "-v", "--remove-orphans"],
                            cwd=source_dir, capture_output=True, text=True, timeout=60
                        )
                        # Also kill any containers with the same names by brute force
                        try:
                            containers_out = subprocess.run(
                                ["docker", "compose", "-f", compose_file, "ps", "-q"],
                                cwd=source_dir, capture_output=True, text=True, timeout=10
                            )
                            ids = containers_out.stdout.strip().split()
                            if ids:
                                subprocess.run(["docker", "rm", "-f"] + ids, capture_output=True, timeout=15)
                        except Exception:
                            pass
                        proc = await asyncio.to_thread(
                            subprocess.run,
                            ["docker", "compose", "-f", compose_file, "up", "-d", "--build"],
                            cwd=source_dir, capture_output=True, text=True, timeout=300
                        )
                    # Common failure: a service has no Dockerfile
                    elif "dockerfile" in stderr_text.lower() or "no such file" in stderr_text.lower():
                        self._vprint(f"  {C.Y}▸ [INFO]{C.RST} {C.SLATE}Some services lack Dockerfiles — deploying buildable services only...{C.RST}")
                        buildable = self._get_buildable_services(compose_file, source_dir)
                        if buildable:
                            self._vprint(f"  {C.GHOST}Deploying: {C.CYAN2}{', '.join(buildable)}{C.RST}")
                            proc = await asyncio.to_thread(
                                subprocess.run,
                                ["docker", "compose", "-f", compose_file, "up", "-d", "--build"] + buildable,
                                cwd=source_dir, capture_output=True, text=True, timeout=300
                            )

                if proc.returncode == 0:
                    # Find the exposed app port from docker-compose
                    port = self._extract_compose_port(compose_file, source_dir)
                    if not port:
                        port = 3000  # Default

                    # Wait for app to be ready
                    url = f"http://localhost:{port}"
                    print(f"  {C.GHOST}Waiting for containers to start...{C.RST}")
                    if MASCOT:
                        mascot.searching("Waiting for containers to start...")
                    for attempt in range(20):
                        await asyncio.sleep(3)
                        try:
                            async with httpx.AsyncClient(timeout=3) as c:
                                r = await c.get(url)
                                if r.status_code < 500:
                                    self.sandbox_info = {
                                        "sandbox_id": self.scan_id,
                                        "port": port,
                                        "url": url,
                                        "status": "running",
                                        "type": "docker-compose",
                                        "source_dir": source_dir,
                                    }
                                    self._docker_compose_dir = source_dir
                                    if MASCOT:
                                        mascot.success(f"Docker stack ready (attempt {attempt + 1})")
                                    print(f"  {C.NEON}✓{C.RST} {C.SLATE}Docker stack ready (attempt {attempt + 1}){C.RST}")
                                    sb = C.gradient("━" * 58, 0, 255, 255, 138, 43, 226)
                                    print(f"  {sb}")
                                    print(f"  {C.CYAN}▸{C.RST} {C.BOLD}SANDBOX LIVE AT:{C.RST}  {C.NEON}{url}{C.RST}")
                                    print(f"  {C.GHOST}  Full stack: app + database + all services{C.RST}")
                                    print(f"  {sb}")
                                    return url
                        except Exception:
                            continue

                    if MASCOT:
                        mascot.error("Docker stack not responding")
                    self._vprint(f"  {C.Y}[WARN]{C.RST} Docker stack started but app not responding on port {port}")
                else:
                    err_lines = [line for line in proc.stderr.splitlines() if "error" in line.lower() or "failed" in line.lower() or "yaml:" in line.lower()]
                    err_msg = err_lines[-1] if err_lines else proc.stderr[-150:].replace("\n", " ")
                    self._vprint(f"  {C.Y}[WARN]{C.RST} docker-compose failed: {err_msg[:150]}")
            except subprocess.TimeoutExpired:
                self._vprint(f"  {C.Y}[WARN]{C.RST} Docker build timed out (300s)")
            except Exception as e:
                self._vprint(f"  {C.Y}[WARN]{C.RST} Docker error: {str(e)[:100]}")

        # ── Priority 2: Docker container (existing OR auto-generated Dockerfile) ──
        # Docker is already confirmed available above (docker_available() returned
        # True, else we'd have returned 'offline_mode'). Build+run a REAL container
        # even when the target ships no Dockerfile — deploy_docker_sandbox() generates
        # one on the fly. This is the actual image+container sandbox (with logs),
        # instead of silently falling through to a bare native process.
        elif docker_ok and shutil.which("docker"):
            if os.path.exists(os.path.join(source_dir, "Dockerfile")):
                print(f"  {C.G}[DOCKER]{C.RST} Found Dockerfile — building container...")
            else:
                print(f"  {C.G}[DOCKER]{C.RST} No Dockerfile — auto-generating one and building container...")
            try:
                from cyphex.docker_sandbox import deploy_docker_sandbox
                result = await deploy_docker_sandbox(source_dir, sandbox_id=self.scan_id)
                if result and result.get("url") and not result.get("error"):
                    self.sandbox_info = result
                    url = result["url"]
                    _gen = " (auto-generated Dockerfile)" if result.get("generated_dockerfile") else ""
                    print(f"  {C.NEON}✓{C.RST} {C.SLATE}Docker container running{_gen}{C.RST}")
                    sb = C.gradient("━" * 58, 0, 255, 255, 138, 43, 226)
                    print(f"  {sb}")
                    print(f"  {C.CYAN}▸{C.RST} {C.BOLD}SANDBOX LIVE AT:{C.RST}  {C.NEON}{url}{C.RST}")
                    print(f"  {C.GHOST}  Container: {result.get('container_name')}  ·  {result.get('log_cmd','')}{C.RST}")
                    _clogs = (result.get("logs") or "").strip()
                    if _clogs:
                        self._vprint(f"  {C.GHOST}  ── container logs (tail) ──{C.RST}")
                        for _ln in _clogs.splitlines()[-15:]:
                            self._vprint(f"  {C.GHOST}  │ {_ln[:200]}{C.RST}")
                    print(f"  {sb}")
                    return url
                elif result and result.get("error"):
                    print(f"  {C.Y}[WARN]{C.RST} Docker deploy failed: {result['error'][:150]} — falling back to native")
            except Exception as e:
                print(f"  {C.Y}[WARN]{C.RST} Docker deploy failed: {str(e)[:100]} — falling back to native")

        # ── Priority 3: Native npm install (original method) ──
        zip_path = os.path.join(tempfile.gettempdir(), f"{self.scan_id}.zip")

        # Create zip from source
        print(f"  Creating sandbox package...")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(source_dir):
                dirs[:] = [d for d in dirs if d not in {'node_modules','.git','__pycache__','.venv'}]
                for f in files:
                    fp = os.path.join(root, f)
                    arcname = os.path.relpath(fp, source_dir)
                    zf.write(fp, arcname)

        print(f"  Deploying sandbox (native)...")
        deploy_id = f"{self.scan_id}_run"
        result = await deploy_sandbox(zip_path, deploy_id)

        if "error" in result:
            # Try monorepo: look for server/ subfolder with package.json
            server_dir = None
            for sub in ['server', 'backend', 'api', 'app']:
                sub_path = os.path.join(source_dir, sub)
                if os.path.isdir(sub_path) and os.path.exists(os.path.join(sub_path, 'package.json')):
                    server_dir = sub_path
                    break

            if server_dir:
                print(f"  {C.Y}[INFO]{C.RST} Monorepo detected - found server at {os.path.basename(server_dir)}/")
                # Re-zip just the server dir
                import tempfile as tf2
                zip2 = os.path.join(tf2.gettempdir(), f"{self.scan_id}_srv.zip")
                with __import__('zipfile').ZipFile(zip2, 'w') as zf:
                    for root, dirs, files in os.walk(server_dir):
                        dirs[:] = [d for d in dirs if d not in {'node_modules','.git','__pycache__'}]
                        for f in files:
                            fp = os.path.join(root, f)
                            zf.write(fp, os.path.relpath(fp, server_dir))
                result = await deploy_sandbox(zip2, deploy_id)
                if "error" not in result:
                    self.sandbox_info = result
                else:
                    print(f"  {C.Y}[INFO]{C.RST} Server deploy failed, falling back to static...")
                    result = {"error": "fallback"}

            if "error" in result and not self.sandbox_info:
                # Fallback: static site
                has_html = any(
                    f.endswith('.html') for _, _, files in os.walk(source_dir)
                    for f in files
                )
                if has_html:
                    print(f"  {C.Y}[INFO]{C.RST} Serving as static site with Python HTTP server...")
                    port = _find_free_port()
                    proc = subprocess.Popen(
                        [sys.executable, "-m", "http.server", str(port)],
                        cwd=source_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    await asyncio.sleep(2)
                    if proc.poll() is not None:
                        print(f"  {C.R}[ERR]{C.RST} Static server failed to start. Proceeding in offline mode.")
                        return "offline_mode"
                    url = f"http://localhost:{port}"
                    self.sandbox_info = {
                        "sandbox_id": deploy_id, "port": port, "url": url,
                        "status": "running", "pid": proc.pid,
                    }
                    self._static_proc = proc
                else:
                    print(f"  {C.Y}[WARN]{C.RST} {result['error'][:200]}. Proceeding in offline mode.")
                    return "offline_mode"
        else:
            self.sandbox_info = result

        url = self.sandbox_info.get("url", "")
        port = self.sandbox_info.get('port', '')
        
        # Only probe for a companion API when the sandbox is a static-file server
        # (no real app logic). If we already have a real sandbox URL on a
        # dynamic port, trust it — don't let an unrelated service on 5000 hijack
        # the scan target.
        sandbox_port = self.sandbox_info.get("port") if isinstance(self.sandbox_info, dict) else None
        is_dynamic_sandbox = sandbox_port and int(sandbox_port) not in (3000, 3001, 3002, 3003, 8000, 8080, 5000)
        if not is_dynamic_sandbox:
            companion_api = await self._detect_companion_api()
            if companion_api and companion_api != url:
                print(f"  {C.Y}[INFO]{C.RST} Companion API detected at {companion_api}. Directing scan to backend.")
                url = companion_api

        print(f"  {C.NEON}✓{C.RST} {C.SLATE}Sandbox deployed successfully!{C.RST}")
        print(f"  {C.GHOST}PID: {self.sandbox_info.get('pid')}, Port: {port}{C.RST}")
        _lf = self.sandbox_info.get("log_file") if isinstance(self.sandbox_info, dict) else None
        if _lf:
            print(f"  {C.GHOST}Logs: {_lf}{C.RST}")
        _nlogs = (self.sandbox_info.get("logs") or "").strip() if isinstance(self.sandbox_info, dict) else ""
        if _nlogs:
            self._vprint(f"  {C.GHOST}── sandbox logs (tail) ──{C.RST}")
            for _ln in _nlogs.splitlines()[-15:]:
                self._vprint(f"  {C.GHOST}│ {_ln[:200]}{C.RST}")
        print()
        sb = C.gradient("━" * 58, 0, 255, 255, 138, 43, 226)
        print(f"  {sb}")
        print(f"  {C.CYAN}▸{C.RST} {C.BOLD}SANDBOX LIVE AT:{C.RST}  {C.NEON}{url}{C.RST}")
        print(f"  {C.GHOST}  Open in browser to see the target app{C.RST}")
        print(f"  {sb}")
        return url

    async def _detect_companion_api(self):
        """If frontend served as static, look for backend running on nearby port."""
        common_backend_ports = [3000, 3001, 3002, 3003, 8000, 8080, 4000, 5000]
        for port in common_backend_ports:
            try:
                async with httpx.AsyncClient(timeout=1) as c:
                    r = await c.get(f"http://localhost:{port}/api/health")
                    if r.status_code < 500:
                        return f"http://localhost:{port}"
            except Exception:
                pass
            try:
                async with httpx.AsyncClient(timeout=1) as c:
                    r = await c.get(f"http://localhost:{port}/api/ping")
                    if r.status_code < 500:
                        return f"http://localhost:{port}"
            except Exception:
                pass
            try:
                async with httpx.AsyncClient(timeout=1) as c:
                    r = await c.get(f"http://localhost:{port}/api/debug")
                    if r.status_code < 500:
                        return f"http://localhost:{port}"
            except Exception:
                pass
        return None

    def _extract_compose_port(self, compose_file, source_dir):
        """Parse docker-compose.yml to find the app's exposed port."""
        try:
            import yaml
        except ImportError:
            # Fallback: regex parse for ports
            pass

        try:
            with open(compose_file, encoding="utf-8") as f:
                content = f.read()

            # Look for port mappings like "3000:3000" or "- 3000:3000"
            import re
            port_matches = re.findall(r'["\']?(\d{4,5}):(\d{4,5})["\']?', content)
            if port_matches:
                # Return the host port of the first non-DB service port
                db_ports = {'3306', '5432', '27017', '6379', '5672'}
                for host_port, container_port in port_matches:
                    if container_port not in db_ports:
                        return int(host_port)
                # If all are DB ports, return first one anyway
                return int(port_matches[0][0])
        except Exception:
            pass
        return None

    def _strip_compose_version(self, compose_file):
        """Remove obsolete 'version' key from docker-compose.yml to prevent warnings."""
        try:
            with open(compose_file, 'r', encoding="utf-8") as f:
                lines = f.readlines()
            # Remove lines that start with 'version:' (top-level only)
            cleaned = [l for l in lines if not re.match(r'^version\s*:', l)]
            if len(cleaned) < len(lines):
                with open(compose_file, 'w', encoding="utf-8") as f:
                    f.writelines(cleaned)
        except Exception:
            pass

    def _get_buildable_services(self, compose_file, source_dir):
        """Find services that have valid Dockerfiles or use pre-built images."""
        import re
        try:
            with open(compose_file, encoding="utf-8") as f:
                content = f.read()

            buildable = []
            # Parse service blocks — look for services with 'image:' or valid 'build:'
            current_service = None
            has_image = False
            has_valid_build = False
            indent_level = 0

            for line in content.split("\n"):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # Detect service names (indented under 'services:')
                match = re.match(r'^  (\w[\w-]*):', line)
                if match and not stripped.startswith(("image:", "build:", "ports:", "environment:",
                                                      "volumes:", "networks:", "depends_on:",
                                                      "command:", "restart:")):
                    # Save previous service if valid
                    if current_service and (has_image or has_valid_build):
                        buildable.append(current_service)
                    current_service = match.group(1)
                    has_image = False
                    has_valid_build = False

                if current_service:
                    if "image:" in stripped:
                        has_image = True
                    if "build:" in stripped:
                        # Check if Dockerfile exists at build context
                        build_match = re.search(r'build:\s*(.+)', stripped)
                        if build_match:
                            build_ctx = build_match.group(1).strip().strip("'\"")
                            dockerfile = os.path.join(source_dir, build_ctx, "Dockerfile")
                            if os.path.exists(dockerfile):
                                has_valid_build = True

            # Don't forget the last service
            if current_service and (has_image or has_valid_build):
                buildable.append(current_service)

            return buildable
        except Exception:
            return []

    # Step 4: Dynamic scan
    async def _dynamic_scan(self, target_url, use_deepagents=False):
        """CLI-focused dynamic scan with explicit per-agent visibility."""
        context = ScanContext(target_url=target_url)

        def agent_header(agent_id: str, name: str, objective: str):
            if MASCOT:
                mascot.searching(label=f"[{agent_id}] {name}", flourish=True)
            if SOC_UI:
                ui.render_agent_header(agent_id, name, objective)
                return
            border = C.gradient("─" * 68, 0, 200, 200, 100, 50, 180)
            print(f"\n  {border}")
            print(f"  {C.CYAN}▸{C.RST} {C.BOLD}{C.CYAN}[{agent_id}]{C.RST} {C.PURP2}{name}{C.RST}")
            print(f"  {C.GHOST}{objective}{C.RST}")
            print(f"  {border}")

        def show_cmd(agent: str, cmd: str):
            self._vprint(f"  {C.DIM}[{agent}]$ {cmd}{C.RST}")

        asi = None
        if use_deepagents:
            print(f"\n  {C.G}[DEEPAGENTS ENABLED]{C.RST} Initialising adaptive intelligence engine...")
            from backend.deepagents.attack_graph import AttackGraph
            from backend.deepagents.attack_surface_index import AttackSurfaceIndex
            from backend.deepagents.oracle_attack import AttackOracle
            from backend.council.council_orchestrator import CouncilOrchestrator
            
            attack_graph = AttackGraph()
            asi = AttackSurfaceIndex()
            orchestrator = CouncilOrchestrator(thread_id=self.scan_id)
            oracle = AttackOracle(orchestrator=orchestrator)

        def agent_header(agent_id: str, name: str, objective: str):
            if MASCOT:
                mascot.searching(label=f"[{agent_id}] {name}", flourish=True)
            if SOC_UI:
                ui.render_agent_header(agent_id, name, objective)
                return
            border = C.gradient("─" * 68, 0, 200, 200, 100, 50, 180)
            print(f"\n  {border}")
            print(f"  {C.CYAN}▸{C.RST} {C.BOLD}{C.CYAN}[{agent_id}]{C.RST} {C.PURP2}{name}{C.RST}")
            print(f"  {C.GHOST}{objective}{C.RST}")
            print(f"  {border}")

        def show_cmd(agent: str, cmd: str):
            self._vprint(f"  {C.DIM}[{agent}]$ {cmd}{C.RST}")

        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            # Agent 02 - Crawler
            agent_header("Agent 02", "Crawler", "Discover pages, forms, parameters")
            pages = ["/"]
            discovered = set()
            forms_found = []

            while pages and len(discovered) < 30:
                path = pages.pop(0)
                if path in discovered:
                    continue
                discovered.add(path)
                url = f"{target_url}{path}"
                show_cmd("Crawler", f'curl -sL "{url}"')
                try:
                    resp = await client.get(url)
                    if asi:
                        asi.ingest_response(url, "GET", "", resp.status_code, resp.text, dict(resp.headers))
                except Exception as exc:
                    print(f"  {C.R}[Crawler][ERR]{C.RST} {path}: {str(exc)[:80]}")
                    continue

                body = resp.text
                context.all_endpoints.append(url)
                context.headers.update(dict(resp.headers))
                self._vprint(f"  {C.G}[Crawler]{C.RST} HTTP {resp.status_code} {url}")

                for link in re.findall(r'href=["\'](/[^"\']*)["\']', body, re.I):
                    clean = link.split("?")[0].split("#")[0]
                    if clean not in discovered and clean not in pages and len(pages) < 40:
                        pages.append(clean)

                form_matches = re.findall(r'<form[^>]*method=["\'](GET|POST)["\'][^>]*action=["\']([^"\']*)["\']', body, re.I)
                for method, action in form_matches:
                    section_start = body.find(f'action="{action}"')
                    section = body[section_start: section_start + 1500] if section_start >= 0 else body
                    inputs = re.findall(r'name=["\']([^"\']+)["\']', section, re.I)
                    full = f"{target_url}{action}" if action.startswith("/") else action
                    forms_found.append(FormData(action=full, method=method.upper(), inputs=inputs, page=path))
                    self._vprint(f"  {C.Y}[Crawler][FORM]{C.RST} {method.upper()} {full} inputs={inputs}")

            context.all_forms = forms_found
            print(f"\n  {C.G}[Crawler][OK]{C.RST} pages={len(context.all_endpoints)} forms={len(forms_found)}")

            # ── API Endpoint Probe (for SPAs with no HTML forms) ──────────
            api_endpoints_found = []
            source_routes = []
            _live_get_with_params = []
            _live_post = []
            _live_id_routes = []
            _live_file_routes = []
            _live_url_routes = []
            _live_debug_routes = []
            if not forms_found:
                agent_header("Agent 02b", "API Discovery", "SPA detected (0 HTML forms). Probing REST API surface...")

                # ── Source-Code Route Discovery ──
                # Use the code indexer to extract REAL routes from source files
                source_routes = []
                if hasattr(self, '_dast_indexer') and self._dast_indexer:
                    source_routes = self._dast_indexer.extract_api_routes()
                elif self.source_dir:
                    try:
                        from backend.rag.code_indexer import CodeIndexer
                        dast_indexer = CodeIndexer(self.source_dir)
                        dast_indexer.build_index()
                        source_routes = dast_indexer.extract_api_routes()
                        self._dast_indexer = dast_indexer
                    except Exception:
                        pass

                if source_routes:
                    route_lines = []
                    for r in source_routes[:15]:  # Cap display at 15
                        params_str = f" params=[{', '.join(r['params'][:3])}]" if r['params'] else ""
                        route_lines.append(f"  {r['method']:6s} {r['path']:30s} ← {r['source']}{params_str}")
                    console.print(Panel(
                        f"[bold]📂 Extracted {len(source_routes)} routes from source code[/bold]\n"
                        f"[dim]Routes parsed from Express/Flask route definitions in source files[/dim]\n\n"
                        + "\n".join(route_lines),
                        title="◈ SOURCE-CODE ROUTE DISCOVERY", border_style="bright_green", padding=(1, 1)
                    ))

                # Build probe list: source-discovered routes FIRST, then fallback guesses
                api_probes = []
                
                # Add source-discovered routes
                for r in source_routes:
                    path = r["path"]
                    method = r["method"]
                    body = None
                    if method == "POST":
                        # Build body from extracted params
                        body = {p: "test" for p in r.get("params", []) if p not in ("id",)}
                        if not body:
                            body = {"test": "value"}
                    elif r.get("params"):
                        # Add query params for GET requests
                        query = "&".join(f"{p}=test" for p in r["params"] if p not in ("id",))
                        if query:
                            path = f"{path}?{query}"
                    api_probes.append((method, path, body))

                # Add fallback hardcoded probes (deduplicated)
                seen_probes = {(m, p.split("?")[0]) for m, p, _ in api_probes}
                fallback_probes = [
                    ("POST", "/api/auth/login",  {"username": "test", "password": "test"}),
                    ("POST", "/api/login",       {"email": "admin@test.com", "password": "admin"}),
                    ("POST", "/login",           {"username": "admin", "password": "admin"}),
                    ("GET",  "/api/health",      None),
                    ("GET",  "/api/debug",       None),
                    ("GET",  "/api/env",         None),
                    ("GET",  "/api/config",      None),
                    ("GET",  "/api/users",       None),
                ]
                for method, path, body in fallback_probes:
                    if (method, path.split("?")[0]) not in seen_probes:
                        api_probes.append((method, path, body))
                        seen_probes.add((method, path.split("?")[0]))
                for method, path, body in api_probes:
                    full_url = f"{target_url}{path}"
                    try:
                        if method == "GET":
                            show_cmd("API", f'curl -s "{full_url}"')
                            resp = await client.get(full_url)
                        else:
                            show_cmd("API", f'curl -s -X POST "{full_url}" -H "Content-Type: application/json" -d \'{{...}}\'')
                            resp = await client.post(full_url, json=body)
                        if asi:
                            body_str = str(body) if body else ""
                            asi.ingest_response(full_url, method, body_str, resp.status_code, resp.text, dict(resp.headers))
                    except Exception:
                        continue
                    if resp.status_code != 404:
                        api_endpoints_found.append((method, path, resp.status_code, resp.text[:500], body))
                        context.all_endpoints.append(full_url)
                        status_tag = C.G if resp.status_code < 400 else C.Y if resp.status_code < 500 else C.R
                        self._vprint(f"  {status_tag}[API]{C.RST} {method} {path} => HTTP {resp.status_code} ({len(resp.text)} bytes)")
                        # Auto-create synthetic forms for login endpoints
                        if body and any(k in path.lower() for k in ("login", "auth")):
                            forms_found.append(FormData(action=full_url, method=method, inputs=list(body.keys()), page=path))
                    else:
                        self._vprint(f"  {C.DIM}[API] {method} {path} => {resp.status_code}{C.RST}")
                context.all_forms = forms_found
                print(f"\n  {C.G}[API Discovery][OK]{C.RST} live_apis={len(api_endpoints_found)} synthetic_forms={len(forms_found)}")

                # ── Prune dead routes ──────────────────────────────────────
                # Only keep source-discovered routes that actually responded
                # (non-404). Routes that 404 on baseline do not exist and must
                # never be handed to the attack agents — that is the 404-storm.
                _live_paths = {p.split("?")[0] for (_m, p, _c, _t, _b) in api_endpoints_found}
                _pre_prune = len(source_routes)
                source_routes = [r for r in source_routes if r["path"] in _live_paths]
                if _pre_prune != len(source_routes):
                    print(f"  {C.DIM}[API Discovery] pruned {_pre_prune - len(source_routes)} dead (404) route(s){C.RST}")

                # ══════════════════════════════════════════════════════════
                # Build smart probe lists from discovered routes for agents
                # ══════════════════════════════════════════════════════════
                _live_get_with_params = []   # GET endpoints with query params
                _live_post = []              # POST endpoints with bodies
                _live_id_routes = []         # Routes with :id params
                _live_file_routes = []       # Routes with file/path params
                _live_url_routes = []        # Routes with url/callback params
                _live_debug_routes = []      # Debug/admin/info routes

                for r in source_routes:
                    path = r["path"]
                    params = [p.lower() for p in r.get("params", [])]
                    method = r["method"]

                    # Categorize by param type
                    if any(p in params for p in ("file", "path", "filename", "name", "doc", "filepath")):
                        _live_file_routes.append(r)
                    if any(p in params for p in ("url", "callback", "callbackurl", "webhook", "target", "redirect")):
                        _live_url_routes.append(r)
                    if ":id" in path or "/:" in path:
                        _live_id_routes.append(r)
                    if any(k in path.lower() for k in ("debug", "admin", "info", "env", "config", "status")):
                        _live_debug_routes.append(r)

                # Build from BOTH source routes AND live API discovery
                # Source routes give us params even for endpoints that returned 500
                for r in source_routes:
                    if r["method"] == "GET" and r.get("params"):
                        # Build URL with params from source code
                        param_str = "&".join(f"{p}=test" for p in r["params"])
                        _live_get_with_params.append((f"{r['path']}?{param_str}", ""))
                    elif r["method"] == "POST":
                        body = {p: "test" for p in r.get("params", [])}
                        if not body:
                            body = {"test": "value"}
                        _live_post.append((r["path"], body))

                # Also add from live API discovery results (may have extra context)
                for m, path, code, text, body in api_endpoints_found:
                    if m == "GET" and "?" in path:
                        _live_get_with_params.append((path, text))
                    elif m == "POST" and body:
                        _live_post.append((path, body))
                # Deduplicate by base path
                seen_bases = set()
                deduped_get = []
                for item in _live_get_with_params:
                    base = item[0].split("?")[0]
                    if base not in seen_bases:
                        seen_bases.add(base)
                        deduped_get.append(item)
                _live_get_with_params = deduped_get

            if use_deepagents:
                from backend.deepagents import (
                    DeepSQLiAgent, DeepXSSAgent, DeepCMDiAgent, DeepAuthAgent,
                    DeepIDORAgent, DeepSSRFAgent, DeepSSTIAgent,
                    DeepPathTraversalAgent, DeepXXEAgent, DeepBusinessLogicAgent,
                    DeepPromptInjectionAgent, DeepRaceConditionAgent,
                    DeepMassAssignmentAgent,
                )
                agents_to_run = [
                    DeepSQLiAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepXSSAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepCMDiAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepAuthAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepIDORAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepSSRFAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepSSTIAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepPathTraversalAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepXXEAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepBusinessLogicAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    # ── Merged from update_y1: LLM prompt injection (OWASP LLM01),
                    #    TOCTOU race conditions, and mass assignment (CWE-915) ──
                    DeepPromptInjectionAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepRaceConditionAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                    DeepMassAssignmentAgent(self.scan_id, target_url, attack_graph, asi, oracle),
                ]

                total = len(agents_to_run)
                # Confirmed live: a `cx deep` run against a trivial dummy app
                # hard-hung past 10 minutes inside a single agent's
                # oracle-guided decide() loop (each local-LLM call can itself
                # take up to ~90s, and the loop is internally bounded but
                # still large — MAX_HYPOTHESES × MAX_ATTEMPTS_PER_HYPOTHESIS).
                # Nothing here ever timed out or capped the phase, unlike the
                # cognee persist step, which uses this exact
                # wait_for-then-skip pattern. Bound both the phase and each
                # individual agent so a slow/looping agent degrades the scan
                # to partial results instead of hanging it indefinitely.
                phase_deadline = time.time() + cyphex_config.DEEPAGENT_PHASE_BUDGET_S
                for idx, agent in enumerate(agents_to_run, 1):
                    if time.time() >= phase_deadline:
                        skipped = total - idx + 1
                        print(
                            f"  {C.Y}[WARN]{C.RST} DeepAgents phase budget "
                            f"({cyphex_config.DEEPAGENT_PHASE_BUDGET_S:.0f}s) exhausted after "
                            f"{idx - 1}/{total} agents — skipping remaining {skipped} to keep "
                            f"the scan bounded (tune via DEEPAGENT_PHASE_BUDGET_S)."
                        )
                        break
                    agent_header(
                        f"DeepAgent {idx}/{total}",
                        f"{agent.__class__.__name__} — {agent.PRIMARY_VULN_CLASS}",
                        "Oracle-Guided Hypothesis Testing",
                    )
                    try:
                        res = await asyncio.wait_for(
                            agent.run(context),
                            timeout=cyphex_config.DEEPAGENT_PER_AGENT_TIMEOUT_S,
                        )
                        self._emit("deepagent_result", agent=agent.__class__.__name__, vulns_found=len(res.vulns))
                        context.confirmed_vulns.extend(res.vulns)
                        if res.vulns:
                            print(
                                f"  {C.NEON}✓{C.RST} {C.BOLD}{agent.__class__.__name__}{C.RST} "
                                f"confirmed {C.R}{len(res.vulns)} vuln(s){C.RST}"
                            )
                        # Display any new attack chains
                        if attack_graph.edges:
                            print(f"  {C.CYAN}▸ Attack chains: {len(attack_graph.edges)} discovered{C.RST}")
                    except (asyncio.TimeoutError, TimeoutError):
                        self._emit("deepagent_timeout", agent=agent.__class__.__name__)
                        print(
                            f"  {C.Y}[WARN]{C.RST} {agent.__class__.__name__} timed out after "
                            f"{cyphex_config.DEEPAGENT_PER_AGENT_TIMEOUT_S:.0f}s (oracle-guided "
                            f"loop too slow on this hardware) — skipping to the next agent."
                        )
                        continue
                    except Exception as e:
                        self._emit("deepagent_error", agent=agent.__class__.__name__, error=str(e)[:200])
                        print(f"  {C.Y}[WARN]{C.RST} {agent.__class__.__name__} failed: {str(e)[:100]}")
                        continue

                # Keep the graph on the context so later steps (Security
                # Report) can reference it without threading a new param
                # through the whole scan() call chain.
                context.attack_graph = attack_graph
                if SOC_UI:
                    ui.render_attack_graph(attack_graph)
                elif attack_graph.edges:
                    print(f"\n  {C.BOLD}{C.CYAN}◈ ATTACK GRAPH{C.RST} — {len(attack_graph.edges)} chain(s) across {len(attack_graph.nodes)} node(s)")
                    for i, e in enumerate(attack_graph.edges, 1):
                        print(f"  {i:>2}. [{e.priority}] {e.source}  ──{e.action}──▶  {e.target}")

                return context


            from backend.config.dast_constants import XSS_PAYLOADS
            # Agent 04 - XSS
            agent_header("Agent 04", "XSS", "Probe reflected XSS payload execution paths")
            seen_xss = set()
            for form in forms_found:
                form_key = form.action
                if form_key in seen_xss or not form.inputs:
                    continue
                for payload in XSS_PAYLOADS:
                    if form.method == "GET":
                        q = "&".join([f"{inp}={payload}" for inp in form.inputs])
                        show_cmd("XSS", f'curl -s "{form.action}?{q}"')
                        resp = await client.get(form.action, params={inp: payload for inp in form.inputs})
                    else:
                        show_cmd("XSS", f'curl -s -X POST "{form.action}" -d "{form.inputs[0]}={payload}"')
                        resp = await client.post(form.action, data={inp: payload for inp in form.inputs})

                    reflected = payload in resp.text
                    self._vprint(f"  {C.Y}[Agent 04 \u25b6 Reasoning]{C.RST} Injecting XSS payload into form fields at {form.action}")
                    self._vprint(f"  {C.DIM}  Payload:  {payload[:60]}{C.RST}")
                    self._vprint(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    if reflected:
                        self._vprint(f"  {C.R}  Decision: Payload reflected in response body \u2192 XSS CONFIRMED \u2713{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] Reflected XSS",
                            severity="High",
                            endpoint=f"{form.action} ({form.inputs})",
                            payload=payload,
                            confirmed=True,
                        ))
                        seen_xss.add(form_key)
                        break
                    else:
                        self._vprint(f"  {C.G}  Decision: Payload not reflected \u2192 endpoint appears clean{C.RST}")

            from backend.config.dast_constants import SQLI_PAYLOADS, SQL_ERROR_SIGS
            # Agent 03 - SQLi
            agent_header("Agent 03", "Injection (SQLi)", "Probe SQL injection indicators")
            seen_sqli = set()
            for form in forms_found:
                if not form.inputs or form.action in seen_sqli:
                    continue
                for payload in SQLI_PAYLOADS:
                    if form.method == "GET":
                        q = "&".join([f"{inp}={payload}" for inp in form.inputs])
                        show_cmd("SQLi", f'curl -s "{form.action}?{q}"')
                        resp = await client.get(form.action, params={inp: payload for inp in form.inputs})
                    else:
                        show_cmd("SQLi", f'curl -s -X POST "{form.action}" -d "{form.inputs[0]}={payload}"')
                        resp = await client.post(form.action, data={inp: payload for inp in form.inputs})

                    lower = resp.text.lower()
                    # A 401/403 means the request was blocked (WAF/RASP) before it could
                    # reach app/DB logic \u2014 that's a defended endpoint, not exploitation
                    # evidence, so don't run the error-signature check on blocked responses.
                    blocked = resp.status_code in (401, 403)
                    matched = [] if blocked else [e for e in SQL_ERROR_SIGS if re.search(e, lower, re.IGNORECASE)]
                    indicator = bool(matched)
                    self._vprint(f"  {C.Y}[Agent 03 \u25b6 Reasoning]{C.RST} Injecting SQL tautology into {form.inputs} at {form.action}")
                    self._vprint(f"  {C.DIM}  Payload:  {payload}{C.RST}")
                    self._vprint(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    if indicator:
                        self._vprint(f"  {C.R}  Decision: SQL error signature matched ({', '.join(matched[:3])}) \u2192 SQLi CONFIRMED \u2713{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] SQL Injection",
                            severity="Critical",
                            endpoint=f"{form.action} ({form.inputs})",
                            payload=payload,
                            confirmed=True,
                        ))
                        seen_sqli.add(form.action)
                        break
                    elif blocked:
                        self._vprint(f"  {C.G}  Decision: Request blocked (HTTP {resp.status_code}, WAF/RASP) \u2192 endpoint appears clean{C.RST}")
                    else:
                        self._vprint(f"  {C.G}  Decision: No SQL error indicators \u2192 endpoint appears clean{C.RST}")

            from backend.config.dast_constants import DEFAULT_CREDS
            # Agent 05 - Auth
            agent_header("Agent 05", "Auth", "Try weak/default credential flows")
            login_forms = [f for f in forms_found if any("pass" in i.lower() for i in f.inputs)]
            for form in login_forms[:2]:
                user_field = next((i for i in form.inputs if i.lower() in ("username", "user", "email")), form.inputs[0])
                pass_field = next((i for i in form.inputs if "pass" in i.lower()), form.inputs[-1])
                for u, p in DEFAULT_CREDS:
                    show_cmd("Auth", f'curl -s -X POST "{form.action}" -d "{user_field}={u}&{pass_field}={p}"')
                    resp = await client.post(form.action, data={user_field: u, pass_field: p})
                    lower = resp.text.lower()
                    success = any(k in lower for k in ("token", "welcome", "dashboard", "success"))
                    self._vprint(f"  {C.Y}[Agent 05 \u25b6 Reasoning]{C.RST} Trying default credentials {u}:{p} on {form.action}")
                    self._vprint(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    if success:
                        matched = [k for k in ("token", "welcome", "dashboard", "success") if k in lower]
                        self._vprint(f"  {C.R}  Decision: Auth success indicator found ('{matched[0]}') \u2192 DEFAULT CREDS CONFIRMED \u2713{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] Default Credentials",
                            severity="Critical",
                            endpoint=form.action,
                            payload=f"{u}:{p}",
                            confirmed=True,
                        ))
                        break
                    else:
                        self._vprint(f"  {C.G}  Decision: No success indicator \u2192 credentials rejected{C.RST}")

            from backend.config.dast_constants import LFI_TARGETS, LFI_PAYLOADS, FILE_PARAM_KEYWORDS
            # Agent 07 - LFI
            agent_header("Agent 07", "LFI", "Try file traversal payloads")
            lfi_targets = LFI_TARGETS.copy()
            # Inject source-discovered routes with file/path params
            for r in _live_file_routes:
                for p in r.get("params", []):
                    if p.lower() in FILE_PARAM_KEYWORDS:
                        for pl in LFI_PAYLOADS:
                            lfi_targets.append(f"{r['path']}?{p}={pl}")
            for suffix in lfi_targets:
                full = f"{target_url}{suffix}"
                show_cmd("LFI", f'curl -s "{full}"')
                try:
                    resp = await client.get(full)
                except Exception:
                    continue
                hit = "root:x:0:0" in resp.text
                self._vprint(f"  {C.Y}[Agent 07 \u25b6 Reasoning]{C.RST} Testing path traversal: {suffix}")
                self._vprint(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                if hit:
                    self._vprint(f"  {C.R}  Decision: /etc/passwd content found \u2192 LFI CONFIRMED \u2713{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] Local File Inclusion",
                        severity="Critical",
                        endpoint=full,
                        payload="../../../etc/passwd",
                        confirmed=True,
                    ))
                else:
                    self._vprint(f"  {C.G}  Decision: No file content leaked \u2192 endpoint clean{C.RST}")

            from backend.config.dast_constants import CMDI_TARGETS, CMDI_INJECT_PAYLOADS
            # Agent 06 - CMDi
            agent_header("Agent 06", "CMDi", "Probe command execution sinks")
            cmdi_targets = CMDI_TARGETS.copy()
            # Inject discovered GET endpoints — try CMDi payloads in each param
            for path, _text in _live_get_with_params:
                base = path.split("?")[0]
                qs = path.split("?", 1)[1] if "?" in path else ""
                for param_pair in qs.split("&"):
                    key = param_pair.split("=")[0]
                    if key:
                        for payload in CMDI_INJECT_PAYLOADS[:2]:  # Limit to 2 payloads per param
                            cmdi_targets.append(f"{base}?{key}={payload}")
            for suffix in cmdi_targets:
                full = f"{target_url}{suffix}"
                show_cmd("CMDi", f'curl -s "{full}"')
                try:
                    resp = await client.get(full)
                except Exception:
                    continue
                hit = any(k in resp.text.lower() for k in ("uid=", "gid=", "root", "www-data", "nt authority"))
                self._vprint(f"  {C.Y}[Agent 06 \u25b6 Reasoning]{C.RST} Testing command injection via GET: {suffix}")
                self._vprint(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                if hit:
                    self._vprint(f"  {C.R}  Decision: OS command output detected \u2192 CMDi CONFIRMED \u2713{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] Command Injection",
                        severity="Critical",
                        endpoint=full,
                        payload=suffix,
                        confirmed=True,
                    ))
                else:
                    self._vprint(f"  {C.G}  Decision: No OS output \u2192 endpoint clean{C.RST}")

            # Agent 08 - Logic/CORS
            agent_header("Agent 08", "Logic", "Check insecure CORS and basic authz gaps")
            show_cmd("Logic", f'curl -sI -H "Origin: https://evil.example" "{target_url}"')
            try:
                head = await client.get(target_url, headers={"Origin": "https://evil.example"})
                acao = head.headers.get("Access-Control-Allow-Origin", "")
                self._vprint(f"  {C.Y}[Agent 08 \u25b6 Reasoning]{C.RST} Sending spoofed Origin header to test CORS policy")
                self._vprint(f"  {C.DIM}  Access-Control-Allow-Origin: {acao or 'not-set'}{C.RST}")
                if acao in ("*", "https://evil.example"):
                    self._vprint(f"  {C.R}  Decision: Server reflects/wildcards origin \u2192 CORS MISCONFIGURATION CONFIRMED \u2713{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] CORS Misconfiguration",
                        severity="High",
                        endpoint=target_url,
                        payload=f"ACAO={acao}",
                        confirmed=True,
                    ))
                else:
                    self._vprint(f"  {C.G}  Decision: CORS policy properly restrictive{C.RST}")
            except Exception:
                pass

            # Agent 11 - Supply chain quick check
            agent_header("Agent 11", "Supply Chain", "Check exposed dependency manifests")
            for manifest in ("/package.json", "/requirements.txt"):
                full = f"{target_url}{manifest}"
                show_cmd("SupplyChain", f'curl -s -o /dev/null -w "%{{http_code}}" "{full}"')
                try:
                    resp = await client.get(full)
                except Exception:
                    continue
                if resp.status_code == 200 and len(resp.text) > 20:
                    context.confirmed_vulns.append(Vuln(
                        name=f"[DYNAMIC] Exposed Manifest {manifest}",
                        severity="High",
                        endpoint=full,
                        confirmed=True,
                    ))
                    self._vprint(f"  {C.R}[SupplyChain][CONFIRMED]{C.RST} exposed {manifest}")
                else:
                    self._vprint(f"  [SupplyChain] {manifest} status={resp.status_code}")

            from backend.config.dast_constants import IDOR_PATHS
            # ── Agent 09 — IDOR Prober ─────────────────────────────────
            agent_header("Agent 09", "IDOR", "Probe insecure direct object references by enumerating sequential IDs")
            idor_paths = IDOR_PATHS.copy()
            # Inject source-discovered routes with :id params
            idor_seen = set(idor_paths)
            for r in _live_id_routes:
                # Convert /users/:id → /users/
                base = r["path"].split(":")[0]
                if base and base not in idor_seen:
                    idor_paths.append(base)
                    idor_seen.add(base)
            for base_path in idor_paths:
                responses = []
                for test_id in [1, 2, 3]:
                    full = f"{target_url}{base_path}{test_id}"
                    show_cmd("IDOR", f'curl -s "{full}"')
                    try:
                        resp = await client.get(full)
                        responses.append((test_id, resp.status_code, len(resp.text)))
                        self._vprint(f"  {C.DIM}[IDOR] GET {base_path}{test_id} => HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    except Exception:
                        continue
                ok_responses = [r for r in responses if r[1] == 200 and r[2] > 20]
                if len(ok_responses) >= 2:
                    self._vprint(f"  {C.Y}[Agent 09 > Reasoning]{C.RST} Multiple sequential IDs return data without authentication.")
                    self._vprint(f"  {C.Y}  Decision:{C.RST} {len(ok_responses)} IDs accessible => {C.R}IDOR CONFIRMED{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] IDOR — Sequential ID Enumeration",
                        severity="High",
                        endpoint=f"{target_url}{base_path}*",
                        payload=f"Accessed IDs: {[r[0] for r in ok_responses]}",
                        confirmed=True,
                    ))
                elif ok_responses:
                    self._vprint(f"  {C.DIM}[IDOR] Only 1 ID responded — not enough for confirmed IDOR{C.RST}")

            from backend.config.dast_constants import SSRF_ENDPOINTS, SSRF_GET_ENDPOINTS, URL_PARAM_KEYWORDS, SSRF_INTERNAL_PAYLOADS
            # ── Agent 10 — SSRF Prober ─────────────────────────────────
            agent_header("Agent 10", "SSRF", "Probe server-side request forgery via URL parameters")
            ssrf_endpoints = SSRF_ENDPOINTS.copy()
            ssrf_get_endpoints = SSRF_GET_ENDPOINTS.copy()
            # Inject source-discovered routes with url/callback params
            for r in _live_url_routes:
                for p in r.get("params", []):
                    if p.lower() in URL_PARAM_KEYWORDS:
                        if r["method"] == "POST":
                            for pl in SSRF_INTERNAL_PAYLOADS:
                                ssrf_endpoints.append((r["path"], {p: pl}))
                        else:
                            for pl in SSRF_INTERNAL_PAYLOADS:
                                ssrf_get_endpoints.append(f"{r['path']}?{p}={pl}")
            for path, body in ssrf_endpoints:
                full = f"{target_url}{path}"
                show_cmd("SSRF", f'curl -s -X POST "{full}" -d \'url={body["url"]}\'')
                try:
                    resp = await client.post(full, json=body)
                    has_internal = any(k in resp.text.lower() for k in ("127.0.0.1", "localhost", "ami-id", "instance-id", "<html", "<!doctype"))
                    self._vprint(f"  {C.DIM}[SSRF] POST {path} => HTTP {resp.status_code} internal_data={'yes' if has_internal else 'no'}{C.RST}")
                    if resp.status_code == 200 and has_internal:
                        self._vprint(f"  {C.Y}[Agent 10 > Reasoning]{C.RST} Server fetched internal URL and returned content.")
                        self._vprint(f"  {C.R}  Decision: SSRF CONFIRMED — server made request to {body['url']}{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] SSRF — Server-Side Request Forgery",
                            severity="Critical",
                            endpoint=full,
                            payload=body["url"],
                            confirmed=True,
                        ))
                except Exception:
                    continue
            for suffix in ssrf_get_endpoints:
                full = f"{target_url}{suffix}"
                show_cmd("SSRF", f'curl -s "{full}"')
                try:
                    resp = await client.get(full)
                    has_internal = any(k in resp.text.lower() for k in ("127.0.0.1", "localhost", "ami-id", "<html", "<!doctype"))
                    if resp.status_code == 200 and has_internal:
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] SSRF — Server-Side Request Forgery",
                            severity="Critical",
                            endpoint=full,
                            payload=suffix.split("url=")[-1],
                            confirmed=True,
                        ))
                        self._vprint(f"  {C.R}[SSRF][CONFIRMED]{C.RST} internal content returned")
                    else:
                        self._vprint(f"  {C.DIM}[SSRF] GET {suffix} => {resp.status_code}{C.RST}")
                except Exception:
                    continue

            from backend.config.dast_constants import SDE_PATHS, SDE_INDICATORS
            # ── Agent 12 — Sensitive Data Exposure ─────────────────────
            agent_header("Agent 12", "Data Exposure", "Probe debug and config endpoints for sensitive data leaks")
            sde_paths = SDE_PATHS.copy()
            # Inject source-discovered debug/admin/info routes
            sde_seen = set(sde_paths)
            for r in _live_debug_routes:
                if r["method"] == "GET" and r["path"] not in sde_seen:
                    sde_paths.append(r["path"])
                    sde_seen.add(r["path"])
            sde_indicators = SDE_INDICATORS
            for path in sde_paths:
                full = f"{target_url}{path}"
                show_cmd("SDE", f'curl -s "{full}"')
                try:
                    resp = await client.get(full)
                    if resp.status_code == 200 and len(resp.text) > 20:
                        hits = [ind for ind in sde_indicators if ind.lower() in resp.text.lower()]
                        if hits:
                            self._vprint(f"  {C.Y}[Agent 12 > Reasoning]{C.RST} Endpoint {path} returns sensitive configuration data.")
                            self._vprint(f"  {C.Y}  Detected keys:{C.RST} {', '.join(hits[:5])}")
                            self._vprint(f"  {C.R}  Decision: DATA EXPOSURE CONFIRMED{C.RST}")
                            context.confirmed_vulns.append(Vuln(
                                name="[DYNAMIC] Sensitive Data Exposure",
                                severity="Critical",
                                endpoint=full,
                                payload=f"Exposed keys: {', '.join(hits[:5])}",
                                confirmed=True,
                            ))
                        else:
                            self._vprint(f"  {C.DIM}[SDE] {path} => HTTP 200 but no sensitive keys found{C.RST}")
                    else:
                        self._vprint(f"  {C.DIM}[SDE] {path} => HTTP {resp.status_code}{C.RST}")
                except Exception:
                    continue

            from backend.config.dast_constants import CMDI_API_TESTS
            # ── Agent 13 — Command Injection (API) ────────────────────
            agent_header("Agent 13", "CMDi (API)", "Probe command injection via API ping/exec endpoints")
            cmdi_api_tests = CMDI_API_TESTS
            # Inject discovered POST endpoints with CMDi payloads
            for path, body in _live_post:
                if body and isinstance(body, dict):
                    for key in list(body.keys())[:3]:  # Test first 3 params
                        cmdi_api_tests.append(("POST", path, {**body, key: "127.0.0.1; id"}))
                        cmdi_api_tests.append(("POST", path, {**body, key: "test && whoami"}))
            cmdi_indicators = ["uid=", "gid=", "root:", "www-data", "nt authority", "groups="]
            for method, path, body in cmdi_api_tests:
                full = f"{target_url}{path}"
                show_cmd("CMDi", f'curl -s -X POST "{full}" -d \'host={body.get("host", body.get("cmd", ""))}\'')
                try:
                    resp = await client.post(full, json=body)
                    hit = any(ind in resp.text.lower() for ind in cmdi_indicators)
                    if hit:
                        self._vprint(f"  {C.Y}[Agent 13 > Reasoning]{C.RST} OS command output detected in response.")
                        self._vprint(f"  {C.R}  Decision: COMMAND INJECTION CONFIRMED{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] Command Injection (API)",
                            severity="Critical",
                            endpoint=full,
                            payload=str(body),
                            confirmed=True,
                        ))
                        break
                    else:
                        self._vprint(f"  {C.DIM}[CMDi] POST {path} => {resp.status_code} (no OS output){C.RST}")
                except Exception:
                    continue

            # ── Agent 14 — JWT Inspector ──────────────────────────────
            agent_header("Agent 14", "JWT Inspector", "Analyze JWT tokens for weak secrets and algorithm flaws")
            jwt_tokens_found = []
            # Collect any tokens from login attempts made by Auth agent or API discovery
            for form in forms_found:
                if not any("pass" in i.lower() for i in form.inputs):
                    continue
                user_field = next((i for i in form.inputs if i.lower() in ("username", "user", "email")), form.inputs[0])
                pass_field = next((i for i in form.inputs if "pass" in i.lower()), form.inputs[-1])
                for u, p in [("admin", "admin"), ("admin", "admin123"), ("test", "test")]:
                    try:
                        show_cmd("JWT", f'curl -s -X POST "{form.action}" -d "{user_field}={u}&{pass_field}={p}"')
                        resp = await client.post(form.action, json={user_field: u, pass_field: p})
                        body_text = resp.text
                        # Look for JWT patterns (xxx.xxx.xxx)
                        jwt_pattern = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body_text)
                        if jwt_pattern:
                            jwt_tokens_found.extend(jwt_pattern[:2])
                            self._vprint(f"  {C.G}[JWT]{C.RST} Token found in response from {form.action} (creds: {u}:{p})")
                            break
                    except Exception:
                        continue
                if jwt_tokens_found:
                    break

            if jwt_tokens_found:
                import base64
                for token in jwt_tokens_found[:1]:
                    parts = token.split(".")
                    if len(parts) >= 2:
                        # Decode header
                        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        try:
                            header = json.loads(base64.urlsafe_b64decode(header_b64))
                            payload_data = json.loads(base64.urlsafe_b64decode(payload_b64))
                            self._vprint(f"  {C.Y}[Agent 14 \u25b6 Reasoning]{C.RST} Decoded JWT token without verification")
                            self._vprint(f"  {C.DIM}  Header:  {json.dumps(header)}{C.RST}")
                            self._vprint(f"  {C.DIM}  Payload: {json.dumps(payload_data)[:120]}{C.RST}")

                            # Check for dangerous algorithm
                            alg = header.get("alg", "")
                            if alg.lower() == "none":
                                self._vprint(f"  {C.R}  Decision: Algorithm 'none' \u2192 JWT BYPASS CONFIRMED \u2713{C.RST}")
                                context.confirmed_vulns.append(Vuln(
                                    name="[DYNAMIC] JWT Algorithm None Bypass",
                                    severity="Critical",
                                    endpoint=form.action if forms_found else target_url,
                                    payload=f"alg=none",
                                    confirmed=True,
                                ))
                            elif "role" in payload_data or "admin" in str(payload_data).lower():
                                self._vprint(f"  {C.Y}  Decision: Role/admin claim in JWT payload \u2192 potential privilege escalation{C.RST}")
                                context.confirmed_vulns.append(Vuln(
                                    name="[DYNAMIC] JWT Role Escalation Risk",
                                    severity="High",
                                    endpoint=form.action if forms_found else target_url,
                                    payload=f"Claims: {list(payload_data.keys())[:5]}",
                                    confirmed=True,
                                ))
                            else:
                                self._vprint(f"  {C.G}  Decision: JWT structure appears standard ({alg}){C.RST}")
                        except Exception:
                            self._vprint(f"  {C.DIM}[JWT] Could not decode token{C.RST}")
            else:
                self._vprint(f"  {C.DIM}[JWT] No JWT tokens found in any endpoint responses{C.RST}")

            # Agent 01 - Recon summary
            agent_header("Agent 01", "Recon", "Fingerprint headers and tech hints")
            context.technologies = []
            server = context.headers.get("server") or context.headers.get("Server")
            if server:
                context.technologies.append(f"Server:{server}")
                print(f"  [Recon] Server: {server}")
            powered = context.headers.get("x-powered-by") or context.headers.get("X-Powered-By")
            if powered:
                context.technologies.append(f"X-Powered-By:{powered}")
                print(f"  [Recon] X-Powered-By: {powered}")

            if COUNCIL_AVAILABLE and context.confirmed_vulns:
                try:
                    agent_header("Council", "Multi-Model Debate", "Validating dynamic findings against false positives")
                    debater = DebateProtocol()
                    original_count = len(context.confirmed_vulns)
                    validated_vulns = await debater.debate_batch(context.confirmed_vulns)

                    discarded = original_count - len(validated_vulns)
                    context.confirmed_vulns = validated_vulns
                    print(f"\n  {C.G}[COUNCIL][OK]{C.RST} Validated {len(validated_vulns)} findings. {C.Y}Discarded {discarded} false positives.{C.RST}")
                except Exception as e:
                    print(f"\n  {C.Y}[COUNCIL][SKIP]{C.RST} Ollama not available — keeping all {len(context.confirmed_vulns)} findings unvalidated")
                    print(f"  {C.DIM}Start Ollama for AI false-positive filtering: ollama serve{C.RST}")

            # ── Nuclei / ZAP DAST Integration ──
            try:
                from cyphex.dynamic_scanner import run_dynamic_analysis, nuclei_available, zap_available
                if nuclei_available() or zap_available():
                    tool_name = "Nuclei" if nuclei_available() else "OWASP ZAP"
                    agent_header("DAST", tool_name, f"Running {tool_name} scan for additional coverage")
                    dast_findings, tool_used = await run_dynamic_analysis(target_url)
                    if dast_findings:
                        # Convert DAST findings to Vuln objects and merge
                        for df in dast_findings:
                            # Avoid duplicates
                            dupe = any(
                                v.name == df.name and v.endpoint == df.url
                                for v in context.confirmed_vulns
                            )
                            if not dupe:
                                context.confirmed_vulns.append(Vuln(
                                    name=df.name,
                                    severity=df.severity,
                                    endpoint=df.url,
                                    evidence=df.evidence or df.curl_command,
                                    cwe=df.cwe,
                                    description=df.description,
                                ))
                        print(f"  {C.G}[OK]{C.RST} {tool_used}: {len(dast_findings)} findings ({len([f for f in dast_findings if f.severity in ('Critical','High')])} critical/high)")
                    else:
                        print(f"  {C.G}[OK]{C.RST} {tool_used}: No additional findings")
            except ImportError:
                pass  # cyphex package not installed — skip DAST tools

            print(f"\n  {C.G}[SCAN][OK]{C.RST} endpoints={len(context.all_endpoints)} forms={len(forms_found)} vulns={len(context.confirmed_vulns)}")

        return context

    async def _run_network_scan(self) -> None:
        """
        Network Security step (Step 3b/9) — runs when --network flag is set.
        Discovers local subnet, port-scans all live hosts, maps open ports to
        known vulnerabilities, and stores findings in self._network_vulns so
        they get merged into confirmed_vulns after the DAST step.
        """
        self._network_vulns: list = []

        try:
            import sys as _sys
            from backend.network.discovery import NetworkDiscovery
            from backend.network.vuln_mapper import NetworkVulnMapper
            from backend.network.network_genome import NetworkBehavioralGenome
        except ImportError as e:
            print(f"  {C.Y}[SKIP]{C.RST} Network scan unavailable: {e}")
            print(f"  {C.DIM}Run: pip install networkx scikit-learn joblib{C.RST}")
            return

        try:
            # ── Discovery ──────────────────────────────────────────────────────
            disc = NetworkDiscovery(timeout=0.6, max_concurrent=192)
            net_map = await disc.discover("auto")
            live = net_map.live_hosts()

            if not live:
                print(f"  {C.Y}[WARN]{C.RST} No live hosts found on local subnet")
                return

            print(f"  {C.G}[OK]{C.RST}  {len(live)} live hosts discovered")

            # ── Vuln mapping ────────────────────────────────────────────────────
            mapper = NetworkVulnMapper()
            net_vulns = await mapper.map(net_map, active_checks=True)

            # ── Train genome baselines (synthetic) ─────────────────────────────
            genome = NetworkBehavioralGenome()
            for host in live:
                genome.train(host.ip, windows=[])
            genome.save()

            # ── Print summary table ─────────────────────────────────────────────
            _SEV_COL = {
                "Critical": C.R, "High": "\033[91m", "Medium": C.Y,
                "Low": C.B, "Info": C.DIM,
            }
            print(f"\n  {'HOST':<18} {'HOSTNAME':<20} {'RISK':<8} PORTS")
            print("  " + "─" * 68)
            for host in net_map.hosts_by_risk():
                if not host.is_up:
                    continue
                ports_str = " ".join(str(p.port) for p in host.open_ports[:7])
                if len(host.open_ports) > 7:
                    ports_str += f" +{len(host.open_ports) - 7}"
                risk_pct = int(host.risk_score * 100)
                risk_col = C.R if risk_pct >= 75 else C.Y if risk_pct >= 40 else C.G
                print(
                    f"  {host.ip:<18} {host.hostname[:19]:<20}"
                    f" {risk_col}{risk_pct}%{C.RST}     {C.DIM}{ports_str}{C.RST}"
                )

            if net_vulns:
                print(f"\n  ◈ Network findings: {len(net_vulns)}")
                crit = sum(1 for v in net_vulns if v.severity == "Critical")
                high = sum(1 for v in net_vulns if v.severity == "High")
                confirmed = sum(1 for v in net_vulns if v.confirmed)
                if crit:
                    print(f"    {C.R}● {crit} Critical{C.RST}", end="")
                if high:
                    print(f"  {C.Y}● {high} High{C.RST}", end="")
                if confirmed:
                    print(f"  {C.G}● {confirmed} confirmed via active probe{C.RST}", end="")
                print()
                for nv in net_vulns[:8]:
                    col = _SEV_COL.get(nv.severity, C.W)
                    confirm_mark = " ✓" if nv.confirmed else ""
                    print(
                        f"  {col}[{nv.severity[:4]}]{C.RST}"
                        f"  {nv.host}:{nv.port}  {nv.service}"
                        f"  {C.DIM}{nv.title[:50]}{C.RST}{confirm_mark}"
                    )
                if len(net_vulns) > 8:
                    print(f"  {C.DIM}  … and {len(net_vulns) - 8} more (see full report){C.RST}")

            # ── Convert NetworkVuln → Vuln objects for the main pipeline ────────
            for nv in net_vulns:
                self._network_vulns.append(Vuln(
                    name=f"[NETWORK] {nv.title}",
                    severity=nv.severity,
                    endpoint=f"{nv.host}:{nv.port}",
                    confirmed=nv.confirmed,
                    cwe="CWE-200" if nv.severity in ("Critical", "High") else "CWE-1035",
                    evidence=nv.evidence or f"{nv.service} on port {nv.port}",
                    fix=nv.remediation,
                    description="; ".join(nv.issues[:3]),
                ))


            print(f"\n  {C.G}[OK]{C.RST} Network genome baselines saved → cyphex netwatch to monitor\n")

        except Exception as e:
            print(f"  {C.Y}[WARN]{C.RST} Network scan error: {str(e)[:120]}")
            print(f"  {C.DIM}Continuing with application scan...{C.RST}")

    async def _build_and_evolve(self, context, generations):
        genome = BehavioralGenome()

        # ── Try loading existing genome for this target ──
        target_hash = hashlib.md5(context.target_url.encode()).hexdigest()[:12]
        genome_path = os.path.join(cyphex_config.GENOME_STORAGE_DIR, f"genome_{target_hash}")
        if os.path.exists(genome_path + ".pkl"):
            try:
                genome = BehavioralGenome.load(genome_path)
                print(f"  {C.G}[OK]{C.RST} Loaded existing genome for this target (continuing evolution)")
            except Exception:
                genome = BehavioralGenome()

        # Only build when the genome has no profiles yet. A freshly loaded genome
        # already carries its profiles/models/attack-history, so re-building here
        # (and again inside run_evolution) would retrain on normal-only samples and
        # wipe the adversarial adaptation we just restored.
        if not genome.endpoint_profiles:
            genome.build_from_scan(context)
        print(f"  {C.G}[OK]{C.RST} Genome built: {len(genome.endpoint_profiles)} endpoints")

        controller = EvolutionController()
        controller.genome = genome  # Use loaded/built genome
        results = await controller.run_evolution(context, generations=generations, payloads_per_gen=30)

        # ── Save genome for next scan ──
        try:
            controller.genome.save(genome_path)
            print(f"  {C.G}[OK]{C.RST} Genome saved to {genome_path}")
        except Exception as e:
            print(f"  {C.Y}[WARN]{C.RST} Could not save genome: {e}")

        # ── Endpoint Map Box ──
        if context.all_endpoints:
            url_lines = []
            for ep in context.all_endpoints[:30]:
                url_lines.append(f"    >> {ep}")
            console.print(Panel("\n".join(url_lines), title="ENDPOINT MAP", border_style="bright_blue", padding=(1, 2)))

        # ── Genome Box ──
        if results:
            gen_lines = (
                f"    Generation:     {generations}\n"
                f"    Trained:        YES\n"
                f"    Profiles:       {len(genome.endpoint_profiles)}\n"
                f"    Block History:  {len(results)} gens\n\n"
                f"    [bold]Feature Vector (15 dims):[/bold]\n"
                f"      [0] input_length      [1] entropy         [2] special_char_ratio\n"
                f"      [3] url_encoding_ratio [4] uppercase_ratio [5] digit_ratio\n"
                f"      [6] max_token_length   [7] keyword_score   [8] sqli_pattern_score\n"
                f"      [9] null_byte         [10] traversal_depth [11] bracket_imbalance\n"
                f"     [12] unicode_ratio     [13] repetition_ratio[14] token_count\n"
            )
            console.print(Panel(gen_lines, title="BEHAVIORAL GENOME", border_style="bright_magenta", padding=(1, 2)))

            # Genome Scoring table demo
            table = Table(title="Genome Scoring", box=ROUNDED)
            table.add_column("Payload", max_width=28)
            table.add_column("Type", justify="center")
            table.add_column("Score", justify="right")
            table.add_column("Verdict", justify="center")
            # Score through the TRAINED genome (score_request = ML + heuristic),
            # not the static heuristic alone — otherwise the evolution/training we
            # just ran has no effect on what the user sees. Use one representative
            # endpoint (avoids max-over-all false-positive inflation) and the single
            # configured block threshold so the verdicts match live operation.
            _thr = cyphex_config.GENOME_BLOCK_THRESHOLD
            _ep = next(iter(genome.endpoint_profiles), None) or getattr(context, "target_url", "/")
            for payload, ptype in [("' OR 1=1--", "sqli"), ("<script>alert(1)</script>", "xss"), ("; cat /etc/passwd", "cmdi"), ("normal search", "benign"), ("John O'Brien", "benign")]:
                score = genome.score_request(_ep, payload)
                verdict = "[red]BLOCK[/red]" if score >= _thr else "[green]ALLOW[/green]"
                table.add_row(payload[:26], ptype, f"{score:.3f}", verdict)
            console.print(table)

        return controller.genome

    def _simulate_attacks(self):
        if not self.genome:
            print(f"  {C.Y}[SKIP]{C.RST} No genome available")
            return

        attacks = [
            ("SQLi Auth Bypass", "' OR '1'='1' --", "sqli"),
            ("SQLi UNION", "' UNION SELECT NULL--", "sqli"),
            ("XSS Script Tag", "<script>alert(1)</script>", "xss"),
            ("XSS Event Handler", "\"><img src=x onerror=1>", "xss"),
            ("CMDi Semicolon", "; whoami", "cmdi"),
            ("CMDi Pipe", "| cat /etc/passwd", "cmdi"),
            ("LFI Traversal", "../../etc/passwd", "lfi"),
            ("SSRF Internal", "http://169.254.169.254/", "ssrf"),
            ("Normal Search", "laptop", "benign"),
            ("Normal Apostrophe", "John O'Brien", "benign"),
            ("Normal Email", "user@example.com", "benign"),
            ("Normal Number", "42", "benign"),
        ]

        # Score through the TRAINED genome (ML + heuristic) against one
        # representative endpoint, at the configured operational threshold — so
        # this "genome defense" reflects the model the evolution loop trained,
        # not the static heuristic that ignores training.
        _thr = cyphex_config.GENOME_BLOCK_THRESHOLD
        _ep = next(iter(self.genome.endpoint_profiles), None) or getattr(self.context, "target_url", "/")
        blocked = fp = mal = 0
        attacks_data = []
        for name, payload, ptype in attacks:
            score = self.genome.score_request(_ep, payload)
            is_blocked = score >= _thr
            is_benign = ptype == "benign"
            before = "[green]ALLOWED[/green]"
            after = "[red]BLOCKED[/red]" if is_blocked else "[green]ALLOWED[/green]"
            
            if not is_benign:
                mal += 1
                if is_blocked: blocked += 1
            elif is_blocked:
                fp += 1
                after = "[bold red]FALSE POS[/bold red]"
                
            attacks_data.append((name, payload[:24], ptype, before, after, score))

        if SOC_UI:
            ui.render_attacks(attacks_data, blocked, mal, fp)
        else:
            table = Table(title="Before / After Simulation", box=ROUNDED)
            table.add_column("Attack", style="white")
            table.add_column("Payload", max_width=26)
            table.add_column("Type", justify="center")
            table.add_column("Before", justify="center")
            table.add_column("After", justify="center")
            table.add_column("Score", justify="right")
            for row in attacks_data:
                n, p, t, b, a, s = row
                table.add_row(n, p, t, b, a, f"{s:.3f}")
            console.print(table)
            rate = (blocked / mal * 100) if mal else 0
            console.print(f"\n  Blocked: {blocked}/{mal} ({rate:.0f}%)  |  False positives: {fp}")

    async def _print_report(self, duration):
        vulns = self.context.confirmed_vulns
        crit = sum(1 for v in vulns if v.severity == "Critical")
        high = sum(1 for v in vulns if v.severity == "High")
        med = sum(1 for v in vulns if v.severity == "Medium")
        low = sum(1 for v in vulns if v.severity in ("Low", "Info"))
        total = len(vulns)
        score = security_score(crit, high, med, low)

        # Label/band comes from scoring.score_band() — the single source of
        # truth for the 20/40/60/80 cutoffs; only the rich colour per label
        # is local to this render site.
        sc_label, _tier = _score_band(score)
        sc_rich = {
            "SECURE": "green", "FAIR": "cyan", "AT RISK": "yellow",
            "POOR": "red", "CRITICAL": "red bold",
        }[sc_label]

        # Score panel
        bar_filled = int(score / 100 * 30)
        bar_empty = 30 - bar_filled
        score_bar = f"[{sc_rich}]{'█' * bar_filled}[/{sc_rich}][dim]{'░' * bar_empty}[/dim]"

        console.print(Panel(
            f"  {score_bar}  [bold {sc_rich}]{score}/100[/bold {sc_rich}]  [{sc_rich}]{sc_label}[/{sc_rich}]\n\n"
            f"  [red]▲ Critical: {crit}[/red]  [magenta]● High: {high}[/magenta]  "
            f"[yellow]◆ Medium: {med}[/yellow]  [dim]○ Low: {low}[/dim]  │  "
            f"[cyan]Total: {total}[/cyan]\n"
            f"  [dim]Duration: {duration:.1f}s  │  Scan ID: {self.scan_id}[/dim]",
            title="[bold cyan]◈ SECURITY ASSESSMENT ◈[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        ))

        if vulns:
            table = Table(
                title=f"[bold]Confirmed Vulnerabilities ({total})[/bold]",
                box=ROUNDED,
                border_style="cyan",
                title_style="bold cyan",
                header_style="bold magenta",
                row_styles=["", "dim"],
            )
            table.add_column("#", justify="right", width=3, style="dim")
            table.add_column("Sev", justify="center", width=10)
            table.add_column("Vulnerability", max_width=35, style="cyan")
            table.add_column("CWE", width=10, style="dim cyan")
            table.add_column("Location", max_width=42, style="dim")

            sev_icons = {
                "Critical": "[bold red]▲ Critical[/bold red]",
                "High": "[magenta]● High[/magenta]",
                "Medium": "[yellow]◆ Medium[/yellow]",
                "Low": "[dim]○ Low[/dim]",
            }

            for i, v in enumerate(vulns, 1):
                vuln_type = v.name.replace("[STATIC] ", "⚡ ").replace("[DYNAMIC] ", "⚔ ")[:35]
                endpoint = (v.endpoint or "")[:42]
                cwe = getattr(v, "cwe", "CWE-???") if getattr(v, "cwe", None) else "CWE-???"
                if cwe == "CWE-???":
                    if "SQL" in vuln_type: cwe = "CWE-89"
                    elif "XSS" in vuln_type or "innerHTML" in vuln_type: cwe = "CWE-79"
                    elif "Command" in vuln_type or "CMDi" in vuln_type: cwe = "CWE-78"
                    elif "Path" in vuln_type or "Traversal" in vuln_type or "LFI" in vuln_type: cwe = "CWE-22"
                    elif "IDOR" in vuln_type: cwe = "CWE-284"
                    elif "SSRF" in vuln_type: cwe = "CWE-918"
                    elif "JWT" in vuln_type: cwe = "CWE-287"
                    elif "Hardcoded" in vuln_type or "Secret" in vuln_type: cwe = "CWE-798"
                    elif "Missing Auth" in vuln_type or "Auth" in vuln_type: cwe = "CWE-306"
                    elif "Root" in vuln_type or "Privilege" in vuln_type: cwe = "CWE-250"
                    elif "Data Exposure" in vuln_type: cwe = "CWE-200"
                    elif "CORS" in vuln_type: cwe = "CWE-942"

                sev_display = sev_icons.get(v.severity, f"[dim]{v.severity}[/dim]")
                table.add_row(str(i), sev_display, vuln_type, cwe, endpoint)
            console.print(table)

        # Tie the findings above back to the exploit sequence that chained
        # them (full detail was already shown once at the end of the dynamic
        # scan step — this is a compact cross-reference, not a re-render).
        attack_graph = getattr(self.context, "attack_graph", None)
        if attack_graph and getattr(attack_graph, "edges", None):
            top = attack_graph.edges[0]
            console.print(
                f"  [dim]◈ Exploit sequence:[/dim] [cyan]{len(attack_graph.edges)} chain(s)[/cyan] "
                f"[dim]discovered during the dynamic scan (top: {top.source} ──{top.action}──▶ {top.target}, "
                f"privilege reached: {getattr(attack_graph, 'privilege_level', 'none')})[/dim]"
            )

        if COUNCIL_AVAILABLE and vulns:
            try:
                analyzer = AnalysisCouncil()
                vuln_dicts = [{"name": v.name, "severity": v.severity, "endpoint": v.endpoint, "evidence": str(v.evidence)} for v in vulns]
                analysis_data = await analyzer.analyse_findings(vuln_dicts)

                if analysis_data:
                    print(f"\n  {C.PURP2}{C.BOLD}◈ Council Security Analysis{C.RST}")
                    for item in analysis_data:
                        validated = item.pop("_validated", True)
                        v_style = "green" if validated else "yellow"
                        console.print(Panel(
                            f"[bold red]Business Impact:[/bold red] {item.get('business_impact', 'N/A')}\n"
                            f"[bold yellow]Attack Scenario:[/bold yellow] {item.get('attack_scenario', 'N/A')}\n"
                            f"[bold cyan]Root Cause:[/bold cyan] {item.get('root_cause', 'N/A')}\n"
                            f"\n[{v_style}]✓ Validated by AI Council: {validated}[/{v_style}]",
                            title=f"[bold]{item.get('vuln_name', 'Vulnerability')}[/bold] [dim]({item.get('cwe', '')})[/dim]",
                            border_style="magenta",
                            padding=(0, 2)
                        ))
            except (Exception, asyncio.CancelledError):
                print(f"  {C.Y}⚠{C.RST} {C.GHOST}Council analysis skipped — start Ollama: {C.CYAN}ollama serve{C.RST}")

        return {
            "scan_id": self.scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "summary": {
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "total_vulns": total,
                "duration_seconds": round(duration, 2),
            },
            "target": self.sandbox_info.get("url") if self.sandbox_info else None,
            "vulnerabilities": [
                {
                    "name": v.name,
                    "severity": v.severity,
                    "endpoint": v.endpoint,
                    "payload": v.payload,
                    "confirmed": v.confirmed,
                }
                for v in vulns
            ],
            "attack_graph": self._attack_graph_summary(),
        }

    def _attack_graph_summary(self):
        """Serialize the DeepAgents AttackGraph (if the swarm ran) into the
        JSON report so downstream consumers (judge artifacts, dashboards) get
        the exploit sequence as structured data, not just a printed table."""
        attack_graph = getattr(self.context, "attack_graph", None) if self.context else None
        if not attack_graph:
            return None
        return {
            "privilege_level": getattr(attack_graph, "privilege_level", "none"),
            "creds_harvested": len(getattr(attack_graph, "confirmed_creds", []) or []),
            "tokens_harvested": len(getattr(attack_graph, "confirmed_tokens", []) or []),
            "nodes_touched": list(getattr(attack_graph, "nodes", {}).keys()),
            "chains": [
                {"seq": i, "source": e.source, "action": e.action, "target": e.target, "priority": e.priority}
                for i, e in enumerate(getattr(attack_graph, "edges", []) or [], 1)
            ],
        }

    def _save_report(self, report, filepath):
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"  {C.G}[OK]{C.RST} Report saved to {filepath}")

    def _save_judge_artifacts(self, report: dict):
        """Save deterministic judge artifacts in JSON, Markdown, and SARIF."""
        out_dir = os.path.join(self.source_dir or WORK_DIR, "cyphex_judge_artifacts")
        os.makedirs(out_dir, exist_ok=True)

        json_path = os.path.join(out_dir, "report.json")
        md_path = os.path.join(out_dir, "report.md")
        sarif_path = os.path.join(out_dir, "report.sarif")

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        md_lines = [
            "# CYPHEX Judge Report",
            f"- Scan ID: `{report.get('scan_id')}`",
            f"- Score: `{report.get('score')}/100`",
            f"- Target: `{report.get('target')}`",
            f"- Duration: `{report.get('summary', {}).get('duration_seconds')}s`",
            "",
            "## Summary",
            f"- Critical: {report.get('summary', {}).get('critical', 0)}",
            f"- High: {report.get('summary', {}).get('high', 0)}",
            f"- Medium: {report.get('summary', {}).get('medium', 0)}",
            f"- Low: {report.get('summary', {}).get('low', 0)}",
            "",
            "## Findings",
        ]
        for v in report.get("vulnerabilities", []):
            md_lines.append(f"- **{v.get('severity')}** {v.get('name')} @ `{v.get('endpoint')}`")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n")

        results = []
        for v in report.get("vulnerabilities", []):
            rule_id = (v.get("name") or "CYPHEX-FINDING").upper().replace(" ", "-")
            results.append({
                "ruleId": rule_id,
                "level": "error" if v.get("severity") in ("Critical", "High") else "warning",
                "message": {"text": f"{v.get('name')} at {v.get('endpoint')}"},
                "locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": v.get("endpoint") or "unknown"}}
                }],
            })

        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "CYPHEX"}}, "results": results}],
        }
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)

        print(f"  {C.G}[OK]{C.RST} Judge artifacts exported:")
        print(f"      - {json_path}")
        print(f"      - {md_path}")
        print(f"      - {sarif_path}")

    # Step 8: Patch workflow
    async def _patch_workflow(self):
        vulns = list(self.context.confirmed_vulns)
        if not vulns:
            print(f"  {C.G}No vulnerabilities to patch.{C.RST}")
            return

        if COUNCIL_AVAILABLE:
            try:
                tracer = RouteTracer(self.source_dir)
                tracer.resolve_dast_vulns(vulns)
            except Exception as e:
                self._vconsole(f"[dim]  Route tracer unavailable or failed: {str(e)}[/dim]")

        # Calculate BEFORE score
        crit_b = sum(1 for v in vulns if v.severity == "Critical")
        high_b = sum(1 for v in vulns if v.severity == "High")
        med_b  = sum(1 for v in vulns if v.severity == "Medium")
        low_b  = sum(1 for v in vulns if v.severity in ("Low", "Info"))
        score_before = security_score(crit_b, high_b, med_b, low_b)

        # ═══════════════════════════════════════════════════════════════
        # V2 PIPELINE: Vectorless RAG + Grounded Reasoning
        # ═══════════════════════════════════════════════════════════════
        # V2 (Vectorless-RAG + source patching) needs a source tree. On a
        # live-URL-only scan self.source_dir is None; keep use_v2 off so we never
        # construct CodeIndexer(None) (which raises), and URL findings fall through
        # to the dynamic_only path instead of a misleading "requires Ollama" crash.
        use_v2 = PATCH_V2_AVAILABLE and bool(self.source_dir)
        indexer = None
        manifest = None
        patch_memory = None
        framework = ""
        # Prior-scan lessons block (session memory). Assigned from
        # session.get_prior_context() below when reasoning is available; kept
        # as "" otherwise so it can be injected unconditionally into every
        # patch-generation prompt without a NameError.
        prior_context = ""

        if use_v2:
            # ── Build Code Index (Vectorless RAG) ──
            console.print(Panel(
                "[bold cyan]Building Vectorless Code Index...[/bold cyan]\n"
                "[dim]Walking source tree → keyword index (no embeddings, no vector DB)[/dim]",
                title="◈ VECTORLESS RAG ENGINE", border_style="bright_cyan"
            ))
            indexer = CodeIndexer(self.source_dir)
            file_count = indexer.build_index()

            # ── Additive: PageIndex-style Knowledge Tree navigator (merged from
            #    update_y1). Fully optional and guarded — it only ENRICHES the
            #    per-vuln prompt with CWE fix-recipes + repo knowledge; it never
            #    replaces the CodeIndexer path above, and any failure here leaves
            #    patching completely unaffected. build() is pure regex unless the
            #    target ships a docs/ dir, and it caches to .cyphex/. ──
            self._tree_navigator = None
            try:
                from backend.rag.knowledge_tree import KnowledgeTreeBuilder
                from backend.rag.tree_navigator import get_navigator
                _kt_builder = KnowledgeTreeBuilder(self.source_dir)
                _kt = _kt_builder.build()
                self._tree_navigator = get_navigator(_kt, getattr(_kt_builder, "cwe_index", None))
                if self._tree_navigator:
                    self._vconsole("  [green]✓[/green] Knowledge Tree navigator ready (CWE fix-recipe enrichment)")
                    if SOC_UI:
                        ui.render_knowledge_graph(_kt, getattr(_kt_builder, "cwe_index", None))
            except Exception as _e:
                self._vconsole(f"[dim]Knowledge Tree navigator unavailable (non-fatal): {type(_e).__name__}[/dim]")

            # Show the code tree
            tree_lines = []
            for rel_path, meta in list(indexer.files.items())[:15]:
                flags = []
                if meta["has_db"]: flags.append("[red]DB[/red]")
                if meta["has_auth"]: flags.append("[yellow]AUTH[/yellow]")
                if meta["has_input"]: flags.append("[magenta]INPUT[/magenta]")
                flag_str = " ".join(flags) if flags else "[dim]—[/dim]"
                funcs = meta["functions"][:3]
                func_str = ", ".join(funcs) if funcs else "—"
                tree_lines.append(f"  [cyan]📄[/cyan] {rel_path:40s} {flag_str:30s} [dim]fn: {func_str}[/dim]")
            if len(indexer.files) > 15:
                tree_lines.append(f"  [dim]... and {len(indexer.files) - 15} more files[/dim]")

            console.print(Panel(
                "\n".join(tree_lines),
                title=f"[bold]Code Tree Index — {file_count} files indexed[/bold]",
                border_style="bright_cyan", padding=(1, 1)
            ))

            # Detect framework
            deps = indexer.get_dependency_info()
            framework = detect_framework(deps)
            if framework:
                self._vconsole(f"  [green]✓[/green] Detected framework: [bold]{framework}[/bold]")

            # Init manifest + patch memory.
            # patch_memory persists to <dir>/.cyphex/patch_memory.json. Point it
            # at the STABLE original path (self.local_path) so verified fixes
            # survive across scans and the exact-cache recall can hit on re-scan;
            # keying it on the ephemeral sandbox copy (self.source_dir) made the
            # cache empty on every run. Falls back to the sandbox dir for
            # repo-clone scans (which carry cross-scan identity via repo_url).
            _mem_dir = os.path.abspath(self.local_path) if getattr(self, "local_path", None) else self.source_dir
            manifest = PatchManifest(self.source_dir)
            patch_memory = PatchMemory(_mem_dir)
            self._vconsole(f"  [green]✓[/green] Patch manifest: .cyphex/patches.json")
            self._vconsole(f"  [green]✓[/green] Patch memory: {os.path.join(_mem_dir, '.cyphex', 'patch_memory.json')}")

        # ── Session Memory + Agent Reasoning ──
        session = None
        reasoner = None
        thread_id = ""

        if REASONING_AVAILABLE:
            # Key the session on the STABLE original path, NOT the per-scan
            # sandbox copy (WORK_DIR/<random>), so create_session re-finds the
            # prior session for this repo and prior lessons actually carry over.
            _stable_src = os.path.abspath(self.local_path) if getattr(self, "local_path", None) else self.source_dir
            session = create_session(
                repo_url=getattr(self, "repo_url", "") or "",
                source_dir=_stable_src,
                framework=framework if use_v2 else "",
                # Reuse the count from the index already built above — calling
                # build_index() again just re-walks the whole tree for no reason.
                file_count=file_count if use_v2 and indexer else 0,
            )
            thread_id = session.thread_id
            prior_context = session.get_prior_context()
            prior_lessons = len(session.model_context.get("lessons", []))
            prior_scans = len(session.reasoning_history)

            reasoner = get_reasoner()
            is_enhanced = reasoner and reasoner.is_enhanced

            # ── Agent Reasoning Engine Panel (show ALL 16 strategies) ──
            strategy_display = reasoner.get_strategy_display() if is_enhanced else "  [dim]Install agent-reasoning for 16 cognitive architectures[/dim]"
            console.print(Panel(
                f"[bold bright_magenta]Oracle Agent-Reasoning Engine[/bold bright_magenta]\n"
                f"[dim]github.com/jasperan/agent-reasoning — 16 cognitive architectures[/dim]\n\n"
                f"[bold]Available Strategies ({len(reasoner.available_strategies) if is_enhanced else 0}/16):[/bold]\n"
                f"{strategy_display}\n\n"
                f"[bold]Strategy Selection:[/bold]\n"
                f"  • CWE-78 (CMDi) → [cyan]🌳 Tree of Thoughts[/cyan] (multi-path search)\n"
                f"  • Critical vulns → [yellow]🗳️ Self-Consistency[/yellow] (majority vote)\n"
                f"  • High vulns → [green]🪞 Self-Reflection[/green] (draft→critique→improve)\n"
                f"  • Standard vulns → [blue]🔗 Chain-of-Thought[/blue] (step-by-step)\n"
                f"  • Patch review → [red]⚔️ Adversarial Debate[/red] (multi-perspective)\n\n"
                f"[bold]Status:[/bold] {'[bold green]ENHANCED[/bold green] — All strategies active' if is_enhanced else '[yellow]BASIC[/yellow] — pip install agent-reasoning'}",
                title="◈ AGENT REASONING ENGINE", border_style="bright_magenta", padding=(1, 2)
            ))

            # ── Session Memory Panel ──
            is_returning = prior_scans > 0 or prior_lessons > 0
            # os.path.basename, not .split("/")[-1] — repo_url is always
            # forward-slash (a URL) so both work there, but a local Windows
            # scan's source_dir is backslash-separated, and split("/") finds
            # no "/" at all in that case, so it fell back to the ENTIRE
            # absolute path instead of just the folder name. basename()
            # handles both separators correctly on every platform.
            repo_name = os.path.basename(
                (getattr(self, "repo_url", "") or self.source_dir or "unknown").rstrip("/\\")
            ).replace(".git", "")
            session_status = "[bold green]🔄 RETURNING SESSION[/bold green] — prior context loaded" if is_returning else "[yellow]🆕 NEW SESSION[/yellow] — building context from scratch"
            
            session_info = (
                f"{session_status}\n\n"
                f"[bold]Thread ID:[/bold]     [cyan]{thread_id}[/cyan]\n"
                f"[bold]Repository:[/bold]    {repo_name}\n"
                f"[bold]Session File:[/bold]  .cyphex/sessions/{thread_id[:8]}...json\n\n"
            )
            
            if is_returning:
                session_info += (
                    f"[bold green]📚 Prior Knowledge:[/bold green]\n"
                    f"  • {prior_scans} patch{'es' if prior_scans != 1 else ''} from previous sessions\n"
                    f"  • {prior_lessons} learned pattern{'s' if prior_lessons != 1 else ''}\n"
                    f"  • Verified fixes: {session.model_context.get('patches_verified', 0)}\n"
                    f"  • Failed fixes:   {session.model_context.get('patches_failed', 0)}\n\n"
                    f"[dim]💡 These lessons are injected into every model prompt to improve fix quality.[/dim]"
                )
            else:
                session_info += (
                    f"[dim]📝 How Session Memory works:[/dim]\n"
                    f"[dim]  1. Each scan creates a persistent thread tied to this repo[/dim]\n"
                    f"[dim]  2. Successful & failed patches are recorded as 'lessons'[/dim]\n"
                    f"[dim]  3. On re-scan, lessons are injected into model prompts[/dim]\n"
                    f"[dim]  4. The LLM learns from past mistakes → better patches over time[/dim]"
                )
            
            console.print(Panel(
                session_info,
                title="◈ SESSION MEMORY (Persistent Cross-Scan Context)", border_style="bright_cyan", padding=(1, 2)
            ))

        # ── RAG Pipeline Status Panel ──
        if use_v2 and indexer:
            rag_tree = indexer.files if hasattr(indexer, 'files') else {}
            db_files = sum(1 for m in rag_tree.values() if m.get("has_db"))
            auth_files = sum(1 for m in rag_tree.values() if m.get("has_auth"))
            input_files = sum(1 for m in rag_tree.values() if m.get("has_input"))
            total_funcs = sum(len(m.get("functions", [])) for m in rag_tree.values())
            console.print(Panel(
                f"[bold bright_green]Vectorless RAG[/bold bright_green] — No embeddings, no vector DB, no external API\n"
                f"[dim]Extracts code structure into a JSON tree for precise context injection[/dim]\n\n"
                f"[bold]📂 Code Tree Index:[/bold] {len(rag_tree)} files indexed\n"
                f"[bold]⚙️  Functions:[/bold]       {total_funcs} extracted for context enrichment\n"
                f"[bold]🔍 Security Flags:[/bold]\n"
                f"  [red]DB[/red]:     {db_files} file{'s' if db_files != 1 else ''} with database operations\n"
                f"  [yellow]AUTH[/yellow]:   {auth_files} file{'s' if auth_files != 1 else ''} with authentication logic\n"
                f"  [magenta]INPUT[/magenta]:  {input_files} file{'s' if input_files != 1 else ''} with user input handling\n"
                f"[bold]📖 KB Recipes:[/bold]    CWE-89, CWE-79, CWE-78, CWE-798, CWE-942 + framework-specific\n"
                f"[bold]🏗️  Framework:[/bold]     {framework or 'auto-detected'}\n\n"
                f"[dim]Context flow: 📂 Code Tree → ⚙️ Functions → 📖 KB Recipe → 📥 Imports → 🤖 Model Prompt[/dim]\n"
                f"[dim]Each vulnerability gets: function body + file imports + CWE recipe + repo patterns[/dim]",
                title="◈ VECTORLESS RAG PIPELINE (Context Enrichment Engine)", border_style="bright_green", padding=(1, 2)
            ))

        # Build status indicators
        council_status = "[green]✓ ON[/green]" if COUNCIL_AVAILABLE else "[red]✗ OFF[/red]"
        reasoning_status = f"[green]✓ ON ({len(reasoner.available_strategies)} strategies)[/green]" if REASONING_AVAILABLE and reasoner and reasoner.is_enhanced else "[yellow]⚡ BASIC[/yellow]"
        rag_status = "[green]✓ ON[/green]" if use_v2 else "[red]✗ OFF[/red]"
        session_status_short = f"[green]✓ {thread_id[:8]}[/green]" if thread_id else "[red]✗ NONE[/red]"
        
        console.print(Panel(
            f"[bold]🎯 {len(vulns)} vulnerabilities to patch[/bold]\n\n"
            f"[bold]Pipeline Steps[/bold] (each vulnerability goes through):\n"
            f"  [cyan]①[/cyan] [bold]Template Match[/bold]  → Try known deterministic fix (fastest, no LLM)\n"
            f"  [cyan]②[/cyan] [bold]RAG Context[/bold]     → Extract function + imports + KB recipe\n"
            f"  [cyan]③[/cyan] [bold]LLM Generation[/bold]  → Model generates fix with reasoning strategy\n"
            f"  [cyan]④[/cyan] [bold]Council Review[/bold]  → 2 reviewer LLMs validate the patch\n"
            f"  [cyan]⑤[/cyan] [bold]Verify Gate[/bold]     → Re-scan + syntax check + blast radius\n\n"
            f"[bold]Component Status:[/bold]\n"
            f"  Council:     {council_status}    Agent Reasoning: {reasoning_status}\n"
            f"  RAG:         {rag_status}    Session Memory:  {session_status_short}",
            title="◈ PATCH WORKFLOW", border_style="magenta", padding=(1, 2)
        ))

        patch_council = PatchCouncil(thread_id=thread_id) if COUNCIL_AVAILABLE else None
        patched_files = []
        verified_count = 0
        template_count = 0
        skipped = 0
        # Identity (not path-substring) set of vulnerabilities that were both patched
        # AND verified with a PASS verdict. Used later to compute the "remaining"
        # vulnerability list / after-patch score, so that (a) patching ONE finding in
        # a file can't silently clear every OTHER finding in that same file, and
        # (b) an UNVERIFIABLE (inconclusive) verdict never counts as "fixed" — only
        # PASS does. Keyed on the Vuln object's identity since `p["vuln"] is v` for
        # the same object drawn from `vulns` below.
        remediated_vuln_ids = set()

        def _record_patch_failure(p, idx, fix_source, fixed_code, why):
            """Persist a FAILED patch attempt into session memory.

            Both the apply gate and the verification gate call this, so
            patches_failed and the "what NOT to do" lessons reflect every
            rejection, not just the ones that survived long enough to be
            verified.
            """
            if not (session and REASONING_AVAILABLE):
                return
            session.add_entry(ReasoningEntry(
                vuln_id=f"vuln_{idx:03d}", cwe=p["cwe"], file=p["rel_path"],
                line=p["line_num"], strategy_used=fix_source, verdict="FAIL",
                patch_hash=hashlib.sha256(fixed_code.encode()).hexdigest()[:12],
                fix_source=fix_source,
            ))
            session.add_lesson(
                f"{p['cwe']} in {os.path.basename(p['rel_path'])}: a {fix_source} fix FAILED "
                f"({why}) — try a different remediation approach"
            )



        cwe_map = {
            "sql injection": "CWE-89", "xss": "CWE-79",
            "command injection": "CWE-78", "cmdi": "CWE-78",
            "ssrf": "CWE-918", "idor": "CWE-284",
            "jwt": "CWE-287", "sensitive data": "CWE-200",
            "hardcoded": "CWE-798", "cors": "CWE-942",
            "lfi": "CWE-22", "path traversal": "CWE-22",
            "csrf": "CWE-352", "cross-site request forgery": "CWE-352",
        }

        # ── Phase 1: Resolve locations using V2 resolver ──
        patchable = []
        dynamic_only = []
        for v in vulns:
            if use_v2:
                loc = resolve_location(v, self.source_dir)
                if loc and is_patchable(loc):
                    content = open(loc.file, "r", encoding="utf-8", errors="ignore").read()
                    lines = content.split("\n")
                    lang = detect_language(loc.file)
                    snippet_fn, ctx_quality, fn_s, fn_e = extract_function_span(content, loc.line, lang)
                    imports_str = extract_imports(content, lang)
                    vuln_type = v.name.replace("[STATIC] ", "").replace("[DYNAMIC] ", "")
                    cwe = getattr(v, "cwe", "") or ""
                    if not cwe or cwe == "CWE-???":
                        for key, val in cwe_map.items():
                            if key in vuln_type.lower():
                                cwe = val
                                break
                    # Replace the WHOLE brace-balanced enclosing function when we have
                    # one — splicing a balanced unit keeps the file's brace/paren
                    # balance intact, which is what prevents the 'invalid syntax →
                    # rolled back' failures caused by rewriting an arbitrary 5-line
                    # window. Fall back to the ±window only when no clean function span
                    # was found (ctx_quality == "window").
                    if ctx_quality == "function" and fn_s and fn_e:
                        start_l = fn_s - 1          # 0-indexed inclusive
                        end_l = fn_e                # 0-indexed exclusive (== 1-indexed inclusive)
                    else:
                        start_l = max(0, loc.line - 3)
                        end_l = min(len(lines), loc.line + 2)
                    raw_snippet = "\n".join(lines[start_l:end_l])
                    patchable.append({
                        "vuln": v, "rel_path": loc.rel, "line_num": loc.line,
                        "lines": [l + "\n" for l in lines], "snippet": raw_snippet,
                        "snippet_fn": snippet_fn, "ctx_quality": ctx_quality,
                        "imports": imports_str, "vuln_type": vuln_type,
                        "cwe": cwe, "start_l": start_l, "end_l": end_l,
                        "filepath": loc.file, "location": loc, "lang": lang,
                    })
                elif loc and loc.kind == "url":
                    dynamic_only.append(v)
                else:
                    dynamic_only.append(v)
            else:
                # Legacy resolver fallback
                endpoint = v.endpoint or ""
                if endpoint.startswith("http://") or endpoint.startswith("https://"):
                    dynamic_only.append(v); continue
                if ":" not in endpoint:
                    dynamic_only.append(v); continue
                parts = endpoint.split(":")
                rel_path = parts[0].strip()
                try:
                    line_num = int(parts[1].split()[0])
                except Exception:
                    dynamic_only.append(v); continue
                filepath = os.path.join(self.source_dir, rel_path)
                if not os.path.exists(filepath):
                    if os.path.exists(rel_path):
                        filepath = rel_path
                        if self.source_dir and rel_path.startswith(self.source_dir):
                            rel_path = os.path.relpath(rel_path, self.source_dir)
                    else:
                        dynamic_only.append(v); continue
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        file_lines = f.readlines()
                except Exception:
                    dynamic_only.append(v); continue
                start_l = max(0, line_num - 3)
                end_l = min(len(file_lines), line_num + 2)
                snippet = "".join(file_lines[start_l:end_l])
                vuln_type = v.name.replace("[STATIC] ", "").replace("[DYNAMIC] ", "")
                cwe = "CWE-unknown"
                for key, val in cwe_map.items():
                    if key in vuln_type.lower(): cwe = val; break
                patchable.append({
                    "vuln": v, "rel_path": rel_path, "line_num": line_num,
                    "lines": file_lines, "snippet": snippet, "vuln_type": vuln_type,
                    "cwe": cwe, "start_l": start_l, "end_l": end_l,
                    "filepath": filepath, "snippet_fn": snippet, "ctx_quality": "window",
                    "imports": "", "location": None, "lang": "js",
                })

        if dynamic_only:
            self._vconsole(f"[dim]  {len(dynamic_only)} dynamic/runtime findings (no source file to auto-patch)[/dim]")

        # ── Phase 1.3: Deduplicate findings at the same (file, line) ──
        # Two findings pointing at the same source line would otherwise produce
        # two patches; the second clobbers the first's edit. Keep the highest
        # severity per location.
        _sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        _deduped: dict[tuple, dict] = {}
        # Every finding that shared a location, including the ones dropped here.
        # A dropped sibling is fixed by the surviving patch, so it MUST clear
        # from the score too — otherwise a patched line keeps being penalised
        # forever by its own duplicate and score_after is permanently understated.
        _loc_members: dict[tuple, list[int]] = {}
        for p in patchable:
            loc_key = (p["rel_path"], p["line_num"])
            _loc_members.setdefault(loc_key, []).append(id(p["vuln"]))
            existing = _deduped.get(loc_key)
            if existing is None or _sev_rank.get(p["vuln"].severity, 0) > _sev_rank.get(existing["vuln"].severity, 0):
                _deduped[loc_key] = p
        if len(_deduped) < len(patchable):
            self._vconsole(f"[dim]  Deduplicated {len(patchable) - len(_deduped)} overlapping finding(s) at shared locations.[/dim]")
        patchable = list(_deduped.values())
        for loc_key, p in _deduped.items():
            p["sibling_ids"] = _loc_members.get(loc_key, [id(p["vuln"])])

        if PATCH_V2_AVAILABLE and self.source_dir:
            try:
                kb = load_security_kb()
                indexer = CodeIndexer(self.source_dir)
                for p in patchable:
                    content = "".join(p["lines"])
                    lang = detect_language(p["filepath"])
                    context_snippet, extraction_quality = extract_function(content, p["line_num"], lang)
                    imports = extract_imports(content, lang)
                    loc = resolve_location(p["vuln"], self.source_dir) if PATCH_PIPELINE_AVAILABLE else None
                    if not loc:
                        loc = SimpleNamespace(rel=p["rel_path"], line=p["line_num"], url=None)

                    strategy = kb.primary_strategy(p["cwe"])
                    anti = kb.anti_patterns(p["cwe"])
                    related_files = indexer.find_for_vuln(p["vuln"], loc)
                    secure_example = indexer.find_secure_pattern(p["cwe"])

                    p["context_snippet"] = context_snippet
                    p["extraction_quality"] = extraction_quality
                    p["imports"] = imports
                    p["related_files"] = related_files
                    p["secure_example"] = secure_example or ""
                    p["kb_strategy"] = strategy.pattern if strategy else ""
                    p["kb_anti_patterns"] = "; ".join(anti[:4]) if anti else ""

                self._vconsole(f"[dim]  RAG context enabled: imports + function window + CWE strategy + related files.[/dim]")
                # Per-vuln quality summary
                fn_count  = sum(1 for p in patchable if p.get("extraction_quality") == "function")
                win_count = sum(1 for p in patchable if p.get("extraction_quality") == "window")
                kb_count  = sum(1 for p in patchable if p.get("kb_strategy"))
                sec_count = sum(1 for p in patchable if p.get("secure_example"))
                self._vconsole(
                    f"  [cyan]RAG:[/cyan] {fn_count} function-level extractions, "
                    f"{win_count} window fallbacks, "
                    f"{kb_count} CWE-KB strategies, "
                    f"{sec_count} in-repo secure examples"
                )
            except Exception as e:
                console.print(f"[yellow][RAG] disabled due to indexing error: {str(e)[:80]}[/yellow]")

        if not patchable:
            console.print(f"[dim]No vulns with file locations to patch.[/dim]")
            return



        # ── Phase 2: Batch generate with ENRICHED context ──
        batch_results = None
        if patch_council and len(patchable) > 0:
            try:
                vuln_inputs = []
                for p in patchable:
                    # The applier overwrites EXACTLY the window [start_l+1, end_l]
                    # (== p["snippet"]), so the model must rewrite that window and
                    # nothing else. The enclosing function, imports, KB recipe and
                    # repo secure-pattern go in a separate READ-ONLY `context` field
                    # — never as the code-to-replace. (Feeding the full brace-
                    # balanced function as the thing-to-replace, then splicing the
                    # reply over the smaller window, is what broke brace balance ->
                    # node --check failed -> auto-rollback -> "0 patches applied".)
                    replace_window = p["snippet"]
                    context_parts = []
                    if use_v2:
                        kb_recipe = format_for_prompt(p["cwe"], framework)
                        if kb_recipe:
                            context_parts.append(kb_recipe)
                        if p.get("imports"):
                            context_parts.append(f"// FILE IMPORTS (read-only context):\n{p['imports']}")
                        fn_ctx = p.get("snippet_fn")
                        if fn_ctx and fn_ctx.strip() != replace_window.strip():
                            context_parts.append(
                                f"// ENCLOSING FUNCTION ({p.get('ctx_quality','window')} extraction, "
                                f"read-only — do NOT return this whole block):\n{fn_ctx}")
                        if indexer:
                            repo_pattern = indexer.find_secure_pattern(p["cwe"])
                            if repo_pattern:
                                context_parts.append(f"// REPO'S OWN SECURE PATTERN (match this style):\n{repo_pattern[:300]}")
                        # Additive Knowledge-Tree enrichment (merged from update_y1):
                        # CWE fix-recipe + related repo knowledge. Fully guarded —
                        # a failure here never affects patch generation.
                        if getattr(self, "_tree_navigator", None):
                            try:
                                kt = self._tree_navigator.get_patch_context(
                                    p["cwe"], p.get("rel_path", ""), p.get("line_num", 0), p["vuln_type"]
                                )
                                if kt.get("fix_recipe"):
                                    context_parts.append(f"// KNOWLEDGE-TREE FIX RECIPE ({p['cwe']}):\n{kt['fix_recipe'][:400]}")
                                if kt.get("related_knowledge"):
                                    context_parts.append(f"// KNOWLEDGE-TREE KB:\n{kt['related_knowledge'][:400]}")
                            except Exception:
                                pass
                    patch_context = "\n\n".join(context_parts)

                    # Inject cross-scan session-memory lessons (get_prior_context)
                    # into EVERY generation prompt — this is what the Session
                    # Memory panel promises ("lessons are injected into every
                    # model prompt"). Prepended as read-only context so the model
                    # applies prior fixes/patterns to this codebase.
                    if prior_context:
                        patch_context = (
                            f"{prior_context}\n\n{patch_context}" if patch_context else prior_context
                        )

                    memory_hint = ""
                    if COGNEE_AVAILABLE:
                        try:
                            hits = await asyncio.wait_for(
                                cognee_memory.recall_similar_fixes(p["cwe"], p.get("snippet_fn", p["snippet"])),
                                timeout=cyphex_config.COGNEE_RECALL_TIMEOUT_S,
                            )
                            memory_hint = cognee_memory.format_hint(hits)
                            self._emit("cognee_recall_result", ok=True, hits=len(hits))
                        except Exception as _e:
                            memory_hint = ""
                            self._emit("cognee_recall_result", ok=False, error=str(_e)[:200])

                    vuln_inputs.append({
                        "vuln_name": p["vuln_type"], "cwe": p["cwe"],
                        "vulnerable_code": replace_window, "file_path": p["rel_path"],
                        "severity": p["vuln"].severity,
                        "memory_hint": memory_hint,
                        "context": patch_context,
                    })

                # Show context enrichment panel
                if use_v2:
                    enrich_lines = []
                    for p in patchable:
                        q = p.get("ctx_quality", "window")
                        has_kb = "[green]✓[/green]" if format_for_prompt(p["cwe"], framework) else "[red]✗[/red]"
                        has_imp = "[green]✓[/green]" if p.get("imports") else "[red]✗[/red]"
                        # Show which reasoning strategy will be used
                        strat = ""
                        if reasoner and reasoner.is_enhanced:
                            from backend.reasoning.oracle_adapter import ALL_STRATEGIES
                            s = reasoner.select_strategy("patch_generate", p["vuln"].severity, p["cwe"])
                            s_info = ALL_STRATEGIES.get(s, {"icon": "⚡", "name": s})
                            strat = f" → {s_info['icon']} {s_info['name']}"
                        enrich_lines.append(
                            f"  [{p['cwe']:10s}] {p['rel_path']:30s} "
                            f"ctx=[bold]{q:8s}[/bold] KB={has_kb} imp={has_imp}{strat}"
                        )
                    self._vconsole(Panel(
                        "[bold]RAG Context → Model Prompt Assembly:[/bold]\n"
                        "[dim]Each vuln gets: function body + file imports + KB recipe + repo secure pattern[/dim]\n\n"
                        + "\n".join(enrich_lines),
                        title="[bold]◈ Context Enrichment — RAG Pipeline + Strategy Selection[/bold]",
                        border_style="bright_magenta", padding=(1, 1)
                    ))


                batch_results = await patch_council.generate_and_validate_batch(vuln_inputs)
            except Exception as e:
                self._vconsole(f"[yellow]⚠ Batch council error: {str(e)[:80]}.[/yellow]")
                self._vconsole(f"[cyan]  → Per-vuln fallback will only generate patches that weren't cached.[/cyan]")
                batch_results = None


        # Verified fixes to persist into cross-project cognee memory. Collected
        # during the loop and drained once afterwards (see the drain block below)
        # so the slow cognify() never stalls interactive remediation.
        cognee_jobs = []

        # ── Phase 3: Present each patch — template → council → verify → apply ──
        for i, p in enumerate(patchable):
            v = p["vuln"]
            sev_colors = {"Critical": "red", "High": "bright_red", "Medium": "yellow", "Low": "green"}
            sev_icons  = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            sev_color = sev_colors.get(v.severity, "white")
            sev_icon = sev_icons.get(v.severity, "●")
            
            self._vconsole(f"\n[bold bright_cyan]{'━' * 70}[/bold bright_cyan]")
            self._vconsole(
                f"[bold][{i+1}/{len(patchable)}] {sev_icon} {p['vuln_type']}[/bold] "
                f"[{sev_color}]({v.severity})[/{sev_color}]"
            )
            self._vconsole(f"[bold]File:[/bold] [cyan]{p['rel_path']}:{p['line_num']}[/cyan]")
            if use_v2:
                self._vconsole(f"[dim]Context: {p.get('ctx_quality','window')} extraction | CWE: {p['cwe']} | Lang: {p.get('lang','?')}[/dim]")

            self._vconsole(f"\n[bold]Vulnerable Code:[/bold]")
            for j in range(p["start_l"], min(p["end_l"], len(p["lines"]))):
                ln = j + 1
                marker = "->" if ln == p["line_num"] else "  "
                line_content = p["lines"][j].rstrip() if j < len(p["lines"]) else ""
                self._vconsole(f"  {marker} {ln:4} | {line_content[:120]}")

            # ── Step A0: exact patch-memory cache (verified fix for
            #    structurally-identical code) — the fastest path, no LLM and no
            #    template regex needed. This is the READ side of the exact
            #    cwe:hash cache that .store() populates on every verified PASS;
            #    without it the cache was write-only and the model regenerated a
            #    fix it had already produced+verified before. ──
            fixed = None
            fix_source = "council"
            if patch_memory:
                cached = patch_memory.recall(p["cwe"], p.get("snippet_fn", p["snippet"]))
                if cached and str(cached.get("patch", "")).strip():
                    fixed = str(cached["patch"]).strip()
                    fix_source = "memory"
                    self._vconsole(Panel(
                        f"[bold green]✓ Reused a previously VERIFIED fix from patch memory (no AI needed)[/bold green]\n"
                        f"[dim]CWE: {p['cwe']} | reuse #{cached.get('reuse_count', 0)} | "
                        f"strategy: {cached.get('strategy', '?')}[/dim]",
                        title="◈ PATCH MEMORY (exact cache hit)", border_style="green"
                    ))

            # ── Step A: Try deterministic template fix first (no model needed) ──
            if not fixed and use_v2:
                vuln_line = p["lines"][p["line_num"] - 1].rstrip() if p["line_num"] - 1 < len(p["lines"]) else ""
                template_result = apply_template(p["cwe"], vuln_line, framework)
                if template_result:
                    fixed = template_result
                    fix_source = "template"
                    template_count += 1
                    self._vconsole(Panel(
                        f"[bold green]✓ Deterministic template fix applied (no AI needed)[/bold green]\n"
                        f"[dim]CWE: {p['cwe']} | Transform: regex-based[/dim]",
                        title="◈ TEMPLATE ENGINE", border_style="green"
                    ))

            # ── Step B: Try council/model-based patch ──
            patch_pkg = None
            if not fixed:
                if batch_results and i < len(batch_results):
                    council_result = batch_results[i]
                    if council_result and council_result.get("fixed_code"):
                        patch_pkg = {
                            "unsafe_reason": council_result.get("unsafe_reason", ""),
                            "fixed_code": council_result.get("fixed_code", ""),
                            "justifications": council_result.get("vote_summary", ""),
                            "patch_safety": council_result.get("patch_safety", ""),
                        }
                        approvals = council_result.get("approvals", [])
                        dissent = council_result.get("dissent_reasons", [])
                        vote_table = Table(title="Council Patch Validation", box=ROUNDED)
                        vote_table.add_column("Model", width=22)
                        vote_table.add_column("Verdict", justify="center", width=10)
                        vote_table.add_column("Reason", max_width=45)
                        for a in approvals:
                            # Use the SAME guard the tally uses (is_approved_vote):
                            # local models often emit the string "false", which is
                            # truthy — raw `a.get("approved")` would print APPROVED
                            # while the council counted it a rejection.
                            _ok = is_approved_vote(a.get("approved")) if COUNCIL_AVAILABLE else bool(a.get("approved"))
                            verdict_color = "green" if _ok else "red"
                            verdict_text = "APPROVED" if _ok else "REJECTED"
                            vote_table.add_row(
                                a.get("model", "unknown"),
                                f"[{verdict_color}]{verdict_text}[/{verdict_color}]",
                                a.get("reason", "")
                            )
                        self._vconsole(vote_table)
                        if dissent:
                            self._vconsole(Panel(
                                "\n".join(f"[red]•[/red] {r}" for r in dissent),
                                title="Dissenting Reasons", border_style="red"
                            ))

                if not patch_pkg:
                    console.print(f"[yellow][SKIP][/yellow] Could not generate patch\n")
                    skipped += 1
                    continue

                # Extract fixed code from council result
                analysis = patch_pkg.get('unsafe_reason', 'No rationale provided.')
                if isinstance(analysis, list): analysis = " ".join(str(x) for x in analysis)
                justifications = patch_pkg.get('justifications', 'N/A')
                if isinstance(justifications, list): justifications = " ".join(str(x) for x in justifications)
                raw_safety = patch_pkg.get("patch_safety", "")
                if isinstance(raw_safety, list): raw_safety = " ".join(str(x) for x in raw_safety)
                llm_patch_safety = str(raw_safety).strip()

                # ── Council verdict: advisory, not a hard gate ──
                # A 0/2 vote from two small local reviewers is subjective and (per the
                # reviewer-context asymmetry bug) over-rejects legitimate multi-line
                # fixes. It must NOT pre-empt the DETERMINISTIC verify gate below
                # (verify_static: re-scan finding-gone + node --check syntax + blast
                # radius, with automatic rollback on FAIL). So: only hard-skip when
                # there is literally no code to try; when a concrete fix exists, note
                # the dissent and let the objective gate be the real arbiter.
                if llm_patch_safety == "rejected":
                    if not str(patch_pkg.get("fixed_code", "")).strip():
                        console.print(
                            f"[bold red][BLOCKED][/bold red] AI Council rejected and there is "
                            f"no code to apply ({justifications})."
                        )
                        skipped += 1
                        continue
                    self._vconsole(
                        f"[yellow][COUNCIL-DISSENT][/yellow] {justifications} — deferring to the "
                        f"objective verification gate (re-scan + syntax + rollback)."
                    )

                self._vconsole(Panel(
                    f"[bold red]Root Cause:[/bold red] {analysis}\n\n"
                    f"[bold green]Justifications:[/bold green] {justifications}",
                    title="Vulnerability Analysis", border_style="cyan", padding=(1, 2)
                ))

                fixed_raw = patch_pkg.get("fixed_code", "")
                if isinstance(fixed_raw, list): fixed_raw = "\n".join(str(x) for x in fixed_raw)
                fixed = str(fixed_raw).strip()
                if not fixed:
                    console.print(f"[yellow][SKIP][/yellow] Model did not return fixed code\n")
                    skipped += 1
                    continue

            # ── Show diff ──
            safety_notes = self._assess_patch_safety(v, p["snippet"], fixed)
            diff_text = Text()
            for ol in p["snippet"].split("\n"):
                if ol.strip(): diff_text.append(f"- {ol[:120]}\n", style="red")
            for nl in fixed.split("\n"):
                if nl.strip(): diff_text.append(f"+ {nl[:120]}\n", style="green")
            self._vconsole(Panel(diff_text, title=f"Proposed Changes ({fix_source.upper()})", border_style="yellow"))

            # ── User approval ──
            # Treat a non-TTY stdin (piped / CI) as non-interactive too — otherwise
            # input() hits EOF, choice becomes "n", and every patch is silently
            # skipped. apply_patch still backs up + node --check + rolls back, and
            # verify_static gates the score, so auto-apply here is safe.
            if self.non_interactive or not sys.stdin.isatty():
                choice = "y"
                self._vconsole(f"[dim]non-interactive mode: auto applying patch[/dim]")
            else:
                print(f"\n  {C.Y}Apply this patch? (y/n/q):{C.RST} ", end="")
                try:
                    choice = input().strip().lower()
                except EOFError:
                    choice = "n"
            if choice == "q": break
            if choice != "y":
                skipped += 1
                console.print(f"[dim][SKIPPED][/dim]\n")
                continue

            # ── Step C: Apply using V2 applier (with backup + syntax check) ──
            original_content = open(p["filepath"], "r", encoding="utf-8", errors="ignore").read()

            if use_v2:
                # Apply over the SAME 1-indexed inclusive range that was shown to the
                # operator in the "Vulnerable Code" / diff panels above (start_l/end_l,
                # 0-indexed with end_l exclusive) — not just the single vuln line —
                # otherwise the other lines in the displayed window are left untouched
                # while `fixed` (which may span multiple lines) only replaces one line.
                apply_result = apply_patch(p["filepath"], p["start_l"] + 1, p["end_l"], fixed)
                if not apply_result.success or not apply_result.parse_valid:
                    if apply_result.success:
                        console.print(f"[bold red][REJECTED][/bold red] Syntax error in patched file — rolling back")
                        rollback(p["filepath"], original_content)
                    else:
                        console.print(f"[bold red][REJECTED][/bold red] Apply failed: {apply_result.error}")
                    skipped += 1
                    # A patch rejected at APPLY time is a failure too. Only the
                    # verification gate used to record one, so patches_failed
                    # stayed 0 after a syntax rollback and the next scan learned
                    # nothing from it.
                    _record_patch_failure(
                        p, i, fix_source, fixed,
                        apply_result.error or "patch produced invalid syntax",
                    )
                    # A memory-sourced patch that just failed a hard, deterministic
                    # gate (structural integrity, or syntax) is a POISONED cache
                    # entry, not a one-off bad model output — it was stored once
                    # under "verified" and would otherwise be replayed verbatim on
                    # every future scan forever. Purge it so the next scan falls
                    # back to real generation instead of repeating the same break.
                    if fix_source == "memory" and patch_memory:
                        patch_memory.invalidate(p["cwe"], p.get("snippet_fn", p["snippet"]))
                        self._vconsole(
                            f"[dim]  ⚠ poisoned patch-memory entry for {p['cwe']} purged — "
                            f"will regenerate next time[/dim]"
                        )
                    continue
            else:
                # Legacy apply
                import tempfile
                ext = os.path.splitext(p["filepath"])[1].lower()
                test_lines = p["lines"].copy()
                for j in range(p["start_l"], p["end_l"]):
                    test_lines[j] = ""
                test_lines[p["start_l"]] = fixed + "\n"
                test_content = "".join(test_lines)
                syntax_passed = True
                if ext in ['.js', '.ts', '.py']:
                    with tempfile.NamedTemporaryFile(suffix=ext, mode='w', delete=False, encoding='utf-8') as tf:
                        tf.write(test_content); tf_name = tf.name
                    try:
                        # sys.executable, not the literal "python" — many Linux
                        # distros (Debian/Ubuntu w/o python-is-python3, Arch,
                        # current Alpine) and macOS since Catalina have no bare
                        # "python" on PATH at all. A FileNotFoundError here was
                        # silently swallowed by the except below, leaving
                        # syntax_passed at its default True — i.e. the
                        # syntax-safety gate silently never ran before a patch
                        # was written to disk. Same fix already used correctly
                        # two lines away at the static-server fallback (~1088).
                        cmd = ["node", "-c", tf_name] if ext in ['.js', '.ts'] else [sys.executable, "-m", "py_compile", tf_name]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                        if result.returncode != 0: syntax_passed = False
                    except Exception: pass
                    finally:
                        if os.path.exists(tf_name): os.unlink(tf_name)
                if not syntax_passed:
                    console.print(f"[bold red][REJECTED][/bold red] Syntax error in proposed patch")
                    skipped += 1; continue
                lines = p["lines"]
                for j in range(p["start_l"], p["end_l"]): lines[j] = ""
                lines[p["start_l"]] = fixed + "\n"
                with open(p["filepath"], "w", encoding="utf-8") as f: f.writelines(lines)

            # ── Step D: Verification Gate (V2 only) ──
            patched_content = open(p["filepath"], "r", encoding="utf-8", errors="ignore").read()
            verify_verdict = "UNVERIFIED"

            if use_v2:
                loc = p.get("location")
                # Severity-scaled blast radius: Critical vulns need more room for proper fixes
                sev_blast_cap = {"Critical": 80, "High": 60, "Medium": 40, "Low": 30}.get(
                    v.severity, 40
                )
                vr = verify_static(
                    loc, v, self.source_dir,
                    parse_valid=True,
                    original_content=original_content,
                    patched_content=patched_content,
                    blast_radius_cap=sev_blast_cap,
                )
                verify_verdict = vr.verdict
                self._emit("patch_verdict", cwe=p["cwe"], file=p["rel_path"], verdict=vr.verdict)

                verdict_color = "green" if vr.verdict == "PASS" else "yellow" if vr.verdict == "UNVERIFIABLE" else "red"
                verdict_icon = "✅" if vr.verdict == "PASS" else "⚠️" if vr.verdict == "UNVERIFIABLE" else "❌"
                
                # Build human-readable check results
                check = lambda ok: "[green]✓ PASS[/green]" if ok else "[red]✗ FAIL[/red]"
                self._vconsole(Panel(
                    f"[bold]{verdict_icon} Verdict: [{verdict_color}]{vr.verdict}[/{verdict_color}][/bold]\n\n"
                    f"[bold]Sub-checks:[/bold]\n"
                    f"  {check(vr.finding_gone)}  Finding Gone    — Re-scanned: vulnerability {'eliminated' if vr.finding_gone else 'STILL PRESENT'}\n"
                    f"  {check(vr.builds)}  Syntax Valid    — Patched code {'compiles' if vr.builds else 'has SYNTAX ERRORS'}\n"
                    f"  {check(vr.no_suppression)}  No Suppression  — {'Clean fix (no noqa/eslint-disable)' if vr.no_suppression else 'Patch ADDED suppression comments'}\n"
                    f"  {check(vr.blast_ok)}  Blast Radius    — Diff {'within' if vr.blast_ok else 'EXCEEDS'} {sev_blast_cap}-line cap ({v.severity})\n"
                    f"  {check(vr.structure_ok)}  Structure Preserved — {'No route/fn/class removed' if vr.structure_ok else 'A route/fn/class was DELETED'}\n"
                    + (f"\n[dim]Evidence: {vr.evidence}[/dim]" if vr.evidence else ""),
                    title="◈ VERIFICATION GATE", border_style=verdict_color
                ))

                if vr.verdict == "FAIL":
                    rollback(p["filepath"], original_content)
                    console.print(f"[bold red][ROLLED BACK][/bold red] Verification failed — patch reverted")
                    skipped += 1
                    # Learn from the FAILURE too. The Session Memory panel promises
                    # "Successful & failed patches are recorded as lessons", but the
                    # `continue` here used to skip the recorder below — so
                    # patches_failed stayed 0 and no "what NOT to do" lesson was ever
                    # captured. Record it before bailing.
                    _why = (
                        "finding still present" if not getattr(vr, "finding_gone", True)
                        else "route/function/class deleted" if not getattr(vr, "structure_ok", True)
                        else "syntax/blast-radius check"
                    )
                    _record_patch_failure(p, i, fix_source, fixed, f"verification: {_why}")
                    # Same poisoned-cache purge as the apply-time rejection above —
                    # this branch is reached when the patch DID apply and DID pass
                    # syntax, but verify_static's independent structure check (or
                    # rescan) still caught it. Equally poisoned, equally must not
                    # survive to the next scan.
                    if fix_source == "memory" and patch_memory:
                        patch_memory.invalidate(p["cwe"], p.get("snippet_fn", p["snippet"]))
                        self._vconsole(
                            f"[dim]  ⚠ poisoned patch-memory entry for {p['cwe']} purged — "
                            f"will regenerate next time[/dim]"
                        )
                    continue

                verified_count += 1 if vr.verdict == "PASS" else 0
                if vr.verdict == "PASS":
                    # Clear every finding that pointed at this exact line, not
                    # only the highest-severity one we kept in Phase 1.3.
                    remediated_vuln_ids.update(p.get("sibling_ids") or [id(v)])

                # Record in manifest
                if manifest:
                    manifest.record(
                        rel_path=p["rel_path"], line=p["line_num"], cwe=p["cwe"],
                        vuln_type=p["vuln_type"], verdict=vr.verdict,
                        original_hash=hashlib.sha256(original_content.encode()).hexdigest()[:16],
                        patched_hash=hashlib.sha256(patched_content.encode()).hexdigest()[:16],
                        exploit_payload=getattr(v, "payload", ""),
                    )

                # Store in patch memory for future reuse
                if patch_memory and vr.verdict == "PASS":
                    patch_memory.store(p["cwe"], p.get("snippet_fn", p["snippet"]), fixed, fix_source, verified=True)
                    if COGNEE_AVAILABLE:
                        # QUEUE the cross-project persist; drain it once AFTER the
                        # patch loop. cognify() runs a multi-minute local-LLM
                        # extraction, so awaiting it inline here froze remediation
                        # of every remaining vuln for up to COGNEE_REMEMBER_TIMEOUT_S
                        # each — the whole scan appeared to hang. Draining after the
                        # loop keeps remediation interactive; the fixes are already
                        # persisted to the fast patch_memory cache above regardless.
                        cognee_jobs.append(dict(
                            cwe=p["cwe"],
                            vulnerable_code=p.get("snippet_fn", p["snippet"]),
                            fixed_code=fixed,
                            project_id=cognee_memory.project_id_for(getattr(self, "repo_url", "") or "", os.path.abspath(self.local_path) if getattr(self, "local_path", None) else self.source_dir),
                            framework=framework,
                        ))

                # ── Record in session memory ──
                if session and REASONING_AVAILABLE:
                    entry = ReasoningEntry(
                        vuln_id=f"vuln_{i:03d}",
                        cwe=p["cwe"],
                        file=p["rel_path"],
                        line=p["line_num"],
                        strategy_used=fix_source,
                        verdict=vr.verdict,
                        patch_hash=hashlib.sha256(fixed.encode()).hexdigest()[:12],
                        fix_source=fix_source,
                    )
                    session.add_entry(entry)

                    # Auto-learn lessons from verified patches
                    if vr.verdict == "PASS":
                        lesson = f"{p['cwe']} in {os.path.basename(p['rel_path'])} fixed via {fix_source}"
                        session.add_lesson(lesson)
                        # Record the CWE→strategy pair as a reusable pattern.
                        # add_pattern() previously had no callers, so
                        # common_patterns (surfaced in get_prior_context) was
                        # always empty; this feeds the cross-scan hint.
                        session.add_pattern(f"{p['cwe']}:{fix_source}")

                    # Build reasoning tree for this patch
                    tree = create_tree(
                        thread_id=thread_id, vuln_cwe=p["cwe"],
                        vuln_type=p["vuln_type"], file_path=p["rel_path"],
                        line=p["line_num"], strategy=fix_source,
                        model="council" if fix_source == "council" else "template",
                    )
                    tree.build_cot_tree(
                        vuln_description=f"{p['vuln_type']} at {p['rel_path']}:{p['line_num']}",
                        thinking_steps=[f"Identified {p['cwe']} vulnerability", f"Applied {fix_source} fix"],
                        final_action=fixed[:500],
                        verify_result={"verdict": vr.verdict, "finding_gone": vr.finding_gone,
                                       "builds": vr.builds, "blast_ok": vr.blast_ok},
                    )
                    tree.final_patch = fixed[:1000]
                    tree.verdict = vr.verdict
                    save_tree(tree, self.source_dir)

            patched_files.append(p["rel_path"])
            console.print(f"[green][APPLIED][/green] Patch applied to {p['rel_path']} [dim]({fix_source})[/dim]\n")

            # NOTE: Disabled write-back to original source directory.
            # Patches are applied in the sandbox copy (self.source_dir).
            # Copying back was causing corruption of demo source files
            # because badly-applied patches would overwrite the originals,
            # breaking subsequent scans.
            # if hasattr(self, "local_path") and self.local_path:
            #     dst_orig = os.path.join(os.path.abspath(self.local_path), p["rel_path"])
            #     if os.path.exists(dst_orig):
            #         import shutil
            #         shutil.copy2(p["filepath"], dst_orig)

        # ── Drain cross-project memory persists (deferred cognify) ──
        # Serial, not concurrent: parallel cognify() calls contend on the same
        # lancedb/graph dataset. This runs after all patches are shown/applied,
        # so a slow local-LLM extraction never blocks remediation.
        if cognee_jobs:
            self._vconsole(
                f"[dim]Persisting {len(cognee_jobs)} verified fix(es) into cross-project memory "
                f"(cognee) — this runs post-remediation…[/dim]"
            )
            _persisted = 0
            for _job in cognee_jobs:
                try:
                    await asyncio.wait_for(
                        cognee_memory.remember_fix(**_job),
                        timeout=cyphex_config.COGNEE_REMEMBER_TIMEOUT_S,
                    )
                    _persisted += 1
                    self._emit("cognee_persist_result", ok=True)
                except (asyncio.TimeoutError, TimeoutError):
                    self._emit("cognee_persist_result", ok=False, reason="timeout")
                    self._vconsole(
                        f"[dim]cognee remember skipped: timed out after "
                        f"{cyphex_config.COGNEE_REMEMBER_TIMEOUT_S:.0f}s "
                        f"(cognify LLM extraction too slow)[/dim]"
                    )
                except Exception as e:
                    # str(e) is empty for many cognee/asyncio errors — show the
                    # type so "remember skipped:" is never a blank, useless line.
                    self._emit("cognee_persist_result", ok=False, error=str(e)[:200])
                    self._vconsole(f"[dim]cognee remember skipped: {type(e).__name__}: {e}[/dim]")
            console.print(f"[dim]cognee memory: {_persisted}/{len(cognee_jobs)} fix(es) persisted.[/dim]")

        # ── Summary Panel ──
        console.print(Panel(
            f"[bold]Patch Results:[/bold]\n"
            f"  ✅ Applied:    [green]{len(patched_files)}[/green]\n"
            f"  ⏭️  Skipped:    [yellow]{skipped}[/yellow]\n"
            + (f"  ✓  Verified:   [cyan]{verified_count}[/cyan]\n"
               f"  🔧 Templates:  [magenta]{template_count}[/magenta]" if use_v2 else ""),
            title="◈ PATCH SUMMARY", border_style="bright_cyan", padding=(1, 2)
        ))

        if use_v2 and manifest:
            stats = manifest.get_durability_stats()
            if stats.get("total", 0) > 0:
                console.print(Panel(
                    f"[bold]Total patches:[/bold] {stats['total']}  "
                    f"[green]Verified:[/green] {stats.get('verified', 0)}  "
                    f"[yellow]Unverified:[/yellow] {stats.get('unverified', 0)}  "
                    f"[bold]Durability:[/bold] {stats.get('durability_pct', 0):.0f}%",
                    title="◈ PATCH MANIFEST", border_style="bright_cyan"
                ))

        # ── Save Session Memory ──
        if session and REASONING_AVAILABLE:
            saved_path = save_session(session, self.source_dir)
            reasoning_stats = ""
            if reasoner:
                stats = reasoner.get_stats()
                usage = stats.get("strategy_usage", {})
                if usage:
                    strat_lines = ", ".join(f"{k}×{v}" for k, v in usage.items())
                    reasoning_stats = (
                        f"\n[bold]Reasoning Stats:[/bold]\n"
                        f"  Calls: {stats['calls']}  |  Avg: {stats['avg_time_ms']:.0f}ms  |  Total: {stats['total_time_ms']:.0f}ms\n"
                        f"  Strategies used: {strat_lines}"
                    )
            console.print(Panel(
                f"[bold]Thread ID:[/bold]        [cyan]{thread_id}[/cyan]\n"
                f"[bold]Session:[/bold]          {saved_path}\n"
                f"[bold]This scan:[/bold]        {len(patched_files)} applied · {verified_count} verified · {skipped} skipped\n"
                f"[bold]Lifetime:[/bold]        "
                f"{session.model_context.get('patches_attempted', 0)} attempted · "
                f"{session.model_context.get('patches_applied', 0)} applied "
                f"[dim](all scans of this repo)[/dim]\n"
                f"[bold]Lifetime verified:[/bold] {session.model_context.get('patches_verified', 0)}  "
                f"[bold]failed:[/bold] {session.model_context.get('patches_failed', 0)}\n"
                f"[bold]Lessons learned:[/bold]  {len(session.model_context.get('lessons', []))}"
                + reasoning_stats +
                f"\n\n[dim]Session persisted — will be loaded on next scan for continuity[/dim]",
                title="◈ SESSION MEMORY SAVED", border_style="bright_green", padding=(1, 2)
            ))


        # ── After-Patching Score ──
        # Match by vulnerability identity (remediated_vuln_ids), NOT a substring
        # match against file paths — a substring match would incorrectly treat
        # every OTHER finding in a patched file as "fixed" too, and would count
        # UNVERIFIABLE patches as remediated even though they were never confirmed.
        remaining = [v for v in vulns if id(v) not in remediated_vuln_ids]
        remaining_vulns = len(remaining)
        crit_a = sum(1 for v in remaining if v.severity == "Critical")
        high_a = sum(1 for v in remaining if v.severity == "High")
        med_a  = sum(1 for v in remaining if v.severity == "Medium")
        low_a  = sum(1 for v in remaining if v.severity in ("Low", "Info"))
        # Same function as score_before — not a hand-copied set of coefficients.
        score_after = security_score(crit_a, high_a, med_a, low_a)
        # Final guard: 0 patches ⇒ 0 improvement
        if not patched_files:
            score_after = score_before

        delta = score_after - score_before
        delta_color = "green" if delta > 0 else "yellow" if delta == 0 else "red"
        delta_str = f"+{delta}" if delta > 0 else str(delta)

        bar_b = int(score_before / 100 * 25)
        bar_a = int(score_after / 100 * 25)
        # Same thresholds as terminal_ui.score_color / _verdict, so a score is
        # never yellow here and "FAIR" in the banner.
        def _band(sc):
            return "red" if sc < 40 else "yellow" if sc < 60 else "cyan" if sc < 80 else "green"
        sc_b_color = _band(score_before)
        sc_a_color = _band(score_after)

        console.print(Panel(
            f"  [bold]Before Patching:[/bold]  [{sc_b_color}]{'█' * bar_b}{'░' * (25 - bar_b)}  {score_before}/100[/{sc_b_color}]\n"
            f"  [bold]After Patching:[/bold]   [{sc_a_color}]{'█' * bar_a}{'░' * (25 - bar_a)}  {score_after}/100[/{sc_a_color}]\n\n"
            f"  [bold]Improvement:[/bold]  [{delta_color}]{delta_str} points[/{delta_color}]  │  "
            f"Cleared: [green]{len(vulns) - len(remaining)}[/green]/{len(vulns)}  "
            f"Applied: [green]{len(patched_files)}[/green]  Remaining: [yellow]{len(remaining)}[/yellow]\n\n"
            f"  [bold]Remaining Vulnerabilities:[/bold]\n"
            f"    🔴 Critical: {crit_a}    🟠 High: {high_a}    🟡 Medium: {med_a}    🟢 Low: {low_a}\n\n"
            f"  [dim]Score = 100 − severity-weighted penalties (higher = safer)[/dim]\n"
            f"  [dim]Only VERIFIED patches (re-scanned + syntax-checked) affect the score[/dim]",
            title="[bold cyan]◈ SECURITY SCORE: BEFORE vs AFTER ◈[/bold cyan]",
            border_style="cyan", padding=(1, 2)
        ))

        # Save post-patch score for final banner
        self._post_patch_score = score_after
        self._post_patch_remaining = remaining
        # Wire the REAL patch counts into the final INTERCEPT banner. Without this
        # the banner reads getattr(self, '_patches_applied', 0) == 0/0 APPLIED even
        # though patches were actually applied (contradicting the PATCH SUMMARY).
        self._patches_applied = len(patched_files)
        # Denominator = every finding that actually entered the patch loop.
        # applied+skipped silently omitted findings that were never attempted
        # (runtime-only, or collapsed into a sibling at the same line), so a
        # scan that confirmed 7 vulnerabilities could report "2/3 APPLIED".
        self._patches_total = len(patchable)
        self._patches_unpatchable = len(dynamic_only)
        _killed = [v for v in vulns if id(v) in remediated_vuln_ids]
        self._killed_counts = (
            sum(1 for v in _killed if v.severity == "Critical"),
            sum(1 for v in _killed if v.severity == "High"),
            sum(1 for v in _killed if v.severity == "Medium"),
            sum(1 for v in _killed if v.severity in ("Low", "Info")),
        )

        if patched_files and self.repo_url and not self.non_interactive:
            print(f"\n  {C.Y}Push patches to GitHub? (y/n):{C.RST} ", end="")
            try:
                push = input().strip().lower()
            except EOFError:
                push = "n"
            if push == "y":
                self._push_to_github()

    async def _get_llm_fix_package(self, vuln, code_snippet, filepath) -> Optional[dict[str, str]]:
        """Try Ollama (local LLM) first, then fall back to built-in rule-based patches."""
        # Dynamically select best patcher model
        try:
            from backend.council.model_selector import get_selector
            selector = await get_selector(quiet=True)
            model_name = os.getenv("OLLAMA_MODEL", selector.get("patcher"))
        except Exception:
            model_name = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
        prompt = (
            "You are a Senior Cyber Security Engineer and Secure Code Expert. "
            "Your task is to analyze the following vulnerability, think step-by-step about the root cause and how to fix it, "
            "and then provide a professional, structured JSON response.\n\n"
            "CRITICAL RULES:\n"
            "1. You MUST enclose your step-by-step thinking inside <thinking> ... </thinking> tags.\n"
            "2. After the thinking block, you MUST output a single valid JSON object with the following keys:\n"
            "   - \"vulnerability_analysis\": Professional explanation of the root cause and business risk.\n"
            "   - \"fixed_code\": The exact, drop-in replacement code that fixes the issue.\n"
            "   - \"justifications\": Why your code changes successfully mitigate the risk.\n"
            "   - \"patch_safety\": Any side-effects or manual testing required after applying.\n\n"
            f"Vulnerability: {vuln.name}\n"
            f"File: {filepath}\n"
            "Original code:\n"
            f"{code_snippet}\n"
        )

        # 1. Try Ollama (local model)
        try:
            if MASCOT:
                # Covers the otherwise-silent gap between issuing the request
                # and the first response headers arriving; handed off to the
                # Rich "Thinking" Live panel below the moment headers land, so
                # the two redraw loops never run at the same time.
                mascot.thinking(f"{model_name} — contacting Ollama...")
            async with httpx.AsyncClient(timeout=90) as client:
                async with client.stream(
                    "POST",
                    "http://127.0.0.1:11434/api/generate",
                    json={"model": model_name, "prompt": prompt, "stream": True}
                ) as resp:
                    if MASCOT:
                        mascot.stop()
                    if resp.status_code == 200:
                        raw = ""
                        thinking_text = ""
                        from rich.live import Live
                        with Live(Panel("Initializing AI Analysis...", title=f"{model_name} Thinking", style="dim italic"), refresh_per_second=10) as live:
                            async for chunk in resp.aiter_lines():
                                if not chunk: continue
                                try:
                                    data = json.loads(chunk)
                                    token = data.get("response", "")
                                    raw += token
                                    if "<thinking>" in raw and "</thinking>" not in raw:
                                        thinking_text = raw.split("<thinking>")[-1]
                                        live.update(Panel(thinking_text, title=f"{model_name} Thinking", style="dim italic", box=ROUNDED))
                                    elif "</thinking>" in raw and thinking_text != "Done":
                                        live.update(Panel(thinking_text + "\n\n[bold green]✓ Analysis Complete[/bold green]", title=f"{model_name} Thinking", style="dim italic", box=ROUNDED))
                                        thinking_text = "Done"
                                except json.JSONDecodeError:
                                    pass

                        parsed = self._extract_json_object(raw)
                        if isinstance(parsed, dict):
                            return {
                                "unsafe_reason": str(parsed.get("vulnerability_analysis", "")).strip(),
                                "fixed_code": str(parsed.get("fixed_code", "")).strip(),
                                "justifications": str(parsed.get("justifications", "")).strip(),
                                "patch_safety": str(parsed.get("patch_safety", "")).strip(),
                            }
                        m = re.search(r"```(?:\w+)?\n(.*?)```", raw, re.DOTALL)
                        fixed = m.group(1).strip() if m else raw
                        if fixed:
                            return {
                                "unsafe_reason": "Model returned code without structured rationale.",
                                "fixed_code": fixed,
                                "justifications": "N/A",
                                "patch_safety": "Review manually before merge.",
                            }
        except Exception as e:
            if MASCOT:
                mascot.error("Ollama unavailable")
            console.print(f"  [yellow][INFO] Ollama unavailable ({str(e)[:50]}). Using built-in patch rules.[/yellow]")

        # 2. Fallback: Rule-based patches (works 100% offline)
        result = self._rule_based_patch(vuln, code_snippet)
        # Phase 1.5 (kills R6): never return comment-as-code / placeholder fixes.
        # Several built-in rules emit `// Use parameterized queries:` style
        # comments as `fixed_code`; applying those deletes real code and leaves a
        # comment. Real deterministic transforms arrive in Phase 5; until then a
        # placeholder result is treated as "no patch" (manual review).
        if result and self._is_placeholder_code(result.get("fixed_code", "")):
            return None
        if result:
            print(f"  {C.G}[OK]{C.RST} Generated patch using built-in security rules (no LLM needed)")
        return result

    @staticmethod
    def _is_placeholder_code(fixed: str) -> bool:
        """
        True if `fixed` is effectively a comment/placeholder rather than real
        code. Used to block R6 (comment-as-code) patches from being written.
        """
        if not fixed or not fixed.strip():
            return True
        comment_prefixes = ("//", "#", "/*", "*", "<!--")
        code_lines = [ln.strip() for ln in fixed.splitlines() if ln.strip()]
        if not code_lines:
            return True
        # Placeholder if every non-blank line is a comment (the R6 pattern:
        # the built-in rules emit "// Use parameterized queries:" as fixed_code).
        return all(ln.startswith(comment_prefixes) for ln in code_lines)


    def _rule_based_patch(self, vuln, snippet) -> Optional[dict[str, str]]:
        """Deterministic template transforms for common CWEs. No template => None."""
        if not PATCH_PIPELINE_AVAILABLE:
            return None

        cwe = (getattr(vuln, "cwe", "") or "").upper().strip()
        if not cwe:
            name_lower = (getattr(vuln, "name", "") or "").lower()
            if "sql" in name_lower:
                cwe = "CWE-89"
            elif "xss" in name_lower:
                cwe = "CWE-79"
            elif "command" in name_lower or "cmdi" in name_lower:
                cwe = "CWE-78"
            elif "path traversal" in name_lower or "lfi" in name_lower:
                cwe = "CWE-22"
            elif "hardcoded" in name_lower or "secret" in name_lower:
                cwe = "CWE-798"
            elif "cors" in name_lower:
                cwe = "CWE-942"

        try:
            from backend.patch import templates as patch_templates
            # NB: the module exposes apply_template(cwe, code, framework), not
            # apply(cwe, file_hint, snippet) — the old call raised AttributeError
            # (swallowed below) so this deterministic fallback always returned None.
            fixed = patch_templates.apply_template(cwe, snippet)
            if not fixed:
                return None
            return {"fixed_code": fixed, "fix_source": "template"}
        except Exception:
            return None

    def _extract_json_object(self, text: str) -> Optional[dict[str, Any]]:
        text = text.strip()
        if not text:
            return None
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z0-9_-]*\\n", "", text)
            text = re.sub(r"\\n```$", "", text)
            
        def _sanitize(obj):
            if isinstance(obj, dict):
                return {k: _sanitize(v) for k, v in obj.items()}
            if isinstance(obj, list) and len(obj) > 0 and all(isinstance(x, str) for x in obj):
                return "\n".join(obj)
            return obj

        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return _sanitize(obj)
        except Exception:
            pass
            
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
            return _sanitize(obj) if isinstance(obj, dict) else None
        except Exception:
            return None

    def _assess_patch_safety(self, vuln, original: str, fixed: str) -> list[str]:
        """Lightweight static checks that compare risky patterns before/after."""
        notes = []
        lowered = (vuln.name or "").lower()

        if "sql" in lowered:
            if re.search(r"SELECT|INSERT|UPDATE|DELETE", original, re.IGNORECASE) and not re.search(r"\?|%s|execute\([^\)]*,", fixed):
                notes.append("Patch may still build SQL dynamically; prefer parameterized queries.")
            else:
                notes.append("Patch appears to move toward parameterized SQL handling.")

        if "xss" in lowered:
            if "innerHTML" in fixed and "sanitize" not in fixed.lower():
                notes.append("Patch still uses innerHTML without explicit sanitization.")
            else:
                notes.append("Patch appears to reduce direct script injection risk.")

        if "command" in lowered:
            if re.search(r"exec\(|system\(|shell=True", fixed):
                notes.append("Patch still uses shell execution primitives; review command construction.")
            else:
                notes.append("Patch appears to reduce shell injection surface.")

        if not notes:
            notes.append("Manual review required: heuristic safety check had no specific rule for this vuln type.")

        return notes

    def _autonomy_status(self) -> tuple[str, str]:
        """Phase 7 autonomy ladder + degradation honesty summary."""
        stats = getattr(self, "_patch_run_stats", None) or {}
        verified = int(stats.get("verified", 0))
        unverified = int(stats.get("unverified", 0))
        rolled_back = int(stats.get("rolled_back", 0))
        rag_enabled = bool(stats.get("rag_enabled", False))
        verifier_enabled = bool(stats.get("verifier_enabled", False))

        if verified > 0 and unverified == 0 and rolled_back == 0 and verifier_enabled:
            level = "L4 fully-verified"
            reason = "All applied patches were objectively verified."
        elif verified > 0 and verifier_enabled:
            level = "L3 guarded-autonomy"
            reason = "Some fixes verified; unverified ones require human review."
        elif verifier_enabled:
            level = "L2 assisted"
            reason = "Patching ran with verification gate, but no fix reached PASS yet."
        else:
            level = "L1 degraded"
            reason = "Verification pipeline unavailable; CYPHEX avoided claiming fixed status."

        if not rag_enabled:
            reason += " RAG context disabled (fallback prompt path)."

        return level, reason

    def _push_to_github(self):
        try:
            # Check if there are any changes to commit first
            status_check = subprocess.run(["git", "status", "--porcelain"], cwd=self.source_dir, capture_output=True, text=True)
            if not status_check.stdout.strip():
                print(f"  {C.Y}[INFO]{C.RST} No changes to commit. Skipping push.")
                return

            for cmd in [["git","add","-A"],["git","commit","-m","fix: CYPHEX auto-patched security vulnerabilities", "--no-verify"],["git","push"]]:
                r = subprocess.run(cmd, cwd=self.source_dir, capture_output=True, text=True)
                if r.returncode != 0:
                    print(f"  {C.R}[ERR]{C.RST} {' '.join(cmd)}: {r.stderr[:100]} {r.stdout[:100]}")
                    return

            remote_url = ""
            rr = subprocess.run(["git", "remote", "get-url", "origin"], cwd=self.source_dir, capture_output=True, text=True)
            if rr.returncode == 0:
                remote_url = rr.stdout.strip().replace(".git", "")

            print(f"  {C.G}[OK]{C.RST} Branch pushed: {branch}")
            if remote_url.startswith("https://github.com/"):
                print(f"  {C.CYAN}Open PR:{C.RST} {remote_url}/compare/{branch}?expand=1")
            else:
                print(f"  {C.Y}[INFO]{C.RST} Open a Pull Request from branch {branch} in your Git host.")
        except Exception as e:
            print(f"  {C.R}[ERR]{C.RST} Push failed: {e}")

    def _final_banner(self):
        self._emit("scan_end")
        # Cleanup Docker Compose if used
        if hasattr(self, '_docker_compose_dir') and self._docker_compose_dir:
            try:
                subprocess.run(
                    ["docker", "compose", "down", "--remove-orphans"],
                    cwd=self._docker_compose_dir,
                    capture_output=True, timeout=30
                )
            except Exception:
                pass

        elapsed = time.time() - self.start_ts

        # Use post-patch score if available, otherwise calculate from raw vulns
        if hasattr(self, '_post_patch_score') and self._post_patch_score is not None:
            score = self._post_patch_score
            remaining = getattr(self, '_post_patch_remaining', [])
            crit = sum(1 for v in remaining if v.severity == "Critical")
            high = sum(1 for v in remaining if v.severity == "High")
            med = sum(1 for v in remaining if v.severity == "Medium")
            low = sum(1 for v in remaining if v.severity in ("Low", "Info"))
        else:
            vulns = self.context.confirmed_vulns if self.context else []
            crit = sum(1 for v in vulns if v.severity == "Critical")
            high = sum(1 for v in vulns if v.severity == "High")
            med = sum(1 for v in vulns if v.severity == "Medium")
            low = sum(1 for v in vulns if v.severity in ("Low", "Info"))
            score = security_score(crit, high, med, low)

        endpoints = len(self.context.all_endpoints) if self.context else 0
        pa = getattr(self, '_patches_applied', 0)
        pt = getattr(self, '_patches_total', 0)

        if SOC_UI:
            ui.render_final_banner(score, crit, high, med, low, elapsed,
                                   self.scan_id, pa, pt, endpoints,
                                   killed=getattr(self, "_killed_counts", None),
                                   unpatchable=getattr(self, "_patches_unpatchable", 0))
            return

        # Fallback: original ANSI rendering. Label/band from scoring.score_band()
        # — the single source of truth for the 20/40/60/80 cutoffs; only the
        # ANSI colour per label is local to this render site.
        sc_label, _tier = _score_band(score)
        sc = {
            "SECURE": C.NEON, "FAIR": C.CYAN, "AT RISK": C.Y,
            "POOR": C.R, "CRITICAL": C.FLAME,
        }[sc_label]
        total = crit + high + med + low
        border = C.gradient("━" * 72, 138, 43, 226, 0, 255, 255)
        border2 = C.gradient("━" * 72, 0, 255, 255, 138, 43, 226)
        print(f"\n{border}")
        print(f"  {C.NEON}✓{C.RST} {C.BOLD}{C.CYAN}CYPHEX SCAN COMPLETE{C.RST}")
        print(f"{border2}\n")
        bar_filled = int(score / 100 * 30)
        bar_empty = 30 - bar_filled
        score_bar = f"{sc}{'█' * bar_filled}{C.GHOST}{'░' * bar_empty}{C.RST}"
        print(f"{sc}{C.BOLD}  ╔═══════════╗  {C.RST}")
        print(f"{sc}{C.BOLD}  ║  {score:3d}/100   ║  {sc_label}{C.RST}")
        print(f"{sc}{C.BOLD}  ╚═══════════╝  {C.RST}")
        print(f"\n  {score_bar}\n")
        if total > 0:
            print(f"  {C.BOLD}Vulnerabilities Found:{C.RST}")
            print(f"    {C.FLAME}🔴 Critical: {crit}{C.RST}    {C.R}🟠 High: {high}{C.RST}    {C.Y}🟡 Medium: {med}{C.RST}    {C.SLATE}🟢 Low: {low}{C.RST}")
        print(f"\n{border}")
        print(f"  {C.PURP2}cyphex{C.RST} {C.GHOST}— Multi-Agent Security Pipeline v4.3{C.RST}")
        print(f"{border2}\n")
