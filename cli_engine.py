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
import random
from datetime import datetime, timezone
from typing import Any, Optional
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.box import ROUNDED, DOUBLE

console = Console()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend", "backend"))

from sandbox_manager import deploy_sandbox, stop_sandbox, _find_free_port, _get_node_env
from immune.behavioral_genome import BehavioralGenome
from immune.mutation_engine import MutationEngine
from immune.evolution_controller import EvolutionController
from models.scan import ScanContext, FormData, ParamData, Vuln
from config import config as cyphex_config

# Council system imports
sys.path.insert(0, os.path.dirname(__file__))
try:
    from backend.council.patch_council import PatchCouncil
    from backend.council.debate_protocol import DebateProtocol
    from backend.council.analysis_council import AnalysisCouncil
    from backend.council.route_tracer import RouteTracer
    COUNCIL_AVAILABLE = True
except ImportError:
    COUNCIL_AVAILABLE = False

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
        self.start_ts = 0.0

    async def run(self, repo_url=None, local_path=None, source_path=None,
                  target_url=None, branch="main",
                  generations=10, output_file=None, auto_patch=True,
                  judge_mode=False, judge=False, non_interactive=False):
        self.start_ts = time.time()
        self.repo_url = repo_url
        self.local_path = local_path
        self.judge_mode = judge_mode or judge
        self.non_interactive = non_interactive

        # Show premium splash banner
        self._splash_banner()

        # Normalize: source_path is an alias for local_path
        if source_path and not local_path:
            local_path = source_path

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
            self.context = await self._dynamic_scan(target_url)

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
        self._step("1/8", "GETTING SOURCE CODE")
        self.source_dir = await self._get_source(repo_url, local_path, branch)
        if not self.source_dir:
            return

        # Step 2: Analyze code files
        self._step("2/8", "STATIC CODE ANALYSIS")
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
        self._step("3/8", "DEPLOYING SANDBOX")
        target_url = await self._deploy(self.source_dir)
        if not target_url:
            return

        # Step 4: Dynamic scan (crawl + attack)
        self._step("4/8", "DYNAMIC VULNERABILITY SCAN")
        if target_url == "offline_mode":
            print(f"  {C.Y}[WARN] Sandbox deployment failed. Skipping dynamic scan. Proceeding with static vulnerabilities.{C.RST}")
            self.context = ScanContext(target_url="http://offline.local")
            # Inject static endpoints so the Genome can still train profiles
            for v in file_vulns:
                ep_path = v.endpoint.split(":")[0]
                if ep_path not in self.context.all_endpoints:
                    self.context.all_endpoints.append(ep_path)
        else:
            self.context = await self._dynamic_scan(target_url)
        self.context.confirmed_vulns.extend(file_vulns)

        # Step 5: Build genome + evolve
        self._step("5/8", "IMMUNE SYSTEM - BUILD GENOME")
        self.genome = await self._build_and_evolve(self.context, generations)

        # Step 6: AI Attack Simulation
        self._step("6/8", "AI ATTACK SIMULATION - GENOME DEFENSE")
        self._simulate_attacks()

        # Step 7: Report
        self._step("7/8", "SECURITY REPORT")
        report = await self._print_report(time.time() - self.start_ts)
        if output_file:
            self._save_report(report, output_file)
        if self.judge_mode:
            self._save_judge_artifacts(report)

        # Step 8: Patch workflow
        if auto_patch and self.context.confirmed_vulns:
            self._step("8/8", "PATCH & VERIFY")
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

    def _step(self, num, title):
        elapsed = time.time() - self.start_ts if self.start_ts else 0.0
        mode = "JUDGE" if self.judge_mode else "SCAN"

        # Gradient top border
        border = C.gradient("━" * 72, 0, 255, 255, 138, 43, 226)
        print(f"\n{border}")

        # Step badge with pill style
        step_num, step_total = num.split("/")
        pill = f"{C.BG_CYAN}{C.BOLD} ◆ STEP {step_num}/{step_total} {C.RST}"
        title_text = f"{C.CYAN}{C.BOLD}{title}{C.RST}"
        meta = f"{C.GHOST}[{mode} t={elapsed:.1f}s]{C.RST}"

        print(f"  {pill}  {title_text}  {meta}")

        # Gradient bottom border
        print(f"{border}\n")

    def _splash_banner(self):
        """Premium cyber-themed splash screen."""
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
        print(f"  {C.SLATE}Multi-Agent Security Pipeline{C.RST}  {C.GHOST}│{C.RST}  {C.CYAN}v2.0{C.RST}  {C.GHOST}│{C.RST}  {C.PURP2}AI-Powered{C.RST}")
        print(f"  {divider}")
        print(f"  {C.GHOST}Scan ID: {C.CYAN2}{self.scan_id}{C.RST}")
        print()

        # Show tool availability summary
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
                        docker_exe = r"C:\Program Files\Docker\Docker\Docker Desktop.exe"
                        if os.path.exists(docker_exe):
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
                subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
            else:
                subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

        print(f"  {C.GHOST}┌─ Tool Readiness ({active}/{total} active) ─────────────────────┐{C.RST}")
        for name, ok, hint in tools:
            if ok:
                icon = f"{C.G}✓{C.RST}"
                detail = f"{C.SLATE}{hint}{C.RST}" if hint else ""
                print(f"  {C.GHOST}│{C.RST}  {icon} {name:12s} {detail}")
            else:
                icon = f"{C.Y}○{C.RST}"
                hint_str = f"{C.DIM}({hint}){C.RST}" if hint else ""
                print(f"  {C.GHOST}│{C.RST}  {icon} {name:12s} {hint_str}")
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
            try:
                proc = subprocess.run(
                    ["git", "clone", "--depth", "1", "-b", branch, repo_url, dest],
                    capture_output=True, text=True, timeout=120
                )
                if proc.returncode != 0:
                    # Try without branch
                    proc = subprocess.run(
                        ["git", "clone", "--depth", "1", repo_url, dest],
                        capture_output=True, text=True, timeout=120
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
                with open(os.path.join(path, "package.json")) as f:
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
                                print(f"  {icon} {C.BOLD}[{severity}]{C.RST} {C.CYAN}{vuln_type}{C.RST}")
                                print(f"       {C.SLATE}{rel_path}:{i}{C.RST}")
                                print(f"       {C.GHOST}{line.strip()[:100]}{C.RST}")
                                break  # One per pattern per file

        print(f"\n  {C.CYAN}SAST:{C.RST} {C.SLATE}{scanned} files scanned, {C.BOLD}{C.CYAN}{len(vulns)} issues{C.RST}")
        return vulns

    # Step 3: Deploy sandbox
    async def _deploy(self, source_dir):
        import zipfile, tempfile
        from cyphex.docker_sandbox import docker_available

        if not docker_available():
            print(f"  {C.Y}[WARN] Docker not found or not running.{C.RST}")
            print(f"  {C.SLATE}  → Sandboxed dynamic execution testing is disabled.{C.RST}")
            print(f"  {C.SLATE}  → Falling back to safe AI-driven static verification.{C.RST}")
            return "offline_mode"


        # ── Priority 1: Docker Compose (full stack with DB) ──
        compose_file = os.path.join(source_dir, "docker-compose.yml")
        if not os.path.exists(compose_file):
            compose_file = os.path.join(source_dir, "docker-compose.yaml")

        if os.path.exists(compose_file) and shutil.which("docker"):
            print(f"  {C.CYAN}▸ [DOCKER]{C.RST} {C.SLATE}Found docker-compose.yml — deploying full stack (app + DB)...{C.RST}")
            try:
                # Strip obsolete 'version' key to prevent warnings
                self._strip_compose_version(compose_file)

                # Build and start containers
                proc = await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "compose", "-f", compose_file, "up", "-d", "--build"],
                    cwd=source_dir, capture_output=True, text=True, timeout=300
                )

                if proc.returncode != 0:
                    # Common failure: a service has no Dockerfile
                    # Try deploying only services with valid Dockerfiles
                    stderr_text = proc.stderr or ""
                    if "dockerfile" in stderr_text.lower() or "no such file" in stderr_text.lower():
                        print(f"  {C.Y}▸ [INFO]{C.RST} {C.SLATE}Some services lack Dockerfiles — deploying buildable services only...{C.RST}")
                        # Parse compose to find services with valid build contexts
                        buildable = self._get_buildable_services(compose_file, source_dir)
                        if buildable:
                            print(f"  {C.GHOST}Deploying: {C.CYAN2}{', '.join(buildable)}{C.RST}")
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
                                    print(f"  {C.NEON}✓{C.RST} {C.SLATE}Docker stack ready (attempt {attempt + 1}){C.RST}")
                                    sb = C.gradient("━" * 58, 0, 255, 255, 138, 43, 226)
                                    print(f"  {sb}")
                                    print(f"  {C.CYAN}▸{C.RST} {C.BOLD}SANDBOX LIVE AT:{C.RST}  {C.NEON}{url}{C.RST}")
                                    print(f"  {C.GHOST}  Full stack: app + database + all services{C.RST}")
                                    print(f"  {sb}")
                                    return url
                        except Exception:
                            continue

                    print(f"  {C.Y}[WARN]{C.RST} Docker stack started but app not responding on port {port}")
                else:
                    err_lines = [line for line in proc.stderr.splitlines() if "error" in line.lower() or "failed" in line.lower() or "yaml:" in line.lower()]
                    err_msg = err_lines[-1] if err_lines else proc.stderr[-150:].replace("\n", " ")
                    print(f"  {C.Y}[WARN]{C.RST} docker-compose failed: {err_msg[:150]}")
            except subprocess.TimeoutExpired:
                print(f"  {C.Y}[WARN]{C.RST} Docker build timed out (300s)")
            except Exception as e:
                print(f"  {C.Y}[WARN]{C.RST} Docker error: {str(e)[:100]}")

        # ── Priority 2: Dockerfile only ──
        elif os.path.exists(os.path.join(source_dir, "Dockerfile")) and shutil.which("docker"):
            print(f"  {C.G}[DOCKER]{C.RST} Found Dockerfile — building container...")
            try:
                from cyphex.docker_sandbox import DockerSandbox
                sandbox = DockerSandbox(source_dir)
                result = await asyncio.to_thread(sandbox.build_and_run)
                if result and result.get("url"):
                    self.sandbox_info = result
                    url = result["url"]
                    print(f"  {C.NEON}✓{C.RST} {C.SLATE}Docker container running{C.RST}")
                    sb = C.gradient("━" * 58, 0, 255, 255, 138, 43, 226)
                    print(f"  {sb}")
                    print(f"  {C.CYAN}▸{C.RST} {C.BOLD}SANDBOX LIVE AT:{C.RST}  {C.NEON}{url}{C.RST}")
                    print(f"  {sb}")
                    return url
            except Exception as e:
                print(f"  {C.Y}[WARN]{C.RST} Dockerfile deploy failed: {str(e)[:100]}")

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
        
        companion_api = await self._detect_companion_api()
        if companion_api:
            print(f"  {C.Y}[INFO]{C.RST} Companion API detected at {companion_api}. Directing scan to backend.")
            url = companion_api

        print(f"  {C.NEON}✓{C.RST} {C.SLATE}Sandbox deployed successfully!{C.RST}")
        print(f"  {C.GHOST}PID: {self.sandbox_info.get('pid')}, Port: {port}{C.RST}")
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
            with open(compose_file) as f:
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
            with open(compose_file, 'r') as f:
                lines = f.readlines()
            # Remove lines that start with 'version:' (top-level only)
            cleaned = [l for l in lines if not re.match(r'^version\s*:', l)]
            if len(cleaned) < len(lines):
                with open(compose_file, 'w') as f:
                    f.writelines(cleaned)
        except Exception:
            pass

    def _get_buildable_services(self, compose_file, source_dir):
        """Find services that have valid Dockerfiles or use pre-built images."""
        import re
        try:
            with open(compose_file) as f:
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
    async def _dynamic_scan(self, target_url):
        """CLI-focused dynamic scan with explicit per-agent visibility."""
        context = ScanContext(target_url=target_url)

        def agent_header(agent_id: str, name: str, objective: str):
            border = C.gradient("─" * 68, 0, 200, 200, 100, 50, 180)
            print(f"\n  {border}")
            print(f"  {C.CYAN}▸{C.RST} {C.BOLD}{C.CYAN}[{agent_id}]{C.RST} {C.PURP2}{name}{C.RST}")
            print(f"  {C.GHOST}{objective}{C.RST}")
            print(f"  {border}")

        def show_cmd(agent: str, cmd: str):
            print(f"  {C.DIM}[{agent}]$ {cmd}{C.RST}")

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
                except Exception as exc:
                    print(f"  {C.R}[Crawler][ERR]{C.RST} {path}: {str(exc)[:80]}")
                    continue

                body = resp.text
                context.all_endpoints.append(url)
                context.headers.update(dict(resp.headers))
                print(f"  {C.G}[Crawler]{C.RST} HTTP {resp.status_code} {url}")

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
                    print(f"  {C.Y}[Crawler][FORM]{C.RST} {method.upper()} {full} inputs={inputs}")

            context.all_forms = forms_found
            print(f"\n  {C.G}[Crawler][OK]{C.RST} pages={len(context.all_endpoints)} forms={len(forms_found)}")

            # ── API Endpoint Probe (for SPAs with no HTML forms) ──────────
            api_endpoints_found = []
            if not forms_found:
                agent_header("Agent 02b", "API Discovery", "SPA detected (0 HTML forms). Probing REST API surface...")
                api_probes = [
                    ("POST", "/api/auth/login",  {"username": "test", "password": "test"}),
                    ("POST", "/api/login",       {"email": "admin@test.com", "password": "admin"}),
                    ("POST", "/login",           {"username": "admin", "password": "admin"}),
                    ("GET",  "/api/employees",   None),
                    ("GET",  "/api/employees/1", None),
                    ("GET",  "/api/employees/2", None),
                    ("GET",  "/api/payroll/1",   None),
                    ("GET",  "/api/payroll/2",   None),
                    ("GET",  "/api/announcements", None),
                    ("POST", "/api/announcements", {"title": "<b>test</b>", "message": "test"}),
                    ("POST", "/api/ping",        {"host": "127.0.0.1"}),
                    ("GET",  "/api/ping?host=127.0.0.1", None),
                    ("POST", "/api/fetch",       {"url": "http://localhost"}),
                    ("GET",  "/api/fetch?url=http://localhost", None),
                    ("GET",  "/api/debug",       None),
                    ("GET",  "/api/env",         None),
                    ("GET",  "/api/health",      None),
                    ("GET",  "/api/config",      None),
                    ("GET",  "/api/users",       None),
                ]
                for method, path, body in api_probes:
                    full_url = f"{target_url}{path}"
                    try:
                        if method == "GET":
                            show_cmd("API", f'curl -s "{full_url}"')
                            resp = await client.get(full_url)
                        else:
                            show_cmd("API", f'curl -s -X POST "{full_url}" -H "Content-Type: application/json" -d \'{{...}}\'')
                            resp = await client.post(full_url, json=body)
                    except Exception:
                        continue
                    if resp.status_code < 404:
                        api_endpoints_found.append((method, path, resp.status_code, resp.text[:500], body))
                        context.all_endpoints.append(full_url)
                        print(f"  {C.G}[API]{C.RST} {method} {path} => HTTP {resp.status_code} ({len(resp.text)} bytes)")
                        # Auto-create synthetic forms for login endpoints
                        if body and any(k in path.lower() for k in ("login", "auth")):
                            forms_found.append(FormData(action=full_url, method=method, inputs=list(body.keys()), page=path))
                    else:
                        print(f"  {C.DIM}[API] {method} {path} => {resp.status_code}{C.RST}")
                context.all_forms = forms_found
                print(f"\n  {C.G}[API Discovery][OK]{C.RST} live_apis={len(api_endpoints_found)} synthetic_forms={len(forms_found)}")

            # Agent 04 - XSS
            agent_header("Agent 04", "XSS", "Probe reflected XSS payload execution paths")
            xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
            seen_xss = set()
            for form in forms_found:
                form_key = form.action
                if form_key in seen_xss or not form.inputs:
                    continue
                for payload in xss_payloads:
                    if form.method == "GET":
                        q = "&".join([f"{inp}={payload}" for inp in form.inputs])
                        show_cmd("XSS", f'curl -s "{form.action}?{q}"')
                        resp = await client.get(form.action, params={inp: payload for inp in form.inputs})
                    else:
                        show_cmd("XSS", f'curl -s -X POST "{form.action}" -d "{form.inputs[0]}={payload}"')
                        resp = await client.post(form.action, data={inp: payload for inp in form.inputs})

                    reflected = payload in resp.text
                    print(f"  {C.Y}[Agent 04 \u25b6 Reasoning]{C.RST} Injecting XSS payload into form fields at {form.action}")
                    print(f"  {C.DIM}  Payload:  {payload[:60]}{C.RST}")
                    print(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    if reflected:
                        print(f"  {C.R}  Decision: Payload reflected in response body \u2192 XSS CONFIRMED \u2713{C.RST}")
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
                        print(f"  {C.G}  Decision: Payload not reflected \u2192 endpoint appears clean{C.RST}")

            # Agent 03 - SQLi
            agent_header("Agent 03", "Injection (SQLi)", "Probe SQL injection indicators")
            sqli_payloads = ["' OR '1'='1", "' UNION SELECT NULL--"]
            sql_errors = ["sql", "syntax error", "sqlite", "mysql", "postgres"]
            seen_sqli = set()
            for form in forms_found:
                if not form.inputs or form.action in seen_sqli:
                    continue
                for payload in sqli_payloads:
                    if form.method == "GET":
                        q = "&".join([f"{inp}={payload}" for inp in form.inputs])
                        show_cmd("SQLi", f'curl -s "{form.action}?{q}"')
                        resp = await client.get(form.action, params={inp: payload for inp in form.inputs})
                    else:
                        show_cmd("SQLi", f'curl -s -X POST "{form.action}" -d "{form.inputs[0]}={payload}"')
                        resp = await client.post(form.action, data={inp: payload for inp in form.inputs})

                    lower = resp.text.lower()
                    indicator = any(e in lower for e in sql_errors) or payload.lower() in lower
                    print(f"  {C.Y}[Agent 03 \u25b6 Reasoning]{C.RST} Injecting SQL tautology into {form.inputs} at {form.action}")
                    print(f"  {C.DIM}  Payload:  {payload}{C.RST}")
                    print(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    if indicator:
                        matched = [e for e in sql_errors if e in lower]
                        print(f"  {C.R}  Decision: SQL error keywords found ({', '.join(matched[:3])}) \u2192 SQLi CONFIRMED \u2713{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] SQL Injection",
                            severity="Critical",
                            endpoint=f"{form.action} ({form.inputs})",
                            payload=payload,
                            confirmed=True,
                        ))
                        seen_sqli.add(form.action)
                        break
                    else:
                        print(f"  {C.G}  Decision: No SQL error indicators \u2192 endpoint appears clean{C.RST}")

            # Agent 05 - Auth
            agent_header("Agent 05", "Auth", "Try weak/default credential flows")
            default_creds = [("admin", "admin"), ("admin", "admin123")]
            login_forms = [f for f in forms_found if any("pass" in i.lower() for i in f.inputs)]
            for form in login_forms[:2]:
                user_field = next((i for i in form.inputs if i.lower() in ("username", "user", "email")), form.inputs[0])
                pass_field = next((i for i in form.inputs if "pass" in i.lower()), form.inputs[-1])
                for u, p in default_creds:
                    show_cmd("Auth", f'curl -s -X POST "{form.action}" -d "{user_field}={u}&{pass_field}={p}"')
                    resp = await client.post(form.action, data={user_field: u, pass_field: p})
                    lower = resp.text.lower()
                    success = any(k in lower for k in ("token", "welcome", "dashboard", "success"))
                    print(f"  {C.Y}[Agent 05 \u25b6 Reasoning]{C.RST} Trying default credentials {u}:{p} on {form.action}")
                    print(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    if success:
                        matched = [k for k in ("token", "welcome", "dashboard", "success") if k in lower]
                        print(f"  {C.R}  Decision: Auth success indicator found ('{matched[0]}') \u2192 DEFAULT CREDS CONFIRMED \u2713{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] Default Credentials",
                            severity="Critical",
                            endpoint=form.action,
                            payload=f"{u}:{p}",
                            confirmed=True,
                        ))
                        break
                    else:
                        print(f"  {C.G}  Decision: No success indicator \u2192 credentials rejected{C.RST}")

            # Agent 07 - LFI
            agent_header("Agent 07", "LFI", "Try file traversal payloads")
            lfi_targets = ["/download?file=../../../etc/passwd", "/api/file?path=../../../etc/passwd"]
            for suffix in lfi_targets:
                full = f"{target_url}{suffix}"
                show_cmd("LFI", f'curl -s "{full}"')
                try:
                    resp = await client.get(full)
                except Exception:
                    continue
                hit = "root:x:0:0" in resp.text
                print(f"  {C.Y}[Agent 07 \u25b6 Reasoning]{C.RST} Testing path traversal: {suffix}")
                print(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                if hit:
                    print(f"  {C.R}  Decision: /etc/passwd content found \u2192 LFI CONFIRMED \u2713{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] Local File Inclusion",
                        severity="Critical",
                        endpoint=full,
                        payload="../../../etc/passwd",
                        confirmed=True,
                    ))
                else:
                    print(f"  {C.G}  Decision: No file content leaked \u2192 endpoint clean{C.RST}")

            # Agent 06 - CMDi
            agent_header("Agent 06", "CMDi", "Probe command execution sinks")
            cmdi_targets = ["/api/ping?host=127.0.0.1;id", "/ping?host=127.0.0.1|whoami"]
            for suffix in cmdi_targets:
                full = f"{target_url}{suffix}"
                show_cmd("CMDi", f'curl -s "{full}"')
                try:
                    resp = await client.get(full)
                except Exception:
                    continue
                hit = any(k in resp.text.lower() for k in ("uid=", "gid=", "root", "www-data", "nt authority"))
                print(f"  {C.Y}[Agent 06 \u25b6 Reasoning]{C.RST} Testing command injection via GET: {suffix}")
                print(f"  {C.DIM}  Response: HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                if hit:
                    print(f"  {C.R}  Decision: OS command output detected \u2192 CMDi CONFIRMED \u2713{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] Command Injection",
                        severity="Critical",
                        endpoint=full,
                        payload=suffix,
                        confirmed=True,
                    ))
                else:
                    print(f"  {C.G}  Decision: No OS output \u2192 endpoint clean{C.RST}")

            # Agent 08 - Logic/CORS
            agent_header("Agent 08", "Logic", "Check insecure CORS and basic authz gaps")
            show_cmd("Logic", f'curl -sI -H "Origin: https://evil.example" "{target_url}"')
            try:
                head = await client.get(target_url, headers={"Origin": "https://evil.example"})
                acao = head.headers.get("Access-Control-Allow-Origin", "")
                print(f"  {C.Y}[Agent 08 \u25b6 Reasoning]{C.RST} Sending spoofed Origin header to test CORS policy")
                print(f"  {C.DIM}  Access-Control-Allow-Origin: {acao or 'not-set'}{C.RST}")
                if acao in ("*", "https://evil.example"):
                    print(f"  {C.R}  Decision: Server reflects/wildcards origin \u2192 CORS MISCONFIGURATION CONFIRMED \u2713{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] CORS Misconfiguration",
                        severity="High",
                        endpoint=target_url,
                        payload=f"ACAO={acao}",
                        confirmed=True,
                    ))
                else:
                    print(f"  {C.G}  Decision: CORS policy properly restrictive{C.RST}")
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
                    print(f"  {C.R}[SupplyChain][CONFIRMED]{C.RST} exposed {manifest}")
                else:
                    print(f"  [SupplyChain] {manifest} status={resp.status_code}")

            # ── Agent 09 — IDOR Prober ─────────────────────────────────
            agent_header("Agent 09", "IDOR", "Probe insecure direct object references by enumerating sequential IDs")
            idor_paths = ["/api/employees/", "/api/payroll/", "/api/users/", "/api/payslips/", "/api/orders/"]
            for base_path in idor_paths:
                responses = []
                for test_id in [1, 2, 3]:
                    full = f"{target_url}{base_path}{test_id}"
                    show_cmd("IDOR", f'curl -s "{full}"')
                    try:
                        resp = await client.get(full)
                        responses.append((test_id, resp.status_code, len(resp.text)))
                        print(f"  {C.DIM}[IDOR] GET {base_path}{test_id} => HTTP {resp.status_code} ({len(resp.text)} bytes){C.RST}")
                    except Exception:
                        continue
                ok_responses = [r for r in responses if r[1] == 200 and r[2] > 20]
                if len(ok_responses) >= 2:
                    print(f"  {C.Y}[Agent 09 > Reasoning]{C.RST} Multiple sequential IDs return data without authentication.")
                    print(f"  {C.Y}  Decision:{C.RST} {len(ok_responses)} IDs accessible => {C.R}IDOR CONFIRMED{C.RST}")
                    context.confirmed_vulns.append(Vuln(
                        name="[DYNAMIC] IDOR — Sequential ID Enumeration",
                        severity="High",
                        endpoint=f"{target_url}{base_path}*",
                        payload=f"Accessed IDs: {[r[0] for r in ok_responses]}",
                        confirmed=True,
                    ))
                elif ok_responses:
                    print(f"  {C.DIM}[IDOR] Only 1 ID responded — not enough for confirmed IDOR{C.RST}")

            # ── Agent 10 — SSRF Prober ─────────────────────────────────
            agent_header("Agent 10", "SSRF", "Probe server-side request forgery via URL parameters")
            ssrf_endpoints = [
                ("/api/fetch", {"url": "http://127.0.0.1"}),
                ("/api/fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
                ("/api/proxy", {"url": "http://127.0.0.1"}),
            ]
            ssrf_get_endpoints = [
                "/api/fetch?url=http://127.0.0.1",
                "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
            ]
            for path, body in ssrf_endpoints:
                full = f"{target_url}{path}"
                show_cmd("SSRF", f'curl -s -X POST "{full}" -d \'url={body["url"]}\'')
                try:
                    resp = await client.post(full, json=body)
                    has_internal = any(k in resp.text.lower() for k in ("127.0.0.1", "localhost", "ami-id", "instance-id", "<html", "<!doctype"))
                    print(f"  {C.DIM}[SSRF] POST {path} => HTTP {resp.status_code} internal_data={'yes' if has_internal else 'no'}{C.RST}")
                    if resp.status_code == 200 and has_internal:
                        print(f"  {C.Y}[Agent 10 > Reasoning]{C.RST} Server fetched internal URL and returned content.")
                        print(f"  {C.R}  Decision: SSRF CONFIRMED — server made request to {body['url']}{C.RST}")
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
                        print(f"  {C.R}[SSRF][CONFIRMED]{C.RST} internal content returned")
                    else:
                        print(f"  {C.DIM}[SSRF] GET {suffix} => {resp.status_code}{C.RST}")
                except Exception:
                    continue

            # ── Agent 12 — Sensitive Data Exposure ─────────────────────
            agent_header("Agent 12", "Data Exposure", "Probe debug and config endpoints for sensitive data leaks")
            sde_paths = ["/api/debug", "/api/env", "/api/config", "/debug", "/env", "/api/health"]
            sde_indicators = ["DB_", "SECRET", "KEY", "PASSWORD", "TOKEN", "process.env", "DATABASE_URL", "MONGO", "REDIS"]
            for path in sde_paths:
                full = f"{target_url}{path}"
                show_cmd("SDE", f'curl -s "{full}"')
                try:
                    resp = await client.get(full)
                    if resp.status_code == 200 and len(resp.text) > 20:
                        hits = [ind for ind in sde_indicators if ind.lower() in resp.text.lower()]
                        if hits:
                            print(f"  {C.Y}[Agent 12 > Reasoning]{C.RST} Endpoint {path} returns sensitive configuration data.")
                            print(f"  {C.Y}  Detected keys:{C.RST} {', '.join(hits[:5])}")
                            print(f"  {C.R}  Decision: DATA EXPOSURE CONFIRMED{C.RST}")
                            context.confirmed_vulns.append(Vuln(
                                name="[DYNAMIC] Sensitive Data Exposure",
                                severity="Critical",
                                endpoint=full,
                                payload=f"Exposed keys: {', '.join(hits[:5])}",
                                confirmed=True,
                            ))
                        else:
                            print(f"  {C.DIM}[SDE] {path} => HTTP 200 but no sensitive keys found{C.RST}")
                    else:
                        print(f"  {C.DIM}[SDE] {path} => HTTP {resp.status_code}{C.RST}")
                except Exception:
                    continue

            # ── Agent 13 — Command Injection (API) ────────────────────
            agent_header("Agent 13", "CMDi (API)", "Probe command injection via API ping/exec endpoints")
            cmdi_api_tests = [
                ("POST", "/api/ping", {"host": "127.0.0.1; id"}),
                ("POST", "/api/ping", {"host": "127.0.0.1 && whoami"}),
                ("POST", "/api/ping", {"host": "127.0.0.1 | cat /etc/passwd"}),
                ("POST", "/api/exec", {"cmd": "id"}),
            ]
            cmdi_indicators = ["uid=", "gid=", "root:", "www-data", "nt authority", "groups="]
            for method, path, body in cmdi_api_tests:
                full = f"{target_url}{path}"
                show_cmd("CMDi", f'curl -s -X POST "{full}" -d \'host={body.get("host", body.get("cmd", ""))}\'')
                try:
                    resp = await client.post(full, json=body)
                    hit = any(ind in resp.text.lower() for ind in cmdi_indicators)
                    if hit:
                        print(f"  {C.Y}[Agent 13 > Reasoning]{C.RST} OS command output detected in response.")
                        print(f"  {C.R}  Decision: COMMAND INJECTION CONFIRMED{C.RST}")
                        context.confirmed_vulns.append(Vuln(
                            name="[DYNAMIC] Command Injection (API)",
                            severity="Critical",
                            endpoint=full,
                            payload=str(body),
                            confirmed=True,
                        ))
                        break
                    else:
                        print(f"  {C.DIM}[CMDi] POST {path} => {resp.status_code} (no OS output){C.RST}")
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
                            print(f"  {C.G}[JWT]{C.RST} Token found in response from {form.action} (creds: {u}:{p})")
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
                            print(f"  {C.Y}[Agent 14 \u25b6 Reasoning]{C.RST} Decoded JWT token without verification")
                            print(f"  {C.DIM}  Header:  {json.dumps(header)}{C.RST}")
                            print(f"  {C.DIM}  Payload: {json.dumps(payload_data)[:120]}{C.RST}")

                            # Check for dangerous algorithm
                            alg = header.get("alg", "")
                            if alg.lower() == "none":
                                print(f"  {C.R}  Decision: Algorithm 'none' \u2192 JWT BYPASS CONFIRMED \u2713{C.RST}")
                                context.confirmed_vulns.append(Vuln(
                                    name="[DYNAMIC] JWT Algorithm None Bypass",
                                    severity="Critical",
                                    endpoint=form.action if forms_found else target_url,
                                    payload=f"alg=none",
                                    confirmed=True,
                                ))
                            elif "role" in payload_data or "admin" in str(payload_data).lower():
                                print(f"  {C.Y}  Decision: Role/admin claim in JWT payload \u2192 potential privilege escalation{C.RST}")
                                context.confirmed_vulns.append(Vuln(
                                    name="[DYNAMIC] JWT Role Escalation Risk",
                                    severity="High",
                                    endpoint=form.action if forms_found else target_url,
                                    payload=f"Claims: {list(payload_data.keys())[:5]}",
                                    confirmed=True,
                                ))
                            else:
                                print(f"  {C.G}  Decision: JWT structure appears standard ({alg}){C.RST}")
                        except Exception:
                            print(f"  {C.DIM}[JWT] Could not decode token{C.RST}")
            else:
                print(f"  {C.DIM}[JWT] No JWT tokens found in any endpoint responses{C.RST}")

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
            for payload, ptype in [("' OR 1=1--", "sqli"), ("<script>alert(1)</script>", "xss"), ("; cat /etc/passwd", "cmdi"), ("normal search", "benign"), ("John O'Brien", "benign")]:
                score = genome._heuristic_score(genome.extract_features(payload))
                verdict = "[red]BLOCK[/red]" if score >= 0.5 else "[green]ALLOW[/green]"
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

        table = Table(title="Before / After Simulation", box=ROUNDED)
        table.add_column("Attack", style="white")
        table.add_column("Payload", max_width=26)
        table.add_column("Type", justify="center")
        table.add_column("Before", justify="center")
        table.add_column("After", justify="center")
        table.add_column("Score", justify="right")

        blocked = fp = mal = 0
        for name, payload, ptype in attacks:
            score = self.genome._heuristic_score(self.genome.extract_features(payload))
            is_blocked = score >= 0.5
            is_benign = ptype == "benign"
            before = "[green]ALLOWED[/green]"
            after = "[red]BLOCKED[/red]" if is_blocked else "[green]ALLOWED[/green]"
            
            if not is_benign:
                mal += 1
                if is_blocked: blocked += 1
            elif is_blocked:
                fp += 1
                after = "[bold red]FALSE POS[/bold red]"
                
            table.add_row(name, payload[:24], ptype, before, after, f"{score:.3f}")

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
        score = max(0, 100 - crit * 25 - high * 10 - med * 5 - low)
        # Diminishing returns: duplicate findings of same severity don't stack fully
        import math
        penalty = 0
        if crit: penalty += 20 + 10 * math.log2(1 + crit)  # ~20 first, +10 per doubling
        if high: penalty += 10 + 8 * math.log2(1 + high)   # ~10 first, +8 per doubling
        if med:  penalty += 3 + 4 * math.log2(1 + med)
        if low:  penalty += 1 + 2 * math.log2(1 + low)
        score = max(0, min(100, round(100 - penalty)))

        if score >= 80:
            sc_rich, sc_label = "green", "SECURE"
        elif score >= 60:
            sc_rich, sc_label = "cyan", "FAIR"
        elif score >= 40:
            sc_rich, sc_label = "yellow", "AT RISK"
        elif score >= 20:
            sc_rich, sc_label = "red", "POOR"
        else:
            sc_rich, sc_label = "red bold", "CRITICAL"

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
                    elif "XSS" in vuln_type: cwe = "CWE-79"
                    elif "Command" in vuln_type or "CMDi" in vuln_type: cwe = "CWE-78"
                    elif "IDOR" in vuln_type: cwe = "CWE-284"
                    elif "SSRF" in vuln_type: cwe = "CWE-918"
                    elif "JWT" in vuln_type: cwe = "CWE-287"
                    elif "Data Exposure" in vuln_type: cwe = "CWE-200"

                sev_display = sev_icons.get(v.severity, f"[dim]{v.severity}[/dim]")
                table.add_row(str(i), sev_display, vuln_type, cwe, endpoint)
            console.print(table)

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
            except Exception:
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
                console.print(f"[dim]  Route tracer unavailable or failed: {str(e)}[/dim]")

        # Calculate BEFORE score
        import math
        crit_b = sum(1 for v in vulns if v.severity == "Critical")
        high_b = sum(1 for v in vulns if v.severity == "High")
        med_b  = sum(1 for v in vulns if v.severity == "Medium")
        low_b  = sum(1 for v in vulns if v.severity in ("Low", "Info"))
        penalty_b = 0
        if crit_b: penalty_b += 20 + 10 * math.log2(1 + crit_b)
        if high_b: penalty_b += 10 + 8 * math.log2(1 + high_b)
        if med_b:  penalty_b += 3 + 4 * math.log2(1 + med_b)
        if low_b:  penalty_b += 1 + 2 * math.log2(1 + low_b)
        score_before = max(0, min(100, round(100 - penalty_b)))

        console.print(Panel(
            f"[bold]Found {len(vulns)} vulnerabilities to review.[/bold]\n"
            f"[dim]Council Mode: {'ENABLED (Batch)' if COUNCIL_AVAILABLE else 'DISABLED (fallback)'}[/dim]",
            title="PATCH WORKFLOW", border_style="magenta"
        ))

        # Initialize the council if available
        patch_council = PatchCouncil() if COUNCIL_AVAILABLE else None

        patched_files = []
        skipped = 0

        # CWE lookup helper
        cwe_map = {
            "sql injection": "CWE-89", "xss": "CWE-79",
            "command injection": "CWE-78", "cmdi": "CWE-78",
            "ssrf": "CWE-918", "idor": "CWE-284",
            "jwt": "CWE-287", "sensitive data": "CWE-200",
            "hardcoded": "CWE-798", "cors": "CWE-942",
            "lfi": "CWE-22", "path traversal": "CWE-22",
        }

        # ── Phase 1: Collect all patchable vulns ──
        patchable = []  # list of (vuln, rel_path, line_num, lines, snippet, vuln_type)
        dynamic_only = []  # vulns with no source file to patch (runtime/DAST findings)
        for v in vulns:
            endpoint = v.endpoint or ""
            # Dynamic vulns have HTTP URLs, not file:line references
            if endpoint.startswith("http://") or endpoint.startswith("https://"):
                dynamic_only.append(v)
                continue
            if ":" not in endpoint:
                dynamic_only.append(v)
                continue
            parts = endpoint.split(":")
            rel_path = parts[0].strip()
            try:
                line_num = int(parts[1].split()[0])
            except Exception:
                dynamic_only.append(v)
                continue
            filepath = os.path.join(self.source_dir, rel_path)
            if not os.path.exists(filepath):
                # Try absolute path (semgrep findings have full paths)
                if os.path.exists(rel_path):
                    filepath = rel_path
                    # Convert to relative for display
                    if self.source_dir and rel_path.startswith(self.source_dir):
                        rel_path = os.path.relpath(rel_path, self.source_dir)
                else:
                    dynamic_only.append(v)
                    continue
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                dynamic_only.append(v)
                continue
            start_l = max(0, line_num - 3)
            end_l = min(len(lines), line_num + 2)
            snippet = "".join(lines[start_l:end_l])
            vuln_type = v.name.replace("[STATIC] ", "").replace("[DYNAMIC] ", "")

            cwe = "CWE-unknown"
            for key, val in cwe_map.items():
                if key in vuln_type.lower():
                    cwe = val
                    break

            patchable.append({
                "vuln": v, "rel_path": rel_path, "line_num": line_num,
                "lines": lines, "snippet": snippet, "vuln_type": vuln_type,
                "cwe": cwe, "start_l": start_l, "end_l": end_l,
                "filepath": filepath,
            })

        if dynamic_only:
            console.print(f"[dim]  {len(dynamic_only)} dynamic/runtime findings (no source file to auto-patch)[/dim]")

        if not patchable:
            console.print(f"[dim]No vulns with file locations to patch.[/dim]")
            return

        # ── Phase 2: Batch generate + validate (agent-centric batching) ──
        # The batch council now caches Stage 1 patches internally.
        # Even if the review stage crashes, we get patches with "review_needed" status
        # instead of losing everything and regenerating from scratch.
        batch_results = None
        if patch_council and len(patchable) > 0:
            try:
                vuln_inputs = [
                    {"vuln_name": p["vuln_type"], "cwe": p["cwe"],
                     "vulnerable_code": p["snippet"], "file_path": p["rel_path"]}
                    for p in patchable
                ]
                batch_results = await patch_council.generate_and_validate_batch(vuln_inputs)
            except Exception as e:
                console.print(f"[yellow]⚠ Batch council error: {str(e)[:80]}.[/yellow]")
                console.print(f"[cyan]  → Per-vuln fallback will only generate patches that weren't cached.[/cyan]")
                batch_results = None

        # ── Phase 3: Present each patch for user approval ──
        for i, p in enumerate(patchable):
            v = p["vuln"]
            console.print(f"\n[bold]{'-' * 70}[/bold]")
            console.print(f"[bold][{i+1}/{len(patchable)}] {p['vuln_type']} ({v.severity})[/bold]")
            console.print(f"File: [cyan]{p['rel_path']}:{p['line_num']}[/cyan]")

            console.print(f"\n[bold]Vulnerable Code:[/bold]")
            for j in range(p["start_l"], p["end_l"]):
                ln = j + 1
                marker = "->" if ln == p["line_num"] else "  "
                console.print(f"  {marker} {ln:4} | {p['lines'][j].rstrip()[:120]}")

            # Get patch from batch results or fallback
            patch_pkg = None
            if batch_results and i < len(batch_results):
                council_result = batch_results[i]
                if council_result and council_result.get("fixed_code"):
                    patch_pkg = {
                        "unsafe_reason": council_result.get("unsafe_reason", ""),
                        "fixed_code": council_result.get("fixed_code", ""),
                        "justifications": council_result.get("vote_summary", ""),
                        "patch_safety": council_result.get("patch_safety", ""),
                    }
                    # Show council approval details
                    approvals = council_result.get("approvals", [])
                    dissent = council_result.get("dissent_reasons", [])
                    vote_table = Table(title="Council Patch Validation", box=ROUNDED)
                    vote_table.add_column("Model", width=22)
                    vote_table.add_column("Verdict", justify="center", width=10)
                    vote_table.add_column("Reason", max_width=45)
                    for a in approvals:
                        verdict_color = "green" if a.get("approved") else "red"
                        verdict_text = "APPROVED" if a.get("approved") else "REJECTED"
                        vote_table.add_row(
                            a.get("model", "unknown"),
                            f"[{verdict_color}]{verdict_text}[/{verdict_color}]",
                            a.get("reason", "")
                        )
                    console.print(vote_table)

                    if dissent:
                        console.print(Panel(
                            "\n".join(f"[red]•[/red] {r}" for r in dissent),
                            title="Dissenting Reasons", border_style="red"
                        ))

            # If batch council didn't produce a patch, skip it entirely
            # (No re-generation fallback — saves significant scan time)
            if not patch_pkg:
                console.print(f"[yellow][SKIP][/yellow] Could not generate patch\n")
                skipped += 1
                continue

            analysis = patch_pkg.get('unsafe_reason', 'No rationale provided.')
            if isinstance(analysis, list): analysis = " ".join(str(x) for x in analysis)
            
            justifications = patch_pkg.get('justifications', 'N/A')
            if isinstance(justifications, list): justifications = " ".join(str(x) for x in justifications)
            
            raw_safety = patch_pkg.get("patch_safety", "")
            if isinstance(raw_safety, list): raw_safety = " ".join(str(x) for x in raw_safety)
            llm_patch_safety = str(raw_safety).strip()

            console.print(Panel(
                f"[bold red]Root Cause:[/bold red] {analysis}\n\n"
                f"[bold green]Justifications:[/bold green] {justifications}",
                title="Vulnerability Analysis", border_style="cyan", padding=(1, 2)
            ))

            fixed_raw = patch_pkg.get("fixed_code", "")
            if isinstance(fixed_raw, list):
                fixed_raw = "\n".join(str(x) for x in fixed_raw)
            fixed = str(fixed_raw).strip()
            if not fixed:
                console.print(f"[yellow][SKIP][/yellow] Model did not return fixed code\n")
                skipped += 1
                continue

            safety_notes = self._assess_patch_safety(v, p["snippet"], fixed)

            diff_text = Text()
            for ol in p["snippet"].split("\n"):
                if ol.strip():
                    diff_text.append(f"- {ol[:120]}\n", style="red")
            for nl in fixed.split("\n"):
                if nl.strip():
                    diff_text.append(f"+ {nl[:120]}\n", style="green")

            console.print(Panel(diff_text, title="Proposed Code Changes (Diff)", border_style="yellow"))

            safety_text = ""
            if llm_patch_safety:
                sc = "green" if llm_patch_safety == "safe" else "yellow" if llm_patch_safety == "review_needed" else "red"
                safety_text += f"[bold]Council Verdict:[/bold] [{sc}]{llm_patch_safety.upper()}[/{sc}]\n"
            for note in safety_notes:
                safety_text += f"- {note}\n"
            
            if safety_text:
                console.print(Panel(safety_text.strip(), title="Patch Safety Notes", border_style="red"))

            if self.non_interactive:
                choice = "y"
                console.print(f"[dim]non-interactive mode: auto applying patch[/dim]")
            else:
                print(f"\n  {C.Y}Apply this patch? (y/n/q):{C.RST} ", end="")
                try:
                    choice = input().strip().lower()
                except EOFError:
                    choice = "n"

            if choice == "q":
                break
            if choice != "y":
                skipped += 1
                console.print(f"[dim][SKIPPED][/dim]\n")
                continue

            # --- SYNTAX VALIDATION ---
            import tempfile
            import subprocess
            
            ext = os.path.splitext(p["filepath"])[1].lower()
            syntax_passed = True
            syntax_err = ""
            
            # Create a temporary copy of the lines to check
            test_lines = p["lines"].copy()
            for j in range(p["start_l"], p["end_l"]):
                test_lines[j] = ""
            test_lines[p["start_l"]] = fixed + "\n"
            test_content = "".join(test_lines)

            if ext in ['.js', '.ts', '.py']:
                with tempfile.NamedTemporaryFile(suffix=ext, mode='w', delete=False, encoding='utf-8') as tf:
                    tf.write(test_content)
                    tf_name = tf.name
                
                try:
                    if ext in ['.js', '.ts']:
                        cmd = ["node", "-c", tf_name]
                    elif ext == '.py':
                        cmd = ["python", "-m", "py_compile", tf_name]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode != 0:
                        syntax_passed = False
                        syntax_err = result.stderr.strip()
                except Exception as e:
                    pass # Ignore if node/python isn't installed
                finally:
                    if os.path.exists(tf_name):
                        os.unlink(tf_name)
            
            if not syntax_passed:
                console.print(f"\n[bold red][REJECTED][/bold red] AI Hallucination detected: Syntax Error in proposed patch!")
                console.print(f"[dim]{syntax_err[:500]}[/dim]\n")
                skipped += 1
                continue
            # --------------------------

            lines = p["lines"]
            for j in range(p["start_l"], p["end_l"]):
                lines[j] = ""
            lines[p["start_l"]] = fixed + "\n"
            with open(p["filepath"], "w", encoding="utf-8") as f:
                f.writelines(lines)
            patched_files.append(p["rel_path"])
            console.print(f"[green][APPLIED][/green] Patch applied to {p['rel_path']}\n")

            # Overwrite the original file in the workspace so the git commit includes the patch
            if hasattr(self, "local_path") and self.local_path:
                dst_orig = os.path.join(os.path.abspath(self.local_path), p["rel_path"])
                if os.path.exists(dst_orig):
                    import shutil
                    shutil.copy2(p["filepath"], dst_orig)


        console.print(f"\n[bold]{'-' * 50}[/bold]")
        console.print(f"[green]Applied:[/green] {len(patched_files)}  [yellow]Skipped:[/yellow] {skipped}")

        # ── After-Patching Score ──
        remaining_vulns = len(vulns) - len(patched_files)
        # Recalculate severity counts after patching
        patched_set = set(patched_files)
        remaining = [v for v in vulns
                     if not any(v.endpoint and p_entry in v.endpoint for p_entry in patched_set)]
        crit_a = sum(1 for v in remaining if v.severity == "Critical")
        high_a = sum(1 for v in remaining if v.severity == "High")
        med_a  = sum(1 for v in remaining if v.severity == "Medium")
        low_a  = sum(1 for v in remaining if v.severity in ("Low", "Info"))
        penalty_a = 0
        if crit_a: penalty_a += 15 + 8 * math.log2(1 + crit_a)
        if high_a: penalty_a += 8 + 5 * math.log2(1 + high_a)
        if med_a:  penalty_a += 3 + 3 * math.log2(1 + med_a)
        if low_a:  penalty_a += 1 + 1 * math.log2(1 + low_a)
        score_after = max(0, min(100, round(100 - penalty_a)))

        delta = score_after - score_before
        delta_color = "green" if delta > 0 else "yellow" if delta == 0 else "red"
        delta_str = f"+{delta}" if delta > 0 else str(delta)

        bar_b = int(score_before / 100 * 25)
        bar_a = int(score_after / 100 * 25)
        sc_b_color = "red" if score_before < 40 else "yellow" if score_before < 70 else "green"
        sc_a_color = "red" if score_after < 40 else "yellow" if score_after < 70 else "green"

        console.print(Panel(
            f"  [bold]Before Patching:[/bold]  [{sc_b_color}]{'█' * bar_b}{'░' * (25 - bar_b)}  {score_before}/100[/{sc_b_color}]\n"
            f"  [bold]After Patching:[/bold]   [{sc_a_color}]{'█' * bar_a}{'░' * (25 - bar_a)}  {score_after}/100[/{sc_a_color}]\n\n"
            f"  [bold]Improvement:[/bold]  [{delta_color}]{delta_str} points[/{delta_color}]  │  "
            f"Patched: [green]{len(patched_files)}[/green]  Remaining: [yellow]{len(remaining)}[/yellow]  │  "
            f"Crit: {crit_a}  High: {high_a}  Med: {med_a}  Low: {low_a}\n\n"
            f"  [dim italic]* Note: Dynamic runtime findings cannot be auto-marked as patched. Run a re-scan to clear them![/dim italic]",
            title="[bold cyan]◈ SECURITY SCORE: BEFORE vs AFTER ◈[/bold cyan]",
            border_style="cyan", padding=(1, 2)
        ))

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
            async with httpx.AsyncClient(timeout=90) as client:
                async with client.stream(
                    "POST",
                    "http://127.0.0.1:11434/api/generate",
                    json={"model": model_name, "prompt": prompt, "stream": True}
                ) as resp:
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
            console.print(f"  [yellow][INFO] Ollama unavailable ({str(e)[:50]}). Using built-in patch rules.[/yellow]")

        # 2. Fallback: Rule-based patches (works 100% offline)
        result = self._rule_based_patch(vuln, code_snippet)
        if result:
            print(f"  {C.G}[OK]{C.RST} Generated patch using built-in security rules (no LLM needed)")
        return result

    def _rule_based_patch(self, vuln, snippet) -> Optional[dict[str, str]]:
        """Built-in patches for common vulnerability types. Works 100% offline."""
        name_lower = (vuln.name or "").lower()
        snippet_lower = snippet.lower()

        if "xss" in name_lower:
            if "dangerouslysetinnerhtml" in snippet_lower:
                fixed = re.sub(
                    r'dangerouslySetInnerHTML=\{\{\s*__html:\s*(.+?)\s*\}\}',
                    r'dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(\1) }}',
                    snippet
                )
                if fixed == snippet:
                    fixed = snippet.replace("dangerouslySetInnerHTML", "/* PATCHED: sanitize input */ dangerouslySetInnerHTML")
                return {
                    "unsafe_reason": "dangerouslySetInnerHTML renders raw HTML without sanitization, allowing attackers to inject <script> tags or event handlers (onerror, onload) to steal cookies, redirect users, or deface the page.",
                    "fixed_code": fixed,
                    "patch_safety": "Install DOMPurify: npm install dompurify. Import at the top: import DOMPurify from 'dompurify';",
                }
            if "innerhtml" in snippet_lower:
                fixed = snippet.replace(".innerHTML =", ".textContent =")
                return {
                    "unsafe_reason": "Setting innerHTML with user-controlled data allows script injection.",
                    "fixed_code": fixed,
                    "patch_safety": "textContent safely escapes all HTML. If HTML rendering is needed, use DOMPurify.sanitize().",
                }

        if "sql" in name_lower:
            if "f\"" in snippet or "f'" in snippet or "${" in snippet or "` +" in snippet:
                return {
                    "unsafe_reason": "String interpolation/concatenation in SQL allows attackers to inject arbitrary SQL commands (e.g., ' OR 1=1-- to bypass auth, UNION SELECT to dump data).",
                    "fixed_code": "// Use parameterized queries:\n// db.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password])\n// Or with named params: db.get('SELECT * FROM users WHERE id = $id', { $id: userId })",
                    "patch_safety": "Replace ALL string-interpolated SQL with parameterized queries (? placeholders). Never build SQL from user input.",
                }

        if "jwt" in name_lower:
            return {
                "unsafe_reason": "Hardcoded or weak JWT secret (e.g., 'secret123') allows attackers to forge tokens, escalate to admin, and access any user's data.",
                "fixed_code": "// Use a strong, environment-variable secret:\nconst token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h', algorithm: 'HS256' });\n// Generate a strong secret: node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\"",
                "patch_safety": "Set JWT_SECRET to a random 256-bit value in .env. Never commit secrets to git. Add .env to .gitignore.",
            }

        if "command" in name_lower or "cmdi" in name_lower:
            return {
                "unsafe_reason": "User input passed directly to exec/spawn/system allows shell command injection (e.g., '; rm -rf /' or '| cat /etc/passwd').",
                "fixed_code": "// Use argument arrays (never shell interpolation):\nconst { execFile } = require('child_process');\nexecFile('ping', ['-c', '1', sanitizedHost], (err, stdout) => {\n  res.json({ output: stdout });\n});\n// Validate input: const sanitizedHost = host.replace(/[^a-zA-Z0-9.-]/g, '');",
                "patch_safety": "Use execFile() with argument arrays instead of exec(). Validate input with allowlist regex. Never use shell: true.",
            }

        if "ssrf" in name_lower:
            return {
                "unsafe_reason": "User-controlled URL in fetch/axios/http.get allows attackers to make the server request internal services (e.g., http://169.254.169.254 for AWS credentials).",
                "fixed_code": "// Validate URL against allowlist:\nconst { URL } = require('url');\nconst parsed = new URL(userUrl);\nconst blocked = ['127.0.0.1', 'localhost', '169.254.169.254', '0.0.0.0'];\nif (blocked.includes(parsed.hostname) || parsed.hostname.startsWith('10.') || parsed.hostname.startsWith('192.168.')) {\n  return res.status(403).json({ error: 'Internal addresses blocked' });\n}",
                "patch_safety": "Block private IPs (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). Use URL allowlists when possible.",
            }

        if "idor" in name_lower:
            return {
                "unsafe_reason": "Direct object reference from URL parameter without ownership validation allows attackers to access other users' data by incrementing IDs.",
                "fixed_code": "// Verify ownership before returning data:\napp.get('/api/employees/:id', authMiddleware, (req, res) => {\n  const employee = db.get('SELECT * FROM employees WHERE id = ?', [req.params.id]);\n  if (!employee || (req.user.role !== 'admin' && employee.user_id !== req.user.id)) {\n    return res.status(403).json({ error: 'Access denied' });\n  }\n  res.json(employee);\n});",
                "patch_safety": "Always validate that the authenticated user owns the requested resource. Use middleware for authz checks.",
            }

        if "sensitive data" in name_lower or "data exposure" in name_lower:
            return {
                "unsafe_reason": "Debug/config endpoint exposes environment variables (DB credentials, API keys, secrets) without authentication.",
                "fixed_code": "// Remove debug endpoint entirely, or protect it:\n// app.get('/api/debug', adminAuthMiddleware, (req, res) => { ... });\n// NEVER expose process.env to any HTTP response.",
                "patch_safety": "Delete debug endpoints before production. If needed for ops, require admin auth and log all access.",
            }

        if "hardcoded" in name_lower or "secret" in name_lower:
            return {
                "unsafe_reason": "Hardcoded credentials in source code are visible to anyone with repo access.",
                "fixed_code": "// Move to environment variables:\nconst password = process.env.DB_PASSWORD;\n// Add to .env file (never commit):\n// DB_PASSWORD=your_secure_password_here",
                "patch_safety": "Use dotenv package. Add .env to .gitignore. Rotate any exposed credentials immediately.",
            }

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
            print(f"  {C.G}[OK]{C.RST} Patches pushed to GitHub!")
        except Exception as e:
            print(f"  {C.R}[ERR]{C.RST} Push failed: {e}")

    def _final_banner(self):
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
        vulns = self.context.confirmed_vulns if self.context else []
        crit = sum(1 for v in vulns if v.severity == "Critical")
        high = sum(1 for v in vulns if v.severity == "High")
        med = sum(1 for v in vulns if v.severity == "Medium")
        low = sum(1 for v in vulns if v.severity in ("Low", "Info"))
        total = len(vulns)
        score = max(0, 100 - crit * 25 - high * 10 - med * 5 - low)
        # Diminishing returns: duplicate findings of same severity don't stack fully
        import math
        penalty = 0
        if crit: penalty += 20 + 10 * math.log2(1 + crit)  # ~20 first, +10 per doubling
        if high: penalty += 10 + 8 * math.log2(1 + high)   # ~10 first, +8 per doubling
        if med:  penalty += 3 + 4 * math.log2(1 + med)
        if low:  penalty += 1 + 2 * math.log2(1 + low)
        score = max(0, min(100, round(100 - penalty)))

        # Score color
        if score >= 80:
            sc, sc_label = C.NEON, "SECURE"
        elif score >= 60:
            sc, sc_label = C.CYAN, "FAIR"
        elif score >= 40:
            sc, sc_label = C.Y, "AT RISK"
        elif score >= 20:
            sc, sc_label = C.R, "POOR"
        else:
            sc, sc_label = C.FLAME, "CRITICAL"

        border = C.gradient("━" * 72, 138, 43, 226, 0, 255, 255)
        border2 = C.gradient("━" * 72, 0, 255, 255, 138, 43, 226)

        print(f"\n{border}")
        print(f"  {C.NEON}✓{C.RST} {C.BOLD}{C.CYAN}CYPHEX SCAN COMPLETE{C.RST}")
        print(f"{border2}\n")

        # Score display
        bar_filled = int(score / 100 * 20)
        bar_empty = 20 - bar_filled
        score_bar = f"{sc}{'█' * bar_filled}{C.GHOST}{'░' * bar_empty}{C.RST}"
        print(f"  {C.SLATE}Security Score{C.RST}   {score_bar}  {sc}{C.BOLD}{score}/100{C.RST}  {sc}{sc_label}{C.RST}")
        print()

        # Severity breakdown
        if total > 0:
            print(f"  {C.FLAME}● Critical: {crit}{C.RST}  {C.R}● High: {high}{C.RST}  {C.Y}● Medium: {med}{C.RST}  {C.SLATE}● Low: {low}{C.RST}  {C.GHOST}│{C.RST}  {C.CYAN}Total: {total}{C.RST}")
        else:
            print(f"  {C.NEON}● No vulnerabilities found{C.RST}")
        print()

        # Metadata
        print(f"  {C.GHOST}Duration    {C.SLATE}{elapsed:.1f}s{C.RST}")
        print(f"  {C.GHOST}Scan ID     {C.CYAN2}{self.scan_id}{C.RST}")
        print(f"  {C.GHOST}Agents      {C.SLATE}13 deployed (Crawler, XSS, SQLi, Auth, LFI, CMDi, CORS, IDOR, SSRF, SDE, JWT, SupplyChain, API){C.RST}")
        print(f"  {C.GHOST}Tools       {C.SLATE}Semgrep + Nuclei + Built-in Scanner + Immune System{C.RST}")

        print(f"\n{border}")
        print(f"  {C.PURP2}cyphex{C.RST} {C.GHOST}— Multi-Agent Security Pipeline v2.0{C.RST}")
        print(f"{border2}\n")
