"""
CYPHEX Doctor — System health check and smart model installer.

Detects hardware, recommends the BEST Ollama models that fit,
and auto-pulls them. No more manual model selection.

Usage:
    cyphex doctor
"""

import os
import sys
import shutil
import asyncio
import subprocess
import platform
import time
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Confirm

from cyphex.hardware import (
    get_gpu_info, detect_mode, recommend_models,
    MODE_DESCRIPTIONS, MIN_PARAMS_FOR_PATCHING, MIN_PARAMS_FOR_DEBATE,
)

try:                      # drag legacy [green]/[red] markup onto the ramp
    from terminal_ui import themed_console as _themed_console
except Exception:         # terminal_ui not importable in this context
    def _themed_console(**kw): return Console(**kw)
console = _themed_console()


def _check_binary(name: str) -> tuple[bool, str]:
    """Check if a binary is available and return its version."""
    if name == "semgrep" and os.name == "nt":
        try:
            result = subprocess.run(
                ["wsl", "semgrep", "--version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0]
                return True, version
        except Exception:
            pass

    path = shutil.which(name)
    if not path:
        return False, "not installed"
        
    if name == "docker":
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
        if r.returncode != 0:
            if sys.platform == "darwin":
                console.print("  [yellow]⚠ Docker Desktop offline — auto-starting...[/yellow]")
                subprocess.run(["open", "-a", "Docker"], capture_output=True)
                time.sleep(3)
            elif sys.platform == "win32":
                docker_exe = r"C:\Program Files\Docker\Docker\Docker Desktop.exe"
                if os.path.exists(docker_exe):
                    console.print("  [yellow]⚠ Docker Desktop offline — auto-starting...[/yellow]")
                    subprocess.Popen([docker_exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(5)
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
        if r.returncode != 0:
            return True, "installed (daemon not running)"
            
    try:
        result = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=5
        )
        version = result.stdout.strip().split("\n")[0]
        return True, version
    except Exception:
        return True, "installed (version unknown)"


async def _check_ollama_models() -> list[dict]:
    """Get list of locally pulled Ollama models with size info."""
    try:
        import httpx
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{ollama_url}/api/tags")
            if r.status_code == 200:
                return r.json().get("models", [])
    except Exception:
        pass
    return []


async def _check_ollama_running() -> bool:
    """Check if Ollama API is responding."""
    try:
        import httpx
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        async with httpx.AsyncClient(timeout=1.0) as client:
            r = await client.get(f"{ollama_url}/api/version")
            if r.status_code == 200:
                return True
    except Exception:
        pass

    if shutil.which("ollama"):
        console.print("  [yellow]⚠ Ollama server offline — auto-starting...[/yellow]")
        if sys.platform == "darwin":
            subprocess.run(["open", "-a", "Ollama"], capture_output=True)
        elif sys.platform == "win32":
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        else:
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)

    try:
        import httpx
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{ollama_url}/api/version")
            return r.status_code == 200
    except Exception:
        return False


def _pull_model(model_tag: str) -> bool:
    """Pull an Ollama model with progress display."""
    console.print(f"  [cyan]Pulling {model_tag}...[/cyan] (this may take a few minutes)")
    try:
        process = subprocess.Popen(
            ["ollama", "pull", model_tag],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in process.stdout:
            line = line.strip()
            if line and ("pulling" in line.lower() or "%" in line or "success" in line.lower()):
                console.print(f"    [dim]{line}[/dim]")
        process.wait()
        return process.returncode == 0
    except Exception as e:
        console.print(f"    [red]Error: {e}[/red]")
        return False


def _format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    gb = size_bytes / (1024 ** 3)
    if gb >= 1:
        return f"{gb:.1f} GB"
    mb = size_bytes / (1024 ** 2)
    return f"{mb:.0f} MB"


def _get_model_params(model: dict) -> float:
    """Extract parameter count from Ollama model info."""
    name = model.get("name", "")
    details = model.get("details", {})
    
    # Try parameter_size field from details
    param_size = details.get("parameter_size", "")
    if param_size:
        param_size = param_size.upper()
        if "B" in param_size:
            try:
                return float(param_size.replace("B", "").strip())
            except ValueError:
                pass

    # Try parsing from tag name
    tag = name.split(":")[-1] if ":" in name else ""
    for suffix in ["b", "B"]:
        if suffix in tag:
            try:
                return float(tag.replace(suffix, "").strip())
            except ValueError:
                pass

    # Estimate from file size
    size = model.get("size", 0)
    if size > 0:
        gb = size / (1024 ** 3)
        return round(gb * 1.8, 1)  # rough heuristic

    return 0.0


async def run_doctor():
    """Run full system health check with smart model installation."""
    console.print(Panel(
        "[bold cyan]CYPHEX System Doctor[/bold cyan]\n"
        "[dim]Detecting hardware → recommending models → auto-installing...[/dim]",
        border_style="cyan"
    ))
    console.print()

    # ═══════════════════════════════════════════
    # 1. System Info & Hardware Detection
    # ═══════════════════════════════════════════
    gpu_info = get_gpu_info()
    vram_gb = gpu_info["vram_gb"]
    mode = detect_mode(vram_gb)
    recommendation = recommend_models(vram_gb)

    sys_table = Table(title="⚙  System Information", show_header=False, border_style="dim")
    sys_table.add_column("Key", style="bold")
    sys_table.add_column("Value")
    sys_table.add_row("Python", f"{sys.version.split()[0]}")
    sys_table.add_row("Platform", f"{sys.platform} ({platform.machine()})")
    sys_table.add_row("GPU/Accelerator", gpu_info["gpu_name"])
    sys_table.add_row("Available VRAM", f"[bold green]{vram_gb} GB[/bold green]" if vram_gb > 0 else "[red]None[/red]")
    sys_table.add_row("Mode", f"[bold cyan]{mode.upper()}[/bold cyan] — {MODE_DESCRIPTIONS[mode]}")
    sys_table.add_row("AI Patching", "[green]✓ Enabled[/green]" if recommendation["can_patch"] else "[yellow]○ Limited (need 7B+ model)[/yellow]")
    sys_table.add_row("Council Debate", "[green]✓ Enabled[/green]" if recommendation["can_debate"] else "[yellow]○ Limited (need 7B+ model)[/yellow]")
    console.print(sys_table)
    console.print()

    # ═══════════════════════════════════════════
    # 2. Dependencies Check
    # ═══════════════════════════════════════════
    deps_table = Table(title="📦 Dependencies", border_style="dim")
    deps_table.add_column("Tool", style="bold")
    deps_table.add_column("Status")
    deps_table.add_column("Action", style="dim")

    checks = {
        "git": ("https://git-scm.com", True),
        "node": ("https://nodejs.org", False),
        "npm": ("comes with Node.js", False),
        "docker": ("https://docker.com (optional, for sandbox)", False),
        "ollama": ("https://ollama.ai", mode != "cloud"),
        "semgrep": ("pip install semgrep (optional, 5000+ SAST rules)", False),
        "nuclei": ("https://github.com/projectdiscovery/nuclei (optional, DAST)", False),
    }

    all_ok = True
    for tool, (install_hint, required) in checks.items():
        found, version = _check_binary(tool)
        if found:
            deps_table.add_row(tool, f"[green]✓[/green] {version}", "")
        elif required:
            deps_table.add_row(tool, "[red]✗ missing[/red]", f"Install: {install_hint}")
            all_ok = False
        else:
            deps_table.add_row(tool, "[yellow]○ optional[/yellow]", f"Install: {install_hint}")

    console.print(deps_table)
    console.print()

    # ═══════════════════════════════════════════
    # 3. Ollama Models — Smart Selection & Install
    # ═══════════════════════════════════════════
    ollama_running = await _check_ollama_running()
    
    if not ollama_running and mode != "cloud":
        console.print("[red]✗ Ollama is not running[/red]")
        console.print("  → Start with: [bold]ollama serve[/bold]")
        if recommendation["code"]:
            console.print(f"  → Then re-run: [bold]cyphex doctor[/bold]")
        all_ok = False
        console.print()
    elif ollama_running:
        pulled_models = await _check_ollama_models()
        pulled_tags = set()
        for m in pulled_models:
            name = m.get("name", "")
            pulled_tags.add(name)
            # Also add base name (qwen2.5-coder:7b matches qwen2.5-coder:7b-instruct)
            pulled_tags.add(name.split(":")[0])

        # ── Show currently installed models ──
        if pulled_models:
            installed_table = Table(title="📋 Installed Models", border_style="dim")
            installed_table.add_column("Model", style="bold")
            installed_table.add_column("Size")
            installed_table.add_column("Parameters")
            installed_table.add_column("Quality")
            
            best_installed_params = 0
            for m in pulled_models:
                name = m.get("name", "")
                size = _format_size(m.get("size", 0))
                params = _get_model_params(m)
                best_installed_params = max(best_installed_params, params)
                
                if params >= MIN_PARAMS_FOR_PATCHING:
                    quality = "[green]✓ Patch-grade[/green]"
                elif params >= 3.0:
                    quality = "[yellow]○ Analysis-only[/yellow]"
                else:
                    quality = "[red]✗ Too small for reliable AI[/red]"
                
                installed_table.add_row(name, size, f"{params}B", quality)
            
            console.print(installed_table)
            console.print()

        # ── Determine what needs to be pulled ──
        models_to_pull = []
        
        rec_code = recommendation["code"]
        rec_general = recommendation["general"]
        
        if rec_code:
            code_base = rec_code["tag"].split(":")[0]
            code_installed = rec_code["tag"] in pulled_tags or code_base in pulled_tags
            # Also check if we have ANY code model ≥7B already
            have_good_code = any(
                _get_model_params(m) >= MIN_PARAMS_FOR_PATCHING
                and any(kw in m.get("name", "").lower() for kw in ["code", "deepseek", "qwen"])
                for m in pulled_models
            )
            if not code_installed and not have_good_code:
                models_to_pull.append(rec_code)
        
        if rec_general:
            gen_base = rec_general["tag"].split(":")[0]
            gen_installed = rec_general["tag"] in pulled_tags or gen_base in pulled_tags
            # Also check if we have ANY general model ≥7B already
            have_good_general = any(
                _get_model_params(m) >= MIN_PARAMS_FOR_DEBATE
                and not any(kw in m.get("name", "").lower() for kw in ["code", "coder"])
                for m in pulled_models
            )
            if not gen_installed and not have_good_general:
                models_to_pull.append(rec_general)

        # ── Show recommendation ──
        rec_table = Table(title=f"🎯 Recommended Models for {mode.upper()} mode ({vram_gb} GB)", border_style="cyan")
        rec_table.add_column("Role", style="bold")
        rec_table.add_column("Model")
        rec_table.add_column("Params")
        rec_table.add_column("VRAM Needed")
        rec_table.add_column("Status")

        for role, model in [("Code/Patch", rec_code), ("General/Report", rec_general), ("Validator", recommendation.get("validator"))]:
            if model:
                tag = model["tag"]
                tag_base = tag.split(":")[0]
                installed = tag in pulled_tags or tag_base in pulled_tags
                status = "[green]✓ installed[/green]" if installed else "[yellow]○ needs pull[/yellow]"
                rec_table.add_row(role, tag, f"{model['params']}B", f"{model['vram']} GB", status)

        console.print(rec_table)
        console.print()

        # ── Auto-pull missing models ──
        if models_to_pull:
            console.print(Panel(
                f"[bold yellow]⬇  {len(models_to_pull)} model(s) need to be downloaded[/bold yellow]\n"
                + "\n".join(f"  • {m['tag']} ({m['params']}B — best for your hardware)" for m in models_to_pull),
                border_style="yellow"
            ))
            
            do_pull = Confirm.ask(
                f"\n  Download {len(models_to_pull)} model(s) now? (recommended)",
                default=True,
            )
            
            if do_pull:
                console.print()
                for m in models_to_pull:
                    success = _pull_model(m["tag"])
                    if success:
                        console.print(f"  [green]✓ {m['tag']} installed successfully[/green]")
                    else:
                        console.print(f"  [red]✗ Failed to pull {m['tag']}[/red]")
                        all_ok = False
                console.print()
            else:
                console.print("  [dim]Skipped. Run [bold]cyphex doctor[/bold] again when ready.[/dim]")
                console.print()
        else:
            # Check if user has models but they're all too small
            if pulled_models and not recommendation["can_patch"]:
                best = max(_get_model_params(m) for m in pulled_models)
                console.print(Panel(
                    f"[yellow]⚠  Your largest model is {best}B — below the {MIN_PARAMS_FOR_PATCHING}B threshold for reliable patching.[/yellow]\n"
                    f"   Recommended upgrade: [bold]ollama pull {rec_code['tag'] if rec_code else 'qwen2.5-coder:7b'}[/bold]\n"
                    f"   Your hardware ({vram_gb} GB) can handle it!",
                    border_style="yellow"
                ))
                console.print()
            elif not models_to_pull:
                console.print("[green]  ✓ All recommended models are installed[/green]")
                console.print()

    elif mode == "cloud":
        # Cloud mode — check for API keys
        groq_key = os.getenv("GROQ_API_KEY", "")
        openai_key = os.getenv("OPENAI_API_KEY", "")
        if groq_key or openai_key:
            console.print("[green]✓[/green] Cloud API key configured")
        else:
            console.print("[red]✗[/red] No cloud API key found")
            console.print("  → Set GROQ_API_KEY or OPENAI_API_KEY in .env")
            all_ok = False

    console.print()

    # ═══════════════════════════════════════════
    # 4. Verdict
    # ═══════════════════════════════════════════
    if all_ok:
        verdict_parts = ["[bold green]✓ READY[/bold green]"]
        if recommendation["can_patch"]:
            verdict_parts.append("AI patching [green]enabled[/green]")
        else:
            verdict_parts.append("AI patching [yellow]limited[/yellow] (upgrade to 7B+ model)")
        verdict_parts.append(f"Run [bold]cyphex scan --repo <url>[/bold] to start.")
        console.print(Panel(" — ".join(verdict_parts), border_style="green"))
    else:
        console.print(Panel(
            "[bold yellow]⚠ PARTIAL[/bold yellow] — Some items need attention. Fix the items above, then re-run [bold]cyphex doctor[/bold].",
            border_style="yellow"
        ))

    return all_ok
