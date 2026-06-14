"""
CYPHEX CLI — One-command security scanner
Usage:
  python cyphex_cli.py scan --repo https://github.com/user/app
  python cyphex_cli.py scan --path ./my-app
  python cyphex_cli.py scan --path ./backend/target2z/target2
"""
import argparse
import asyncio
import os
import sys
import shutil
import subprocess
import time
import uuid
import json
import glob
import re
import logging
# Silence httpx INFO logs globally (they flood DAST output)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def load_env_file():
    """Lightweight, standard-library-only .env file loader."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    # Strip quotes if present
                    val = v.strip().strip("'\"")
                    os.environ[k.strip()] = val

load_env_file()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend", "backend"))

class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"; BOLD="\033[1m"
    DIM="\033[2m"; RST="\033[0m"

BANNER = f"""
{C.CY}
   _____ __     __ _____   _    _  ______ __   __
  / ____|\\ \\   / /|  __ \\ | |  | ||  ____|\\ \\ / /
 | |      \\ \\_/ / | |__) || |__| || |__    \\ V / 
 | |       \\   /  |  ___/ |  __  ||  __|    > <  
 | |____    | |   | |     | |  | || |____  / . \\ 
  \\_____|   |_|   |_|     |_|  |_||______|/_/ \\_\\
{C.RST}
  {C.BOLD}Autonomous Cyber Defence | v4.3 | OFFLINE-FIRST{C.RST}
  {C.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RST}
"""

def _load_engine():
    """
    Import the engine lazily so we can show a clean dependency error
    instead of a raw traceback during startup.
    """
    try:
        from cli_engine import CyphexEngine
        return CyphexEngine
    except ModuleNotFoundError as exc:
        missing = getattr(exc, "name", None) or str(exc)
        print(f"{C.R}[ERR]{C.RST} Missing Python dependency: {missing}")
        print("Install required packages and retry:")
        print("  python -m pip install -r backend/backend/requirements.txt numpy scikit-learn joblib")
        raise SystemExit(1)

def main():
    parser = argparse.ArgumentParser(description="CYPHEX CLI")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a codebase")
    scan_p.add_argument("--repo", help="GitHub repo URL to clone and scan")
    scan_p.add_argument("--path", help="Local folder path to scan")
    scan_p.add_argument("--branch", default="main", help="Git branch")
    scan_p.add_argument("--generations", type=int, default=10)
    scan_p.add_argument("--output", help="Save report to file")
    scan_p.add_argument("--no-patch", action="store_true", help="Skip patching")
    scan_p.add_argument(
        "--judge",
        action="store_true",
        help="Deterministic judge mode with machine-readable artifacts",
    )
    scan_p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt for patch apply decisions",
    )

    sub.add_parser("doctor", help="Check local runtime/tooling readiness")
    sub.add_parser("council-doctor", help="Check all 4 council models are available in Ollama")

    watch_p = sub.add_parser("watch", help="Start the RASP auto-healing daemon (background server)")
    watch_p.add_argument("--port", type=int, default=3004, help="Daemon port (default: 3004)")
    watch_p.add_argument("--host", default="127.0.0.1", help="Bind host")

    gh_p = sub.add_parser("github-hook", help="Start GitHub webhook receiver for repo-connected RASP")
    gh_p.add_argument("--port", type=int, default=3005, help="Webhook port (default: 3005)")
    gh_p.add_argument("--secret", default="", help="GitHub webhook secret for signature verification")
    # === ONBOARD COMMAND (Zero-Click RASP) ===
    onboard_p = sub.add_parser("onboard", help="Zero-click RASP integration for a new or existing repo")
    onboard_p.add_argument("--repo", help="GitHub repo URL to clone and onboard")
    onboard_p.add_argument("--path", help="Local folder path to onboard")
    onboard_p.add_argument("--scan", action="store_true", help="Also run full Cyphex scan (Semgrep, SAST, DAST, Council, Patcher)")

    args = parser.parse_args()
    if not args.command:
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        parser.print_help()
        return

    if args.command == "onboard":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        if not args.repo and not args.path:
            print(f"{C.R}[ERR]{C.RST} Must provide either --repo or --path")
            sys.exit(1)
        import cyphex.onboarder
        app_dir = cyphex.onboarder.onboard_project(repo_url=args.repo, local_path=args.path)
        if args.scan and app_dir:
            print(f"\n  {C.CY}{'=' * 58}")
            print(f"   PHASE 2: Full Security Scan")
            print(f"  {'=' * 58}{C.RST}\n")
            CyphexEngine = _load_engine()
            engine = CyphexEngine()
            asyncio.run(engine.run(
                local_path=app_dir,
                branch="main",
                generations=10,
                auto_patch=True,
                non_interactive=True,
            ))
        sys.exit(0)

    if args.command == "doctor":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        CyphexEngine = _load_engine()
        engine = CyphexEngine()
        ok = engine.doctor()
        raise SystemExit(0 if ok else 1)

    if args.command == "council-doctor":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        import httpx
        from rich.console import Console
        console = Console()

        REQUIRED_MODELS = [
            ("deepseek-coder:1.3b",  "Detector",    "always-on",   1.0),
            ("phi3:mini",             "Validator",   "always-on",   2.2),
            ("llama3.2:1b",           "Narrator",    "phase-swap",  1.0),
            ("cyphex-patch",          "Patch Agent", "patch-only",  4.5),
        ]

        console.print("[bold cyan]CYPHEX Council Model Health Check[/bold cyan]\n")
        all_ok = True
        for tag, role, schedule, vram in REQUIRED_MODELS:
            try:
                r = httpx.post(
                    "http://localhost:11434/api/generate",
                    json={"model": tag, "prompt": "respond with the word ready", "stream": False},
                    timeout=30.0
                )
                response = r.json().get("response", "")
                if "ready" in response.lower():
                    console.print(f"  [green]✓[/green] {role:12} {tag:30} {vram} GB  ({schedule})")
                else:
                    console.print(f"  [yellow]⚠[/yellow] {role:12} {tag:30} {vram} GB  ({schedule}) — unexpected response")
            except Exception:
                console.print(f"  [red]✗[/red] {role:12} {tag:30} NOT FOUND")
                console.print(f"       → Run: [bold]ollama pull {tag}[/bold]")
                all_ok = False

        print()
        if all_ok:
            console.print("[bold green]All council models are ready![/bold green]")
        else:
            console.print("[bold yellow]Some models are missing. Pull them with ollama.[/bold yellow]")
        raise SystemExit(0 if all_ok else 1)

    if args.command == "watch":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        print(f"  {C.BOLD}Starting CYPHEX Daemon (Auto-Healing Mode){C.RST}")
        print(f"  {C.DIM}Your app's RASP SDK will send attack telemetry here.{C.RST}")
        print(f"  {C.DIM}The AI Council will auto-patch vulnerable source code.{C.RST}\n")
        from cyphex.daemon import run_daemon
        run_daemon(host=args.host, port=args.port)
        return

    if args.command == "github-hook":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        print(f"  {C.BOLD}Starting GitHub Webhook Receiver{C.RST}")
        print(f"  {C.DIM}Connect your GitHub repo's webhook to this endpoint.{C.RST}\n")
        from cyphex.github_hook import run_github_hook
        run_github_hook(port=args.port, secret=args.secret)
        return

    if args.command == "scan":
        if not args.repo and not args.path:
            print(f"{C.R}Error: Provide --repo or --path{C.RST}")
            return
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        CyphexEngine = _load_engine()
        engine = CyphexEngine()
        asyncio.run(engine.run(
            repo_url=args.repo,
            local_path=args.path,
            branch=args.branch,
            generations=args.generations,
            output_file=args.output,
            auto_patch=not args.no_patch,
            judge_mode=args.judge,
            non_interactive=args.non_interactive,
        ))

if __name__ == "__main__":
    main()
