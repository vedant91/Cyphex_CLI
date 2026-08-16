"""
CYPHEX — Interactive CLI Shell  v4.4
Autonomous cyber-defence · Local-first · Offline-capable

Usage:
  python cyphex.py              → Interactive shell
  python cyphex.py /scan <url>  → Direct command
  python cyphex.py /deep <url>  → Direct command

Commands inside the shell:
  /scan  <target>  Static + DAST scan (all recon/crawler/attack agents)
  /deep  <target>  + DeepAgents swarm (Oracle-guided adaptive attacks)
  /full  <target>  DeepAgents + network map (complete scan mode)
  /net   [host]    Network map / subnet audit only
  /watch           RASP auto-heal daemon (monitor active target)
  /setup           Install & verify required tools
  /doctor          Health check (Ollama, models, curl, dependencies)
  /help            Show all commands
  /exit            Quit the shell

  You can also type a URL or local path directly to trigger a /deep scan.
"""

import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
import uuid
from datetime import datetime

# ── Windows UTF-8 + ANSI ──────────────────────────────────────────────────────
if os.name == "nt":
    os.system("")  # Enable ANSI on Windows terminal
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Path setup ────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND_ROOT = os.path.dirname(_HERE)  # backend/
sys.path.insert(0, _HERE)              # backend/backend/ → config, models, agents
sys.path.insert(1, _BACKEND_ROOT)      # backend/ → deepagents package

from config import config
from agents.terminal import Colors

# ── ANSI colour helpers ───────────────────────────────────────────────────────
R   = "\033[0m"
B   = "\033[1m"
DIM = "\033[2m"
CY  = "\033[36m"
GR  = "\033[32m"
YL  = "\033[33m"
RD  = "\033[31m"
MG  = "\033[35m"
BL  = "\033[34m"
WHT = "\033[97m"

# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = f"""
{CY}{B}
   ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝
  ██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝
  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗
  ╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗
   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{R}
{DIM}  Autonomous cyber-defence · Local-first · Offline-capable    v4.4{R}
"""

HELP_BOX = f"""
{DIM}┌─────────────────────────────────────────────────────────────────────┐{R}
{DIM}│{R}  {B}{GR}/scan{R} <target>   Static + DAST scan      {B}{CY}/watch{R}    RASP auto-heal daemon
{DIM}│{R}  {B}{GR}/deep{R} <target>   {B}+ DeepAgents swarm{R}     {B}{CY}/setup{R}    Install tools
{DIM}│{R}  {B}{GR}/full{R} <target>   DeepAgents + network   {B}{CY}/doctor{R}   Health check
{DIM}│{R}  {B}{GR}/net{R}  [host]     Network map / audit    {B}{CY}/help{R}     All commands
{DIM}│{R}
{DIM}│{R}  {DIM}flags   --timeout <sec>  --output <file>  --no-patch{R}
{DIM}│{R}  {DIM}tip     type a URL directly to start a /deep scan{R}
{DIM}└─────────────────────────────────────────────────────────────────────┘{R}
"""


# ── Doctor / health check ─────────────────────────────────────────────────────

def _check_tool(name: str, cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return True, ""
    except FileNotFoundError:
        return False, "not found in PATH"
    except Exception as e:
        return False, str(e)


def _check_ollama_models() -> tuple[bool, list[str]]:
    try:
        import httpx
        r = httpx.get("http://localhost:11434/api/tags", timeout=5)
        models = [m["name"] for m in r.json().get("models", [])]
        return True, models
    except Exception:
        return False, []


def cmd_doctor():
    print(f"\n{B}  ◆ HEALTH CHECK{R}")
    print(f"  {DIM}{'─' * 50}{R}\n")

    required_tools = [
        ("Python 3.10+", [sys.executable, "--version"]),
        ("curl.exe",     ["curl.exe", "--version"]),
        ("git",          ["git", "--version"]),
        ("node",         ["node", "--version"]),
        ("ollama",       ["ollama", "--version"]),
    ]

    all_ok = True
    for name, cmd in required_tools:
        ok, err = _check_tool(name, cmd)
        icon = f"{GR}✓{R}" if ok else f"{RD}✗{R}"
        status = "" if ok else f"  {RD}← {err}{R}"
        print(f"  {icon}  {name:<20}{status}")
        if not ok:
            all_ok = False

    # Ollama models
    print()
    ollama_ok, models = _check_ollama_models()
    if ollama_ok:
        print(f"  {GR}✓{R}  Ollama running   {DIM}{len(models)} model(s){R}")
        required_models = ["qwen2.5-coder:7b", "llama3.1:8b", "deepseek-coder:6.7b"]
        for m in required_models:
            found = any(m.split(":")[0] in x for x in models)
            icon = f"{GR}✓{R}" if found else f"{YL}?{R}"
            print(f"  {icon}    {m:<30} {'[FOUND]' if found else '[MISSING — run: ollama pull ' + m + ']'}")
    else:
        print(f"  {RD}✗{R}  Ollama          offline — run: ollama serve")
        all_ok = False

    # Python packages
    print()
    py_pkgs = ["httpx", "fastapi", "uvicorn", "rich", "cognee"]
    for pkg in py_pkgs:
        try:
            __import__(pkg)
            print(f"  {GR}✓{R}  pip:{pkg}")
        except ImportError:
            print(f"  {RD}✗{R}  pip:{pkg}  {RD}← run: pip install {pkg}{R}")
            all_ok = False

    print()
    if all_ok:
        print(f"  {GR}{B}All systems nominal. You are ready to scan.{R}\n")
    else:
        print(f"  {YL}Some tools missing. Run {B}/setup{R}{YL} to fix automatically.{R}\n")


# ── Setup / auto-install ──────────────────────────────────────────────────────

def cmd_setup():
    print(f"\n{B}  ◆ SETUP — Installing tools{R}\n")
    packages = ["httpx", "fastapi", "uvicorn[standard]", "websockets", "rich",
                "numpy", "scikit-learn", "joblib", "cognee"]
    print(f"  Installing Python packages...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q"] + packages)
    print(f"  {GR}✓{R}  Python packages installed\n")

    # Check Ollama models
    ollama_ok, models = _check_ollama_models()
    if not ollama_ok:
        print(f"  {YL}⚠{R}  Ollama not running — skipping model pull")
        print(f"     Start Ollama first, then run {B}/setup{R} again.\n")
        return

    required_models = ["qwen2.5-coder:7b", "llama3.1:8b", "deepseek-coder:6.7b"]
    for m in required_models:
        if not any(m.split(":")[0] in x for x in models):
            print(f"  Pulling {m}...")
            subprocess.run(["ollama", "pull", m])
            print(f"  {GR}✓{R}  {m} ready")
        else:
            print(f"  {GR}✓{R}  {m} already available")

    print(f"\n  {GR}{B}Setup complete.{R}\n")


# ── Parse flags from args ─────────────────────────────────────────────────────

def _parse_flags(parts: list[str]) -> tuple[str, dict]:
    """Extract target and flags from command parts."""
    target = ""
    flags = {"timeout": 1800, "output": "", "no_patch": False, "network": False}
    i = 0
    while i < len(parts):
        p = parts[i]
        if p == "--timeout" and i + 1 < len(parts):
            try:
                flags["timeout"] = int(parts[i + 1])
                i += 2
                continue
            except ValueError:
                pass
        elif p == "--output" and i + 1 < len(parts):
            flags["output"] = parts[i + 1]
            i += 2
            continue
        elif p == "--no-patch":
            flags["no_patch"] = True
        elif p == "--network":
            flags["network"] = True
        elif not p.startswith("--") and not target:
            target = p
        i += 1
    return target, flags


# ── Core scan runner ──────────────────────────────────────────────────────────

async def _run_scan(target: str, mode: str, flags: dict):
    """Run the full scan pipeline with the given mode."""
    from scan_orchestrator import ScanOrchestrator

    # Normalise target
    if not target.startswith("http") and not target.startswith("/") and "." in target:
        target = f"http://{target}"

    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    config.SCAN_TIMEOUT_SECONDS = flags["timeout"]

    mode_label = {
        "scan": "Static + DAST",
        "deep": "DeepAgents Swarm",
        "full": "DeepAgents + Network",
    }.get(mode, mode)

    print(f"\n  {MG}◆{R}  Scanning {B}{target}{R}")
    print(f"  {DIM}Mode: {mode_label}{R}\n")

    orchestrator = ScanOrchestrator()

    try:
        report = await asyncio.wait_for(
            orchestrator.run_scan(scan_id, target, config.CEREBRAS_API_KEY),
            timeout=config.SCAN_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        print(f"\n  {RD}Scan timed out after {config.SCAN_TIMEOUT_SECONDS}s{R}")
        report = {"error": "timeout"}
    except KeyboardInterrupt:
        print(f"\n  {YL}Scan interrupted{R}")
        report = {"error": "interrupted"}

    # Save report
    output_file = flags["output"] or os.path.join(
        config.WORKING_DIR, scan_id, "report.json"
    )
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  {GR}Report saved → {output_file}{R}")

    return report


# ── Network scan ──────────────────────────────────────────────────────────────

async def _run_net(host: str):
    """Run network mapping via agent_15_network."""
    try:
        from agents.agent_15_network import NetworkAgent
        from models.scan import ScanContext
        scan_id = f"net_{uuid.uuid4().hex[:8]}"
        target = host or "192.168.1.0/24"
        ctx = ScanContext(target_url=target)
        agent = NetworkAgent(scan_id, target)
        result = await agent.run(ctx)
        print(f"\n  {GR}Network scan complete.{R}\n")
    except ImportError:
        print(f"  {YL}Network agent not available in this build.{R}\n")


# ── Command dispatch ──────────────────────────────────────────────────────────

async def dispatch(line: str):
    """Parse and dispatch a command line."""
    line = line.strip()
    if not line:
        return

    parts = line.split()
    cmd = parts[0].lower()
    rest = parts[1:]

    # Direct URL / path → treat as /deep
    if (cmd.startswith("http://") or cmd.startswith("https://") or
            (not cmd.startswith("/") and ("." in cmd or "/" in cmd))):
        target, flags = _parse_flags(parts)
        await _run_scan(target, "deep", flags)
        return

    if cmd in ("/exit", "/quit", "exit", "quit"):
        print(f"\n  {DIM}Bye.{R}\n")
        sys.exit(0)

    elif cmd == "/help":
        print(HELP_BOX)

    elif cmd == "/doctor":
        cmd_doctor()

    elif cmd == "/setup":
        cmd_setup()

    elif cmd == "/scan":
        target, flags = _parse_flags(rest)
        if not target:
            print(f"  {YL}Usage: /scan <target> [--timeout 600]{R}\n")
            return
        # /scan uses standard scan (no --deepagents flag needed, DeepAgents are default)
        await _run_scan(target, "scan", flags)

    elif cmd == "/deep":
        target, flags = _parse_flags(rest)
        if not target:
            print(f"  {YL}Usage: /deep <target> [--timeout 600]{R}\n")
            return
        await _run_scan(target, "deep", flags)

    elif cmd == "/full":
        target, flags = _parse_flags(rest)
        if not target:
            print(f"  {YL}Usage: /full <target> [--timeout 1800]{R}\n")
            return
        flags["network"] = True
        await _run_scan(target, "full", flags)

    elif cmd == "/net":
        host = rest[0] if rest else ""
        await _run_net(host)

    elif cmd == "/watch":
        print(f"  {YL}RASP daemon: not yet implemented in this build.{R}\n")

    else:
        print(f"  {RD}Unknown command:{R} {cmd}  (try {B}/help{R})\n")


# ── Status bar ────────────────────────────────────────────────────────────────

def _status_bar() -> str:
    ollama_ok, models = _check_ollama_models()
    ollama_str = f"{GR}OLLAMA OK{R}" if ollama_ok else f"{RD}OLLAMA DOWN{R}"
    model_count = len(models)
    return (
        f"  {DIM}│{R} {ollama_str} "
        f"{DIM}│{R} {model_count} model(s) "
        f"{DIM}│{R} cwd: {os.getcwd()} "
        f"{DIM}│{R} {datetime.now().strftime('%H:%M')}"
    )


# ── Interactive shell loop ────────────────────────────────────────────────────

async def shell():
    print(BANNER)
    print(HELP_BOX)
    print(_status_bar())
    print()

    while True:
        try:
            line = input(f"\n  {CY}⊕ cx{R} {DIM}▶{R}  ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Interrupted. Type /exit to quit.{R}")
            continue

        if not line:
            continue

        try:
            await dispatch(line)
        except Exception as e:
            print(f"  {RD}Error: {e}{R}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    # If args given, dispatch directly (non-interactive mode)
    if len(sys.argv) > 1:
        line = " ".join(sys.argv[1:])
        await dispatch(line)
    else:
        await shell()


if __name__ == "__main__":
    asyncio.run(main())
