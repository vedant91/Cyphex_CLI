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
    scan_p.add_argument(
        "--network",
        action="store_true",
        help="Also run network security scan (host discovery + port scan + vuln report)",
    )
    scan_p.add_argument(
        "--use-deepagents",
        action="store_true",
        help="Use the new experimental DeepAgents for adaptive Oracle-guided DAST",
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

    # === NETWORK SECURITY COMMANDS ===
    netmap_p = sub.add_parser("netmap", help="Network discovery, port scan, and vulnerability report")
    netmap_p.add_argument("--target", default="auto",
        help="Target CIDR or IP (default: auto-detect local subnet)")
    netmap_p.add_argument("--no-active", action="store_true",
        help="Skip active verification probes (FTP anon, Redis auth, etc.)")
    netmap_p.add_argument("--output", default="",
        help="Save JSON report to file")

    netwatch_p = sub.add_parser("netwatch",
        help="Continuous behavioural anomaly monitoring (no signatures)")
    netwatch_p.add_argument("--interval", type=int, default=60,
        help="Sampling interval in seconds (default: 60)")
    netwatch_p.add_argument("--train-first", action="store_true",
        help="Run netmap to build baselines before watching")

    netaudit_p = sub.add_parser("netaudit",
        help="Deep security audit of a single host")
    netaudit_p.add_argument("--host", required=True,
        help="Target IP address to audit")
    netaudit_p.add_argument("--oracle", action="store_true",
        help="Use Ollama Oracle to explain findings")

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

    if args.command == "netmap":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        asyncio.run(_cmd_netmap(args))
        return

    if args.command == "netwatch":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        asyncio.run(_cmd_netwatch(args))
        return

    if args.command == "netaudit":
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        asyncio.run(_cmd_netaudit(args))
        return

    if args.command == "scan":
        if not args.repo and not args.path:
            print(f"{C.R}Error: Provide --repo or --path{C.RST}")
            return
        os.system("cls" if os.name == "nt" else "clear")
        # Engine prints its own full banner — don't double-print here
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
            network_scan=args.network,
            use_deepagents=args.use_deepagents,
        ))



# ═══════════════════════════════════════════════════════════════════════════════
#  Network command handlers
# ═══════════════════════════════════════════════════════════════════════════════

async def _cmd_netmap(args):
    """cyphex netmap — discover network, scan ports, report vulnerabilities."""
    try:
        import sys as _sys
        from backend.network.discovery import NetworkDiscovery
        from backend.network.vuln_mapper import NetworkVulnMapper
        from backend.network.network_genome import NetworkBehavioralGenome
        from backend.network.topology_builder import TopologyBuilder
    except ImportError as e:
        print(f"{C.R}[netmap] Missing dependency: {e}{C.RST}")
        print("  Install: pip install networkx scikit-learn joblib")
        return

    print(f"  {C.BOLD}◈ CYPHEX NETWORK MAP{C.RST}")
    print(f"  {C.DIM}Target: {args.target}{C.RST}\n")

    # Phase 1: Discovery
    disc = NetworkDiscovery()
    nmap = await disc.discover(args.target)
    live = nmap.live_hosts()

    if not live:
        print(f"  {C.Y}No live hosts found on {args.target}{C.RST}")
        return

    # Phase 2: Vulnerability mapping
    print(f"\n  {C.BOLD}◈ VULNERABILITY MAPPING{C.RST}")
    mapper = NetworkVulnMapper()
    vulns = await mapper.map(nmap, active_checks=not args.no_active)

    # Phase 3: Topology
    topo = TopologyBuilder()
    G = topo.build(nmap)
    topo.annotate_vulns(G, vulns)

    # Phase 4: Train genome baselines (synthetic — real training needs netwatch)
    genome = NetworkBehavioralGenome()
    for host in live:
        genome.train(host.ip, windows=[])   # trains on synthetic normal samples
    genome.save()

    # ── Print results ──────────────────────────────────────────────────────────
    _SEV_COLORS = {
        "Critical": C.R, "High": "\033[91m", "Medium": C.Y, "Low": C.B
    }

    print(f"\n  {C.BOLD}{'HOST':<18} {'HOSTNAME':<22} {'OS':<16} {'RISK':<8} PORTS{C.RST}")
    print("  " + "─" * 76)
    for host in nmap.hosts_by_risk():
        if not host.is_up:
            continue
        ports_str = " ".join(str(p.port) for p in host.open_ports[:6])
        if len(host.open_ports) > 6:
            ports_str += f" +{len(host.open_ports) - 6}"
        risk_pct = int(host.risk_score * 100)
        risk_col = C.R if risk_pct >= 75 else C.Y if risk_pct >= 40 else C.G
        print(
            f"  {host.ip:<18} {host.hostname[:21]:<22} {host.os_guess[:15]:<16}"
            f" {risk_col}{risk_pct}%{C.RST}     {C.DIM}{ports_str}{C.RST}"
        )

    if vulns:
        print(f"\n  {C.BOLD}◈ NETWORK VULNERABILITIES ({len(vulns)} findings){C.RST}")
        print("  " + "─" * 76)
        for v in vulns[:20]:
            col = _SEV_COLORS.get(v.severity, C.W)
            confirm = " ✓ CONFIRMED" if v.confirmed else ""
            print(f"  {col}[{v.severity:8}]{C.RST}  {v.host}:{v.port}  {v.service}")
            print(f"             {v.title}{confirm}")
            if v.issues:
                for issue in v.issues[:2]:
                    print(f"             {C.DIM}• {issue}{C.RST}")
            if v.mitre_technique:
                print(f"             {C.DIM}MITRE: {v.mitre_technique}{C.RST}")
            print()

    if G is not None:
        print(f"\n  {C.BOLD}◈ NETWORK TOPOLOGY{C.RST}")
        print(topo.summary_text(G, vulns))

    print(f"\n  {C.G}Scan complete.{C.RST} {len(live)} hosts, {len(vulns)} findings.")
    print(f"  Genome baselines saved. Run {C.BOLD}cyphex netwatch{C.RST} to monitor deviations.\n")

    # Save JSON report
    if args.output:
        import json as _json
        report = {
            "target": args.target,
            "hosts": [
                {"ip": h.ip, "hostname": h.hostname, "os": h.os_guess,
                 "ports": [p.port for p in h.open_ports],
                 "risk_score": h.risk_score, "device_type": h.device_type}
                for h in live
            ],
            "vulnerabilities": [
                {"host": v.host, "port": v.port, "service": v.service,
                 "severity": v.severity, "title": v.title,
                 "confirmed": v.confirmed, "mitre": v.mitre_technique}
                for v in vulns
            ],
            "topology": topo.to_dict(G) if G else {},
        }
        with open(args.output, "w") as f:
            _json.dump(report, f, indent=2)
        print(f"  {C.G}Report saved → {args.output}{C.RST}\n")


async def _cmd_netwatch(args):
    """cyphex netwatch — continuous behavioural anomaly monitoring."""
    try:
        import sys as _sys
        from backend.network.network_genome import NetworkBehavioralGenome
        from backend.network.flow_collector import continuous_sample
        from backend.network.oracle_network import NetworkOracle
    except ImportError as e:
        print(f"{C.R}[netwatch] Missing dependency: {e}{C.RST}")
        return

    interval = args.interval
    print(f"  {C.BOLD}◈ CYPHEX NETWORK WATCH{C.RST}")
    print(f"  {C.DIM}Sampling every {interval}s — Ctrl+C to stop{C.RST}\n")

    genome = NetworkBehavioralGenome()
    loaded = genome.load()
    if not loaded:
        print(f"  {C.Y}No genome baselines found.{C.RST} Run {C.BOLD}cyphex netmap{C.RST} first to train baselines.")
        if args.train_first:
            print("  Running netmap to build baselines...")

            class _FakeArgs:
                target = "auto"
                no_active = False
                output = ""
            await _cmd_netmap(_FakeArgs())
            genome.load()
        else:
            print("  Starting with synthetic baselines (less accurate).")

    oracle = NetworkOracle()

    async def on_anomaly(score):
        from datetime import datetime as _dt
        ts = _dt.now().strftime("%H:%M:%S")
        col = C.R if score.score >= 0.85 else C.Y
        print(f"\n  {col}⚠  ANOMALY DETECTED [{ts}]{C.RST}")
        print(f"     Device:  {score.device_ip}")
        print(f"     Score:   {score.score:.3f} / 1.0  ({score.severity})")
        if score.top_deviating_features:
            for feat in score.top_deviating_features[:3]:
                print(f"     {C.DIM}→ {feat}{C.RST}")
        # Oracle enrichment
        enriched = await oracle.enrich(score)
        if enriched.threat_scenario:
            print(f"     {C.BOLD}Scenario:{C.RST}  {enriched.threat_scenario}")
            print(f"     {C.BOLD}MITRE:{C.RST}     {enriched.mitre_technique}")
            print(f"     {C.BOLD}Confidence:{C.RST} {enriched.confidence:.0%}")
            if enriched.containment_actions:
                print(f"     {C.BOLD}Actions:{C.RST}")
                for act in enriched.containment_actions:
                    print(f"       • {act}")
        print()

    print(f"  {C.G}Monitoring active.{C.RST} Watching {len(genome.trained_devices())} device baselines.\n")
    await continuous_sample(genome, interval_s=interval, alert_callback=on_anomaly)


async def _cmd_netaudit(args):
    """cyphex netaudit --host IP — deep audit of a single host."""
    try:
        import sys as _sys
        from backend.network.discovery import NetworkDiscovery
        from backend.network.vuln_mapper import NetworkVulnMapper
        from backend.network.oracle_network import NetworkOracle
    except ImportError as e:
        print(f"{C.R}[netaudit] Missing dependency: {e}{C.RST}")
        return

    host_ip = args.host
    print(f"  {C.BOLD}◈ CYPHEX HOST AUDIT — {host_ip}{C.RST}\n")

    disc = NetworkDiscovery(timeout=1.5)
    nmap = await disc.discover(host_ip)
    live = nmap.live_hosts()

    if not live:
        print(f"  {C.R}Host {host_ip} appears offline or unreachable.{C.RST}")
        return

    host = live[0]
    print(f"  Hostname: {host.hostname or '(unknown)'}")
    print(f"  OS:       {host.os_guess or '(unknown)'}")
    print(f"  MAC:      {host.mac or '(unknown)'}")
    print(f"  Device:   {host.device_type}")
    print(f"  Ports:    {len(host.open_ports)} open\n")

    mapper = NetworkVulnMapper()
    vulns = await mapper.map(nmap, active_checks=True)

    _SEV_COLORS = {"Critical": C.R, "High": "\033[91m", "Medium": C.Y, "Low": C.B}

    if vulns:
        print(f"  {C.BOLD}◈ FINDINGS ({len(vulns)}){C.RST}")
        print("  " + "─" * 66)
        oracle = NetworkOracle() if args.oracle else None

        for v in vulns:
            col = _SEV_COLORS.get(v.severity, C.W)
            confirm = f" {C.G}✓ CONFIRMED{C.RST}" if v.confirmed else ""
            print(f"\n  {col}[{v.severity}]{C.RST} {v.title}{confirm}")
            print(f"  Port: {v.port}/{v.service}")
            for issue in v.issues:
                print(f"  {C.DIM}• {issue}{C.RST}")
            if v.cve_refs:
                print(f"  CVEs: {', '.join(v.cve_refs[:3])}")
            if v.mitre_technique:
                print(f"  MITRE: {C.DIM}{v.mitre_technique}{C.RST}")
            if v.remediation:
                print(f"  Fix:  {C.G}{v.remediation}{C.RST}")

        if oracle:
            from backend.network.models import AnomalyScore
            print(f"\n  {C.BOLD}◈ ORACLE THREAT ASSESSMENT{C.RST}")
            # Build a pseudo anomaly score for Oracle reasoning
            pseudo = AnomalyScore(
                device_ip=host_ip,
                score=host.risk_score,
                is_anomaly=host.risk_score > 0.5,
                reason=f"{len(vulns)} vulnerabilities found",
                top_deviating_features=[v.title for v in vulns[:3]],
            )
            enriched = await oracle.enrich(pseudo)
            print(f"  Scenario:   {enriched.threat_scenario}")
            print(f"  MITRE:      {enriched.mitre_technique}")
            print(f"  Confidence: {enriched.confidence:.0%}")
            if enriched.containment_actions:
                print("  Containment:")
                for act in enriched.containment_actions:
                    print(f"    • {act}")
    else:
        print(f"  {C.G}No known vulnerabilities detected on {host_ip}.{C.RST}")

    print(f"\n  {C.BOLD}Risk Score: {int(host.risk_score * 100)}/100{C.RST}\n")


if __name__ == "__main__":
    main()
