"""
CYPHEX CLI — Main Entry Point

Usage:
    cyphex scan ./my-app              # Scan local source code
    cyphex scan https://example.com   # Scan a live URL
    cyphex scan --repo https://...    # Clone and scan a repo
    cyphex setup                      # Auto-install optional tools
    cyphex doctor                     # System health check
    cyphex version                    # Show version
"""

import sys
import os
import asyncio
import argparse
import shutil
import subprocess
import platform

# Fix Windows terminal encoding for rich characters like ✓
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
# Ensure project root is in path so existing modules resolve
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
# Backend modules expect backend/backend on the path
_BACKEND_DIR = os.path.join(_PROJECT_ROOT, "backend", "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


def _setup_tools():
    """Auto-install optional security tools for enhanced scanning."""
    # Cyber palette
    CY = "\033[38;2;0;255;255m"
    P2 = "\033[38;2;161;100;255m"
    GH = "\033[38;2;100;100;120m"
    SL = "\033[38;2;140;150;170m"
    NE = "\033[38;2;57;255;20m"
    FL = "\033[38;2;255;69;0m"
    BD = "\033[1m"
    RS = "\033[0m"
    YL = "\033[93m"

    def _grad(text, r1, g1, b1, r2, g2, b2):
        out = []
        n = max(len(text) - 1, 1)
        for i, ch in enumerate(text):
            r = int(r1 + (r2 - r1) * i / n)
            g = int(g1 + (g2 - g1) * i / n)
            b = int(b1 + (b2 - b1) * i / n)
            out.append(f"\033[38;2;{r};{g};{b}m{ch}")
        out.append(RS)
        return "".join(out)

    border = _grad("━" * 56, 0, 255, 255, 138, 43, 226)
    print(f"\n{border}")
    print(f"  {CY}{BD}◈ CYPHEX{RS} {SL}— One-Time Setup{RS}")
    print(f"{border}\n")

    installed = []
    skipped = []

    # 1. Semgrep (Python package — cross-platform)
    if shutil.which("semgrep"):
        print(f"  {NE}✓{RS} {SL}Semgrep already installed{RS}")
        skipped.append("semgrep")
    else:
        print(f"  {CY}⏳{RS} {SL}Installing Semgrep (5000+ SAST rules)...{RS}")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "semgrep", "--quiet"],
                check=True, timeout=120
            )
            print(f"  {NE}✓{RS} {SL}Semgrep installed{RS}")
            installed.append("semgrep")
        except Exception as e:
            print(f"  {FL}✗{RS} Semgrep failed: {e}")

    # 2. Nuclei (Go binary — platform-specific download)
    if shutil.which("nuclei"):
        print(f"  {NE}✓{RS} {SL}Nuclei already installed{RS}")
        skipped.append("nuclei")
    else:
        print(f"  {CY}⏳{RS} {SL}Installing Nuclei (8000+ DAST templates)...{RS}")
        system = platform.system().lower()
        machine = platform.machine().lower()

        if system == "darwin":
            # macOS — try Homebrew first
            if shutil.which("brew"):
                try:
                    subprocess.run(
                        ["brew", "install", "nuclei"],
                        check=True, timeout=180, capture_output=True
                    )
                    print(f"  {NE}✓{RS} {SL}Nuclei installed via Homebrew{RS}")
                    installed.append("nuclei")
                except Exception:
                    _install_nuclei_binary(system, machine, installed)
            else:
                _install_nuclei_binary(system, machine, installed)

        elif system == "linux":
            # Linux — try apt, then binary
            if shutil.which("apt-get"):
                try:
                    subprocess.run(
                        ["sudo", "apt-get", "install", "-y", "nuclei"],
                        check=True, timeout=120, capture_output=True
                    )
                    print(f"  {NE}✓{RS} {SL}Nuclei installed via apt{RS}")
                    installed.append("nuclei")
                except Exception:
                    _install_nuclei_binary(system, machine, installed)
            else:
                _install_nuclei_binary(system, machine, installed)

        elif system == "windows":
            # Windows — try winget or scoop
            if shutil.which("winget"):
                try:
                    subprocess.run(
                        ["winget", "install", "ProjectDiscovery.Nuclei"],
                        check=True, timeout=180, capture_output=True
                    )
                    print(f"  {NE}✓{RS} {SL}Nuclei installed via winget{RS}")
                    installed.append("nuclei")
                except Exception:
                    print("  ✗ Nuclei: Install manually from https://github.com/projectdiscovery/nuclei/releases")
            elif shutil.which("scoop"):
                try:
                    subprocess.run(
                        ["scoop", "install", "nuclei"],
                        check=True, timeout=180, capture_output=True
                    )
                    print(f"  {NE}✓{RS} {SL}Nuclei installed via scoop{RS}")
                    installed.append("nuclei")
                except Exception:
                    print("  ✗ Nuclei: Install manually from https://github.com/projectdiscovery/nuclei/releases")

    # 3. Ollama models (auto-pull if Ollama is installed)
    if shutil.which("ollama"):
        print(f"  {NE}✓{RS} {SL}Ollama installed{RS}")
        # Check if Ollama is running
        try:
            import urllib.request
            urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
            ollama_running = True
        except Exception:
            ollama_running = False
            print(f"  {CY}⏳{RS} {SL}Starting Ollama...{RS}")
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            import time
            time.sleep(3)
            ollama_running = True

        if ollama_running:
            # Dynamic model discovery — use whatever the user has
            try:
                result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=10)
                existing_lines = [l for l in result.stdout.strip().split("\n")[1:] if l.strip()]
                existing_models = [l.split()[0] for l in existing_lines if l.split()]
            except Exception:
                existing_models = []

            if existing_models:
                # User already has models — report them, don't force specific ones
                print(f"  {NE}✓{RS} {SL}Found {len(existing_models)} Ollama model(s) — CYPHEX will auto-select the best:{RS}")
                for m in existing_models:
                    print(f"    • {m}")
                skipped.extend(existing_models)
            else:
                # No models at all — pull lightweight defaults based on system resources
                print(f"  {CY}⏳{RS} {SL}No Ollama models found. Pulling lightweight defaults...{RS}")
                defaults = ["deepseek-coder:1.3b", "phi3:mini"]
                for model in defaults:
                    print(f"  ⏳ Pulling {model} (this may take a few minutes)...")
                    try:
                        subprocess.run(
                            ["ollama", "pull", model],
                            timeout=600, check=True
                        )
                        print(f"  ✓ Model {model} ready")
                        installed.append(model)
                    except subprocess.TimeoutExpired:
                        print(f"  {FL}✗{RS} {model} pull timed out (try manually: ollama pull {model})")
                    except Exception as e:
                        print(f"  {FL}✗{RS} {model} failed: {e}")
    else:
        print(f"  {YL}⚠{RS} {SL}Ollama not found — needed for AI council & patching{RS}")
        print("    Install from: https://ollama.ai")

    # 4. Docker status
    if shutil.which("docker"):
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
            if result.returncode == 0:
                print(f"  {NE}✓{RS} {SL}Docker is running{RS}")
                skipped.append("docker")
            else:
                print(f"  {YL}⚠{RS} {SL}Docker is installed but not running — start Docker Desktop{RS}")
        except Exception:
            print(f"  {YL}⚠{RS} {SL}Docker check failed{RS}")
    else:
        print(f"  {YL}⚠{RS} {SL}Docker not found — needed for full-stack scanning{RS}")
        print("    Install from: https://www.docker.com/products/docker-desktop/")

    border = _grad("━" * 56, 138, 43, 226, 0, 255, 255)
    print(f"\n{border}")
    print(f"  {NE}✓{RS} {BD}Setup complete:{RS} {CY}{len(installed)} installed{RS}, {SL}{len(skipped)} already present{RS}")
    print(f"  {GH}Run '{CY}cyphex doctor{GH}' to verify everything{RS}")
    print(f"{border}\n")


def _safe_extract_zip(zf, dest_dir: str):
    """Extract a ZipFile into dest_dir, rejecting any member whose resolved
    path would escape dest_dir (zip-slip: `../` traversal or absolute paths)."""
    dest_root = os.path.realpath(dest_dir)
    for member in zf.infolist():
        member_path = os.path.realpath(os.path.join(dest_dir, member.filename))
        if member_path != dest_root and not member_path.startswith(dest_root + os.sep):
            print(f"  ✗ Skipping unsafe zip entry (path traversal): {member.filename}")
            continue
        zf.extract(member, dest_dir)


def _fetch_nuclei_release_metadata(os_name: str, arch_name: str):
    """Best-effort lookup of the exact asset download URL + expected SHA256
    for the current platform from the latest Nuclei GitHub release.

    Returns (zip_url, expected_sha256_or_None). Never raises — any failure
    just means checksum verification will be skipped (with a warning).
    """
    import urllib.request
    import json as _json

    fallback_url = f"https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_{os_name}_{arch_name}.zip"
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",
            headers={"User-Agent": "cyphex-setup", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            release = _json.loads(resp.read().decode("utf-8"))

        version = str(release.get("tag_name", "")).lstrip("v")
        assets = {a.get("name", ""): a.get("browser_download_url", "") for a in release.get("assets", [])}
        zip_name = f"nuclei_{version}_{os_name}_{arch_name}.zip"
        checksums_name = f"nuclei_{version}_checksums.txt"

        zip_url = assets.get(zip_name, fallback_url)
        checksums_url = assets.get(checksums_name)
        if not checksums_url:
            return zip_url, None

        creq = urllib.request.Request(checksums_url, headers={"User-Agent": "cyphex-setup"})
        with urllib.request.urlopen(creq, timeout=15) as cresp:
            checksums_text = cresp.read().decode("utf-8", errors="ignore")

        for line in checksums_text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].strip().lstrip("*") == zip_name:
                return zip_url, parts[0].strip().lower()

        return zip_url, None
    except Exception:
        return fallback_url, None


def _install_nuclei_binary(system: str, machine: str, installed: list):
    """Download Nuclei binary directly from GitHub releases.

    Verifies the downloaded archive's SHA256 against the checksums file
    ProjectDiscovery publishes alongside each release (when it can be
    resolved), and safely extracts the zip (rejecting zip-slip entries).
    """
    try:
        import urllib.request
        import zipfile
        import tempfile
        import hashlib

        # Map platform to release name
        os_map = {"darwin": "macOS", "linux": "linux"}
        arch_map = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
        os_name = os_map.get(system, system)
        arch_name = arch_map.get(machine, "amd64")

        url, expected_sha256 = _fetch_nuclei_release_metadata(os_name, arch_name)
        if not expected_sha256:
            print("  ⚠ TODO/WARNING: could not resolve the Nuclei release checksum — "
                  "proceeding WITHOUT integrity verification.")
            print("    Verify manually against: https://github.com/projectdiscovery/nuclei/releases")

        with tempfile.TemporaryDirectory() as tmp:
            zip_path = os.path.join(tmp, "nuclei.zip")
            urllib.request.urlretrieve(url, zip_path)

            if expected_sha256:
                hasher = hashlib.sha256()
                with open(zip_path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        hasher.update(chunk)
                actual_sha256 = hasher.hexdigest().lower()
                if actual_sha256 != expected_sha256:
                    print(f"  ✗ Nuclei checksum MISMATCH (expected {expected_sha256}, got {actual_sha256}) — aborting install.")
                    return
                print("  ✓ Nuclei archive checksum verified")

            extract_dir = os.path.join(tmp, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                _safe_extract_zip(zf, extract_dir)

            nuclei_bin = os.path.join(extract_dir, "nuclei")
            if os.path.exists(nuclei_bin):
                # Install to user bin
                user_bin = os.path.expanduser("~/.local/bin")
                os.makedirs(user_bin, exist_ok=True)
                dest = os.path.join(user_bin, "nuclei")
                shutil.copy2(nuclei_bin, dest)
                os.chmod(dest, 0o755)
                print(f"  ✓ Nuclei installed to {dest}")
                print(f"    (Add {user_bin} to your PATH if not already)")
                installed.append("nuclei")
            else:
                print("  ✗ Nuclei binary not found in archive")

    except Exception as e:
        print(f"  ✗ Nuclei download failed: {e}")
        print("    Install manually: https://github.com/projectdiscovery/nuclei/releases")


def _launch_workspace():
    """Drop into the interactive CYPHEX workspace (the slash-command REPL).

    This is the default when `cyphex` is run with no subcommand — so, like
    `claude` or `codex`, a single `cyphex` opens the workspace and everything
    else (/scan, /deep, /net, /doctor, /watch …) happens inside it.
    """
    try:
        import cx  # top-level module at the project root (on sys.path above)
    except Exception as e:
        print(f"Could not load the CYPHEX workspace: {e}")
        print("Run from the project directory, or reinstall with: pip install -e .")
        sys.exit(1)
    cx.run_workspace()


def main():
    parser = argparse.ArgumentParser(
        prog="cyphex",
        description="CYPHEX — AI Security Scanner with Adversarial Immune System. "
                    "Run `cyphex` with no arguments to open the interactive workspace.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── cyphex  (no subcommand) / cyphex repl ──
    # Enter the interactive workspace. Registered as explicit subcommands too so
    # `cyphex repl` / `cyphex workspace` / `cyphex shell` all work.
    for _alias in ("repl", "workspace", "shell"):
        subparsers.add_parser(_alias, help="Open the interactive CYPHEX workspace (default)")

    # ── cyphex scan ──
    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("target", nargs="?", type=str,
                             help="Path to source code OR live URL (e.g. ./my-app or http://...)")
    scan_parser.add_argument("--path", type=str, help="Path to local source code")
    scan_parser.add_argument("--repo", type=str, help="Git repo URL to clone and scan")
    scan_parser.add_argument("--format", type=str, default="table",
                             choices=["table", "json", "sarif", "markdown"],
                             help="Output format (default: table)")
    scan_parser.add_argument("--judge", action="store_true",
                             help="Deterministic mode for benchmarking (SARIF output)")
    scan_parser.add_argument("--no-patch", action="store_true",
                             help="Skip patch generation step")
    scan_parser.add_argument("--deepagents", "--deep", action="store_true", dest="deepagents",
                             help="Enable the full DeepAgents Oracle-guided attack swarm (adaptive DAST)")
    scan_parser.add_argument("--network", action="store_true",
                             help="Also run the network security scan (host discovery + port scan)")
    scan_parser.add_argument("--mode", type=str,
                             choices=["full", "standard", "lite", "cloud"],
                             help="Override auto-detected hardware mode")

    # ── cyphex setup ──
    subparsers.add_parser("setup", help="Auto-install optional security tools (Semgrep, Nuclei)")

    # ── cyphex doctor ──
    subparsers.add_parser("doctor", help="Check system dependencies and hardware")

    # ── cyphex version ──
    subparsers.add_parser("version", help="Show CYPHEX version")

    # ── cyphex council-doctor ──
    subparsers.add_parser("council-doctor", help="Check council model status")

    args = parser.parse_args()

    if args.command in (None, "repl", "workspace", "shell"):
        # `cyphex` with no subcommand → open the interactive workspace.
        _launch_workspace()

    elif args.command == "setup":
        _setup_tools()

    elif args.command == "doctor":
        from cyphex.doctor import run_doctor
        asyncio.run(run_doctor())

    elif args.command == "version":
        from cyphex import __version__
        print(f"cyphex {__version__}")

    elif args.command == "scan":
        # Resolve target: positional arg > --path > --repo
        target = getattr(args, "target", None) or args.path or args.repo
        if not target:
            scan_parser.error("Provide a target: cyphex scan ./my-app  OR  cyphex scan http://example.com")

        from cli_engine import CyphexEngine
        engine = CyphexEngine()

        is_url = target.startswith("http://") or target.startswith("https://")
        is_repo = target.endswith(".git") or (is_url and "github.com" in target)

        # Forward the declared flags that were previously parsed and dropped:
        # --no-patch now actually skips patching, and --deepagents/--network
        # reach the engine so the DeepAgents swarm can be enabled from the CLI.
        auto_patch = not args.no_patch
        use_deepagents = getattr(args, "deepagents", False)
        network_scan = getattr(args, "network", False)

        if is_repo or args.repo:
            asyncio.run(engine.run(repo_url=target, judge=args.judge, auto_patch=auto_patch,
                                   use_deepagents=use_deepagents, network_scan=network_scan))
        elif is_url:
            # Live URL scan — skip sandbox, go directly to dynamic scan
            asyncio.run(engine.run(target_url=target, judge=args.judge, auto_patch=auto_patch,
                                   use_deepagents=use_deepagents))
        else:
            # Local source path
            asyncio.run(engine.run(source_path=target, judge=args.judge, auto_patch=auto_patch,
                                   use_deepagents=use_deepagents, network_scan=network_scan))

    elif args.command == "council-doctor":
        sys.path.insert(0, _PROJECT_ROOT)
        from cyphex_cli import council_doctor
        asyncio.run(council_doctor())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
