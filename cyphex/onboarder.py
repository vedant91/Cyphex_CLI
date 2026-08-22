"""
CYPHEX Onboarder — Zero-Click Vibe Coder Integration

Automatically injects the Cyphex RASP SDK into a target Node.js Express application.

Usage:
  python cyphex_cli.py onboard --repo https://github.com/user/repo.git
  python cyphex_cli.py onboard --path ./demo/vibemart
"""
import os
import sys
import shutil
import re
import subprocess
import json
import time

class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"; BOLD="\033[1m"
    DIM="\033[2m"; RST="\033[0m"


def _find_express_entry(directory: str) -> str:
    """Heuristically find the main Express entry point."""
    common_names = ["index.js", "app.js", "server.js", "main.js"]

    # First check package.json for "main" or "start" script
    pkg_path = os.path.join(directory, "package.json")
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            # Check "main"
            if "main" in pkg:
                candidate = os.path.join(directory, pkg["main"])
                if os.path.exists(candidate):
                    return candidate
            # Check scripts.start
            if "scripts" in pkg and "start" in pkg["scripts"]:
                start_script = pkg["scripts"]["start"]
                parts = start_script.split()
                for part in parts:
                    if part.endswith(".js"):
                        candidate = os.path.join(directory, part)
                        if os.path.exists(candidate):
                            return candidate
        except Exception:
            pass

    # Fallback to searching common paths
    search_paths = ["", "src", "backend", "backend/src", "server"]
    for sp in search_paths:
        for name in common_names:
            candidate = os.path.join(directory, sp, name)
            if os.path.exists(candidate):
                return candidate

    # Final fallback: walk the tree
    for root, _, files in os.walk(directory):
        if "node_modules" in root:
            continue
        for file in files:
            if file in common_names:
                return os.path.join(root, file)

    return ""


def _inject_rasp(file_path: str, app_dir: str) -> bool:
    """Injects the RASP middleware into the Express app's entry file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if "cyphex-rasp" in content:
            print(f"  {C.Y}[!] Cyphex RASP is already injected in {os.path.basename(file_path)}{C.RST}")
            return True

        # Compute relative path from entry file to the SDK
        sdk_dest = os.path.join(app_dir, "cyphex-rasp.js")
        rel_sdk = os.path.relpath(sdk_dest, os.path.dirname(file_path)).replace("\\", "/")
        if not rel_sdk.startswith("."):
            rel_sdk = "./" + rel_sdk
        # Remove .js extension for require()
        if rel_sdk.endswith(".js"):
            rel_sdk = rel_sdk[:-3]

        # Compute the repoRoot (the app_dir relative to the entry file's directory)
        rel_root = os.path.relpath(app_dir, os.path.dirname(file_path)).replace("\\", "/")
        if rel_root == ".":
            root_expr = "__dirname"
        else:
            root_expr = f"require('path').resolve(__dirname, '{rel_root}')"

        # The injection lines
        rasp_require = f"const cyphexRasp = require('{rel_sdk}');"
        rasp_use = f"app.use(cyphexRasp({{ repoRoot: {root_expr} }}));"
        injection = f"\n// CYPHEX RASP -- Auto-Injected by Cyphex Onboarder\n{rasp_require}\n{rasp_use}\n"

        # Strategy 1: Insert AFTER the last body-parser middleware line
        # Find all app.use(express.json()) or app.use(express.urlencoded()) lines
        body_parser_pattern = re.compile(
            r'^(app\.use\(express\.(?:json|urlencoded)\([^)]*\)\);?\s*)$',
            re.MULTILINE
        )
        matches = list(body_parser_pattern.finditer(content))
        if matches:
            # Insert after the LAST body parser
            last_match = matches[-1]
            insert_pos = last_match.end()
            new_content = content[:insert_pos] + injection + content[insert_pos:]
        else:
            # Strategy 2: Insert after `const app = express();`
            app_init_pattern = re.compile(
                r'^((?:const|let|var)\s+app\s*=\s*express\(\)\s*;?\s*)$',
                re.MULTILINE
            )
            match = app_init_pattern.search(content)
            if match:
                insert_pos = match.end()
                new_content = content[:insert_pos] + injection + content[insert_pos:]
            else:
                print(f"  {C.R}[X] Could not find injection point in {os.path.basename(file_path)}{C.RST}")
                return False

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return True

    except Exception as e:
        print(f"  {C.R}[X] Failed to inject RASP: {e}{C.RST}")
        return False


def onboard_project(repo_url: str = None, local_path: str = None) -> str:
    """
    Main entrypoint for the onboarder.
    Accepts either a GitHub URL (clones it) or a local path (uses it directly).
    Returns the app_dir path on success, or None on failure.
    """
    print(f"\n{C.CY}{'=' * 58}")
    print(f"   CYPHEX ONBOARDER -- Zero-Click Integration")
    print(f"{'=' * 58}{C.RST}\n")

    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # ── Step 1: Resolve target directory ──
    if repo_url:
        # Defense-in-depth against git argument/transport injection: only
        # accept plain https:// URLs, and reject anything that could be
        # parsed as a CLI option (starts with "-").
        if not repo_url.startswith("https://") or repo_url.startswith("-"):
            print(f"  {C.R}[X] Refusing to clone: repo URL must be a plain https:// URL ({repo_url!r}){C.RST}")
            return None

        sandbox_name = f"onboard_{int(time.time())}"
        target_dir = os.path.join(workspace_dir, "backend", "sandboxes", sandbox_name)
        print(f"  {C.B}[1/4] Cloning repository...{C.RST}")
        print(f"  {C.DIM}$ git clone --depth 1 {repo_url}{C.RST}")
        clone_env = os.environ.copy()
        clone_env["GIT_ALLOW_PROTOCOL"] = "https"
        res = subprocess.run(
            ["git", "clone", "--depth", "1", "--", repo_url, target_dir],
            capture_output=True, text=True, env=clone_env
        )
        if res.returncode != 0:
            print(f"  {C.R}[X] Clone failed: {res.stderr.strip()}{C.RST}")
            return None
        print(f"  {C.G}[OK] Cloned to: {target_dir}{C.RST}\n")
    else:
        target_dir = os.path.abspath(local_path)
        if not os.path.exists(target_dir):
            print(f"  {C.R}[X] Path not found: {target_dir}{C.RST}")
            return None
        print(f"  {C.B}[1/4] Using existing project...{C.RST}")
        print(f"  {C.G}[OK] Target: {target_dir}{C.RST}\n")

    # ── Step 2: Locate the app directory (where package.json lives) ──
    print(f"  {C.B}[2/4] Locating Express application...{C.RST}")
    app_dir = target_dir
    if os.path.exists(os.path.join(target_dir, "backend", "package.json")):
        app_dir = os.path.join(target_dir, "backend")
    elif os.path.exists(os.path.join(target_dir, "package.json")):
        app_dir = target_dir
    else:
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d != "node_modules" and d != ".git"]
            if "package.json" in files:
                app_dir = root
                break

    print(f"  {C.DIM}App directory: {app_dir}{C.RST}")

    entry_file = _find_express_entry(app_dir)
    if not entry_file:
        print(f"  {C.Y}[!] Could not find Express entry point automatically.{C.RST}")
        print(f"  {C.Y}    Please add the following to your main server file:{C.RST}")
        print(f"  {C.W}    const cyphexRasp = require('./cyphex-rasp');{C.RST}")
        print(f"  {C.W}    app.use(cyphexRasp({{ repoRoot: __dirname }}));{C.RST}")
    else:
        rel_entry = os.path.relpath(entry_file, app_dir)
        print(f"  {C.G}[OK] Entry point: {rel_entry}{C.RST}\n")

    # ── Step 3: Copy SDK + Inject ──
    print(f"  {C.B}[3/4] Injecting Cyphex RASP SDK...{C.RST}")
    sdk_src = os.path.join(workspace_dir, "sdks", "node", "cyphex-rasp.js")
    sdk_dest = os.path.join(app_dir, "cyphex-rasp.js")

    if not os.path.exists(sdk_src):
        print(f"  {C.R}[X] SDK not found at: {sdk_src}{C.RST}")
        return

    shutil.copy2(sdk_src, sdk_dest)
    print(f"  {C.DIM}Copied cyphex-rasp.js -> {os.path.relpath(sdk_dest, workspace_dir)}{C.RST}")

    if entry_file:
        success = _inject_rasp(entry_file, app_dir)
        if success:
            print(f"  {C.G}[OK] RASP middleware injected into {os.path.basename(entry_file)}{C.RST}\n")
        else:
            print(f"  {C.Y}[!] Auto-injection failed. Please inject manually (see above).{C.RST}\n")

    # ── Step 4: Install dependencies ──
    print(f"  {C.B}[4/4] Installing dependencies...{C.RST}")
    npm_lock = os.path.join(app_dir, "node_modules")
    if os.path.exists(npm_lock):
        print(f"  {C.DIM}node_modules already exists, skipping npm install.{C.RST}")
    else:
        print(f"  {C.DIM}$ npm install (in {os.path.relpath(app_dir, workspace_dir)}){C.RST}")
        # npm resolves to npm.cmd on Windows — a bare "npm" with shell=False
        # (Win32 CreateProcess only auto-appends .exe, never .cmd/.bat) raises
        # FileNotFoundError. Same resolution pattern already used correctly
        # elsewhere in this codebase (cli_engine.py, sandbox_manager.py).
        npm_cmd = shutil.which("npm") or ("npm.cmd" if os.name == "nt" else "npm")
        try:
            subprocess.run(
                [npm_cmd, "install", "--ignore-scripts"],
                cwd=app_dir, capture_output=True
            )
        except FileNotFoundError:
            print(f"  {C.Y}[!] npm not found on PATH — install dependencies manually with "
                  f"'npm install --ignore-scripts' in {os.path.relpath(app_dir, workspace_dir)}.{C.RST}")
    print(f"  {C.G}[OK] Dependencies ready.{C.RST}\n")

    # ── Summary ──
    rel_app = os.path.relpath(app_dir, workspace_dir)
    print(f"{C.CY}{'=' * 58}")
    print(f"   ONBOARDING COMPLETE")
    print(f"{'=' * 58}{C.RST}\n")

    print(f"  Your app is now protected by Cyphex RASP.\n")
    print(f"  {C.BOLD}Next steps:{C.RST}")
    print(f"  -------------------------------------------------------")
    print(f"  {C.W}1. Start the Cyphex Auto-Healing Daemon:{C.RST}")
    print(f"     python cyphex_cli.py watch --port 3004\n")
    print(f"  {C.W}2. Start your application:{C.RST}")
    print(f"     cd {rel_app} && npm start\n")
    print(f"  {C.W}3. (Optional) Run a classic scan:{C.RST}")
    print(f"     python cyphex_cli.py scan --path {rel_app}\n")
    print(f"  {C.W}4. Send an attack to test:{C.RST}")
    print(f"     curl -X POST http://localhost:3003/api/users/login \\")
    print(f"       -H \"Content-Type: application/json\" \\")
    print(f"       -d '{{\"username\": \"\\' OR 1=1 --\", \"password\": \"x\"}}'\n")
    print(f"  {C.DIM}The RASP will block the attack and the Daemon will")
    print(f"  auto-patch the vulnerable code via the AI Council.{C.RST}\n")

    return app_dir
