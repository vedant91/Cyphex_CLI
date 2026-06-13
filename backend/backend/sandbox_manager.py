"""
CYPHEX — Sandbox Manager

Handles uploading, deploying, and managing sandbox (vulnerable web app) targets.
Flow:
  1. User uploads a ZIP via the frontend
  2. Backend extracts it into /sandboxes/<id>/
  3. Runs `npm install` then `node app.js` (or app_standalone.js)
  4. Returns the localhost URL to scan
"""

import asyncio
import os
import shutil
import signal
import subprocess
import tempfile
import zipfile
import uuid
import json
import glob
import sys
from datetime import datetime
from typing import Dict, Optional


# Active sandbox processes  { sandbox_id: { process, port, path, ... } }
active_sandboxes: Dict[str, dict] = {}

# Base directory for sandbox files
SANDBOX_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sandboxes")
os.makedirs(SANDBOX_BASE, exist_ok=True)


def _get_node_env() -> dict:
    """
    Build an environment dict that includes node/npm in PATH.
    Handles nvm, homebrew, standard install locations, and Windows.
    """
    env = os.environ.copy()
    extra_paths = []
    home = os.path.expanduser("~")

    if os.name == "nt":
        # Windows: add common Node.js install locations
        for p in [
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "nodejs"),
            os.path.join(os.environ.get("APPDATA", ""), "npm"),
        ]:
            if os.path.isdir(p):
                extra_paths.append(p)
    else:
        # macOS / Linux: check nvm versions
        nvm_dir = os.path.join(home, ".nvm", "versions", "node")
        if os.path.isdir(nvm_dir):
            versions = sorted(os.listdir(nvm_dir), reverse=True)
            for v in versions:
                bin_dir = os.path.join(nvm_dir, v, "bin")
                if os.path.isfile(os.path.join(bin_dir, "npm")):
                    extra_paths.append(bin_dir)
                    break
        for p in ["/opt/homebrew/bin", "/usr/local/bin", os.path.join(home, ".npm-global", "bin")]:
            if os.path.isdir(p):
                extra_paths.append(p)

    if extra_paths:
        sep = ";" if os.name == "nt" else ":"
        env["PATH"] = sep.join(extra_paths) + sep + env.get("PATH", "")

    return env

# Pre-compute once at import time
_NODE_ENV = _get_node_env()


def _robust_rmtree(path: str, retries: int = 3):
    """
    Robustly remove a directory on Windows.
    Handles PermissionError from locked files (e.g. node.exe still running)
    by clearing read-only flags, killing stale node processes, and retrying.
    """
    import stat
    import time

    def _onerror(func, fpath, exc_info):
        """Clear read-only flag and retry the removal."""
        try:
            os.chmod(fpath, stat.S_IWRITE)
            func(fpath)
        except Exception:
            pass

    for attempt in range(retries):
        try:
            shutil.rmtree(path, onerror=_onerror)
            return
        except PermissionError:
            if attempt < retries - 1:
                # Kill any node processes that may be locking files in this sandbox
                if os.name == "nt":
                    try:
                        subprocess.run(
                            'taskkill /F /IM node.exe /T',
                            shell=True, capture_output=True, timeout=10
                        )
                    except Exception:
                        pass
                time.sleep(2)
            else:
                # Final attempt: just warn and continue
                import traceback
                traceback.print_exc()


async def deploy_sandbox(zip_path: str, sandbox_id: Optional[str] = None) -> dict:
    """
    Extract a ZIP file, install deps, and start the sandbox app.
    Returns { sandbox_id, port, url, status, app_file }.
    """
    sandbox_id = sandbox_id or f"sb_{uuid.uuid4().hex[:8]}"
    sandbox_dir = os.path.join(SANDBOX_BASE, sandbox_id)

    # Clean up if exists — Windows needs special handling for locked files
    if os.path.exists(sandbox_dir):
        _robust_rmtree(sandbox_dir)
    os.makedirs(sandbox_dir, exist_ok=True)

    # ── Extract ZIP ──────────────────────────────────────────
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(sandbox_dir)
    except zipfile.BadZipFile:
        return {"error": "Invalid ZIP file", "sandbox_id": sandbox_id}

    # If the ZIP had a single top-level folder, descend into it
    entries = os.listdir(sandbox_dir)
    if len(entries) == 1 and os.path.isdir(os.path.join(sandbox_dir, entries[0])):
        inner = os.path.join(sandbox_dir, entries[0])
        # Move contents up
        for item in os.listdir(inner):
            shutil.move(os.path.join(inner, item), sandbox_dir)
        os.rmdir(inner)

    # ── Detect app type and entry file ───────────────────────
    app_file = _detect_entry_file(sandbox_dir)
    if not app_file:
        return {
            "error": "Could not find an entry file (app.js, app_standalone.js, index.js, server.js, app.py)",
            "sandbox_id": sandbox_id,
            "files": os.listdir(sandbox_dir),
        }

    # ── Pick a free port ─────────────────────────────────────
    port = _find_free_port()

    # ── Install dependencies ─────────────────────────────────
    pkg_json = os.path.join(sandbox_dir, "package.json")
    if os.path.exists(pkg_json):
        # Remove pre-existing node_modules & lock to force a clean
        # native rebuild for the current platform (fixes sqlite3, etc.)
        stale_nm = os.path.join(sandbox_dir, "node_modules")
        if os.path.exists(stale_nm):
            _robust_rmtree(stale_nm)
        stale_lock = os.path.join(sandbox_dir, "package-lock.json")
        if os.path.exists(stale_lock):
            try:
                os.remove(stale_lock)
            except Exception:
                pass

        npm_cmd = shutil.which("npm") or ("npm.cmd" if os.name == "nt" else "npm")
        # Do not quote when passing as a list with shell=False
        npm_cmd_clean = npm_cmd.strip('"')

        install_result = await _run_cmd(
            [npm_cmd_clean, "install", "--no-audit", "--no-fund"],
            cwd=sandbox_dir,
            timeout=180,
        )
        if install_result["exit_code"] != 0:
            err_detail = install_result['stderr'][:500] or install_result['stdout'][:500]
            return {
                "error": f"npm install failed: {err_detail}",
                "sandbox_id": sandbox_id,
            }
            
        try:
            with open(pkg_json) as f:
                pkg_data = json.load(f)
            deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
            if "prisma" in deps:
                await _run_cmd([npm_cmd_clean, "exec", "prisma", "generate"], cwd=sandbox_dir, timeout=120)
        except Exception:
            pass


    # For Python sandboxes
    requirements = os.path.join(sandbox_dir, "requirements.txt")
    if os.path.exists(requirements):
        await _run_cmd([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=sandbox_dir, timeout=120)
    elif app_file and app_file.endswith(".py"):
        await _run_cmd([sys.executable, "-m", "pip", "install", "flask", "requests"], cwd=sandbox_dir, timeout=120)

    # ── Patch entry file to respect PORT env var ─────────────
    _patch_port_in_entry(sandbox_dir, app_file, port)

    # ── Start the sandbox server ─────────────────────────────
    env = _NODE_ENV.copy()
    env["PORT"] = str(port)

    npm_cmd = shutil.which("npm") or ("npm.cmd" if os.name == "nt" else "npm")
    npm_cmd_clean = npm_cmd.strip('"')
        
    if app_file == "__NPM_RUN_START_DEV__":
        cmd = [npm_cmd_clean, "run", "start:dev"]
    elif app_file == "__NPM_RUN_DEV__":
        cmd = [npm_cmd_clean, "run", "dev"]
    elif app_file == "__NPM_RUN_START__":
        cmd = [npm_cmd_clean, "run", "start"]
    elif app_file.endswith(".js"):
        cmd = ["node", app_file]
    elif app_file.endswith(".py"):
        cmd = [sys.executable, app_file]
    else:
        cmd = ["node", app_file]

    proc = subprocess.Popen(
        cmd, shell=False,
        cwd=sandbox_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid if os.name != 'nt' else None,
    )

    # Wait for the server to start (native modules like sqlite3 can be slow)
    await asyncio.sleep(5)

    # Check if process is still running
    if proc.poll() is not None:
        stdout = proc.stdout.read().decode(errors='replace')[:500]
        stderr = proc.stderr.read().decode(errors='replace')[:500]
        return {
            "error": f"Sandbox process exited immediately. stdout: {stdout}, stderr: {stderr}",
            "sandbox_id": sandbox_id,
        }

    # Verify the server is responding
    url = f"http://localhost:{port}"
    is_up = await _check_server_up(url)

    sandbox_meta = {
        "sandbox_id": sandbox_id,
        "port": port,
        "url": url,
        "status": "running" if is_up else "starting",
        "app_file": app_file,
        "path": sandbox_dir,
        "started_at": datetime.now().isoformat(),
        "pid": proc.pid,
    }

    active_sandboxes[sandbox_id] = {
        **sandbox_meta,
        "process": proc,
    }

    return sandbox_meta


def stop_sandbox(sandbox_id: str) -> dict:
    """Stop a running sandbox."""
    if sandbox_id not in active_sandboxes:
        return {"error": "Sandbox not found"}

    info = active_sandboxes[sandbox_id]
    proc = info.get("process")

    if proc and proc.poll() is None:
        try:
            # Kill the entire process group
            if os.name != 'nt':
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)], capture_output=True)
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    info["status"] = "stopped"
    return {"sandbox_id": sandbox_id, "status": "stopped"}


def list_sandboxes() -> list:
    """List all sandboxes with current status."""
    result = []
    for sid, info in active_sandboxes.items():
        proc = info.get("process")
        if proc and proc.poll() is not None:
            info["status"] = "stopped"
        result.append({
            "sandbox_id": info["sandbox_id"],
            "port": info.get("port"),
            "url": info.get("url"),
            "status": info.get("status"),
            "app_file": info.get("app_file"),
            "started_at": info.get("started_at"),
        })
    return result


def get_sandbox(sandbox_id: str) -> Optional[dict]:
    """Get a specific sandbox."""
    if sandbox_id not in active_sandboxes:
        return None
    info = active_sandboxes[sandbox_id]
    proc = info.get("process")
    if proc and proc.poll() is not None:
        info["status"] = "stopped"
    return {
        "sandbox_id": info["sandbox_id"],
        "port": info.get("port"),
        "url": info.get("url"),
        "status": info.get("status"),
        "app_file": info.get("app_file"),
        "started_at": info.get("started_at"),
    }


# ── Helpers ─────────────────────────────────────────────────────

def _detect_entry_file(directory: str) -> Optional[str]:
    """Detect the main entry file in a sandbox directory."""
    # Priority order
    candidates = [
        "app_standalone.js",
        "app.js",
        "server.js",
        "index.js",
        "main.js",
        "app.py",
        "server.py",
        "main.py",
    ]
    for f in candidates:
        if os.path.exists(os.path.join(directory, f)):
            return f

    # Check package.json for "main" or "start" script
    pkg = os.path.join(directory, "package.json")
    if os.path.exists(pkg):
        try:
            with open(pkg) as fh:
                data = json.load(fh)
            scripts = data.get("scripts", {})
            if "start:dev" in scripts:
                return "__NPM_RUN_START_DEV__"
            elif "dev" in scripts:
                return "__NPM_RUN_DEV__"
            elif "start" in scripts:
                return "__NPM_RUN_START__"
                
            main = data.get("main")
            if main and os.path.exists(os.path.join(directory, main)):
                return main
        except Exception:
            pass

    # Glob for any .js files
    js_files = glob.glob(os.path.join(directory, "*.js"))
    if js_files:
        return os.path.basename(js_files[0])

    return None


def _patch_port_in_entry(sandbox_dir: str, app_file: str, port: int):
    """
    Patch the entry file so the app listens on our assigned port.
    Many uploaded apps hardcode `const port = 3000`. This rewrites
    those patterns to `process.env.PORT || <port>`.
    """
    if app_file and app_file.startswith("__NPM_RUN"):
        return

    import re

    filepath = os.path.join(sandbox_dir, app_file)
    if not os.path.isfile(filepath):
        return

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except Exception:
        return

    original = content

    if app_file.endswith('.js'):
        # Match patterns like:
        #   const port = 3000
        #   let port = 8080;
        #   var PORT = 5000;
        #   app.listen(3000, ...
        content = re.sub(
            r'((?:const|let|var)\s+(?:port|PORT)\s*=\s*)\d{2,5}',
            rf'\g<1>parseInt(process.env.PORT) || {port}',
            content,
        )
        content = content.replace('app.listen(port, ()', 'app.listen(port, "127.0.0.1", ()')
        # Also catch: app.listen(3000  or  .listen(8080,
        content = re.sub(
            r'(\.listen\()\s*(\d{2,5})\s*([,)])',
            rf'\g<1>(parseInt(process.env.PORT) || {port}), "127.0.0.1"\g<3>',
            content,
        )

    elif app_file.endswith('.py'):
        # Match: port = 3000  or  PORT = 5000  or  app.run(port=3000
        content = re.sub(
            r'((?:port|PORT)\s*=\s*)\d{2,5}',
            rf'\g<1>int(os.environ.get("PORT", {port}))',
            content,
        )
        # Ensure import os is present
        if 'import os' not in content:
            content = 'import os\n' + content

    if content != original:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception:
            pass


def _find_free_port() -> int:
    """Find a free TCP port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


async def _run_cmd(cmd: str, cwd: str, timeout: int = 60) -> dict:
    """Run a shell command and return result. Uses threaded subprocess on Windows."""
    import traceback

    def _sync_run():
        is_shell = isinstance(cmd, str)
        return subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd, env=_NODE_ENV, shell=is_shell, timeout=timeout
        )

    try:
        proc = await asyncio.to_thread(_sync_run)
        return {
            "stdout": proc.stdout.decode(errors='replace'),
            "stderr": proc.stderr.decode(errors='replace'),
            "exit_code": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Command timed out", "exit_code": -1}
    except Exception:
        return {"stdout": "", "stderr": traceback.format_exc(), "exit_code": -1}


async def _check_server_up(url: str, retries: int = 5, delay: float = 1.0) -> bool:
    """Check if a server is responding."""
    import httpx
    for _ in range(retries):
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(url)
                if resp.status_code < 500:
                    return True
        except Exception:
            pass
        await asyncio.sleep(delay)
    return False
