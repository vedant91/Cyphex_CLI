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

# resource limits (RLIMIT_*) are POSIX-only; the module doesn't exist on Windows.
if os.name != "nt":
    import resource
else:
    resource = None


# Active sandbox processes  { sandbox_id: { process, port, path, ... } }
active_sandboxes: Dict[str, dict] = {}

# Base directory for sandbox files
SANDBOX_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sandboxes")
os.makedirs(SANDBOX_BASE, exist_ok=True)

# ── Hardening constants ──────────────────────────────────────────
# Zip-bomb guard: max total *uncompressed* bytes we'll extract from an
# uploaded ZIP. The upload handler in api.py separately caps the raw
# (compressed-on-disk) upload size; this caps the decompressed size.
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024  # 1 GB

# Resource caps applied to the sandboxed app process on POSIX (see
# _sandbox_preexec below). These bound a malicious/runaway uploaded app's
# memory and CPU consumption on the host.
SANDBOX_MAX_MEMORY_BYTES = 1024 * 1024 * 1024  # 1 GB virtual address space
SANDBOX_MAX_CPU_SECONDS = 3600  # 1 hour of CPU time


def _get_node_env() -> dict:
    """
    Build an explicit allow-list environment for launching `npm install` and
    the sandboxed app process.

    IMPORTANT: we deliberately do NOT do `os.environ.copy()` here. The
    sandbox runs untrusted, uploaded application code — blindly inheriting
    the full host environment would hand that code any API keys, tokens, or
    other secrets present in the host process's environment. Instead we
    allow-list only the handful of variables node/npm plausibly need to
    locate their binaries and run correctly (PATH, HOME/USERPROFILE for the
    npm cache, TEMP/TMP for scratch files, a couple of Windows OS-loader
    variables) plus NODE_ENV.
    """
    home = os.path.expanduser("~")

    env: dict = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", home),
        "NODE_ENV": "production",
    }

    if os.name == "nt":
        # Windows needs a few more variables for node/npm and the OS loader
        # to function at all — none of these are secrets.
        for var in ("SystemRoot", "SystemDrive", "TEMP", "TMP", "APPDATA", "USERPROFILE", "ComSpec"):
            val = os.environ.get(var)
            if val:
                env[var] = val
    else:
        for var in ("TMPDIR", "LANG", "LC_ALL"):
            val = os.environ.get(var)
            if val:
                env[var] = val

    extra_paths = []

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


def _sandbox_preexec():
    """
    preexec_fn for the sandboxed app subprocess (POSIX only).

    Combines the existing "own session" setup (so the whole process group
    can be killed on stop_sandbox) with resource limits that bound how much
    memory and CPU time a malicious/runaway uploaded app can consume on the
    host. Both must run in the *same* preexec callback since Popen only
    accepts one.
    """
    os.setsid()
    if resource is not None:
        try:
            resource.setrlimit(
                resource.RLIMIT_AS,
                (SANDBOX_MAX_MEMORY_BYTES, SANDBOX_MAX_MEMORY_BYTES),
            )
        except Exception:
            pass
        try:
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (SANDBOX_MAX_CPU_SECONDS, SANDBOX_MAX_CPU_SECONDS),
            )
        except Exception:
            pass


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


def safe_extract_zip(zip_path: str, dest_dir: str) -> Optional[dict]:
    """
    Safely extract a ZIP file into dest_dir.

    Guards against:
      - Zip-slip: archive members whose resolved path would land outside
        dest_dir (via "../" traversal or an absolute path).
      - Symlink members: archive entries that are themselves symlinks
        (which could point outside dest_dir once followed/created).
      - Zip bombs: archives whose total *uncompressed* size exceeds
        MAX_UNCOMPRESSED_BYTES.

    Returns None on success. Returns an error dict (same shape used
    elsewhere in this module) if the archive is rejected — in which case
    NOTHING is extracted.
    """
    dest_root = os.path.realpath(dest_dir)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            infolist = zf.infolist()

            total_uncompressed = 0
            for member in infolist:
                name = member.filename
                normalized = name.replace("\\", "/")

                # Reject path traversal via ".." path segments.
                if any(part == ".." for part in normalized.split("/")):
                    return {"error": f"Refusing to extract ZIP: unsafe path in archive entry '{name}'"}

                # Reject anything that resolves outside dest_dir (belt-and-braces
                # in case of absolute paths, drive letters, etc.).
                dest = os.path.realpath(os.path.join(dest_dir, name))
                if dest != dest_root and not dest.startswith(dest_root + os.sep):
                    return {"error": f"Refusing to extract ZIP: path traversal detected in entry '{name}'"}

                # Reject symlink entries — the unix file-type bits live in the
                # high 16 bits of external_attr; 0o120000 (S_IFLNK) marks a symlink.
                unix_mode = (member.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    return {"error": f"Refusing to extract ZIP: symlink entry not allowed ('{name}')"}

                total_uncompressed += member.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    return {
                        "error": (
                            "Refusing to extract ZIP: uncompressed size exceeds "
                            f"{MAX_UNCOMPRESSED_BYTES // (1024 * 1024)}MB limit"
                        )
                    }

            # All members validated as safe — extract the whole archive.
            zf.extractall(dest_dir)
    except zipfile.BadZipFile:
        return {"error": "Invalid ZIP file"}

    return None


def flatten_single_top_level(dest_dir: str):
    """
    If dest_dir contains exactly one entry and it's a directory, move that
    directory's contents up into dest_dir and remove it.

    Many ZIP exports (e.g. GitHub's "Download ZIP") wrap the project in a
    single top-level folder; this normalizes that away so entry-file
    detection (package.json, app.py, etc.) works against dest_dir directly.
    """
    entries = os.listdir(dest_dir)
    if len(entries) == 1 and os.path.isdir(os.path.join(dest_dir, entries[0])):
        inner = os.path.join(dest_dir, entries[0])
        for item in os.listdir(inner):
            shutil.move(os.path.join(inner, item), dest_dir)
        os.rmdir(inner)


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

    # ── Extract ZIP (zip-slip / zip-bomb / symlink safe) ──────
    extract_error = safe_extract_zip(zip_path, sandbox_dir)
    if extract_error is not None:
        extract_error.setdefault("sandbox_id", sandbox_id)
        return extract_error

    # If the ZIP had a single top-level folder, descend into it
    flatten_single_top_level(sandbox_dir)

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
            [npm_cmd_clean, "install", "--ignore-scripts", "--no-audit", "--no-fund"],
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

    # Stream the sandbox's stdout+stderr to a persistent log file instead of PIPE
    # buffers that are never drained — undrained PIPEs both HIDE the logs (nothing
    # reads them while the process runs) AND can DEADLOCK the child once the ~64 KB
    # OS pipe buffer fills. A file lets us both surface logs and avoid the stall.
    log_path = os.path.join(sandbox_dir, "_cyphex_sandbox.log")
    log_fh = open(log_path, "wb")
    proc = subprocess.Popen(
        cmd, shell=False,
        cwd=sandbox_dir,
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        preexec_fn=_sandbox_preexec if os.name != 'nt' else None,
    )

    def _read_log_tail(n=4000):
        try:
            log_fh.flush()
        except Exception:
            pass
        try:
            with open(log_path, "r", errors="replace") as _lf:
                return _lf.read()[-n:]
        except Exception:
            return ""

    # Wait for the server to start (native modules like sqlite3 can be slow)
    await asyncio.sleep(5)

    # Check if process is still running
    if proc.poll() is not None:
        return {
            "error": f"Sandbox process exited immediately. logs: {_read_log_tail(1000)}",
            "sandbox_id": sandbox_id,
            "log_file": log_path,
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
        "log_file": log_path,
        "logs": _read_log_tail(),
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


def _build_start_argv(app_file: str) -> list[str]:
    """Reconstruct the start argv for a sandbox (mirrors deploy_sandbox)."""
    npm_cmd = shutil.which("npm") or ("npm.cmd" if os.name == "nt" else "npm")
    if app_file == "__NPM_RUN_START_DEV__":
        return [npm_cmd, "run", "start:dev"]
    if app_file == "__NPM_RUN_DEV__":
        return [npm_cmd, "run", "dev"]
    if app_file == "__NPM_RUN_START__":
        return [npm_cmd, "run", "start"]
    if app_file.endswith(".js"):
        return ["node", app_file]
    if app_file.endswith(".py"):
        return [sys.executable, app_file]
    return ["node", app_file]


def _kill_proc_tree(proc) -> None:
    """Cross-platform process-tree kill (a node/npm parent spawns children)."""
    if not proc or proc.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def sync_file_to_sandbox(sandbox_id: str, rel_path: str, content: str) -> bool:
    """
    Write `content` to `rel_path` inside the sandbox's deployed copy so a restart
    picks up a patched file. Returns False if the sandbox is unknown or the path
    escapes the sandbox directory (path-traversal guard).
    """
    info = active_sandboxes.get(sandbox_id)
    if not info:
        return False
    sandbox_dir = info.get("path")
    if not sandbox_dir:
        return False
    target = os.path.abspath(os.path.join(sandbox_dir, rel_path))
    if not target.startswith(os.path.abspath(sandbox_dir) + os.sep):
        return False
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except OSError:
        return False


async def restart_sandbox(sandbox_id: str, wait_seconds: float = 5.0) -> dict:
    """
    Restart a NATIVE (node/python) sandbox process in place so the running app
    reflects any patched files synced into its directory. Used by the patch
    verifier's dynamic branch. Docker/compose stacks are restarted by the caller
    (cli_engine tracks _docker_compose_dir). Returns updated meta or {"error"}.
    """
    info = active_sandboxes.get(sandbox_id)
    if not info:
        return {"error": "Sandbox not found"}

    _kill_proc_tree(info.get("process"))

    sandbox_dir = info.get("path")
    app_file = info.get("app_file")
    port = info.get("port")
    if not (sandbox_dir and app_file and port):
        return {"error": "Insufficient sandbox metadata to restart", "sandbox_id": sandbox_id}

    env = _NODE_ENV.copy()
    env["PORT"] = str(port)
    cmd = _build_start_argv(app_file)

    proc = subprocess.Popen(
        cmd,
        cwd=sandbox_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        preexec_fn=os.setsid if os.name != "nt" else None,
    )

    await asyncio.sleep(wait_seconds)

    if proc.poll() is not None:
        out = proc.stdout.read().decode(errors="replace")[:300]
        err = proc.stderr.read().decode(errors="replace")[:300]
        info["status"] = "stopped"
        return {"error": f"Restart exited immediately: {err or out}", "sandbox_id": sandbox_id}

    url = f"http://localhost:{port}"
    is_up = await _check_server_up(url)

    info["process"] = proc
    info["pid"] = proc.pid
    info["status"] = "running" if is_up else "starting"
    return {
        "sandbox_id": sandbox_id,
        "port": port,
        "url": url,
        "status": info["status"],
        "app_file": app_file,
    }


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


async def _run_cmd(cmd: list[str], cwd: str, timeout: int = 60) -> dict:
    """Run a subprocess command and return result (no shell execution)."""
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


def _safe_extract_zip(zf: zipfile.ZipFile, target_dir: str) -> None:
    """
    Zip Slip protection: ensure every archive member resolves inside target_dir
    before extraction. Reject absolute paths, parent traversal, and symlinks.
    """
    base = os.path.realpath(target_dir)
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if not name or name.endswith("/"):
            continue
        if name.startswith("/") or name.startswith("../") or "/../" in name:
            raise ValueError(f"path traversal entry: {info.filename}")
        out_path = os.path.realpath(os.path.join(base, name))
        if not out_path.startswith(base + os.sep):
            raise ValueError(f"entry escapes sandbox: {info.filename}")

        # Reject symlink entries in zip archives.
        unix_mode = (info.external_attr >> 16) & 0o170000
        if unix_mode == 0o120000:
            raise ValueError(f"symlink entry not allowed: {info.filename}")

    zf.extractall(target_dir)


async def _check_server_up(url: str, retries: int = 5, delay: float = 1.0) -> bool:
    """Check if a server is responding."""
    import httpx
    import logging
    # Suppress httpx INFO logs during health checks (e.g., "HTTP/1.1 404 Not Found")
    # These are expected during startup and confuse users into thinking there's an error
    httpx_logger = logging.getLogger("httpx")
    prev_level = httpx_logger.level
    httpx_logger.setLevel(logging.WARNING)
    try:
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
    finally:
        httpx_logger.setLevel(prev_level)
