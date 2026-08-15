"""
CYPHEX — Docker Sandbox Manager

Containerized sandbox for cross-platform, isolated target deployment.
Fallback chain:
  1. Docker (safest, most portable)
  2. Native Node.js / Python (current sandbox_manager.py)
  3. Static analysis only (no sandbox)
"""

import asyncio
import json
import os
import shutil
import subprocess
import uuid
from typing import Optional


def docker_available() -> bool:
    """Check if Docker is installed and running."""
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _detect_app_type(source_dir: str) -> dict:
    """
    Detect application type and entry point.
    Returns: {"type": "node"|"python"|"static", "entry": str, "port": int}
    """
    # Node.js
    pkg_json = os.path.join(source_dir, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json) as f:
                data = json.load(f)
            scripts = data.get("scripts", {})
            # Find start script
            for key in ("start:dev", "dev", "start"):
                if key in scripts:
                    return {"type": "node", "entry": f"npm run {key}", "port": 3000}
            main = data.get("main", "index.js")
            return {"type": "node", "entry": f"node {main}", "port": 3000}
        except Exception:
            return {"type": "node", "entry": "node index.js", "port": 3000}

    # Python
    for entry in ("app.py", "server.py", "main.py", "manage.py"):
        if os.path.exists(os.path.join(source_dir, entry)):
            return {"type": "python", "entry": f"python {entry}", "port": 5000}

    if os.path.exists(os.path.join(source_dir, "requirements.txt")):
        return {"type": "python", "entry": "python app.py", "port": 5000}

    return {"type": "static", "entry": "", "port": 8080}


def _generate_dockerfile(source_dir: str, app_info: dict) -> str:
    """Generate a Dockerfile for the target app if one doesn't exist.

    Each variant creates/uses an unprivileged user and switches to it with
    USER before the app's CMD, so the uploaded (untrusted) app never runs
    as root inside the container even if the container's other isolation
    (cap-drop, no-new-privileges, etc.) were somehow bypassed.
    """
    if app_info["type"] == "node":
        # The official node images already ship a non-root "node" user.
        return f"""FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN chown -R node:node /app
USER node
ENV PORT={app_info['port']}
EXPOSE {app_info['port']}
CMD {json.dumps(app_info['entry'].split())}
"""
    elif app_info["type"] == "python":
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || pip install flask
COPY . .
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 10001 sandboxuser \\
    && chown -R sandboxuser:sandboxuser /app
USER sandboxuser
ENV PORT={app_info['port']}
EXPOSE {app_info['port']}
CMD {json.dumps(app_info['entry'].split())}
"""
    else:
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 10001 sandboxuser \\
    && chown -R sandboxuser:sandboxuser /app
USER sandboxuser
ENV PORT={app_info['port']}
EXPOSE {app_info['port']}
CMD ["python", "-m", "http.server", "{app_info['port']}"]
"""


def _find_free_port() -> int:
    """Find a free TCP port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


async def deploy_docker_sandbox(
    source_dir: str,
    sandbox_id: Optional[str] = None
) -> dict:
    """
    Build and run the target app in a Docker container.
    Returns: {"sandbox_id", "port", "url", "container_name", "status"}
    """
    sandbox_id = sandbox_id or f"cyphex-{uuid.uuid4().hex[:8]}"
    container_name = f"cyphex-{sandbox_id}"
    port = _find_free_port()
    app_info = _detect_app_type(source_dir)

    # Use existing Dockerfile or generate one
    dockerfile_path = os.path.join(source_dir, "Dockerfile")
    generated = False
    if not os.path.exists(dockerfile_path):
        with open(dockerfile_path, "w") as f:
            f.write(_generate_dockerfile(source_dir, app_info))
        generated = True

    try:
        # Build
        build = await asyncio.to_thread(
            subprocess.run,
            ["docker", "build", "-t", container_name, "."],
            cwd=source_dir, capture_output=True, text=True, timeout=180
        )
        if build.returncode != 0:
            return {
                "error": f"Docker build failed: {build.stderr[:500]}",
                "sandbox_id": sandbox_id,
            }

        # Run with resource limits + a hardened security profile:
        #   --pids-limit   caps forkbombs / runaway process spawning
        #   --cap-drop ALL drops all Linux capabilities (no raw sockets, no
        #                  chown/setuid tricks, etc.)
        #   --security-opt no-new-privileges
        #                  blocks setuid/setgid binaries from escalating
        #                  privileges inside the container
        # The port is published on 127.0.0.1 only, so the container is not
        # reachable from other hosts on the network — only from this host.
        run_cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "--memory", "512m",
            "--cpus", "1",
            "--pids-limit", "200",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-p", f"127.0.0.1:{port}:{app_info['port']}",
            "-e", f"PORT={app_info['port']}",
            container_name,
        ]
        run = await asyncio.to_thread(
            subprocess.run, run_cmd,
            capture_output=True, text=True, timeout=30
        )
        if run.returncode != 0:
            return {
                "error": f"Docker run failed: {run.stderr[:500]}",
                "sandbox_id": sandbox_id,
            }

        # Wait for container to start
        await asyncio.sleep(5)

        # Verify it's running
        ps = subprocess.run(
            ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=10
        )
        is_running = "Up" in ps.stdout

        # Capture container stdout+stderr so the scan can surface real logs
        # (the container runs detached, so nothing else drains them).
        try:
            logs_res = subprocess.run(
                ["docker", "logs", "--tail", "200", container_name],
                capture_output=True, text=True, timeout=10
            )
            container_logs = ((logs_res.stdout or "") + (logs_res.stderr or ""))[-4000:]
        except Exception:
            container_logs = ""

        return {
            "sandbox_id": sandbox_id,
            "port": port,
            "url": f"http://localhost:{port}",
            "container_name": container_name,
            "status": "running" if is_running else "failed",
            "app_type": app_info["type"],
            "generated_dockerfile": generated,
            "logs": container_logs,
            "log_cmd": f"docker logs -f {container_name}",
        }

    finally:
        # Clean up generated Dockerfile
        if generated and os.path.exists(dockerfile_path):
            os.remove(dockerfile_path)


def stop_docker_sandbox(container_name: str) -> dict:
    """Stop and remove a Docker sandbox container."""
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True, text=True, timeout=15
        )
        return {"status": "stopped", "container": container_name}
    except Exception as e:
        return {"error": str(e), "container": container_name}


def cleanup_all_sandboxes():
    """Remove all CYPHEX sandbox containers and images."""
    try:
        # Stop and remove containers
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=cyphex-", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        for name in result.stdout.strip().split("\n"):
            if name:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10)

        # Remove images
        result = subprocess.run(
            ["docker", "images", "--filter", "reference=cyphex-*", "--format", "{{.Repository}}"],
            capture_output=True, text=True, timeout=10
        )
        for img in result.stdout.strip().split("\n"):
            if img:
                subprocess.run(["docker", "rmi", "-f", img], capture_output=True, timeout=10)
    except Exception:
        pass
