"""
CYPHEX GitHub Hook — Zero-Command Security for Vibe Coders

HOW IT WORKS FOR THE DEVELOPER:
───────────────────────────────
1. Developer creates a GitHub repo and pushes their code.
2. Developer goes to GitHub → Settings → Webhooks → Add webhook:
     - Payload URL: http://<their-machine>:3005/api/github/webhook
       (or use a tunnel like ngrok/cloudflare for public access)
     - Content type: application/json
     - Events: "Just the push event"
3. That's it. Every time they `git push`, this hook:
     a. Clones the repo to a temp sandbox
     b. Runs the full Cyphex scan (SAST + DAST + Genome)
     c. Generates patches for every vulnerability found
     d. Commits the patches to a new branch: `cyphex/auto-fix-<timestamp>`
     e. Creates a Pull Request on GitHub with the fixes

The developer NEVER has to run `cyphex scan` manually.
They just push code and get a PR with security fixes.

REQUIREMENTS:
  - GITHUB_TOKEN env var set (for creating branches/PRs via GitHub API)
  - Ollama running locally (for the AI Council)
  - Optional: GITHUB_WEBHOOK_SECRET for signature verification
"""

import asyncio
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend", "backend"))

try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), "..", "backend", ".env")
    load_dotenv(env_path)
except ImportError:
    pass

try:
    from rich.console import Console
    console = Console()
except ImportError:
    class console:
        @staticmethod
        def print(msg, **kwargs): print(msg)


class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RST="\033[0m"


def _verify_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature (HMAC SHA-256)."""
    if not secret:
        return True  # No secret configured — skip verification
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


async def _process_push(repo_url: str, branch: str, clone_url: str):
    """
    The core workflow triggered by a GitHub push event.

    1. Clone the repo into a temporary sandbox
    2. Run the full Cyphex scan
    3. If patches were applied, commit them to a new branch
    4. Push the branch and create a PR via GitHub API
    """
    console.print(f"\n[bold cyan]📦 Processing push to {repo_url} ({branch})[/bold cyan]")

    # Create a temporary working directory
    sandbox_dir = os.path.join(
        os.path.dirname(__file__), "..", "backend", "sandboxes",
        f"gh_{int(time.time())}"
    )
    sandbox_dir = os.path.abspath(sandbox_dir)

    try:
        # Step 1: Clone the repo
        console.print(f"[dim]  Cloning {clone_url}...[/dim]")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "-b", branch, clone_url, sandbox_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            console.print(f"[red]  Clone failed: {result.stderr[:200]}[/red]")
            return {"status": "error", "reason": "Clone failed"}

        # Step 2: Run Cyphex scan engine
        console.print(f"[dim]  Running Cyphex scan...[/dim]")
        try:
            from cli_engine import CyphexEngine
            engine = CyphexEngine()
            await engine.run(
                local_path=sandbox_dir,
                branch=branch,
                auto_patch=True,
                non_interactive=True,  # No prompts — fully automatic
            )
        except Exception as e:
            console.print(f"[red]  Scan error: {e}[/red]")
            return {"status": "error", "reason": str(e)}

        # Step 3: Check if any files were modified
        diff_result = subprocess.run(
            ["git", "diff", "--name-only"],
            cwd=sandbox_dir, capture_output=True, text=True
        )
        changed_files = [f for f in diff_result.stdout.strip().split("\n") if f]

        if not changed_files:
            console.print(f"[green]  ✓ No vulnerabilities found (or all patches rejected)[/green]")
            return {"status": "clean", "changed_files": 0}

        console.print(f"[yellow]  {len(changed_files)} files patched: {', '.join(changed_files[:5])}[/yellow]")

        # Step 4: Create a fix branch and commit
        fix_branch = f"cyphex/auto-fix-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        subprocess.run(["git", "checkout", "-b", fix_branch], cwd=sandbox_dir, capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=sandbox_dir, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m",
             f"🛡️ CYPHEX: Auto-fix {len(changed_files)} security vulnerabilities\n\n"
             f"Patched files:\n" + "\n".join(f"  - {f}" for f in changed_files)],
            cwd=sandbox_dir, capture_output=True
        )

        # Step 5: Push the branch (requires GITHUB_TOKEN for auth)
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if github_token:
            # Rewrite remote URL to include token for auth
            auth_url = clone_url.replace("https://", f"https://x-access-token:{github_token}@")
            subprocess.run(
                ["git", "remote", "set-url", "origin", auth_url],
                cwd=sandbox_dir, capture_output=True
            )
            push_result = subprocess.run(
                ["git", "push", "origin", fix_branch],
                cwd=sandbox_dir, capture_output=True, text=True
            )

            if push_result.returncode == 0:
                console.print(f"[green]  ✓ Pushed branch: {fix_branch}[/green]")

                # Step 6: Create a PR via GitHub API
                pr_result = await _create_pull_request(
                    repo_url, fix_branch, branch, changed_files, github_token
                )
                return {
                    "status": "pr_created",
                    "branch": fix_branch,
                    "changed_files": len(changed_files),
                    "pr_url": pr_result.get("html_url", ""),
                }
            else:
                console.print(f"[red]  Push failed: {push_result.stderr[:200]}[/red]")
                return {"status": "push_failed", "branch": fix_branch}
        else:
            console.print(f"[yellow]  ⚠ GITHUB_TOKEN not set — patches saved locally in {sandbox_dir}[/yellow]")
            console.print(f"[dim]    Set GITHUB_TOKEN env var to enable auto-PR creation.[/dim]")
            return {
                "status": "local_only",
                "branch": fix_branch,
                "sandbox": sandbox_dir,
                "changed_files": len(changed_files),
            }

    except Exception as e:
        console.print(f"[red]  Error: {e}[/red]")
        return {"status": "error", "reason": str(e)}


async def _create_pull_request(
    repo_url: str, head_branch: str, base_branch: str,
    changed_files: list, token: str
) -> dict:
    """Create a Pull Request on GitHub via the REST API."""
    try:
        import httpx
    except ImportError:
        console.print("[yellow]  httpx not installed — skipping PR creation[/yellow]")
        return {}

    # Extract owner/repo from URL
    # https://github.com/owner/repo.git → owner/repo
    parts = repo_url.rstrip("/").rstrip(".git").split("/")
    owner = parts[-2]
    repo = parts[-1]

    pr_body = (
        "## 🛡️ CYPHEX Auto-Fix\n\n"
        "The Cyphex AI Security Council has automatically detected and patched "
        f"**{len(changed_files)} security vulnerabilities** in this repository.\n\n"
        "### Changed Files\n"
        + "\n".join(f"- `{f}`" for f in changed_files)
        + "\n\n### How This Works\n"
        "1. Your push triggered the Cyphex webhook\n"
        "2. Cyphex ran SAST + DAST scans on the codebase\n"
        "3. The AI Council (multi-model debate) generated and validated each patch\n"
        "4. Only patches approved by the council are included\n\n"
        "**Review these changes carefully before merging.**\n\n"
        "---\n"
        "*Generated by [CYPHEX](https://github.com/VishalMache/cyphex) — "
        "Autonomous Cyber Defence*"
    )

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={
                "title": f"🛡️ CYPHEX: Auto-fix {len(changed_files)} security vulnerabilities",
                "body": pr_body,
                "head": head_branch,
                "base": base_branch,
            },
            timeout=30,
        )

        if resp.status_code == 201:
            pr_data = resp.json()
            console.print(f"[bold green]  ✓ PR created: {pr_data.get('html_url')}[/bold green]")
            return pr_data
        else:
            console.print(f"[yellow]  PR creation failed ({resp.status_code}): {resp.text[:200]}[/yellow]")
            return {}


def create_github_hook_app(secret: str = ""):
    """Create the FastAPI app for receiving GitHub webhooks."""
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
    except ImportError:
        console.print("[red]FastAPI not installed. Run: pip install fastapi uvicorn[/red]")
        return None

    app = FastAPI(title="CYPHEX GitHub Hook", version="1.0.0")

    @app.post("/api/github/webhook")
    async def github_webhook(request: Request):
        """
        Receives GitHub push events.
        Automatically scans the pushed code and creates a PR with fixes.
        """
        # Verify signature if secret is configured
        body = await request.body()
        sig = request.headers.get("X-Hub-Signature-256", "")
        if secret and not _verify_signature(body, sig, secret):
            return JSONResponse({"error": "Invalid signature"}, status_code=401)

        event_type = request.headers.get("X-GitHub-Event", "")
        if event_type == "ping":
            return JSONResponse({"status": "pong", "message": "CYPHEX webhook connected!"})

        if event_type != "push":
            return JSONResponse({"status": "ignored", "reason": f"Event type '{event_type}' not handled"})

        try:
            data = json.loads(body)
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        repo_url = data.get("repository", {}).get("html_url", "")
        clone_url = data.get("repository", {}).get("clone_url", "")
        branch = data.get("ref", "refs/heads/main").split("/")[-1]
        pusher = data.get("pusher", {}).get("name", "unknown")

        console.print(f"\n[bold cyan]🔔 GitHub Push Event[/bold cyan]")
        console.print(f"[dim]  Repo:   {repo_url}[/dim]")
        console.print(f"[dim]  Branch: {branch}[/dim]")
        console.print(f"[dim]  Pusher: {pusher}[/dim]")

        # Process in background (don't block the webhook response)
        asyncio.create_task(_process_push(repo_url, branch, clone_url))

        return JSONResponse({
            "status": "accepted",
            "message": "Cyphex scan triggered. A PR will be created if vulnerabilities are found.",
        })

    @app.get("/api/github/status")
    async def status():
        return {
            "status": "running",
            "github_token_set": bool(os.environ.get("GITHUB_TOKEN")),
        }

    return app


def run_github_hook(port: int = 3005, secret: str = ""):
    """Start the GitHub webhook server."""
    app = create_github_hook_app(secret)
    if app is None:
        return

    has_token = bool(os.environ.get("GITHUB_TOKEN"))

    console.print(f"""
[bold cyan]
  ╔══════════════════════════════════════════════════════╗
  ║       CYPHEX GitHub Hook — Push-to-Secure           ║
  ║                                                     ║
  ║  Webhook URL: http://localhost:{port}/api/github/webhook  ║
  ║  Status:      GET /api/github/status                ║
  ║                                                     ║
  ║  GitHub Token: {'✓ Set' if has_token else '✗ Not set (set GITHUB_TOKEN for auto-PR)':43}║
  ╚══════════════════════════════════════════════════════╝
[/bold cyan]

[dim]  Setup in GitHub:
    1. Go to your repo → Settings → Webhooks → Add webhook
    2. Payload URL: http://<your-ip>:{port}/api/github/webhook
    3. Content type: application/json
    4. Events: "Just the push event"
    5. Done! Every push will trigger a Cyphex scan + auto-PR.[/dim]
""")

    try:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[/red]")


if __name__ == "__main__":
    run_github_hook()
