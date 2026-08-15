"""
CYPHEX Daemon — Background Auto-Healing Server

Runs on localhost:3004. Receives attack telemetry from the RASP SDK
running inside the developer's application.

HOW IT SOLVES THE "DAST DISCONNECT":
────────────────────────────────────
Traditional DAST scanners attack a running app from OUTSIDE, so they only
know the URL (e.g., /api/auth/login) and have to GUESS the source file.

The RASP SDK runs INSIDE the app. When it detects an attack, it captures
the live JavaScript/Python STACK TRACE at that exact moment. The stack trace
contains the EXACT file path and line number of the vulnerable code.

    Error: SQL Injection Detected
        at loginHandler (backend/src/routes/auth.js:42:15)  <-- EXACT LOCATION
        at Layer.handle [as handle_request] (express/lib/router/layer.js:95:5)

This is sent to the daemon, which passes it straight to the AI Patch Council.
No regex guessing. No heuristic matching. EXACT file:line from the runtime.

Flow:
  1. Developer runs their app with `require('cyphex-rasp')` in their Express app
  2. RASP detects attack payload (using Cyphex Behavioral Genome heuristics)
  3. RASP blocks the request (returns 403)
  4. RASP captures stack trace → sends JSON to localhost:3004/api/telemetry/attack
  5. Daemon receives it → reads the vulnerable source file → triggers PatchCouncil
  6. PatchCouncil generates + reviews fix → writes the fixed code to disk
  7. Developer sees: "CYPHEX auto-healed auth.js:42 (SQL Injection)"
"""

import asyncio
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# Ensure project imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend", "backend"))

from auth import get_or_create_api_key, install_api_key_middleware

try:
    from rich.console import Console
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class console:
        @staticmethod
        def print(msg, **kwargs): print(msg)

# ── ANSI colors for non-rich output ──
class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"; BOLD="\033[1m"
    DIM="\033[2m"; RST="\033[0m"

# ── Healing event log ──
HEAL_LOG: list[dict] = []

# ── Try to import council components ──
COUNCIL_AVAILABLE = False
try:
    from backend.council.patch_council import PatchCouncil
    COUNCIL_AVAILABLE = True
except ImportError:
    pass


class TelemetryEvent:
    """A single attack event received from the RASP SDK."""
    def __init__(self, data: dict):
        self.vuln_type: str = data.get("vuln_type", "Unknown")
        self.payload: str = data.get("payload", "")
        self.method: str = data.get("method", "GET")
        self.url: str = data.get("url", "")
        self.stack_trace: str = data.get("stack_trace", "")
        self.source_file: str = data.get("source_file", "")
        self.source_line: int = data.get("source_line", 0)
        self.repo_root: str = data.get("repo_root", "")
        self.timestamp: str = data.get("timestamp", datetime.now().isoformat())
        self.blocked: bool = data.get("blocked", True)
        self.confidence: float = data.get("confidence", 0.0)
        # CWE mapping for common attack types
        self._cwe_map = {
            "SQL Injection": "CWE-89",
            "XSS": "CWE-79",
            "Command Injection": "CWE-78",
            "Path Traversal": "CWE-22",
            "SSRF": "CWE-918",
            "IDOR": "CWE-639",
        }

    @property
    def cwe(self) -> str:
        return self._cwe_map.get(self.vuln_type, "CWE-Unknown")

    def __repr__(self):
        return f"<TelemetryEvent {self.vuln_type} @ {self.source_file}:{self.source_line}>"


def _parse_stack_trace(stack_trace: str, repo_root: str = "") -> tuple[str, int]:
    """
    Parse a JavaScript or Python stack trace to extract the FIRST
    application-level file path and line number.

    THIS IS THE KEY TO SOLVING THE DAST DISCONNECT:
    Instead of guessing which file handles /api/auth/login using regex,
    we get the exact file and line from the runtime stack trace.

    Filters out:
    - node_modules (framework internals)
    - cyphex-rasp.js (our own middleware)
    - Python stdlib frames

    Returns: (file_path, line_number) or ("", 0) if parsing fails.
    """
    import re

    # ── JavaScript stack traces ──
    # Format: "    at functionName (filepath:line:col)"
    # or:     "    at filepath:line:col"
    js_pattern = re.compile(
        r'at\s+(?:.*?\s+\()?'      # "at functionName (" or just "at "
        r'([^():]+?)'               # file path (capture group 1)
        r':(\d+)'                   # :line (capture group 2)
        r'(?::\d+)?'                # :col (optional, don't capture)
        r'\)?'                      # closing paren if present
    )

    # ── Python stack traces ──
    # Format: '  File "filepath", line 42, in function_name'
    py_pattern = re.compile(
        r'File\s+"([^"]+)",\s+line\s+(\d+)'
    )

    # Skip patterns (framework internals, not user code)
    skip_patterns = [
        "node_modules", "cyphex-rasp", "cyphex_rasp",
        "internal/", "<anonymous>", "<frozen",
        "site-packages", "asyncio/", "uvicorn/",
        "starlette/", "fastapi/",
    ]

    for line in stack_trace.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Try JS pattern first
        match = js_pattern.search(line)
        if not match:
            match = py_pattern.search(line)
        if not match:
            continue

        filepath = match.group(1).strip()
        line_num = int(match.group(2))

        # Skip framework internals
        if any(skip in filepath for skip in skip_patterns):
            continue

        # Normalize path
        filepath = filepath.replace("\\", "/")

        # If repo_root is provided, make the path relative to it
        if repo_root:
            repo_root_norm = repo_root.replace("\\", "/").rstrip("/")
            if filepath.startswith(repo_root_norm):
                filepath = filepath[len(repo_root_norm):].lstrip("/")

        return filepath, line_num

    return "", 0


async def _auto_heal(event: TelemetryEvent) -> dict:
    """
    The core auto-healing pipeline.

    1. Parse stack trace to get exact file:line
    2. Read the vulnerable source code from disk
    3. Send it to the PatchCouncil for AI-powered fix generation
    4. Write the fixed code back to disk
    5. Log the healing event

    Returns a result dict with status and details.
    """
    result = {
        "status": "skipped",
        "vuln_type": event.vuln_type,
        "file": "",
        "line": 0,
        "patch_applied": False,
        "reason": "",
    }

    # Step 1: Get the exact source location
    source_file = event.source_file
    source_line = event.source_line

    # If the RASP didn't pre-parse the stack, do it ourselves
    if not source_file and event.stack_trace:
        source_file, source_line = _parse_stack_trace(
            event.stack_trace, event.repo_root
        )

    # Fallback to RouteTracer if stack trace failed or pointed to a generic entry point
    if not source_file or source_file.endswith("index.js") or source_file.endswith("app.js"):
        console.print("  [dim]Stack trace lacked app frame; falling back to RouteTracer for URL matching...[/dim]")
        try:
            # `os`/`sys` are already imported at module level — re-importing
            # them here (even inside this nested `try`) makes Python treat
            # both names as local to the whole `_auto_heal` function, which
            # crashes every module-level `os.`/`sys.` use elsewhere in this
            # function with UnboundLocalError whenever this branch isn't
            # taken. Just use the module-level imports.
            backend_path = os.path.join(os.path.dirname(__file__), "..", "backend", "backend")
            if backend_path not in sys.path:
                sys.path.insert(0, backend_path)
            from backend.council.route_tracer import RouteTracer
            
            tracer = RouteTracer(event.repo_root)
            match = tracer._regex_route_match(event.url)
            if match:
                parts = match.rsplit(":", 1)
                source_file = parts[0]
                source_line = int(parts[1]) if len(parts) > 1 else 1
        except Exception as e:
            console.print(f"  [dim]RouteTracer fallback failed: {e}[/dim]")

    if not source_file:
        result["reason"] = "Could not determine source file from stack trace or RouteTracer"
        console.print(f"  [yellow]⚠ {result['reason']}[/yellow]")
        return result

    result["file"] = source_file
    result["line"] = source_line

    # Step 2: Resolve the full file path, staying inside repo_root.
    # (repo_root itself is still attacker-supplied in the request body —
    # this only stops a source_file value like "../../etc/passwd" or a
    # symlink from escaping *that* root, not a malicious root value.)
    full_path = source_file
    if event.repo_root and not os.path.isabs(source_file):
        full_path = os.path.join(event.repo_root, source_file)

    if event.repo_root:
        repo_root_real = os.path.realpath(event.repo_root)
        full_path_real = os.path.realpath(full_path)
        if os.path.islink(full_path) or (
            full_path_real != repo_root_real
            and not full_path_real.startswith(repo_root_real + os.sep)
        ):
            result["reason"] = f"Refusing to read outside repo_root: {source_file}"
            console.print(f"  [red]⚠ {result['reason']}[/red]")
            return result
        full_path = full_path_real

    if not os.path.exists(full_path):
        result["reason"] = f"Source file not found on disk: {full_path}"
        console.print(f"  [yellow]⚠ {result['reason']}[/yellow]")
        return result

    # Step 3: Extract the vulnerable code snippet (±10 lines around the target)
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        if source_line < 1 or source_line > len(lines):
            result["reason"] = f"Line {source_line} out of range (file has {len(lines)} lines)"
            return result

        # Extract a window of code around the vulnerable line
        start = max(0, source_line - 6)
        end = min(len(lines), source_line + 5)
        vulnerable_snippet = "".join(lines[start:end])

    except Exception as e:
        result["reason"] = f"Error reading source file: {e}"
        return result

    # Step 4: Send to PatchCouncil
    if not COUNCIL_AVAILABLE:
        result["reason"] = "AI Council not available (install Ollama models)"
        result["status"] = "deferred"
        console.print(f"  [yellow]⚠ Council unavailable — logging for manual review[/yellow]")
        return result

    console.print(f"\n  [bold magenta]🧬 AUTO-HEALING:[/bold magenta] {event.vuln_type}")
    console.print(f"  [dim]  File: {source_file}:{source_line}[/dim]")
    console.print(f"  [dim]  Payload: {event.payload[:80]}...[/dim]")

    try:
        council = PatchCouncil()
        patch_result = await council.generate_and_validate_patch(
            vuln_name=event.vuln_type,
            cwe=event.cwe,
            vulnerable_code=vulnerable_snippet,
            file_path=source_file,
        )

        fixed_code = patch_result.get("fixed_code", "")
        safety = patch_result.get("patch_safety", "rejected")

        if safety in ("safe", "review_needed") and fixed_code.strip():
            # Step 5: Apply the patch by replacing the snippet in the file
            original_content = "".join(lines)
            original_snippet = "".join(lines[start:end])

            if original_snippet in original_content:
                new_content = original_content.replace(original_snippet, fixed_code + "\n", 1)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(new_content)

                result["status"] = "healed"
                result["patch_applied"] = True
                result["safety"] = safety
                console.print(f"  [bold green]✓ AUTO-HEALED:[/bold green] {source_file}:{source_line}")
                console.print(f"  [dim]  Safety: {safety} | Council: {patch_result.get('vote_summary', 'N/A')}[/dim]")
            else:
                result["status"] = "failed"
                result["reason"] = "Could not locate snippet in file for replacement"
        else:
            result["status"] = "rejected"
            result["reason"] = f"Patch safety: {safety}"
            console.print(f"  [red]✗ Patch rejected by council ({safety})[/red]")

    except Exception as e:
        result["status"] = "error"
        result["reason"] = str(e)
        console.print(f"  [red]✗ Auto-heal error: {e}[/red]")

    # Log the event
    HEAL_LOG.append({
        **result,
        "timestamp": datetime.now().isoformat(),
        "payload_preview": event.payload[:100],
    })

    return result


def create_daemon_app():
    """
    Create the FastAPI application for the Cyphex Daemon.

    Endpoints:
      POST /api/telemetry/attack  — Receives attack events from RASP SDK
      GET  /api/status             — Health check + healing stats
      GET  /api/heal-log           — Full healing history
    """
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        console.print("[red]FastAPI not installed. Run: pip install fastapi uvicorn[/red]")
        return None

    app = FastAPI(
        title="CYPHEX Daemon",
        description="Closed-Loop Auto-Healing Security Server",
        version="1.0.0",
    )

    # API-key auth — registered BEFORE CORSMiddleware below so CORS ends up
    # outermost (Starlette wraps middleware so the LAST one added sees the
    # request first) and can answer OPTIONS preflight requests directly,
    # before they ever reach this check. See backend/backend/auth.py.
    install_api_key_middleware(app)

    _cors_origins = [
        o.strip()
        for o in os.environ.get(
            "CYPHEX_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/api/telemetry/attack")
    async def receive_attack(request: Request):
        """
        Receives attack telemetry from the RASP SDK.

        Expected JSON body:
        {
            "vuln_type": "SQL Injection",
            "payload": "' OR 1=1 --",
            "method": "POST",
            "url": "/api/auth/login",
            "stack_trace": "Error: ...\n    at loginHandler (backend/src/routes/auth.js:42:15)\n...",
            "repo_root": "C:/Users/dev/my-project",
            "confidence": 0.95,
            "blocked": true
        }
        """
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        event = TelemetryEvent(data)
        console.print(f"\n[bold cyan]📡 RASP TELEMETRY:[/bold cyan] {event.vuln_type} on {event.url}")

        # Only auto-heal if confidence is high enough
        if event.confidence < 0.7:
            console.print(f"  [dim]Low confidence ({event.confidence:.0%}) — logging only[/dim]")
            HEAL_LOG.append({
                "status": "low_confidence",
                "vuln_type": event.vuln_type,
                "file": event.source_file,
                "confidence": event.confidence,
                "timestamp": datetime.now().isoformat(),
            })
            return JSONResponse({
                "status": "logged",
                "reason": "Confidence below auto-heal threshold (70%)",
            })

        # Trigger auto-healing
        result = await _auto_heal(event)
        return JSONResponse(result)

    @app.get("/api/status")
    async def status():
        """Health check and stats."""
        return {
            "status": "running",
            "version": "1.0.0",
            "council_available": COUNCIL_AVAILABLE,
            "total_events": len(HEAL_LOG),
            "healed": sum(1 for e in HEAL_LOG if e.get("status") == "healed"),
            "rejected": sum(1 for e in HEAL_LOG if e.get("status") == "rejected"),
            "uptime_seconds": int(time.time() - _START_TIME),
        }

    @app.get("/api/heal-log")
    async def heal_log():
        """Return full healing history."""
        return {"events": HEAL_LOG}

    return app


_START_TIME = time.time()


def run_daemon(host: str = "127.0.0.1", port: int = 3004):
    """Start the Cyphex Daemon server."""
    app = create_daemon_app()
    if app is None:
        return

    console.print(f"""
[bold cyan]
  ╔══════════════════════════════════════════════════════╗
  ║         CYPHEX DAEMON — Auto-Healing Active         ║
  ║                                                     ║
  ║  Listening: http://{host}:{port}                   ║
  ║  Telemetry: POST /api/telemetry/attack              ║
  ║  Status:    GET  /api/status                        ║
  ║                                                     ║
  ║  Council:   {'✓ Ready' if COUNCIL_AVAILABLE else '✗ Unavailable (install Ollama models)':44}║
  ╚══════════════════════════════════════════════════════╝
[/bold cyan]
[dim]  Waiting for RASP telemetry from your application...[/dim]
""")
    console.print(f"  [bold]API key:[/bold] {get_or_create_api_key()}")
    console.print("  [dim](persisted at ~/.cyphex/api_key — set CYPHEX_API_KEY to override;"
                  " same key used by the RASP SDK's CYPHEX_API_KEY env var)[/dim]\n")

    try:
        import uvicorn
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[/red]")


if __name__ == "__main__":
    run_daemon()
