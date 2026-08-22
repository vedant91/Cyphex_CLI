"""
CYPHEX — FastAPI Web Server + WebSocket API

Bridges the Python scan engine to the React frontend.

Endpoints:
  POST /api/scan           — Start a new scan
  GET  /api/scan/{scan_id} — Get scan status / final report
  GET  /api/scans          — List all scans
  POST /api/sandbox/upload — Upload a ZIP/folder and deploy a sandbox
  GET  /api/sandboxes      — List active sandboxes
  POST /api/sandbox/{id}/stop — Stop a sandbox
  WS   /ws/{scan_id}       — Real-time event stream during scan
"""

import asyncio
import json
import os
import shutil
import sys
import uuid
import tempfile
import zipfile
from datetime import datetime
from typing import Dict, Set, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add parent dir for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Repo root — needed so scan_orchestrator's `from scoring import ...` (the
# single source of truth for the security posture score, shared with the
# CLI's terminal_ui.py/cli_engine.py) resolves regardless of launch cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scan_orchestrator import ScanOrchestrator
from config import config
from auth import get_or_create_api_key, install_api_key_middleware, verify_ws_key
from sandbox_manager import (
    deploy_sandbox,
    list_sandboxes,
    stop_sandbox,
    safe_extract_zip,
    flatten_single_top_level,
)
from cyphex.docker_sandbox import docker_available, deploy_docker_sandbox

# Maximum size (bytes) accepted for an uploaded sandbox ZIP. Enforced while
# streaming the upload to disk (see upload_sandbox) so we never write an
# unbounded amount of attacker-controlled data to disk.
MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB

# ═══════════════════════════════════════════════════════════════
#  FastAPI Application
# ═══════════════════════════════════════════════════════════════

app = FastAPI(
    title="CYPHEX API",
    description="Multi-Agent Exploitation Pipeline API",
    version="2.0.0",
)

# API-key auth — registered BEFORE CORSMiddleware below. Starlette wraps
# middleware so the LAST one added ends up OUTERMOST (sees the request
# first); CORS must be outermost so it can answer OPTIONS preflight
# requests directly, before they ever reach this check (verified: a
# middleware added before CORSMiddleware never sees preflight requests
# at all — CORS short-circuits them).
install_api_key_middleware(app)

# CORS — allow only the Vite dev server (or whatever CYPHEX_CORS_ORIGINS
# lists), never a wildcard. Credentials aren't needed since auth is via
# the X-API-Key header, not cookies.
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


def _is_localhost_host(host: str | None) -> bool:
    if not host:
        return False
    return host in {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}


def _require_api_access(request: Request) -> None:
    """
    Access control policy:
      1) If API_AUTH_TOKEN is set, every request must send X-API-Key.
      2) If API_AUTH_TOKEN is empty, only localhost clients are allowed.
    """
    token = (config.API_AUTH_TOKEN or "").strip()
    if token:
        supplied = request.headers.get("x-api-key", "")
        if supplied != token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        return

    client_host = request.client.host if request.client else None
    if not _is_localhost_host(client_host):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Remote access disabled. Set API_AUTH_TOKEN to enable authenticated remote API access.",
        )

# ── In-memory state ──────────────────────────────────────────
# scan_id -> scan metadata
scans: Dict[str, dict] = {}
# scan_id -> set of connected websocket clients
ws_clients: Dict[str, Set[WebSocket]] = {}
# sandbox_id -> set of connected websocket clients (for sandbox terminal feed)
sandbox_ws_clients: Dict[str, Set[WebSocket]] = {}
# sandbox_id -> list of terminal log lines
sandbox_terminal_logs: Dict[str, List[str]] = {}


# ── Request / Response models ────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str
    cerebras_key: str = ""
    timeout: int = 1800


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target_url: str
    started_at: str


# ═══════════════════════════════════════════════════════════════
#  WebSocket Event Broadcaster
# ═══════════════════════════════════════════════════════════════

async def broadcast_event(scan_id: str, event: dict):
    """Send an event to all WebSocket clients watching this scan."""
    if scan_id not in ws_clients:
        return
    dead = set()
    message = json.dumps(event, default=str)
    for ws in ws_clients[scan_id]:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    ws_clients[scan_id] -= dead


async def broadcast_sandbox_event(sandbox_id: str, event: dict):
    """Send an event to all WebSocket clients watching this sandbox."""
    if sandbox_id not in sandbox_ws_clients:
        return
    dead = set()
    message = json.dumps(event, default=str)
    for ws in sandbox_ws_clients[sandbox_id]:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    sandbox_ws_clients[sandbox_id] -= dead


def make_event_callback(scan_id: str):
    """
    Returns an async callback function that the ScanOrchestrator
    will call for every significant event during the scan.
    """
    async def callback(event: dict):
        event["scan_id"] = scan_id
        event["timestamp"] = datetime.now().isoformat()
        await broadcast_event(scan_id, event)

        # Also forward terminal_log events to any sandbox WS that had this scan started
        if event.get("type") == "terminal_log":
            # Broadcast to all sandbox terminals
            for sid in sandbox_ws_clients:
                await broadcast_sandbox_event(sid, event)

    return callback


# ═══════════════════════════════════════════════════════════════
#  REST Endpoints
# ═══════════════════════════════════════════════════════════════

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest, request: Request):
    """Start a new vulnerability scan."""
    _require_api_access(request)
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    target = req.target_url.strip().rstrip("/")
    if not target.startswith("http"):
        target = f"http://{target}"

    scan_meta = {
        "scan_id": scan_id,
        "target_url": target,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "report": None,
        "error": None,
    }
    scans[scan_id] = scan_meta
    ws_clients[scan_id] = set()

    # Override timeout
    config.SCAN_TIMEOUT_SECONDS = req.timeout

    # Override Cerebras key if provided
    cerebras_key = req.cerebras_key or config.CEREBRAS_API_KEY

    # Launch scan in background
    asyncio.create_task(_run_scan_task(scan_id, target, cerebras_key))

    return ScanResponse(
        scan_id=scan_id,
        status="running",
        target_url=target,
        started_at=scan_meta["started_at"],
    )


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    """Get scan status and/or final report."""
    _require_api_access(request)
    if scan_id not in scans:
        return {"error": "Scan not found"}, 404
    return scans[scan_id]


@app.get("/api/scans")
async def get_scans(request: Request):
    """List all scans (most recent first)."""
    _require_api_access(request)
    scan_list = sorted(
        scans.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"scans": scan_list}


# ═══════════════════════════════════════════════════════════════
#  Sandbox Endpoints
# ═══════════════════════════════════════════════════════════════

@app.post("/api/sandbox/upload")
async def upload_sandbox(request: Request, file: UploadFile = File(...)):
    """
    Upload a zipped source code application (sandbox) and deploy it.
    Accepts ZIP files up to 500 MB. Also accepts any file — if it's
    not a valid ZIP the sandbox_manager will report an error.
    """

    _require_api_access(request)

    # Save the uploaded file temporarily with strict size cap
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, file.filename or "upload.zip")
    max_bytes = max(1, int(config.MAX_UPLOAD_MB)) * 1024 * 1024
    total_bytes = 0

    try:
        bytes_written = 0
        with open(zip_path, "wb") as f:
            # Stream-write in chunks to handle large files, enforcing
            # MAX_UPLOAD_BYTES so we never buffer/write an unbounded upload.
            while True:
                chunk = await file.read(1024 * 1024)  # 1 MB chunks
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_UPLOAD_BYTES:
                    raise ValueError(
                        f"Uploaded file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit"
                    )
                f.write(chunk)
    except ValueError as e:
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if os.path.exists(temp_dir):
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass
        return JSONResponse(
            status_code=413,
            content={"error": str(e)},
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to save uploaded file: {str(e)}"},
        )

    try:
        # Prefer the isolated Docker sandbox when Docker is available; only
        # fall back to running the untrusted upload directly on the host
        # (native sandbox) when Docker isn't installed/running.
        if docker_available():
            extract_dir = tempfile.mkdtemp()
            try:
                extract_error = safe_extract_zip(zip_path, extract_dir)
                if extract_error is not None:
                    return JSONResponse(status_code=400, content=extract_error)

                flatten_single_top_level(extract_dir)

                sandbox_meta = await deploy_docker_sandbox(extract_dir)
            finally:
                shutil.rmtree(extract_dir, ignore_errors=True)
        else:
            sandbox_meta = await deploy_sandbox(zip_path)

        if "error" in sandbox_meta:
            return JSONResponse(
                status_code=400,
                content=sandbox_meta,
            )

        # Initialise terminal log buffer for this sandbox
        sandbox_id = sandbox_meta["sandbox_id"]
        sandbox_terminal_logs[sandbox_id] = []
        sandbox_ws_clients[sandbox_id] = set()

        return JSONResponse(status_code=200, content=sandbox_meta)

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)},
        )
    finally:
        # Cleanup temp file
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if os.path.exists(temp_dir):
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass


@app.get("/api/sandboxes")
async def get_sandboxes(request: Request):
    """List currently active sandboxes"""
    _require_api_access(request)
    return {"sandboxes": list_sandboxes()}

@app.post("/api/sandbox/{sandbox_id}/stop")
async def kill_sandbox(sandbox_id: str, request: Request):
    _require_api_access(request)
    return stop_sandbox(sandbox_id)


# ═══════════════════════════════════════════════════════════════
#  WebSocket Endpoints
# ═══════════════════════════════════════════════════════════════

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """Real-time event stream for a scan."""
    if not verify_ws_key(websocket):
        await websocket.close(code=4401)
        return
    await websocket.accept()

    if scan_id not in ws_clients:
        ws_clients[scan_id] = set()
    ws_clients[scan_id].add(websocket)

    try:
        # Keep connection alive — client can also send messages  
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=15)
                # Client can send ping/control messages
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                # Send keepalive
                await websocket.send_text(json.dumps({"type": "keepalive"}))
    except WebSocketDisconnect:
        pass
    finally:
        if scan_id in ws_clients:
            ws_clients[scan_id].discard(websocket)


@app.websocket("/ws/sandbox/{sandbox_id}")
async def sandbox_websocket(websocket: WebSocket, sandbox_id: str):
    """
    Real-time terminal feed for a sandbox.
    Streams all scan terminal_log events to connected clients.
    """
    if not verify_ws_key(websocket):
        await websocket.close(code=4401)
        return
    await websocket.accept()

    if sandbox_id not in sandbox_ws_clients:
        sandbox_ws_clients[sandbox_id] = set()
    sandbox_ws_clients[sandbox_id].add(websocket)

    # Send any buffered terminal logs
    if sandbox_id in sandbox_terminal_logs:
        for line in sandbox_terminal_logs[sandbox_id]:
            try:
                await websocket.send_text(json.dumps({
                    "type": "terminal_log",
                    "line": line,
                }))
            except Exception:
                break

    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=15)
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "keepalive"}))
    except WebSocketDisconnect:
        pass
    finally:
        if sandbox_id in sandbox_ws_clients:
            sandbox_ws_clients[sandbox_id].discard(websocket)


# ═══════════════════════════════════════════════════════════════
#  Background Scan Task
# ═══════════════════════════════════════════════════════════════

async def _run_scan_task(scan_id: str, target: str, cerebras_key: str):
    """Run the full scan pipeline in the background."""
    callback = make_event_callback(scan_id)
    orchestrator = ScanOrchestrator(event_callback=callback)

    try:
        report = await asyncio.wait_for(
            orchestrator.run_scan(scan_id, target, cerebras_key),
            timeout=config.SCAN_TIMEOUT_SECONDS,
        )
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["completed_at"] = datetime.now().isoformat()
        scans[scan_id]["report"] = report

        await callback({
            "type": "scan_complete",
            "report": report,
        })

    except asyncio.TimeoutError:
        scans[scan_id]["status"] = "timeout"
        scans[scan_id]["error"] = f"Scan timed out after {config.SCAN_TIMEOUT_SECONDS}s"
        await callback({"type": "scan_error", "error": "timeout"})

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
        await callback({"type": "scan_error", "error": str(e)})


# ═══════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    _host = os.environ.get("CYPHEX_API_HOST", "127.0.0.1")
    _port = int(os.environ.get("CYPHEX_API_PORT", "8000"))
    _reload = os.environ.get("CYPHEX_API_RELOAD", "true").lower() == "true"

    print(f"\n  🚀 CYPHEX API starting on http://{_host}:{_port}")
    print(f"  🔑 API key: {get_or_create_api_key()}")
    print(f"     (persisted at ~/.cyphex/api_key — set CYPHEX_API_KEY to override)\n")

    uvicorn.run(
        "api:app",
        host=_host,
        port=_port,
        reload=_reload,
        log_level="info",
    )
