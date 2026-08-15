"""
CYPHEX — shared local-service authentication.

api.py and daemon.py are both plain local HTTP services meant to be used
by their own frontend/SDK running on the same machine. Neither should be
reachable by an arbitrary webpage a developer has open in another tab, or
by anything else on the network — so both require a per-installation
shared-secret header on every REST request and a matching query param on
every WebSocket connection.

The key is either supplied via the CYPHEX_API_KEY environment variable,
or generated once and persisted at ~/.cyphex/api_key so every local
process (api.py, daemon.py, the frontend dev server) converges on the
same value without any manual setup.
"""

import hmac
import os
import secrets
import stat
from pathlib import Path

_KEY_DIR = Path.home() / ".cyphex"
_KEY_FILE = _KEY_DIR / "api_key"


def get_or_create_api_key() -> str:
    """Return the shared API key, generating and persisting one on first use."""
    env_key = os.getenv("CYPHEX_API_KEY", "")
    if env_key:
        return env_key

    try:
        return _KEY_FILE.read_text().strip()
    except FileNotFoundError:
        pass

    _KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = secrets.token_urlsafe(32)

    try:
        fd = os.open(str(_KEY_FILE), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        try:
            os.write(fd, key.encode())
        finally:
            os.close(fd)
        return key
    except FileExistsError:
        # Lost a race with another process (api.py/daemon.py starting at the
        # same time) — whatever it wrote is the key everyone should use.
        return _KEY_FILE.read_text().strip()


def install_api_key_middleware(app) -> None:
    """
    Require a valid X-API-Key header on every HTTP request.

    Must be added to `app` BEFORE CORSMiddleware. Starlette wraps middleware
    so the LAST one added ends up outermost (sees the request first) — CORS
    needs to be outermost so it can see and answer OPTIONS preflight requests
    directly, before they ever reach this check. Get the order backwards and
    every cross-origin request from the frontend breaks (preflight gets a
    401 from this middleware before CORS ever has a chance to respond).
    """
    from fastapi import Request
    from fastapi.responses import JSONResponse

    api_key = get_or_create_api_key()

    @app.middleware("http")
    async def _check_api_key(request: Request, call_next):
        provided = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(provided, api_key):
            return JSONResponse({"error": "Missing or invalid X-API-Key header"}, status_code=401)
        return await call_next(request)


def verify_ws_key(websocket) -> bool:
    """
    Check a WebSocket connection's `?api_key=` query param before accepting it.

    Browsers can't set custom headers on the WebSocket handshake, so the key
    has to travel as a query parameter instead of the X-API-Key header used
    for REST calls.
    """
    provided = websocket.query_params.get("api_key", "")
    return hmac.compare_digest(provided, get_or_create_api_key())
