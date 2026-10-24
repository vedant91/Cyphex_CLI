"""Live scan log to Google Sheets, connected the same way as the chat webhook.

You deploy a small Apps Script web app bound to your sheet (`/sheet setup`
prints it), paste its /exec URL into `/sheet <url>`, and every scan appends
one row per tested hypothesis: endpoint, payload, outcome, reason. Rows only
ever append, so later scans/commits land below earlier ones on the same sheet.

No Google client library and no OAuth: the script is just another webhook.
The web app is reachable by URL, so each request carries a shared secret that
the script checks before writing; both the URL and the secret are stored
0600 and never printed.
"""
import json
import os
import pathlib
import secrets
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# One worker keeps rows in order; Python joins it at exit so the last row still sends.
_pool = ThreadPoolExecutor(max_workers=1)

COLUMNS = ["Timestamp", "Scan ID", "Service", "Agent", "Method", "Endpoint", "Payload",
           "Vulnerability", "CWE", "Severity", "Outcome", "Confidence", "Reason"]

SETUP_SCRIPT = """\
const SECRET = '__SECRET__';
const COLUMNS = __COLUMNS__;

function doPost(e) {
  let d;
  try { d = JSON.parse(e.postData.contents); } catch (_) { return out('bad request'); }
  if (d.secret !== SECRET) return out('forbidden');
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  if (sheet.getLastRow() === 0) sheet.appendRow(COLUMNS);
  if (d.type === 'row') sheet.appendRow(COLUMNS.map(c => String(d.row[c] ?? '').slice(0, 2000)));
  return out('ok');
}
function out(s) { return ContentService.createTextOutput(s); }
"""


def _store() -> pathlib.Path:
    return pathlib.Path(os.environ.get("CYPHEX_SHEETS_FILE") or pathlib.Path.home() / ".cyphex" / "sheets.json")


def saved() -> list[dict]:
    try:
        return [c for c in json.loads(_store().read_text(encoding="utf-8"))
                if isinstance(c, dict) and c.get("url") and c.get("secret")]
    except Exception:
        return []  # missing or corrupt file just means "nothing connected"


def _save(conns: list[dict]) -> None:
    path = _store()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(conns), encoding="utf-8")
    try:
        path.chmod(0o600)  # the URL and secret are credentials
    except Exception:
        pass  # chmod bits don't exist on Windows


def new_secret() -> str:
    return secrets.token_urlsafe(24)


def _pending() -> pathlib.Path:
    return _store().with_suffix(".pending")


def start_setup() -> str:
    """Generate the shared secret for /sheet setup and remember it, so the
    following `/sheet <url>` can connect without the user re-typing it."""
    secret = new_secret()
    path = _pending()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(secret, encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass
    return secret


def pending_secret() -> str:
    try:
        return _pending().read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def clear_pending() -> None:
    try:
        _pending().unlink()
    except Exception:
        pass


def setup_script(secret: str) -> str:
    return (SETUP_SCRIPT.replace("__SECRET__", secret)
            .replace("__COLUMNS__", json.dumps(COLUMNS)))


def label(url: str) -> str:
    """Safe to print: the script id's tail only, never the full URL."""
    return f"Google Sheet via Apps Script · …{url.split('?')[0].removesuffix('/exec')[-6:]}"


def _post_now(url: str, body: dict) -> str:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return r.read().decode(errors="replace")


def connect(url: str, secret: str) -> dict:
    """Validate by sending a ping the script must accept, and remember the
    connection only if it did. Returns {"ok", "label", "error"}."""
    url, secret = url.strip(), secret.strip()
    if not url.startswith("https://script.google.com/"):
        return {"ok": False, "error": "Expected an Apps Script web-app link (https://script.google.com/macros/s/…/exec). Run /sheet setup."}
    if not secret:
        return {"ok": False, "error": "A secret is required. Run /sheet setup to generate one."}
    try:
        reply = _post_now(url, {"type": "ping", "secret": secret})
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"Google rejected that link (HTTP {e.code}). Redeploy the web app and copy the /exec link again."}
    except Exception as e:
        return {"ok": False, "error": f"Could not reach it ({type(e).__name__}). Check the link and your network."}
    if reply.strip() != "ok":
        return {"ok": False, "error": f"The script answered '{reply.strip()[:40]}'. The secret in the script must match the one from /sheet setup."}
    _save([c for c in saved() if c["url"] != url] + [{"url": url, "secret": secret}])
    return {"ok": True, "label": label(url)}


def disconnect(which: str) -> int:
    """Remove one saved sheet by its 1-based number, or all with 'all'. Returns how many were removed."""
    conns = saved()
    keep = [] if which == "all" else [c for i, c in enumerate(conns, 1) if str(i) != which]
    _save(keep)
    return len(conns) - len(keep)


def _post(conn: dict, row: dict) -> None:
    try:
        _post_now(conn["url"], {"type": "row", "secret": conn["secret"], "row": row})
    except Exception:
        pass  # a sheet outage must never break a scan; never print the URL


def log_row(row: dict) -> None:
    """Queue one row (keys = COLUMNS) to every connected sheet. Never raises, never blocks."""
    for conn in saved():
        _pool.submit(_post, conn, row)
