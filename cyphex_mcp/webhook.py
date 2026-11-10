"""Cyphex MCP — GitHub webhook receiver and CI workflow template.

A webhook can *record* "a push landed" but it cannot *scan*: the MCP hosts no model,
and the deep-agent roles need one. So the loop has two halves:

  1. This receiver verifies the delivery, turns a push to the default branch or a
     merged pull request into a queued job in the ledger, and serves finished
     reports at GET /report/<job_id>.
  2. Something has to run an agent against that commit. workflow_yaml() writes a
     GitHub Actions workflow that does it with a headless coding agent
     (`claude -p`) wired to the Cyphex MCP, on the same two events.

Status: the receiver is unit-tested here. The workflow template and the headless
agent run have NOT been run against GitHub, so treat it as a starting point.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import ledger, report

MAX_BODY = 1_000_000  # webhook payloads are small; refuse anything bigger before reading it


def verify_signature(body: bytes, header: str, secret: str) -> bool:
    """GitHub signs the raw body: X-Hub-Signature-256 = 'sha256=' + HMAC-SHA256(secret, body)."""
    if not secret or not header.startswith("sha256="):
        return False
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)


def parse_event(event: str, p: dict) -> dict | None:
    """The delivery as a trigger dict, or None when it should not start a scan."""
    repo = (p.get("repository") or {}).get("full_name", "")
    if event == "push":
        ref = p.get("ref", "")
        branch = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ""
        default = (p.get("repository") or {}).get("default_branch")
        if p.get("deleted") or not branch or branch != default:
            return None
        return {"event": "push", "repo": repo, "ref": branch, "commit": p.get("after", ""),
                "pusher": (p.get("pusher") or {}).get("name", "")}
    if event == "pull_request":
        pr = p.get("pull_request") or {}
        if p.get("action") != "closed" or pr.get("merged") is not True:
            return None
        return {"event": "pull_request", "repo": repo, "ref": (pr.get("base") or {}).get("ref", ""),
                "commit": pr.get("merge_commit_sha", ""), "pr": pr.get("number"), "title": str(pr.get("title", ""))[:120]}
    return None


_seen_deliveries: set[str] = set()  # GitHub retries a delivery with the same id; do not queue it twice


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj).encode())

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"status": "ok"})
        if self.path.startswith("/report/"):
            try:
                return self._send(200, report.render_report(ledger.load_job(self.path[len("/report/"):])).encode(), "text/html; charset=utf-8")
            except (ValueError, KeyError):
                return self._json(404, {"error": "no such job"})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/github":
            return self._json(404, {"error": "not found"})
        secret = ledger.webhook_secret()  # env var, or the secret start_scan generated for the human
        if not secret:  # an unconfigured receiver must refuse, never accept unsigned input
            return self._json(503, {"error": "no webhook secret: set CYPHEX_WEBHOOK_SECRET or answer 'yes' to the webhook question in start_scan"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._json(413, {"error": "payload too large"})
        body = self.rfile.read(length)
        if not verify_signature(body, self.headers.get("X-Hub-Signature-256", ""), secret):
            return self._json(401, {"error": "bad signature"})
        event = self.headers.get("X-GitHub-Event", "")
        if event == "ping":
            return self._json(200, {"status": "pong"})
        try:
            payload = json.loads(body)
        except ValueError:
            return self._json(400, {"error": "invalid json"})
        trig = parse_event(event, payload)
        if trig is None:
            return self._json(200, {"status": "ignored", "event": event})
        delivery = self.headers.get("X-GitHub-Delivery", "")
        if delivery and delivery in _seen_deliveries:
            return self._json(200, {"status": "duplicate"})
        _seen_deliveries.add(delivery)
        job = ledger.new_job(trigger=trig)
        job["status"] = "queued"
        ledger.save_job(job)
        self._json(202, {"status": "queued", "job_id": job["job_id"], "trigger": trig})


def serve(host: str = "127.0.0.1", port: int = 3005):
    ThreadingHTTPServer((host, port), Handler).serve_forever()


_PROMPT = """You are running a Cyphex security scan with the Cyphex MCP tools.
Repo: ${{ github.repository }}  commit: ${{ github.sha }}  event: ${{ github.event_name }}  ref: ${{ github.ref_name }}  PR: ${{ github.event.pull_request.number }}
1. Call start_scan(stack=<detect from the repo>, repo_path="${{ github.workspace }}", event="${{ github.event_name }}", repo="${{ github.repository }}", ref="${{ github.ref_name }}", commit="${{ github.sha }}", pr=<PR number or 0>).
2. Follow its run_in_order list. For each role call get_playbook, do the work yourself, then call submit_result with the JSON the playbook asks for.
3. Build the sandbox from the recipe only if Docker is available; otherwise submit deep_dast as not run and say why.
4. For each patch, test it on a scratch copy of the repo (never edit the checked-out branch), replay the exploit, then call verify_patch with the result.
5. Call build_genome, then get_report with out_path="cyphex-report.html". Print the path and the one-line verdict."""


def workflow_yaml() -> str:
    indented = "\n".join("          " + ln for ln in _PROMPT.splitlines())
    return f"""name: Cyphex security scan
# Runs on pushes to main and on merged pull requests. Needs the repo secret ANTHROPIC_API_KEY.
on:
  push:
    branches: [main]
  pull_request:
    types: [closed]
    branches: [main]
jobs:
  scan:
    if: github.event_name == 'push' || github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {{python-version: "3.12"}}
      - uses: actions/setup-node@v4
        with: {{node-version: "22"}}
      - run: pip install "cyphex[mcp] @ git+https://github.com/vedant91/Cyphex_CLI"
      - run: npm install -g @anthropic-ai/claude-code
      - run: echo '{{"mcpServers":{{"cyphex":{{"command":"cyphex-mcp","env":{{"CYPHEX_DATA_DIR":"${{{{ runner.temp }}}}/cyphex"}}}}}}}}' > mcp.json
      - name: Scan with a headless agent
        env:
          ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
          PROMPT: |
{indented}
        run: claude -p "$PROMPT" --mcp-config mcp.json --max-turns 80 --allowedTools "mcp__cyphex__*,Read,Grep,Glob,Bash(docker:*),Bash(curl:*),Bash(cp:*),Bash(node:*)"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cyphex-report
          path: cyphex-report.html
"""


if __name__ == "__main__":
    serve(os.environ.get("CYPHEX_WEBHOOK_HOST", "127.0.0.1"), int(os.environ.get("CYPHEX_WEBHOOK_PORT", "3005")))
