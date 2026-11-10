# Demo image for cyphex_mcp — the thin MCP server, not the full Cyphex engine.
# core.py is stdlib-only by design (see its module docstring), so this image
# needs exactly one dependency: the mcp SDK. No scikit-learn/pillow/etc. from
# the main repo's pyproject — that weight belongs to the CLI, not the MCP.
FROM python:3.12-slim

# Pinned <2: server.py uses the v1 FastMCP API, renamed in mcp 2.x.
RUN pip install --no-cache-dir "mcp>=1.2.0,<2"

# Non-root: this container never runs the user's target — it only serves
# playbooks and the deterministic gates — but least privilege by default
# costs nothing here either.
RUN useradd -u 10001 -m cyphex && mkdir /data && chown cyphex /data  # job ledger + reports
WORKDIR /app
COPY --chown=cyphex:cyphex . /app/cyphex_mcp
USER cyphex

ENV CYPHEX_MCP_TRANSPORT=streamable-http \
    CYPHEX_MCP_PORT=8765 \
    CYPHEX_DATA_DIR=/data \
    PYTHONUNBUFFERED=1
EXPOSE 8765

CMD ["python", "-m", "cyphex_mcp.server"]
