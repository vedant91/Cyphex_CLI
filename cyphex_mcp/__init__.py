"""Cyphex MCP — a thin orchestration + artifact server over the Cyphex engine.

The server hosts no model and runs no target: it hands the host coding agent
playbooks and runs the deterministic gates. See core.py for the substance and
docs/mcp-blueprint/architecture.html for the design.
"""
__all__ = ["core"]
