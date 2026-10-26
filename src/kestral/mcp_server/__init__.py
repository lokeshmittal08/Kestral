"""Standalone MCP server exposing kestral's scan API as MCP tools.

Consumed by MCP clients such as Claude Desktop, Cursor, VS Code Copilot Chat,
and n8n. Runs over stdio.

Entry points:
    python -m kestral.mcp_server
    kestral-mcp

Re-exports are LAZY: ``import kestral.mcp_server`` succeeds even when
the optional ``[mcp]`` extra (which pulls in the ``mcp`` Python SDK) is
missing. The ``mcp`` import only fires when a caller reaches for
``build_server``, ``run_stdio`` or ``warm_up`` — at which point the
``kestral-mcp`` entry point's guard has already had its chance to
print an install hint on stderr.
"""

from __future__ import annotations

from typing import Any

__all__ = ["build_server", "run_stdio", "warm_up"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from kestral.mcp_server.server import build_server, run_stdio, warm_up

        table = {"build_server": build_server, "run_stdio": run_stdio, "warm_up": warm_up}
        return table[name]
    raise AttributeError(f"module 'kestral.mcp_server' has no attribute {name!r}")
