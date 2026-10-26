"""Standalone MCP server exposing kestral's scan API as MCP tools.

Tools exposed to MCP clients (Claude Desktop, Cursor, VS Code Copilot Chat, n8n):

* ``scan_input`` — detect prompt injection in user input before it reaches the LLM.
  Backed by the input-detector engine (``KestralEngine.scan``).
* ``scan_output`` — scan LLM output for toxicity, code injection, prompt leakage,
  PII, jailbreak markers, and other policy violations. Backed by the dedicated
  output-scanner engine (``OutputScanEngine.scan``) — a different pipeline
  from ``scan_input``.
* ``scan_tool_result`` — detect indirect injection in tool return values, with
  an optional sanitized copy of the text redacting matched instructions.
* ``list_detectors`` — enumerate enabled input detectors + output scanners.

The server is transport-agnostic at the ``build_server`` layer; ``run_stdio``
wraps it for the stdio transport that Claude Desktop / Cursor speak.

The ``mcp`` Python SDK is imported lazily inside :func:`build_server` and
:func:`run_stdio` so that ``import kestral.mcp_server`` does not fail
for users who installed kestral without the ``[mcp]`` extra — the
``kestral-mcp`` entry point's own guard prints a helpful install
hint in that case.

Concurrency & safety notes:

* Every scan runs on a worker thread via ``anyio.to_thread.run_sync`` — the
  sync scan API stays as-is, and the async event loop remains free to serve
  ping / cancellation / concurrent tool calls.
* A byte cap (``MAX_INPUT_BYTES``, 1 MiB by default) rejects oversize inputs
  with a proper MCP ``isError=True`` response instead of blocking the loop.
* Errors travel through the MCP protocol's ``isError=True`` channel so the
  calling LLM sees them as tool failures, not as JSON success payloads.
"""

from __future__ import annotations

import importlib.metadata
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from kestral import KestralEngine
from kestral.output_scanners import OutputScanEngine
from kestral.tool_guard._sanitize import sanitize_text
from kestral.tool_guard.guard import ToolResultGuard

if TYPE_CHECKING:  # pragma: no cover — imports below are typing-only
    from mcp.server import Server
    from mcp.types import CallToolResult, Tool

    from kestral.models import ScanReport
    from kestral.output_scanners import OutputScanReport

# Path to the bundled interactive-assistant profile applied when the client
# has not supplied its own KESTRAL_CONFIG.
_BUNDLED_MCP_PROFILE = Path(__file__).with_name("mcp_profile.yaml")

logger = logging.getLogger("kestral.mcp_server")

SERVER_NAME = "kestral"

# 1 MiB is a comfortable ceiling for interactive LLM prompts and typical
# tool-result payloads. Bigger blobs get rejected up-front so we never park
# the async event loop on a multi-second sync scan.
MAX_INPUT_BYTES = 1 * 1024 * 1024

SERVER_INSTRUCTIONS = (
    "kestral is a defense-in-depth firewall against prompt injection. "
    "Use `scan_input` before sending user text to an LLM; use `scan_output` "
    "before showing LLM text to a user; use `scan_tool_result` on any tool "
    "return that will re-enter the LLM's context; use `list_detectors` for "
    "introspection. Every tool returns a JSON payload with `action`, "
    "`risk_score`, and per-detector detections."
)


def _server_version() -> str:
    """Best-effort self-version so the MCP handshake reports kestral's
    version, not the SDK's.

    Prefers ``kestral.__version__`` (always in sync with source) over
    ``importlib.metadata.version("kestral")`` (which can lag behind
    source under ``pip install -e .`` after a version bump). Both agree for
    a normal ``pip install kestral`` from PyPI.
    """
    try:
        from kestral import __version__

        return __version__
    except Exception:
        try:
            return importlib.metadata.version("kestral")
        except Exception:
            return "unknown"


def _resolved_config_path() -> str | None:
    """Return the config path an engine built by this module would use.

    Callers that need to reproduce the MCP server's config choice (for
    example, ``kestral-mcp --selftest``) route through this helper so
    the resolution stays in one place.
    """
    override = os.environ.get("KESTRAL_CONFIG")
    if override:
        return override
    if _BUNDLED_MCP_PROFILE.exists():
        return str(_BUNDLED_MCP_PROFILE)
    return None


def _report_to_dict(report: ScanReport) -> dict[str, Any]:
    """Project an input ``ScanReport`` into a JSON-safe dict for MCP tool return."""
    return {
        "action": report.action.value,
        "risk_score": round(report.overall_risk_score, 3),
        "scan_id": report.scan_id,
        "duration_ms": round(report.scan_duration_ms, 2),
        "detectors_run": report.total_detectors_run,
        "detections": [
            {
                "detector_id": d.detector_id,
                "confidence": round(d.confidence, 3),
                "severity": d.severity.value,
                "explanation": d.explanation,
            }
            for d in report.detections
            if d.detected
        ],
    }


def _output_report_to_dict(report: OutputScanReport) -> dict[str, Any]:
    """Project an ``OutputScanReport`` into the same shape as ``_report_to_dict``.

    Callers of ``scan_output`` see a consistent envelope regardless of which
    engine ran. ``action`` is derived from the flagged state so a downstream
    LLM can branch on the same field it uses for ``scan_input``.
    """
    action = "flag" if report.flagged else "pass"
    return {
        "action": action,
        "risk_score": round(report.overall_risk_score, 3),
        "duration_ms": round(report.scan_duration_ms, 2),
        "scanners_run": report.total_scanners_run,
        "detections": [
            {
                "detector_id": f.scanner_id,
                "confidence": round(f.confidence, 3),
                "categories": list(f.categories),
                "explanation": f.explanation,
            }
            for f in report.flags
            if f.flagged
        ],
    }


def _tool_definitions() -> list[Tool]:
    """Return the MCP Tool schemas advertised by this server."""
    from mcp.types import Tool

    return [
        Tool(
            name="scan_input",
            description=(
                "Scan a text prompt for prompt-injection attempts. Returns the "
                "recommended action (block/flag/pass), a risk score in [0,1], and "
                "per-detector detection details. Use before sending user input "
                "to an LLM."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to scan (user prompt or LLM input).",
                    },
                },
                "required": ["text"],
            },
        ),
        Tool(
            name="scan_output",
            description=(
                "Scan an LLM output for policy violations using the dedicated "
                "output-scanner pipeline: toxicity, code injection, prompt "
                "leakage, PII, schema validation, bias/fairness, sentiment, "
                "hallucination/grounding, and relevance. Different from "
                "`scan_input` — runs a separate set of scanners tuned for "
                "output text. Use before displaying LLM output to users."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The LLM output text to scan.",
                    },
                    "scanners": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Optional subset of scanners to run "
                            "(names: toxicity, code_injection, prompt_leakage, "
                            "pii, schema_validation, bias_fairness, sentiment, "
                            "hallucination, relevance). Omit to run all."
                        ),
                    },
                },
                "required": ["text"],
            },
        ),
        Tool(
            name="scan_tool_result",
            description=(
                "Scan a tool call's return value for INDIRECT prompt injection "
                "before it re-enters the LLM context. Detects instructions that "
                "an attacker planted in retrieved content (search results, email "
                "bodies, database rows). Optionally returns a sanitized copy of "
                "the text with detected instructions redacted."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The tool call's return-value text.",
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Optional name of the tool that produced this output.",
                    },
                    "sanitize": {
                        "type": "boolean",
                        "description": (
                            "If true, return a sanitized copy of the text with "
                            "detected instructions redacted."
                        ),
                        "default": False,
                    },
                },
                "required": ["text"],
            },
        ),
        Tool(
            name="list_detectors",
            description=(
                "List all enabled input detectors and output scanners in this "
                "kestral instance with their metadata. Useful for "
                "introspection and debugging."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


def _error_result(message: str) -> CallToolResult:
    """Build an MCP tool-call result that flags a failure via ``isError=True``."""
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps({"error": message}))],
        isError=True,
    )


def _oversize_message(actual_bytes: int) -> str:
    return (
        f"Input too large: {actual_bytes} bytes exceeds "
        f"MAX_INPUT_BYTES={MAX_INPUT_BYTES}. Chunk the payload before scanning."
    )


def _text_size_ok(text: str) -> tuple[bool, int]:
    size = len(text.encode("utf-8", "replace"))
    return size <= MAX_INPUT_BYTES, size


def _build_engine_from_env() -> KestralEngine:
    """Build a KestralEngine using the same config resolution the MCP
    server uses when no engine is passed in.
    """
    return KestralEngine(config_path=_resolved_config_path())


def build_server(
    engine: KestralEngine | None = None,
    output_engine: OutputScanEngine | None = None,
) -> Server:
    """Build the MCP Server object with kestral tool handlers attached.

    Parameters
    ----------
    engine:
        Pre-built ``KestralEngine``. If ``None``, an engine is created with
        the default config (the ``KESTRAL_CONFIG`` environment variable is
        honored as a path override, and the bundled interactive-assistant
        profile is used otherwise).
    output_engine:
        Pre-built ``OutputScanEngine`` for ``scan_output``. If ``None``, a new
        one is created with default per-scanner settings.
    """
    # mcp is imported lazily so importing this module (via
    # ``kestral.mcp_server``) succeeds without the ``[mcp]`` extra;
    # the actual failure happens only when a caller reaches build_server /
    # run_stdio, which is the point at which the entrypoint's guard has
    # already had its chance to print an install hint.
    import anyio
    from mcp.server import Server
    from mcp.types import CallToolResult, TextContent

    if engine is None:
        engine = _build_engine_from_env()

    if output_engine is None:
        output_engine = OutputScanEngine()

    tool_guard = ToolResultGuard(engine=engine, mode="log")

    server: Server = Server(
        SERVER_NAME,
        version=_server_version(),
        instructions=SERVER_INSTRUCTIONS,
    )

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return _tool_definitions()

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        try:
            if name == "scan_input":
                text = str(arguments.get("text", ""))
                ok, size = _text_size_ok(text)
                if not ok:
                    return _error_result(_oversize_message(size))
                report = await anyio.to_thread.run_sync(
                    lambda: engine.scan(text, context={"gate": "input"})
                )
                payload = _report_to_dict(report)
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(payload, indent=2))]
                )

            if name == "scan_output":
                text = str(arguments.get("text", ""))
                ok, size = _text_size_ok(text)
                if not ok:
                    return _error_result(_oversize_message(size))
                scanners = arguments.get("scanners")
                if scanners is not None and not isinstance(scanners, list):
                    return _error_result("`scanners` must be a list of scanner names.")
                out_report = await anyio.to_thread.run_sync(
                    lambda: output_engine.scan(text, scanners=scanners)
                )
                payload = _output_report_to_dict(out_report)
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(payload, indent=2))]
                )

            if name == "scan_tool_result":
                text = str(arguments.get("text", ""))
                ok, size = _text_size_ok(text)
                if not ok:
                    return _error_result(_oversize_message(size))
                tool_name = arguments.get("tool_name")
                should_sanitize = bool(arguments.get("sanitize", False))
                report = await anyio.to_thread.run_sync(
                    lambda: tool_guard.scan(text, tool_name=tool_name)
                )
                payload = _report_to_dict(report)
                if should_sanitize and report.detections:
                    payload["sanitized_text"] = sanitize_text(
                        text,
                        report,
                        replacement="[REDACTED by Kestral]",
                    )
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(payload, indent=2))]
                )

            if name == "list_detectors":
                input_detectors = engine.list_detectors()
                output_scanners = output_engine.list_scanners()
                payload = {
                    "input_detectors": input_detectors,
                    "output_scanners": output_scanners,
                }
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=json.dumps(payload, indent=2, default=str),
                        )
                    ]
                )

            return _error_result(f"unknown tool: {name}")
        except Exception as exc:
            logger.exception("MCP tool %s failed", name)
            return _error_result(f"{type(exc).__name__}: {exc}")

    return server


def warm_up(engine: KestralEngine, output_engine: OutputScanEngine) -> None:
    """Trigger lazy detector loading before we accept our first client call.

    Some detectors (notably d022 semantic classifier via transformers, and d035
    perplexity-spectral via distilgpt2) download hundreds of MB on their first
    ``scan()``. Doing that inside a ``tools/call`` handler makes the first
    invocation exceed Claude Desktop's ~30 s tool timeout. Running one warm
    scan at startup pushes the download into the visible startup window.
    """
    try:
        engine.scan("kestral MCP warm-up", context={"gate": "warmup"})
        output_engine.scan("kestral MCP warm-up")
    except Exception:
        logger.warning("MCP warm-up scan failed; continuing", exc_info=True)


async def run_stdio(
    engine: KestralEngine | None = None,
    output_engine: OutputScanEngine | None = None,
) -> None:
    """Run the MCP server on stdio until the transport closes.

    Runs a warm-up scan through both engines before opening the transport so
    the very first tool call is fast enough for Claude Desktop / Cursor
    timeout windows.
    """
    from mcp.server.stdio import stdio_server

    if engine is None:
        engine = _build_engine_from_env()
    if output_engine is None:
        output_engine = OutputScanEngine()

    warm_up(engine, output_engine)

    server = build_server(engine=engine, output_engine=output_engine)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )
