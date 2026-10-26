"""In-path gateway for OpenAI-compatible chat requests.

An application points its client at Kestral instead of at the model provider.
Kestral checks every message before forwarding the request and checks the
reply before returning it, so inspection cannot be skipped by ignoring a
verdict:

* user text is scanned and the request is refused if it is an attack;
* tool results and attached files are inspected, and the model receives only
  the safe copy, inside isolation markers;
* remote references the gateway cannot read are refused;
* in the reply, images and links to hosts that are not allowed are removed,
  because a rendered image URL is the usual way stolen data leaves.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import uuid
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from kestral.inspector import MODEL_INSTRUCTION
from kestral.models import Action as ScanAction

if TYPE_CHECKING:
    from kestral.engine import KestralEngine
    from kestral.inspector import Inspector

WITHHELD = "[KESTRAL: content withheld: {reason}]"
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)")
_HTML_IMG = re.compile(r"<img\b[^>]*>", re.I)
_ORDER = {"allow": 0, "annotate": 1, "sanitize": 2, "quarantine": 3}


class GatewayRefusal(Exception):  # noqa: N818
    """The request must not be forwarded."""

    def __init__(self, status: int, code: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.code = code
        self.reason = reason


def error_body(code: str, reason: str, request_id: str) -> dict[str, Any]:
    return {"error": {"code": code, "reason": reason, "request_id": request_id}}


def allowed_hosts() -> set[str]:
    raw = os.environ.get("KESTRAL_EGRESS_ALLOWED_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _host_allowed(url: str, hosts: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return bool(host) and any(host == h or host.endswith("." + h) for h in hosts)


def filter_reply(
    text: str, hosts: set[str] | None = None, strip_links: bool = False
) -> tuple[str, int]:
    """Remove images (and optionally links) that point at hosts not allowed.

    Returns the filtered text and the number of items removed.
    """
    hosts = allowed_hosts() if hosts is None else hosts
    removed = 0

    def image(match: re.Match[str]) -> str:
        nonlocal removed
        url = match.group(2)
        if url.startswith(("http://", "https://", "//")) and not _host_allowed(url, hosts):
            removed += 1
            return "[image removed by Kestral]"
        return match.group(0)

    def link(match: re.Match[str]) -> str:
        nonlocal removed
        if not _host_allowed(match.group(2), hosts):
            removed += 1
            return match.group(1)
        return match.group(0)

    def html_image(match: re.Match[str]) -> str:
        nonlocal removed
        src = re.search(r"src\s*=\s*[\"']?([^\"'\s>]+)", match.group(0), re.I)
        if (
            src
            and src.group(1).startswith(("http://", "https://", "//"))
            and not _host_allowed(src.group(1), hosts)
        ):
            removed += 1
            return "[image removed by Kestral]"
        return match.group(0)

    text = _MD_IMAGE.sub(image, text)
    text = _HTML_IMG.sub(html_image, text)
    if strip_links:
        text = _MD_LINK.sub(link, text)
    return text, removed


class Gateway:
    """Checks a chat request on the way in and the reply on the way out."""

    def __init__(
        self,
        engine: KestralEngine,
        inspector: Inspector,
        *,
        scan_system_prompt: bool = False,
    ) -> None:
        """
        Args:
            engine: scans user text.
            inspector: inspects tool results and attached files.
            scan_system_prompt: scan system messages as if a user wrote them.
                Off by default: the system prompt belongs to the application
                that holds the gateway key, and prompts like "You are a
                support assistant" look like role-change attacks to a scanner.
        """
        self._engine = engine
        self._inspector = inspector
        self._scan_system = scan_system_prompt

    # ---- request side -------------------------------------------------

    def _check_user_text(self, text: str) -> None:
        if not text.strip():
            return
        report = self._engine.scan(text, context={"gate": "gateway", "tier": "user"})
        if report.action == ScanAction.BLOCK:
            raise GatewayRefusal(403, "blocked", "unsafe_request")

    def _inspect_retrieved(self, content: str | bytes, summary: dict[str, Any]) -> str:
        result = self._inspector.inspect(content)
        summary["inspected"] += 1
        summary["removed"] += result.removed_count
        if _ORDER[result.action] > _ORDER[summary["action"]]:
            summary["action"] = result.action
        if result.wrapped_content is None:
            return WITHHELD.format(reason=result.reason)
        return result.wrapped_content

    def _data_url(self, url: str) -> bytes:
        try:
            header, _, payload = url.partition(",")
            if ";base64" in header:
                return base64.b64decode(payload, validate=True)
            return payload.encode("utf-8")
        except (binascii.Error, ValueError) as exc:
            raise GatewayRefusal(422, "unparseable", "bad_data_url") from exc

    def _user_parts(self, parts: list[Any], summary: dict[str, Any]) -> list[Any]:
        out: list[Any] = []
        for part in parts:
            if not isinstance(part, dict):
                raise GatewayRefusal(422, "unparseable", "bad_content_part")
            kind = part.get("type")
            if kind == "text":
                self._check_user_text(str(part.get("text", "")))
                out.append(part)
            elif kind in ("image_url", "file", "input_file", "input_image"):
                # A file is someone else's content even when the user attaches it.
                inner = part.get(kind) if isinstance(part.get(kind), dict) else part
                url = str((inner or {}).get("url") or (inner or {}).get("file_data") or "")
                if not url.startswith("data:"):
                    # A URL or file id the gateway cannot read cannot be vouched for.
                    raise GatewayRefusal(415, "unsupported_content", "remote_reference")
                text = self._inspect_retrieved(self._data_url(url), summary)
                out.append({"type": "text", "text": text})
            else:
                raise GatewayRefusal(415, "unsupported_content", f"content_part:{kind}")
        return out

    def prepare(self, body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Check a request body. Returns the body to forward and a summary.

        Raises :class:`GatewayRefusal` if the request must not be forwarded.
        """
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise GatewayRefusal(422, "unparseable", "messages_missing")
        summary: dict[str, Any] = {"action": "allow", "inspected": 0, "removed": 0}
        out: list[Any] = []
        for message in messages:
            if not isinstance(message, dict) or "role" not in message:
                raise GatewayRefusal(422, "unparseable", "bad_message")
            message = dict(message)
            role, content = message["role"], message.get("content")
            if role in ("tool", "function"):
                if isinstance(content, list):
                    content = "\n".join(
                        str(p.get("text", "")) if isinstance(p, dict) else str(p) for p in content
                    )
                if content:
                    message["content"] = self._inspect_retrieved(str(content), summary)
            elif role == "user" or (role in ("system", "developer") and self._scan_system):
                if isinstance(content, str):
                    self._check_user_text(content)
                elif isinstance(content, list):
                    message["content"] = self._user_parts(content, summary)
                elif content is not None:
                    raise GatewayRefusal(422, "unparseable", "bad_content")
            out.append(message)
        if summary["inspected"]:
            out.insert(0, {"role": "system", "content": MODEL_INSTRUCTION})
        forwarded = dict(body)
        forwarded["messages"] = out
        return forwarded, summary

    # ---- response side ------------------------------------------------

    def filter_response(self, data: dict[str, Any]) -> int:
        """Apply egress control to a completion in place. Returns items removed."""
        strip_links = os.environ.get("KESTRAL_EGRESS_STRIP_LINKS", "").lower() in ("1", "true")
        removed = 0
        for choice in data.get("choices") or []:
            message = choice.get("message") if isinstance(choice, dict) else None
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                message["content"], count = filter_reply(
                    message["content"], strip_links=strip_links
                )
                removed += count
        return removed


def as_event_stream(data: dict[str, Any]) -> str:
    """Replay a complete reply in streaming format.

    The gateway reads the whole upstream reply so it can check it before the
    client sees any of it, then hands it over in the format the client asked for.
    """
    base = {
        "id": data.get("id", "chatcmpl-" + uuid.uuid4().hex[:12]),
        "object": "chat.completion.chunk",
        "created": data.get("created", 0),
        "model": data.get("model", ""),
    }
    events = []
    for choice in data.get("choices") or []:
        message = choice.get("message") or {}
        delta = {k: v for k, v in message.items() if k in ("role", "content", "tool_calls")}
        events.append({**base, "choices": [{"index": choice.get("index", 0), "delta": delta}]})
        events.append(
            {
                **base,
                "choices": [
                    {
                        "index": choice.get("index", 0),
                        "delta": {},
                        "finish_reason": choice.get("finish_reason", "stop"),
                    }
                ],
            }
        )
    return "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"
