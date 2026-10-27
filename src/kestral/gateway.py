"""In-path gateway for OpenAI-compatible chat requests.

An application points its client at Kestral instead of at the model provider.
Kestral checks every message before forwarding the request and checks the
reply before returning it, so inspection cannot be skipped by ignoring a
verdict:

* user text is scanned and the request is refused if it is an attack;
* tool results and attached files are inspected, and the model receives only
  the safe copy, inside isolation markers;
* the arguments of tool calls the model made are inspected, and a request
  whose history holds an unsafe call is refused;
* remote references the gateway cannot read, and roles it does not know, are
  refused;
* in the reply, images and links to hosts that are not allowed are removed,
  because a rendered image URL is the usual way stolen data leaves, and tool
  calls that carry an injection or reach a host that is not allowed are
  withheld.

In monitor mode (``mode: monitor`` in the engine configuration) the gateway
logs and reports what it would have done, but forwards everything unchanged
and refuses nothing.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import uuid
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from kestral.config import get_action_for_severity
from kestral.inspector import MODEL_INSTRUCTION
from kestral.models import Action as ScanAction
from kestral.models import Severity

if TYPE_CHECKING:
    from kestral.engine import KestralEngine
    from kestral.inspector import Inspector, InspectResult
    from kestral.models import ScanReport

logger = logging.getLogger("kestral.gateway")

WITHHELD = "[KESTRAL: content withheld: {reason}]"
CALL_WITHHELD = "[KESTRAL: tool call {name} withheld: {reason}]"
IMAGE_REMOVED = "[image removed by Kestral]"
LINK_REMOVED = "[link removed by Kestral]"
_REMOTE = r"(?:https?:)?//"
_ALT = r"!\[((?:[^\[\]]|\[[^\[\]]*\])*)\]"  # alt text may hold one level of brackets
_MD_IMAGE = re.compile(_ALT + r"\(\s*<?([^)\s>]+)>?[^)]*\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*<?(" + _REMOTE + r"[^)\s>]+)>?[^)]*\)", re.I)
# Reference style: ![alt][label], ![label][] and ![label], defined elsewhere
# by a line "[label]: url".
_MD_REF_DEF = re.compile(r"^[ \t]{0,3}\[([^\]]+)\]:[ \t]*<?([^\s>]+)>?.*$\n?", re.M)
_MD_REF_IMAGE = re.compile(_ALT + r"(?:\[([^\]]*)\])?(?![(:])")
_MD_REF_LINK = re.compile(r"(?<![!\]])\[([^\]]+)\]\[([^\]]*)\]")
_AUTOLINK = re.compile(r"<(" + _REMOTE + r"[^\s<>]+)>", re.I)
_HTML_TAG = re.compile(r"<([a-z][\w:-]*)\b(?:[^>\"']|\"[^\"]*\"|'[^']*')*>", re.I)
# Elements the client fetches on its own when it renders them.
_FETCHING = {
    "img", "image", "source", "picture", "video", "audio", "track", "input", "iframe",
    "embed", "object", "use", "feimage", "script", "link", "frame",
}  # fmt: skip
_TAG_URL = re.compile(_REMOTE + r"[^\s\"'<>,)]+", re.I)
_CSS_URL = re.compile(r"url\(\s*[\"']?(" + _REMOTE + r"[^\s\"')]+)", re.I)
_HREF = re.compile(r"href\s*=\s*[\"']?(" + _REMOTE + r"[^\s\"'>]+)", re.I)
_EMAIL = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[a-z]{2,})", re.I)
_ORDER = {"allow": 0, "annotate": 1, "sanitize": 2, "quarantine": 3}
_SEVERITY = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
# Roles whose content was produced by a tool, under the names different
# providers and frameworks give them.
_TOOL_ROLES = {"tool", "function", "ipython", "tool_result"}
_ROLES = _TOOL_ROLES | {"user", "assistant", "system", "developer"}


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


def _is_remote(url: str) -> bool:
    return re.match(_REMOTE, url, re.I) is not None


def _label(text: str) -> str:
    return " ".join(text.split()).lower()


def filter_reply(
    text: str, hosts: set[str] | None = None, strip_links: bool = False
) -> tuple[str, int]:
    """Remove images (and optionally links) that point at hosts not allowed.

    Returns the filtered text and the number of items removed.
    """
    hosts = allowed_hosts() if hosts is None else hosts
    removed = 0

    def bad(url: str) -> bool:
        return _is_remote(url) and not _host_allowed(url, hosts)

    # Reference definitions do not render, so they are judged by what uses them.
    bad_refs = {_label(m.group(1)) for m in _MD_REF_DEF.finditer(text) if bad(m.group(2))}
    drop = set(bad_refs) if strip_links else set()

    def image(match: re.Match[str]) -> str:
        nonlocal removed
        if bad(match.group(2)):
            removed += 1
            return IMAGE_REMOVED
        return match.group(0)

    def ref_image(match: re.Match[str]) -> str:
        nonlocal removed
        label = _label(match.group(2) or match.group(1))
        if label in bad_refs:
            removed += 1
            drop.add(label)
            return IMAGE_REMOVED
        return match.group(0)

    def link(match: re.Match[str]) -> str:
        nonlocal removed
        if not _host_allowed(match.group(2), hosts):
            removed += 1
            return match.group(1)
        return match.group(0)

    def ref_link(match: re.Match[str]) -> str:
        nonlocal removed
        if _label(match.group(2) or match.group(1)) in drop:
            removed += 1
            return match.group(1)
        return match.group(0)

    def autolink(match: re.Match[str]) -> str:
        nonlocal removed
        if bad(match.group(1)):
            removed += 1
            return LINK_REMOVED
        return match.group(0)

    def html_tag(match: re.Match[str]) -> str:
        nonlocal removed
        tag, name = match.group(0), match.group(1).lower().rsplit(":", 1)[-1]
        # Any URL in a fetching element counts (src, srcset, href, data-src,
        # poster, ...), and so does a CSS url() on any element.
        urls = _TAG_URL.findall(tag) if name in _FETCHING else _CSS_URL.findall(tag)
        if any(bad(url) for url in urls):
            removed += 1
            return IMAGE_REMOVED
        href = _HREF.search(tag) if name == "a" and strip_links else None
        if href and bad(href.group(1)):
            removed += 1
            return ""
        return match.group(0)

    text = _MD_IMAGE.sub(image, text)
    text = _MD_REF_IMAGE.sub(ref_image, text)
    text = _HTML_TAG.sub(html_tag, text)
    if strip_links:
        text = _MD_LINK.sub(link, text)
        text = _MD_REF_LINK.sub(ref_link, text)
        text = _AUTOLINK.sub(autolink, text)
    if drop:

        def definition(match: re.Match[str]) -> str:
            return "" if _label(match.group(1)) in drop else match.group(0)

        text = _MD_REF_DEF.sub(definition, text)
    return text, removed


def _strings(node: Any) -> list[str]:
    """Every string value in a parsed JSON value, at any depth."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for value in node.values() for s in _strings(value)]
    if isinstance(node, list):
        return [s for value in node for s in _strings(value)]
    return []


def _calls(message: dict[str, Any]) -> list[Any]:
    """The tool calls in an assistant message, including the legacy single call."""
    calls = message.get("tool_calls")
    out = list(calls) if isinstance(calls, list) else []
    if isinstance(message.get("function_call"), dict):
        out.append({"function": message["function_call"]})
    return out


def _call_name(call: Any) -> str:
    function = call.get("function") if isinstance(call, dict) else None
    name = function.get("name") if isinstance(function, dict) else None
    return str(name or "unknown")


def _call_arguments(call: Any) -> tuple[str, Any]:
    """Return a call's arguments as text to inspect, and parsed if they are JSON."""
    function = call.get("function") if isinstance(call, dict) else None
    if not isinstance(function, dict):
        raise GatewayRefusal(422, "unparseable", "bad_tool_call")
    raw = function.get("arguments")
    if raw is None or raw == "":
        return "", None
    if not isinstance(raw, str):
        return json.dumps(raw), raw
    try:
        return raw, json.loads(raw)
    except ValueError:
        return raw, raw


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
            inspector: inspects tool results, attached files and tool-call
                arguments.
            scan_system_prompt: scan system messages as if a user wrote them.
                Off by default: the system prompt belongs to the application
                that holds the gateway key, and prompts like "You are a
                support assistant" look like role-change attacks to a scanner.
        """
        self._engine = engine
        self._inspector = inspector
        self._scan_system = scan_system_prompt

    def _monitoring(self) -> bool:
        config = self._engine.config
        return bool(config.get("kestral", config).get("mode") == "monitor")

    def _inspect(self, content: str | bytes, summary: dict[str, Any]) -> InspectResult:
        result = self._inspector.inspect(content)
        summary["inspected"] += 1
        # The inspector's own word on monitor mode wins over the engine config.
        monitor = getattr(result, "monitor", None)
        if isinstance(monitor, bool):
            summary["monitor"] = monitor
        return result

    # ---- request side -------------------------------------------------

    def _blocks(self, report: ScanReport) -> bool:
        if report.action == ScanAction.BLOCK:
            return True
        if not self._monitoring() or not report.detections:
            return False
        # Monitor mode turns every verdict into "log"; work out what the
        # configured action for the worst detection would have been.
        worst = max(report.detections, key=lambda d: _SEVERITY.index(d.severity))
        return get_action_for_severity(self._engine.config, worst.severity) == "block"

    def _check_user_text(self, text: str) -> None:
        if not text.strip():
            return
        report = self._engine.scan(text, context={"gate": "gateway", "tier": "user"})
        if self._blocks(report):
            raise GatewayRefusal(403, "blocked", "unsafe_request")

    def _inspect_retrieved(self, content: str | bytes, summary: dict[str, Any]) -> str:
        result = self._inspect(content, summary)
        summary["removed"] += result.removed_count
        if _ORDER[result.action] > _ORDER[summary["action"]]:
            summary["action"] = result.action
        if result.wrapped_content is None:
            return WITHHELD.format(reason=result.reason)
        return result.wrapped_content

    def _unsafe_call(self, call: Any, summary: dict[str, Any]) -> str | None:
        """Inspect a tool call's arguments. Returns why it is unsafe, or None."""
        text, _ = _call_arguments(call)
        if not text.strip():
            return None
        result = self._inspect(text, summary)
        if result.removed_count or result.action == "quarantine":
            summary["removed"] += result.removed_count
            return "unsafe_tool_call"
        return None

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
        In monitor mode nothing is refused or changed: the summary says what
        would have happened, under ``monitor`` and ``would_refuse``.
        """
        summary: dict[str, Any] = {
            "action": "allow",
            "inspected": 0,
            "removed": 0,
            "monitor": self._monitoring(),
        }
        try:
            forwarded = self._prepare(body, summary)
        except GatewayRefusal as refusal:
            if not summary["monitor"]:
                raise
            summary["would_refuse"] = refusal.reason
            logger.warning(
                "monitor: would refuse request (%s %s %s)",
                refusal.status,
                refusal.code,
                refusal.reason,
            )
        if not summary["monitor"]:
            return forwarded, summary
        if summary["action"] != "allow":
            logger.warning(
                "monitor: would forward request with action %s, %d removed",
                summary["action"],
                summary["removed"],
            )
        return dict(body), summary

    def _prepare(self, body: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise GatewayRefusal(422, "unparseable", "messages_missing")
        out: list[Any] = []
        wrapped = False
        for message in messages:
            if not isinstance(message, dict) or not isinstance(message.get("role"), str):
                raise GatewayRefusal(422, "unparseable", "bad_message")
            message = dict(message)
            # Providers differ in what they accept; "USER" or "Tool" must not
            # slip past checks that compare against "user" and "tool".
            role = message["role"].strip().lower()
            if role not in _ROLES:
                raise GatewayRefusal(415, "unsupported_content", f"role:{role or 'empty'}")
            message["role"] = role
            content = message.get("content")
            if role in _TOOL_ROLES:
                if isinstance(content, list):
                    content = "\n".join(
                        str(p.get("text", "")) if isinstance(p, dict) else str(p) for p in content
                    )
                if content:
                    message["content"] = self._inspect_retrieved(str(content), summary)
                    wrapped = True
            elif role == "user" or (role in ("system", "developer") and self._scan_system):
                if isinstance(content, str):
                    self._check_user_text(content)
                elif isinstance(content, list):
                    before = summary["inspected"]
                    message["content"] = self._user_parts(content, summary)
                    wrapped = wrapped or summary["inspected"] > before
                elif content is not None:
                    raise GatewayRefusal(422, "unparseable", "bad_content")
            elif role == "assistant":
                # A call the model was steered into making stays in the
                # history and steers the next turn as well.
                for call in _calls(message):
                    reason = self._unsafe_call(call, summary)
                    if reason:
                        raise GatewayRefusal(403, "blocked", reason)
            out.append(message)
        if wrapped:
            out.insert(0, {"role": "system", "content": MODEL_INSTRUCTION})
        forwarded = dict(body)
        forwarded["messages"] = out
        return forwarded

    # ---- response side ------------------------------------------------

    def _withhold_reason(self, call: Any, hosts: set[str], summary: dict[str, Any]) -> str | None:
        try:
            reason = self._unsafe_call(call, summary)
        except GatewayRefusal as refusal:
            return refusal.reason
        if reason or not hosts:
            return reason
        # The agent runs a tool call without asking anyone, so a URL or
        # address in its arguments is a way out like an image URL is.
        _, parsed = _call_arguments(call)
        for value in _strings(parsed):
            urls = _TAG_URL.findall(value)
            domains = _EMAIL.findall(value)
            if any(not _host_allowed(u, hosts) for u in urls) or any(
                not _host_allowed("//" + d, hosts) for d in domains
            ):
                return "egress_host"
        return None

    def _filter_calls(self, choice: dict[str, Any], message: dict[str, Any]) -> int:
        hosts = allowed_hosts()
        summary: dict[str, Any] = {"inspected": 0, "removed": 0}
        kept: list[Any] = []
        notices: list[str] = []
        for call in _calls(message):
            reason = self._withhold_reason(call, hosts, summary)
            if reason:
                notices.append(CALL_WITHHELD.format(name=_call_name(call), reason=reason))
            else:
                kept.append(call)
        if not notices or self._monitoring():
            for notice in notices:
                logger.warning("monitor: would withhold %s", notice)
            return len(notices)
        legacy = message.get("function_call")
        calls = [c for c in kept if legacy is None or c.get("function") is not legacy]
        if legacy is not None and len(calls) == len(kept):
            del message["function_call"]
        if calls:
            message["tool_calls"] = calls
        else:
            message.pop("tool_calls", None)
        if not kept and choice.get("finish_reason") in ("tool_calls", "function_call"):
            choice["finish_reason"] = "stop"
        content = message.get("content")
        text = content if isinstance(content, str) else ""
        message["content"] = "\n".join([text, *notices] if text else notices)
        return len(notices)

    def filter_response(self, data: dict[str, Any]) -> int:
        """Apply egress control to a completion in place. Returns items removed.

        Withheld tool calls count as removed items. In monitor mode the
        completion is left as it is and the count is what would have gone.
        """
        strip_links = os.environ.get("KESTRAL_EGRESS_STRIP_LINKS", "").lower() in ("1", "true")
        removed = 0
        for choice in data.get("choices") or []:
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict):
                continue
            if isinstance(message.get("content"), str):
                text, count = filter_reply(message["content"], strip_links=strip_links)
                if count and self._monitoring():
                    logger.warning("monitor: would remove %d items from reply", count)
                else:
                    message["content"] = text
                removed += count
            removed += self._filter_calls(choice, message)
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
