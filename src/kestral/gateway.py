"""In-path gateway for OpenAI-compatible chat requests.

An application points its client at Kestral instead of at the model provider.
Kestral checks every message before forwarding the request and checks the
reply before returning it, so inspection cannot be skipped by ignoring a
verdict:

* user text is scanned and the request is refused if it is an attack;
* tool results and attached files are inspected, and the model receives only
  the safe copy, inside isolation markers;
* system and developer messages other than the application's own prompt
  (the first one, before any other message) are inspected the same way,
  because frameworks put retrieved context there;
* the arguments of tool calls the model made are inspected, and a request
  whose history holds an unsafe call is refused;
* remote references the gateway cannot read, and roles it does not know, are
  refused;
* in the reply, images and links to hosts that are not allowed are removed,
  because a rendered image URL is the usual way stolen data leaves, and tool
  calls that carry an injection or reach a host that is not allowed are
  withheld. With no hosts allowed (the default), every remote host is
  refused, for images and for tool calls alike;
* leaked credentials in the reply are redacted, and optionally all personal
  data.

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
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import unquote, urlparse

from kestral._tlds import TLDS
from kestral.config import get_action_for_severity
from kestral.inspector import MODEL_INSTRUCTION
from kestral.models import Action as ScanAction
from kestral.models import Severity
from kestral.pii.entity_types import EntityType
from kestral.pii.redactor import PIIRedactor

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
# "<" cannot occur inside a tag, so a run of unclosed "<a" stops at the next one.
_HTML_TAG = re.compile(r"<([a-z][\w:-]*)\b(?:[^<>\"']|\"[^\"]*\"|'[^']*')*>", re.I)
# Elements the client fetches on its own when it renders them.
_FETCHING = {
    "img", "image", "source", "picture", "video", "audio", "track", "input", "iframe",
    "embed", "object", "use", "feimage", "script", "link", "frame",
}  # fmt: skip
_TAG_URL = re.compile(_REMOTE + r"[^\s\"'<>,)]+", re.I)
_CSS_URL = re.compile(r"url\(\s*[\"']?(" + _REMOTE + r"[^\s\"')]+)", re.I)
_HREF = re.compile(r"href\s*=\s*[\"']?(" + _REMOTE + r"[^\s\"'>]+)", re.I)
# The lookbehind anchors the match at the start of the address, so a long run
# of dots and letters without an "@" is scanned once, not from every position.
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@((?:[\w-]+\.)+[a-z]{2,})", re.I)
# Hosts in tool-call arguments. A URL with a scheme ("https://h/..."), a
# scheme-relative URL ("//h/...") and an email address name a host wherever
# they appear. A bare name ("h.example/collect") counts when it is the whole
# value, or appears in a value whose key names a destination: in running text
# or code ("df.size/2", "Node.js/Express") a dotted name is rarely a host.
_SCHEME_URL = re.compile(r"\b([a-z][a-z0-9+.-]{0,15})://([^\s/?#\"'<>\\]*)", re.I)
_RELATIVE_URL = re.compile(r"(?:^|[\s\"'(=,\[])//([^\s/?#\"'<>\\]+)")
_HOST_NAME = r"(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z][a-z0-9-]{1,62}|\d{1,3}(?:\.\d{1,3}){3}"
_WHOLE_HOST = re.compile(
    rf"(?:[\w.+-]+@)?({_HOST_NAME}|\[[0-9a-f:.]+\])(?::\d{{1,5}})?(?:[/?#]\S*)?", re.I
)
_ANY_HOST = re.compile(rf"(?<![\w.@-])({_HOST_NAME})(?![\w-])", re.I)
# A command that opens a network connection: hosts named anywhere in it count.
_NETWORK_COMMAND = re.compile(
    r"(?<![\w-])(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|ftp|telnet|ping|nslookup|dig"
    r"|rsync|httpie|http|https|invoke-webrequest|invoke-restmethod|iwr|irm|git\s+(?:clone|fetch"
    r"|pull|push|remote))(?![\w-])",
    re.I,
)
# The last word of a key that names a destination ("url", "callback_url",
# "toAddress", "recipient_email"); "email_body" or "original_text" do not.
_DESTINATION_WORDS = frozenset(
    {
        "url", "urls", "uri", "uris", "href", "src", "link", "links", "host", "hosts",
        "hostname", "domain", "domains", "endpoint", "endpoints", "server", "servers",
        "address", "addresses", "addr", "origin", "dest", "destination", "webhook",
        "callback", "redirect", "site", "to", "cc", "bcc", "recipient", "recipients",
        "email", "emails", "mail", "mailto", "ip", "proxy", "remote", "upstream", "base",
    }
)  # fmt: skip
_UNC = re.compile(r"\\\\([^\\/\s]+)[\\/]")


def _destination_key(key: str) -> bool:
    words = re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower())
    return bool(words) and words[-1] in _DESTINATION_WORDS


_ORDER = {"allow": 0, "annotate": 1, "sanitize": 2, "quarantine": 3}
_SEVERITY = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
# Roles whose content was produced by a tool, under the names different
# providers and frameworks give them.
_TOOL_ROLES = {"tool", "function", "ipython", "tool_result"}
_ROLES = _TOOL_ROLES | {"user", "assistant", "system", "developer"}
_SYSTEM_ROLES = {"system", "developer"}

# How system and developer messages are checked.
#   first_trusted  the first one, if it comes before any other message, is the
#                  application's prompt and is passed as it is; every other
#                  one is inspected and forwarded without what the inspector
#                  removes, still as an instruction (default)
#   inspect        every one is inspected that way, the first one too
#   isolate        like first_trusted, but every other one is forwarded as
#                  data inside isolation markers, like a tool result: for
#                  applications that put only retrieved text there
#   scan           every one is scanned like user text
#   trusted        none is checked
SystemPolicy = Literal["first_trusted", "inspect", "isolate", "scan", "trusted"]
SYSTEM_POLICIES: tuple[str, ...] = ("first_trusted", "inspect", "isolate", "scan", "trusted")

# What is redacted from the text of a reply.
#   secrets  credentials in a known vendor format (default)
#   pii      those and all personal data (emails, phone numbers, card numbers ...)
#   off      nothing
RedactionPolicy = Literal["secrets", "pii", "off"]
REDACTION_POLICIES: tuple[str, ...] = ("secrets", "pii", "off")


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


def tool_egress_checked() -> bool:
    """Whether hosts in tool-call arguments must be on the allowlist.

    On unless ``KESTRAL_TOOL_EGRESS=off``. With no hosts allowed, a tool call
    that names any remote host or email address is withheld.
    """
    return os.environ.get("KESTRAL_TOOL_EGRESS", "allowlist").strip().lower() not in (
        "off",
        "0",
        "false",
    )


def _host_allowed(url: str, hosts: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return bool(host) and any(host == h or host.endswith("." + h) for h in hosts)


# Names reserved for special use (RFC 2606, 6761, 6762, 7686, ICANN): not in
# the root zone, but resolvable inside a network.
_SPECIAL_TLDS = frozenset({"example", "test", "invalid", "localhost", "local", "onion", "internal"})


_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


def _is_host(name: str) -> bool:
    """A dotted name that can be a host: an IP address, or ends in a real TLD."""
    name = name.lower().rstrip(".")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\]", name):
        return True
    if "." not in name:
        return False
    tld = name.rsplit(".", 1)[1]
    return tld in TLDS or tld in _SPECIAL_TLDS


def hosts_named(node: Any, key: str = "") -> set[str]:
    """Every host a tool-call argument names, in values and in keys, at any depth."""
    found: set[str] = set()
    if isinstance(node, dict):
        for k, value in node.items():
            found |= hosts_named(str(k))
            found |= hosts_named(value, str(k))
        return found
    if isinstance(node, list):
        for value in node:
            found |= hosts_named(value, key)
        return found
    if not isinstance(node, str):
        return found
    # Full-width and ideographic dots are read as dots by resolvers.
    texts = {node.translate(_DOTS)}
    for _ in range(2):  # percent-encoded, possibly twice
        texts |= {unquote(t) for t in texts}
    destination = bool(key) and _destination_key(key)
    for text in texts:
        network = destination or bool(_NETWORK_COMMAND.search(text))
        for scheme, authority in _SCHEME_URL.findall(text):
            host = authority.rsplit("@", 1)[-1]
            host = host[1:].split("]")[0] if host.startswith("[") else host.split(":")[0]
            if scheme.lower() != "file" and host:
                found.add(host.lower())
        for authority in _RELATIVE_URL.findall(text):
            host = authority.rsplit("@", 1)[-1].split(":")[0]
            if _is_host(host):
                found.add(host.lower())
        found |= {d.lower() for d in _EMAIL.findall(text)}
        found |= {h.lower() for h in _UNC.findall(text) if _is_host(h)}
        whole = _WHOLE_HOST.fullmatch(text.strip())
        # A whole value that is only a dotted name ("main.py", "setup.sh",
        # "1.2.3.4") is a file or a version as often as a host: it counts
        # with a path, port or user, or under a destination key.
        if whole and _is_host(whole.group(1)) and (destination or whole.group(0) != whole.group(1)):
            found.add(whole.group(1).lower().strip("[]"))
        if network:
            # Under a key such as "url", "host" or "to", or in a command such
            # as curl or ssh, any host name counts.
            found |= {h.lower() for h in _ANY_HOST.findall(text) if _is_host(h)}
    return found


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


_FILE_PARTS = ("image_url", "file", "input_file", "input_image")


def _part_url(part: dict[str, Any], kind: str) -> str:
    inner = part.get(kind) if isinstance(part.get(kind), dict) else part
    return str((inner or {}).get("url") or (inner or {}).get("file_data") or "")


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
        system_messages: SystemPolicy | None = None,
        redact_replies: RedactionPolicy = "secrets",
    ) -> None:
        """
        Args:
            engine: scans user text.
            inspector: inspects tool results, attached files, tool-call
                arguments and system messages that carry context.
            scan_system_prompt: kept for compatibility; True is the same as
                ``system_messages="scan"``.
            system_messages: how system and developer messages are checked
                (see :data:`SystemPolicy`). The default, ``first_trusted``,
                passes the application's own prompt as it is, because prompts
                like "You are a support assistant" look like role-change
                attacks to a scanner, and inspects every other one, because
                frameworks put retrieved documents there.
            redact_replies: what to redact from the text of a reply (see
                :data:`RedactionPolicy`).
        """
        if system_messages is None:
            system_messages = "scan" if scan_system_prompt else "first_trusted"
        if system_messages not in SYSTEM_POLICIES:
            raise ValueError(f"unknown system message policy: {system_messages}")
        if redact_replies not in REDACTION_POLICIES:
            raise ValueError(f"unknown reply redaction policy: {redact_replies}")
        self._engine = engine
        self._inspector = inspector
        self._system: SystemPolicy = system_messages
        self._redactor: PIIRedactor | None = None
        if redact_replies == "secrets":
            self._redactor = PIIRedactor(enabled_entities={EntityType.API_KEY})
        elif redact_replies == "pii":
            self._redactor = PIIRedactor()

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

    def _inspect_retrieved(
        self, content: str | bytes, summary: dict[str, Any], *, wrap: bool = True
    ) -> str:
        """The safe copy of retrieved content: inside isolation markers, or,
        with ``wrap=False``, as it is when nothing was removed."""
        result = self._inspect(content, summary)
        summary["removed"] += result.removed_count
        # Text forwarded as it is (an instruction, not data) changes nothing
        # when nothing was found, so it does not raise the reported action.
        unchanged = not wrap and result.action == "annotate"
        if not unchanged and _ORDER[result.action] > _ORDER[summary["action"]]:
            summary["action"] = result.action
        if result.wrapped_content is None or result.safe_content is None:
            return WITHHELD.format(reason=result.reason)
        if wrap:
            return result.wrapped_content
        if result.action == "annotate" and isinstance(content, str):
            return content
        return result.safe_content

    def _retrieved(self, content: Any, summary: dict[str, Any], *, wrap: bool = True) -> str:
        """Inspect message content that is not the user's own: a string or a
        list of parts. Attached files are inspected as documents; a remote
        reference the gateway cannot read is refused."""
        if content is None:
            return ""
        if not isinstance(content, list):
            text = str(content)
            return self._inspect_retrieved(text, summary, wrap=wrap) if text else ""
        texts: list[str] = []
        out: list[str] = []
        for part in content:
            if isinstance(part, str):
                texts.append(part)
                continue
            if not isinstance(part, dict):
                raise GatewayRefusal(422, "unparseable", "bad_content_part")
            kind = part.get("type")
            if kind in _FILE_PARTS:
                url = _part_url(part, str(kind))
                if not url.startswith("data:"):
                    raise GatewayRefusal(415, "unsupported_content", "remote_reference")
                out.append(self._inspect_retrieved(self._data_url(url), summary, wrap=wrap))
            elif "text" in part or kind in ("text", "input_text", "output_text"):
                texts.append(str(part.get("text") or ""))
            elif isinstance(kind, str) and kind in part:
                # Another structured part ({"type": "json", "json": {...}}):
                # inspect its value as text.
                value = part[kind]
                texts.append(value if isinstance(value, str) else json.dumps(value))
            else:
                raise GatewayRefusal(415, "unsupported_content", f"content_part:{kind}")
        text = "\n".join(t for t in texts if t)
        if text:
            out.insert(0, self._inspect_retrieved(text, summary, wrap=wrap))
        return "\n".join(out)

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
            elif kind in _FILE_PARTS:
                # A file is someone else's content even when the user attaches it.
                url = _part_url(part, str(kind))
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
        for index, message in enumerate(messages):
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
            if role in _SYSTEM_ROLES and self._system in ("first_trusted", "inspect", "isolate"):
                if self._system == "inspect" or index > 0:
                    # Later system messages carry context frameworks retrieved.
                    # By default they stay instructions, without what the
                    # inspector removes; "isolate" forwards them as data.
                    isolate = self._system == "isolate"
                    checked = self._retrieved(content, summary, wrap=isolate)
                    if checked:
                        message["content"] = checked
                        wrapped = wrapped or isolate
            elif role in _TOOL_ROLES:
                checked = self._retrieved(content, summary)
                if checked:
                    message["content"] = checked
                    wrapped = True
            elif role == "user" or (role in _SYSTEM_ROLES and self._system == "scan"):
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
        if reason or not tool_egress_checked():
            return reason
        # The agent runs a tool call without asking anyone, so a URL, host or
        # address in its arguments is a way out like an image URL is.
        _, parsed = _call_arguments(call)
        for host in hosts_named(parsed):
            if not any(host == h or host.endswith("." + h) for h in hosts):
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

    def redact_response(self, data: dict[str, Any]) -> int:
        """Redact credentials (and, if configured, personal data) from the
        text of a completion in place. Returns the number of items redacted.

        In monitor mode the completion is left as it is and the count is
        what would have been redacted.
        """
        redactor = self._redactor
        if redactor is None:
            return 0
        monitoring = self._monitoring()
        count = 0

        def clean(text: str) -> str:
            nonlocal count
            result = redactor.redact(text)
            count += result.redaction_count
            return text if monitoring else result.redacted_text

        def clean_value(node: Any) -> Any:
            if isinstance(node, str):
                return clean(node)
            if isinstance(node, dict):
                return {k: clean_value(v) for k, v in node.items()}
            if isinstance(node, list):
                return [clean_value(v) for v in node]
            return node

        for choice in data.get("choices") or []:
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict):
                continue
            for field in ("content", "refusal", "reasoning_content"):
                value = message.get(field)
                if isinstance(value, str):
                    message[field] = clean(value)
                elif isinstance(value, list):
                    for part in value:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            part["text"] = clean(part["text"])
            # A credential in a tool call's arguments leaves with the call.
            for call in _calls(message):
                function = call.get("function") if isinstance(call, dict) else None
                if not isinstance(function, dict):
                    continue
                if isinstance(function.get("arguments"), (dict, list)):
                    cleaned_args = clean_value(function["arguments"])
                    if not monitoring:
                        function["arguments"] = cleaned_args
                    continue
                if not isinstance(function.get("arguments"), str):
                    continue
                try:
                    parsed = json.loads(function["arguments"])
                except ValueError:
                    function["arguments"] = clean(function["arguments"])
                else:
                    cleaned = clean_value(parsed)
                    if not monitoring and cleaned != parsed:
                        function["arguments"] = json.dumps(cleaned, ensure_ascii=False)
        if count and monitoring:
            logger.warning("monitor: would redact %d items from reply", count)
        return count


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
        if isinstance(delta.get("tool_calls"), list):
            # Streaming clients assemble calls by their index.
            delta["tool_calls"] = [
                {"index": i, **call} if isinstance(call, dict) else call
                for i, call in enumerate(delta["tool_calls"])
            ]
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
