"""Redact personal data from a chat request before it reaches the model.

Off by default. With ``mask`` every value found becomes a typed placeholder
such as ``[EMIRATES_ID]``. With ``tokenize`` it becomes a numbered token such
as ``[EMIRATES_ID_1#7f3a9c2e]``, the same token for the same value within the
request, and the gateway puts the values back into the reply.

The checks on a request always run on the original text; redaction runs
after them and changes only what is forwarded. A request that cannot be
redacted is refused, never forwarded as it is.

Tokens carry a random per-request nonce, so text in the request (a document,
a tool result) cannot name a token in advance, and a token from another
request is never restored. The map from tokens to values lives only in the
:class:`Redaction` object of one request; it is not logged or stored.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from kestral.pii.recognizers import find_all, uae_set

if TYPE_CHECKING:
    from collections.abc import Sequence

    from kestral.pii.recognizers import Recognizer

Mode = Literal["off", "mask", "tokenize"]
MODES: tuple[Mode, ...] = ("off", "mask", "tokenize")
Source = Literal["user", "system", "tool", "file", "assistant"]
SOURCES: tuple[Source, ...] = ("user", "system", "tool", "file", "assistant")

DEFAULT_ENTITIES = ("emirates_id", "iban", "phone", "email", "credit_card", "api_key")
# Values the end user sent, and values earlier replies already showed them.
# A value from a tool result or a retrieved document (a CRM record about
# someone else) stays masked unless configured.
DEFAULT_RESTORE_FROM: tuple[Source, ...] = ("user", "assistant")
DEFAULT_MAX_FIELD_CHARS = 1_000_000
DEFAULT_DEADLINE_SECONDS = 5.0


class RedactionFailed(Exception):  # noqa: N818 - mirrors GatewayRefusal codes
    """The request could not be redacted; it must not be forwarded."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class Policy:
    """Request-redaction settings, read once at start-up."""

    mode: Mode = "off"
    entities: frozenset[str] = frozenset(DEFAULT_ENTITIES)
    restore_from: frozenset[str] = frozenset(DEFAULT_RESTORE_FROM)
    restore_tool_args: bool = False
    max_field_chars: int = DEFAULT_MAX_FIELD_CHARS
    deadline_seconds: float = DEFAULT_DEADLINE_SECONDS
    recognizers: tuple[Recognizer, ...] = field(default=(), compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"unknown request redaction mode: {self.mode!r}; use one of {MODES}")
        unknown = set(self.restore_from) - set(SOURCES)
        if unknown:
            raise ValueError(f"unknown restore sources: {sorted(unknown)}; use {SOURCES}")
        if self.mode != "off" and not self.recognizers:
            object.__setattr__(self, "recognizers", tuple(uae_set()))

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    def start(self) -> Redaction:
        return Redaction(self)


def _label(entity: str) -> str:
    return re.sub(r"[^A-Z0-9_]", "_", entity.upper())


class Redaction:
    """The redaction of one request, and the token map for its reply."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.nonce = secrets.token_hex(4)
        self._deadline = time.monotonic() + policy.deadline_seconds
        # (entity, value) -> token, and token -> (value, sources)
        self._tokens: dict[tuple[str, str], str] = {}
        self._values: dict[str, tuple[str, set[str]]] = {}
        self._numbers: dict[str, int] = {}
        self.counts: dict[tuple[str, str], int] = {}
        """Values redacted per (source, entity), for headers."""
        self.found: list[tuple[str, str, str]] = []
        """``(source, entity, value)`` per redacted value, for the evidence log.
        Held only for this request."""
        self._token_re = re.compile(r"\[[A-Z0-9_]+_[0-9]+#" + self.nonce + r"\]")

    def __repr__(self) -> str:
        # The values must not end up in a traceback or a log line.
        return f"<Redaction mode={self.policy.mode} values={len(self.found)}>"

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    # ---- request side ---------------------------------------------------

    def _check_budget(self, text: str) -> None:
        if len(text) > self.policy.max_field_chars:
            raise RedactionFailed(413, "redaction_budget_exceeded")
        if time.monotonic() > self._deadline:
            raise RedactionFailed(413, "redaction_budget_exceeded")

    def _replacement(self, entity: str, value: str, source: Source) -> str:
        if self.policy.mode == "mask":
            return f"[{_label(entity)}]"
        key = (entity, value)
        token = self._tokens.get(key)
        if token is None:
            number = self._numbers.get(entity, 0) + 1
            self._numbers[entity] = number
            token = f"[{_label(entity)}_{number}#{self.nonce}]"
            self._tokens[key] = token
            self._values[token] = (value, set())
        self._values[token][1].add(source)
        return token

    def text(self, text: str, source: Source) -> str:
        """``text`` with every enabled entity replaced."""
        if not text:
            return text
        self._check_budget(text)
        try:
            spans = find_all(self.policy.recognizers, text)
        except TimeoutError as exc:
            raise RedactionFailed(413, "redaction_budget_exceeded") from exc
        out: list[str] = []
        last = 0
        for span in spans:
            if span.entity not in self.policy.entities:
                continue
            out.append(text[last : span.start])
            out.append(self._replacement(span.entity, text[span.start : span.end], source))
            last = span.end
            key = (source, span.entity)
            self.counts[key] = self.counts.get(key, 0) + 1
            self.found.append((source, span.entity, text[span.start : span.end]))
        out.append(text[last:])
        return "".join(out)

    def value(self, node: Any, source: Source) -> Any:
        """A JSON value with every string (and object key) redacted.

        Numbers long enough to be an identifier are checked as text and
        become strings when they are redacted.
        """
        if isinstance(node, str):
            return self.text(node, source)
        if isinstance(node, bool) or node is None:
            return node
        if isinstance(node, int) and abs(node) >= 10**6:
            redacted = self.text(str(node), source)
            return node if redacted == str(node) else redacted
        if isinstance(node, dict):
            return {self.text(str(k), source): self.value(v, source) for k, v in node.items()}
        if isinstance(node, list):
            return [self.value(v, source) for v in node]
        return node

    def arguments(self, arguments: Any, source: Source) -> Any:
        """Tool-call arguments: parsed JSON when they are JSON, else text."""
        if isinstance(arguments, (dict, list)):
            return self.value(arguments, source)
        if not isinstance(arguments, str):
            return arguments
        try:
            parsed = json.loads(arguments)
        except ValueError:
            return self.text(arguments, source)
        redacted = self.value(parsed, source)
        return arguments if redacted == parsed else json.dumps(redacted, ensure_ascii=False)

    # ---- reply side -----------------------------------------------------

    def restore_text(self, text: str) -> str:
        """Put back the values of this request's tokens whose source allows it."""
        if self.policy.mode != "tokenize" or "#" + self.nonce not in text:
            return text

        def back(match: re.Match[str]) -> str:
            entry = self._values.get(match.group())
            if entry is None:
                return match.group()
            value, sources = entry
            return value if sources & self.policy.restore_from else match.group()

        return self._token_re.sub(back, text)

    def restore_value(self, node: Any) -> Any:
        if isinstance(node, str):
            return self.restore_text(node)
        if isinstance(node, dict):
            return {k: self.restore_value(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self.restore_value(v) for v in node]
        return node


def policy_from_env(env: dict[str, str]) -> Policy:
    """Read the ``KESTRAL_REDACT_*`` request settings. Raises ValueError on a bad value."""

    def items(name: str, default: Sequence[str]) -> frozenset[str]:
        raw = env.get(name, "").strip()
        if not raw:
            return frozenset(default)
        return frozenset(x.strip().lower() for x in raw.split(",") if x.strip())

    mode = env.get("KESTRAL_REDACT_REQUESTS", "").strip().lower() or "off"
    restore_args = env.get("KESTRAL_RESTORE_TOOL_ARGS", "").strip().lower()
    if restore_args not in ("", "0", "1", "true", "false"):
        raise ValueError(f"KESTRAL_RESTORE_TOOL_ARGS must be true or false, not {restore_args!r}")
    return Policy(
        mode=mode,  # type: ignore[arg-type]
        entities=items("KESTRAL_REDACT_ENTITIES", DEFAULT_ENTITIES),
        restore_from=items("KESTRAL_RESTORE_FROM", DEFAULT_RESTORE_FROM),
        restore_tool_args=restore_args in ("1", "true"),
    )


__all__ = [
    "DEFAULT_ENTITIES",
    "DEFAULT_RESTORE_FROM",
    "MODES",
    "SOURCES",
    "Policy",
    "Redaction",
    "RedactionFailed",
    "policy_from_env",
]
