"""The recognizer interface, overlap rules and the registry."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

logger = logging.getLogger("kestral.pii")

# Entity and version names end up in logs, evidence rows and CSV exports;
# third-party recognizers are untrusted, so the names are kept plain.
_NAME = re.compile(r"^[a-z0-9_.-]{1,64}$")
ENTRY_POINT_GROUP = "kestral.recognizers"


@dataclass(frozen=True)
class Span:
    """One value found in a text: ``text[start:end]``."""

    start: int
    end: int
    entity: str
    score: float
    validated: bool
    """True when a checksum or numbering plan confirmed the value."""


@runtime_checkable
class Recognizer(Protocol):
    """Finds one kind of personal data in a text."""

    entity: str
    version: str
    languages: frozenset[str]

    def find(self, text: str) -> Iterable[Span]:
        """Every value in ``text``. Positions index ``text`` as given."""
        ...


def check_names(recognizer: Recognizer) -> None:
    for field in ("entity", "version"):
        value = getattr(recognizer, field, None)
        if not isinstance(value, str) or not _NAME.match(value):
            raise ValueError(f"recognizer {field} must match {_NAME.pattern}: {value!r}")


def resolve(spans: Iterable[Span]) -> list[Span]:
    """Pick non-overlapping spans.

    Validated spans win over unvalidated ones: an Emirates ID that passes its
    check digit is not cut up by a looser phone pattern. Among the rest, the
    earliest start wins and then the longest, as the redactor always did.
    """
    by_start = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    chosen: list[Span] = []
    for span in [s for s in by_start if s.validated] + [s for s in by_start if not s.validated]:
        if any(span.start < c.end and c.start < span.end for c in chosen):
            continue
        chosen.append(span)
    return sorted(chosen, key=lambda s: s.start)


def discover() -> list[Recognizer]:
    """Recognizers installed by other packages under the ``kestral.recognizers`` entry point."""
    from importlib.metadata import entry_points

    found: list[Recognizer] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            obj = ep.load()
            recognizer = obj() if isinstance(obj, type) else obj
            if not isinstance(recognizer, Recognizer):
                raise TypeError("not a Recognizer")
            check_names(recognizer)
        except Exception as exc:
            logger.warning("Skipping recognizer entry point %s: %s", ep.name, exc)
            continue
        found.append(recognizer)
    return found


def find_all(recognizers: Sequence[Recognizer], text: str) -> list[Span]:
    spans: list[Span] = []
    for recognizer in recognizers:
        spans.extend(recognizer.find(text))
    return resolve(spans)
