"""The original regex table (``DEFAULT_PII_PATTERNS``) as a recognizer."""

from __future__ import annotations

from typing import TYPE_CHECKING

import regex

from kestral.pii.entity_types import DEFAULT_PII_PATTERNS, LEGACY_ENTITIES, EntityType
from kestral.pii.recognizers.uae import TIMEOUT, luhn

if TYPE_CHECKING:
    from collections.abc import Iterable

    from kestral.pii.recognizers.base import Span

# The table's email pattern backtracks quadratically on long runs such as
# "a@" + "a." * n (200 KB took about two seconds). Redaction paths that take
# arbitrary request text use this bounded form instead; the parts of an
# address are limited by RFC 5321 anyway.
BOUNDED_EMAIL = r"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,24}"


class PatternTable:
    """Today's email, phone, SSN, card, API-key and IP patterns, unchanged.

    Card numbers that pass the Luhn check are marked validated; the others
    are still reported, as before.
    """

    entity = "legacy"
    version = "1.0"
    languages = frozenset({"en"})

    def __init__(
        self, entities: frozenset[EntityType] = LEGACY_ENTITIES, bounded_email: bool = True
    ) -> None:
        self._patterns: list[tuple[EntityType, regex.Pattern[str]]] = []
        for entity, pattern, _ in DEFAULT_PII_PATTERNS:
            if entity not in entities:
                continue
            if bounded_email and entity == EntityType.EMAIL:
                pattern = BOUNDED_EMAIL
            self._patterns.append((entity, regex.compile(pattern, regex.IGNORECASE)))

    def find(self, text: str) -> Iterable[Span]:
        from kestral.pii.recognizers.base import Span

        for entity, pattern in self._patterns:
            for m in pattern.finditer(text, timeout=TIMEOUT):
                validated = False
                if entity == EntityType.CREDIT_CARD:
                    digits = "".join(ch for ch in m.group() if ch.isdigit())
                    validated = digits.isascii() and luhn(digits)
                yield Span(m.start(), m.end(), entity.value, 0.8, validated)
