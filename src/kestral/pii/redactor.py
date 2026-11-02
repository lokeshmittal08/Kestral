"""Standalone PII redactor with entity-type-aware placeholders."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import regex

from kestral.models import RedactionResult
from kestral.pii.entity_types import (
    DEFAULT_PII_PATTERNS,
    DEFAULT_REPLACEMENTS,
    LEGACY_ENTITIES,
    EntityType,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from kestral.pii.recognizers import Recognizer


class PIIRedactor:
    """Detects and redacts PII from text with entity-type-aware placeholders.

    Can be used standalone (without AgentGuard) or integrated into the
    sanitization pipeline.

    Without ``recognizers`` it uses the original regex table for six entity
    types (email, phone, SSN, card, API key, IP address). With
    ``recognizers`` (see :func:`kestral.pii.recognizers.uae_set`) it uses
    those instead: Emirates ID, IBAN and UAE phones in any digit script, with
    checksum-validated values winning overlaps.
    """

    def __init__(
        self,
        replacements: dict[EntityType, str] | None = None,
        enabled_entities: set[EntityType] | None = None,
        recognizers: Sequence[Recognizer] | None = None,
    ) -> None:
        self._replacements = replacements or dict(DEFAULT_REPLACEMENTS)
        self._enabled_entities = set(enabled_entities or LEGACY_ENTITIES)
        self._recognizers = list(recognizers) if recognizers is not None else None
        if recognizers is not None and enabled_entities is None:
            self._enabled_entities = set(EntityType)
        self._compiled_patterns: list[tuple[EntityType, regex.Pattern[str], str]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._compiled_patterns = []
        for entity_type, pattern_str, description in DEFAULT_PII_PATTERNS:
            if entity_type in self._enabled_entities:
                compiled = regex.compile(pattern_str, regex.IGNORECASE)
                self._compiled_patterns.append((entity_type, compiled, description))

    def _matches(self, text: str) -> list[tuple[int, int, str, str]]:
        """Non-overlapping ``(start, end, entity, value)``, in text order."""
        if self._recognizers is not None:
            from kestral.pii.recognizers import find_all

            wanted = {e.value for e in self._enabled_entities}
            return [
                (s.start, s.end, s.entity, text[s.start : s.end])
                for s in find_all(self._recognizers, text)
                if s.entity in wanted
            ]
        raw_matches: list[tuple[int, int, str, str]] = []
        for entity_type, compiled, _description in self._compiled_patterns:
            for m in compiled.finditer(text):
                raw_matches.append((m.start(), m.end(), entity_type.value, m.group()))
        # Deduplicate overlapping matches: keep the longest match at each position
        raw_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        deduped: list[tuple[int, int, str, str]] = []
        for match in raw_matches:
            if deduped and match[0] < deduped[-1][1]:
                # Overlapping — skip shorter match
                continue
            deduped.append(match)
        return deduped

    def _placeholder(self, entity: str) -> str:
        try:
            return self._replacements.get(EntityType(entity), f"[{entity.upper()}_REDACTED]")
        except ValueError:
            return f"[{entity.upper()}_REDACTED]"

    def redact(self, text: str) -> RedactionResult:
        """Detect and redact all PII from the given text.

        Returns a RedactionResult with the redacted text, counts, and entity details.
        """
        deduped = self._matches(text)
        if not deduped:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                redaction_count=0,
                entity_counts={},
                redacted_entities=[],
            )

        # Replace in reverse order to preserve positions
        entity_counts: dict[str, int] = {}
        redacted_entities: list[dict[str, str]] = []
        result = text

        for start, end, entity, matched_text in reversed(deduped):
            result = result[:start] + self._placeholder(entity) + result[end:]
            entity_counts[entity] = entity_counts.get(entity, 0) + 1
            redacted_entities.append({"entity_type": entity, "original": matched_text})

        redacted_entities.reverse()

        return RedactionResult(
            original_text=text,
            redacted_text=result,
            redaction_count=len(deduped),
            entity_counts=entity_counts,
            redacted_entities=redacted_entities,
            spans=[(entity, start, end) for start, end, entity, _ in deduped],
        )

    def placeholder_for(self, description: str) -> str:
        """The placeholder for a d023 match, from its ``[entity_type] ...`` description."""
        replacement = self._replacements.get(EntityType.EMAIL, "[PII_REDACTED]")  # fallback
        if description.startswith("["):
            closing = description.find("]")
            if closing > 0:
                entity_str = description[1:closing]
                try:
                    entity_type = EntityType(entity_str)
                    replacement = self._replacements.get(
                        entity_type, f"[{entity_str.upper()}_REDACTED]"
                    )
                except ValueError:
                    replacement = f"[{entity_str.upper()}_REDACTED]"
        return replacement

    def redact_with_detections(self, text: str, matches: list[dict[str, Any]]) -> str:
        """Redact text using pre-existing detection matches from d023.

        Each match dict should have 'description' with '[entity_type] ...' prefix
        and 'position' as (start, end) tuple.
        """
        replacements: list[tuple[int, int, str]] = []

        for match in matches:
            position = match.get("position")
            if not position:
                continue
            start, end = position
            replacements.append((start, end, self.placeholder_for(match.get("description", ""))))

        if not replacements:
            return text

        # Sort by position descending for safe replacement
        replacements.sort(key=lambda x: x[0], reverse=True)

        # Deduplicate overlapping
        deduped: list[tuple[int, int, str]] = []
        for r in replacements:
            if deduped and r[1] > deduped[-1][0]:
                continue
            deduped.append(r)

        result = text
        for start, end, replacement in deduped:
            result = result[:start] + replacement + result[end:]

        return result
