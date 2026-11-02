"""Shared text sanitizer for tool results and agent gates.

Extracted from ``AgentGuard._sanitize_text`` so ``ToolResultGuard`` and
``AgentGuard`` share the same logic. PII detections route through the
entity-type-aware ``PIIRedactor`` (`d023_pii_detection`); other detections
get replaced with a generic placeholder string.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kestral.models import ScanReport


def sanitize_text(
    text: str,
    report: ScanReport,
    replacement: str = "[REDACTED by Kestral]",
) -> str:
    """Replace matched detection spans in ``text`` with a safe placeholder.

    PII spans use entity-type-aware redaction; other spans use ``replacement``.
    """
    if not report.detections:
        return text

    # Every position indexes ``text`` as given, so all cuts are collected
    # first and made in one pass; cutting one span before computing the next
    # would shift the later positions.
    spans: list[tuple[int, int, str, bool]] = []  # start, end, placeholder, is_pii
    redactor = None
    for det in report.detections:
        is_pii = det.detector_id == "d023_pii_detection"
        if is_pii and redactor is None:
            from kestral.pii.redactor import PIIRedactor

            redactor = PIIRedactor()
        for match in det.matches:
            if not match.position:
                continue
            start, end = match.position
            placeholder = (
                redactor.placeholder_for(match.description)
                if is_pii and redactor is not None
                else replacement
            )
            spans.append((start, end, placeholder, is_pii))

    # Overlapping spans become one cut. A detection that is not PII covers
    # more than a PII value inside it, so its placeholder wins.
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged: list[tuple[int, int, str, bool]] = []
    for start, end, placeholder, is_pii in spans:
        if merged and start < merged[-1][1]:
            m_start, m_end, m_placeholder, m_is_pii = merged[-1]
            if m_is_pii and not is_pii:
                m_placeholder, m_is_pii = placeholder, False
            merged[-1] = (m_start, max(m_end, end), m_placeholder, m_is_pii)
            continue
        merged.append((start, end, placeholder, is_pii))

    for start, end, placeholder, _ in reversed(merged):
        text = text[:start] + placeholder + text[end:]
    return text


__all__ = ["sanitize_text"]
