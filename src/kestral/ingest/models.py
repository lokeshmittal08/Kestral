"""Document and segment model shared by every content extractor."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SourceType = Literal[
    "plain_text",
    "markdown",
    "html",
    "email",
    "json",
    "source_code",
    "ocr_text",
    "pdf",
    "docx",
    "image",
]


class Segment(BaseModel):
    """One piece of text taken from a document, with where it came from."""

    id: str
    text: str
    source_type: SourceType
    channel: str
    location: str = ""
    hidden: bool = False
    hidden_reason: str | None = None
    # A second reading of the same text to scan as well (e.g. OCR-repaired).
    alt_text: str | None = None
    # Position of this segment in the rendered output; None = never rendered.
    block: int | None = None


class ExtractedDocument(BaseModel):
    """A document split into labelled segments."""

    source_type: SourceType
    declared_type: str | None = None
    segments: list[Segment] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    # Extractor-private data needed to rebuild the document (parsed JSON,
    # ordered blocks, original code). Never serialised to callers.
    payload: Any = Field(default=None, exclude=True)
