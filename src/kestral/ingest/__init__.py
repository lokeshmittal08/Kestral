"""Content ingestion: split documents into labelled segments."""

from kestral.ingest.documents import extract_bytes, sniff_bytes
from kestral.ingest.extractors import (
    COLLAPSED,
    DOUBTFUL,
    GAP_MARKER,
    LOW_CONTRAST,
    VALUE_MARKER,
    extract,
    render,
    repair_ocr,
    sniff,
)
from kestral.ingest.models import DocumentError, ExtractedDocument, Segment, SourceType

__all__ = [
    "COLLAPSED",
    "DOUBTFUL",
    "GAP_MARKER",
    "LOW_CONTRAST",
    "VALUE_MARKER",
    "DocumentError",
    "ExtractedDocument",
    "Segment",
    "SourceType",
    "extract",
    "extract_bytes",
    "render",
    "repair_ocr",
    "sniff",
    "sniff_bytes",
]
