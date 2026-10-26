"""Content ingestion: split documents into labelled segments."""

from kestral.ingest.documents import DocumentError, extract_bytes, sniff_bytes
from kestral.ingest.extractors import GAP_MARKER, VALUE_MARKER, extract, render, repair_ocr, sniff
from kestral.ingest.models import ExtractedDocument, Segment, SourceType

__all__ = [
    "GAP_MARKER",
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
