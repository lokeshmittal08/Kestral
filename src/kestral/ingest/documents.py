"""Extractors for binary documents: Word (.docx), PDF and images.

Word files are read with the standard library. PDF needs ``pypdf`` and
images need ``Pillow`` plus an OCR engine (``rapidocr-onnxruntime``); both
are optional, installed with ``pip install "kestral[documents]"``. When a
library is missing the document is reported as unreadable, never passed on
unread.

Every extractor enforces hard limits before and during parsing, because a
document sent to a firewall is attacker-controlled input.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree

from kestral.ingest.extractors import MIN_CHARS, _Builder, repair_ocr
from kestral.ingest.models import DocumentError

if TYPE_CHECKING:
    from kestral.ingest.models import ExtractedDocument

MAX_BYTES = 20 * 1024 * 1024
MAX_UNZIPPED_BYTES = 60 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
MAX_PAGES = 200
MAX_PIXELS = 40_000_000

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
)


def sniff_bytes(data: bytes) -> str | None:
    """Return 'pdf', 'docx' or 'image' from the file's leading bytes."""
    head = data[:16]
    if data[:1024].lstrip().startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if "word/document.xml" in archive.namelist():
                    return "docx"
        except zipfile.BadZipFile:
            return None
        return None
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image"
    for magic, _ in _IMAGE_MAGIC:
        if head.startswith(magic):
            return "image"
    return None


# --------------------------------------------------------------------- Word


def _read_xml(archive: zipfile.ZipFile, name: str) -> ElementTree.Element | None:
    try:
        raw = archive.read(name)
    except KeyError:
        return None
    # Office files never declare a DTD. One that does is trying to abuse
    # the XML parser (entity expansion), so refuse it.
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise DocumentError("unsafe_xml")
    try:
        return ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise DocumentError("unparseable") from exc


def _run_hidden_reason(run: ElementTree.Element) -> str | None:
    props = run.find(_W + "rPr")
    if props is None:
        return None
    vanish = props.find(_W + "vanish")
    if vanish is not None and vanish.get(_W + "val", "true") not in ("0", "false"):
        return "hidden_run"
    colour = props.find(_W + "color")
    if colour is not None and colour.get(_W + "val", "").upper() in ("FFFFFF", "FEFEFE"):
        return "css_same_colour"
    size = props.find(_W + "sz")
    if size is not None:
        try:
            if int(size.get(_W + "val", "20")) <= 4:  # half-points: 2pt or less
                return "tiny_text"
        except ValueError:
            pass
    return None


def _paragraphs(root: ElementTree.Element) -> list[tuple[str, list[tuple[str, str]]]]:
    """Return (visible text, [(hidden text, reason)]) for each paragraph."""
    out: list[tuple[str, list[tuple[str, str]]]] = []
    deleted_runs = {id(r) for d in root.iter(_W + "del") for r in d.iter(_W + "r")}
    for para in root.iter(_W + "p"):
        visible: list[str] = []
        hidden: dict[str, list[str]] = {}
        for run in para.iter(_W + "r"):
            if id(run) in deleted_runs:
                text = "".join(t.text or "" for t in run.iter(_W + "delText"))
                if text:
                    hidden.setdefault("tracked_deletion", []).append(text)
                continue
            text = "".join(
                (t.text or "") if t.tag == _W + "t" else " "
                for t in run
                if t.tag in (_W + "t", _W + "tab", _W + "br")
            )
            if not text:
                continue
            reason = _run_hidden_reason(run)
            if reason:
                hidden.setdefault(reason, []).append(text)
            else:
                visible.append(text)
        for field in para.iter(_W + "instrText"):
            if field.text and len(field.text.strip()) >= MIN_CHARS:
                hidden.setdefault("field_code", []).append(field.text)
        out.append(("".join(visible).strip(), [("".join(v).strip(), k) for k, v in hidden.items()]))
    return out


def extract_docx(data: bytes) -> ExtractedDocument:
    builder = _Builder("docx")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise DocumentError("unparseable") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_UNZIPPED_BYTES:
            raise DocumentError("limit_exceeded")
        names = set(archive.namelist())
        body = _read_xml(archive, "word/document.xml")
        if body is None:
            raise DocumentError("unparseable")

        core = _read_xml(archive, "docProps/core.xml")
        if core is not None:
            for element in core.iter():
                value = (element.text or "").strip()
                if len(value) >= MIN_CHARS:
                    name = element.tag.rsplit("}", 1)[-1]
                    builder.add_hidden(value, f"docx.property.{name}", "metadata", name)

        def add_part(root: ElementTree.Element, channel: str, rendered: bool) -> None:
            for visible, hidden in _paragraphs(root):
                if visible:
                    if rendered:
                        builder.add_block(visible, channel)
                    elif len(visible) >= MIN_CHARS:
                        builder.add_hidden(visible, channel, "comment")
                for text, reason in hidden:
                    if len(text) >= MIN_CHARS:
                        builder.add_hidden(text, "docx." + reason, reason)

        for name in sorted(n for n in names if re.fullmatch(r"word/header\d*\.xml", n)):
            part = _read_xml(archive, name)
            if part is not None:
                add_part(part, "docx.header_footer", True)
        add_part(body, "visible_text", True)
        for name, channel, rendered in (
            ("word/footnotes.xml", "docx.footnote", True),
            ("word/endnotes.xml", "docx.footnote", True),
            ("word/comments.xml", "docx.comment", False),
        ):
            part = _read_xml(archive, name)
            if part is not None:
                add_part(part, channel, rendered)
        for name in sorted(n for n in names if re.fullmatch(r"word/footer\d*\.xml", n)):
            part = _read_xml(archive, name)
            if part is not None:
                add_part(part, "docx.header_footer", True)
        if any(n.startswith("word/embeddings/") for n in names):
            builder.anomalies.append("embedded_object_not_inspected")
        if "word/vbaProject.bin" in names:
            builder.anomalies.append("macros_present")
    return builder.build()


# ---------------------------------------------------------------------- PDF


def _pdf_text(value: Any) -> str:
    try:
        return str(value).strip()
    except Exception:
        return ""


def extract_pdf(data: bytes) -> ExtractedDocument:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise DocumentError("pdf_support_not_installed") from exc

    builder = _Builder("pdf")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted and not reader.decrypt(""):
            raise DocumentError("encrypted")
        page_count = len(reader.pages)
    except DocumentError:
        raise
    except Exception as exc:
        raise DocumentError("unparseable") from exc
    if page_count > MAX_PAGES:
        raise DocumentError("limit_exceeded")

    try:
        meta: Any = reader.metadata or {}
        for key in ("/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer"):
            value = _pdf_text(meta.get(key, ""))
            if len(value) >= MIN_CHARS:
                builder.add_hidden(value, f"pdf.metadata.{key[1:].lower()}", "metadata", key[1:])
    except Exception:
        builder.anomalies.append("metadata_unreadable")

    for number, page in enumerate(reader.pages, start=1):
        tiny: list[str] = []

        def visit(
            text: str, cm: Any, tm: Any, font: Any, size: float, _tiny: list[str] = tiny
        ) -> None:
            if not text or not text.strip():
                return
            try:
                scale = abs(float(tm[3]) or float(tm[0]) or 1.0) * abs(float(cm[3]) or 1.0)
                effective = abs(float(size)) * scale
            except Exception:
                return
            if 0 < effective < 2.0:  # text under two points cannot be read by a person
                _tiny.append(text.strip())

        try:
            text = page.extract_text(visitor_text=visit) or ""
        except Exception:
            builder.anomalies.append("page_unreadable")
            continue
        hidden_text = " ".join(tiny)
        for paragraph in re.split(r"\n\s*\n|(?<=[.!?])\n(?=[A-Z])", text):
            paragraph = " ".join(paragraph.split())
            for piece in tiny:
                paragraph = paragraph.replace(" ".join(piece.split()), " ")
            paragraph = " ".join(paragraph.split())
            if paragraph:
                builder.add_block(paragraph, "pdf.text", f"page {number}")
        if len(hidden_text) >= MIN_CHARS:
            builder.add_hidden(hidden_text, "pdf.hidden_text", "tiny_text", f"page {number}")
        try:
            for ref in page.get("/Annots") or []:
                annotation = ref.get_object()
                for key in ("/Contents", "/T", "/TU", "/V"):
                    value = _pdf_text(annotation.get(key, ""))
                    if len(value) >= MIN_CHARS:
                        builder.add_hidden(value, "pdf.annotation", "comment", f"page {number}")
        except Exception:
            builder.anomalies.append("annotations_unreadable")
    try:
        if reader.attachments:
            builder.anomalies.append("embedded_file_not_inspected")
    except Exception:
        pass
    if not builder.blocks and not builder.segments:
        # No text layer: a scanned document. Its pages are images.
        builder.anomalies.append("no_text_layer")
    return builder.build()


# ------------------------------------------------------------------- images

_ocr_engine: Any = None


def _ocr_lines(image: Any) -> list[tuple[str, float]]:
    global _ocr_engine
    try:
        import numpy as np
        from rapidocr_onnxruntime import RapidOCR
    except ImportError as exc:
        raise DocumentError("ocr_support_not_installed") from exc
    if _ocr_engine is None:
        _ocr_engine = RapidOCR()
    result, _ = _ocr_engine(np.asarray(image.convert("RGB")))
    return [
        (str(item[1]).strip(), float(item[2])) for item in (result or []) if str(item[1]).strip()
    ]


_OCR_SAME = str.maketrans({"i": "l", "1": "l", "|": "l", "!": "l", "0": "o", "5": "s"})


def _key(text: str) -> str:
    """Comparison key that ignores spacing and look-alike glyphs, so the same
    line read twice by OCR compares equal."""
    return re.sub(r"[\W_]+", "", text.lower().translate(_OCR_SAME))


def extract_image(data: bytes) -> ExtractedDocument:
    try:
        from PIL import Image, ImageOps
    except ImportError as exc:
        raise DocumentError("image_support_not_installed") from exc

    builder = _Builder("image")
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
    except Exception as exc:
        raise DocumentError("unparseable") from exc
    if image.width * image.height > MAX_PIXELS:
        raise DocumentError("limit_exceeded")

    # Text stored in the file but never drawn: PNG text chunks, EXIF fields.
    for key, value in (image.info or {}).items():
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if (
            isinstance(value, str)
            and len(value.strip()) >= MIN_CHARS
            and key not in ("icc_profile",)
        ):
            builder.add_hidden(
                " ".join(value.split()), f"image.metadata.{key}", "metadata", str(key)
            )
    try:
        for tag, value in image.getexif().items():
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            if isinstance(value, str) and len(value.strip()) >= MIN_CHARS:
                builder.add_hidden(
                    " ".join(value.split()), f"image.metadata.exif_{tag}", "metadata"
                )
    except Exception:
        builder.anomalies.append("exif_unreadable")

    frames = getattr(image, "n_frames", 1)
    if frames > 1:
        builder.anomalies.append("multi_frame_first_frame_only")
        image.seek(0)
    base = image.convert("RGB")
    if base.width < 1200:  # small text reads better enlarged
        ratio = 1200 / base.width
        base = base.resize((1200, max(1, int(base.height * ratio))))

    normal = _ocr_lines(base)
    seen = {_key(text) for text, _ in normal}
    if any(confidence < 0.5 for _, confidence in normal):
        builder.anomalies.append("low_ocr_confidence")
    # Lines are grouped into short paragraphs, so an instruction that wraps
    # across lines is scanned, and removed, as one piece.
    chunk: list[str] = []
    for text, _ in [*normal, ("", 1.0)]:
        if text and sum(len(c) for c in chunk) + len(text) <= 320:
            chunk.append(text)
            continue
        if chunk:
            paragraph = " ".join(chunk)
            builder.add_block(paragraph, "ocr.text")
            if builder.segments and builder.segments[-1].block == len(builder.blocks) - 1:
                repaired = repair_ocr(paragraph)
                if repaired != paragraph:
                    builder.segments[-1].alt_text = repaired
        chunk = [text] if text else []
    # Text that only appears once contrast is stretched was drawn to be
    # unreadable to a person: near-white on white, near-black on black.
    enhanced = ImageOps.equalize(ImageOps.grayscale(base))
    for text, _ in _ocr_lines(enhanced):
        key = _key(text)
        already = any(key in other or other in key for other in seen if len(other) >= 8)
        if key and not already and len(text) >= MIN_CHARS:
            seen.add(_key(text))
            builder.add_hidden(text, "image.low_contrast_text", "low_contrast")
    return builder.build()


_BINARY = {"pdf": extract_pdf, "docx": extract_docx, "image": extract_image}


def extract_bytes(data: bytes, declared_type: str | None = None) -> ExtractedDocument:
    """Read a binary document. Raises :class:`DocumentError` if it cannot be
    read safely; the caller withholds the document in that case."""
    if len(data) > MAX_BYTES:
        raise DocumentError("limit_exceeded")
    kind = sniff_bytes(data)
    if kind is None:
        raise DocumentError("unsupported_format")
    doc = _BINARY[kind](data)
    doc.declared_type = declared_type
    if declared_type and declared_type != kind and "declared_type_mismatch" not in doc.anomalies:
        doc.anomalies.append("declared_type_mismatch")
    return doc
