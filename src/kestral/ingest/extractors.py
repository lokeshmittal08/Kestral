"""Turn raw content into labelled segments, and rebuild a safe copy.

Each ``extract_*`` function returns an :class:`ExtractedDocument`. Text a
reader would not see (comments, hidden elements, attributes, metadata) is
returned as a segment with ``hidden=True`` so the caller can treat an
instruction found there as suspicious regardless of its wording.

``render`` rebuilds the form that is safe to pass to a model: hidden text is
left out, and segments the caller marks as removed are replaced by a marker.
Standard library only.
"""

from __future__ import annotations

import copy
import email
import email.policy
import io
import json
import re
import tokenize
from email.header import decode_header, make_header
from html.parser import HTMLParser
from typing import Any

from kestral.ingest.models import ExtractedDocument, Segment, SourceType

GAP_MARKER = "[… withheld by Kestral …]"
VALUE_MARKER = "[withheld by Kestral]"
MIN_CHARS = 12  # fragments shorter than this carry no instruction worth scanning
MAX_BLOCK_CHARS = 600

_HIDDEN_STYLE = [
    (re.compile(r"display\s*:\s*none", re.I), "css_display_none"),
    (re.compile(r"visibility\s*:\s*(?:hidden|collapse)", re.I), "css_visibility_hidden"),
    (
        re.compile(r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|$|!)", re.I),
        "css_zero_size",
    ),
    (re.compile(r"(?:^|;)\s*opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|!)", re.I), "css_opacity_zero"),
    (re.compile(r"(?:left|top|text-indent|margin-left)\s*:\s*-\d{3,}", re.I), "css_off_screen"),
    (re.compile(r"(?:^|;)\s*(?:height|width)\s*:\s*0(?:px)?\s*(?:;|$)", re.I), "css_zero_size"),
    (
        re.compile(r"(?:^|;)\s*color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b", re.I),
        "css_same_colour",
    ),
]
_STYLE_BLOCK = re.compile(r"<style[^>]*>(.*?)</style>", re.I | re.S)
_CSS_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_TEXT_ATTRS = ("alt", "title", "aria-label", "placeholder", "value", "content", "summary")
_VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
    "source", "track", "wbr",
}  # fmt: skip
_BLOCK = {
    "p", "div", "li", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "td", "th",
    "table", "section", "article", "header", "footer", "nav", "main", "aside", "blockquote",
    "pre", "br", "hr", "title", "form", "body", "html", "dd", "dt", "figcaption", "option",
    "label", "button", "head",
}  # fmt: skip
_NOT_RENDERED = {"template", "noscript"}
_SKIP = {"script", "style"}
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁩﻿\U000e0000-\U000e007f]")
_HTML_TAG = re.compile(
    r"<(?:!--|/?(?:html|body|div|span|p|a|img|script|style|br|h[1-6]|ul|ol|li|table|tr|td"
    r"|meta|input|form|section|article|template|noscript)\b)",
    re.I,
)


def _style_reason(style: str) -> str | None:
    for rx, reason in _HIDDEN_STYLE:
        if rx.search(style):
            return reason
    return None


def _hidden_selectors(html: str) -> dict[str, str]:
    """Class and id names that a <style> block hides, mapped to the reason."""
    hidden: dict[str, str] = {}
    for css in _STYLE_BLOCK.findall(html):
        for selectors, body in _CSS_RULE.findall(css):
            reason = _style_reason(body)
            if not reason:
                continue
            for name in re.findall(r"[.#][\w-]+", selectors):
                hidden[name] = reason
    return hidden


class _HtmlWalker(HTMLParser):
    def __init__(self, hidden_selectors: dict[str, str]) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_selectors = hidden_selectors
        self.stack: list[tuple[str, str | None]] = []  # (tag, hidden reason)
        self.skip: str | None = None
        self.buf: list[str] = []
        self.buf_reason: str | None = None
        self.links: list[str] = []
        # (text, hidden reason or None, channel)
        self.out: list[tuple[str, str | None, str]] = []

    def _reason(self) -> str | None:
        for _, reason in reversed(self.stack):
            if reason:
                return reason
        return None

    def _flush(self) -> None:
        text = " ".join(" ".join(self.buf).split())
        if text:
            channel = "html.hidden_element" if self.buf_reason else "visible_text"
            self.out.append((text, self.buf_reason, channel))
        self.buf = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        reason = _style_reason(a.get("style", ""))
        if reason is None and ("hidden" in a or a.get("aria-hidden") == "true"):
            reason = "attr_hidden"
        if reason is None and tag == "input" and a.get("type", "").lower() == "hidden":
            reason = "attr_hidden"
        if reason is None and tag in _NOT_RENDERED:
            reason = "non_rendered_element"
        if reason is None:
            names = ["." + c for c in a.get("class", "").split()]
            if a.get("id"):
                names.append("#" + a["id"])
            for name in names:
                if name in self.hidden_selectors:
                    reason = self.hidden_selectors[name]
                    break
        if tag in _BLOCK or reason != self._reason():
            self._flush()
        for key, value in a.items():
            if (key in _TEXT_ATTRS or key.startswith("data-")) and len(value.strip()) >= MIN_CHARS:
                if tag == "meta":
                    channel = "html.meta." + (a.get("name") or a.get("property") or "content")
                else:
                    channel = "html.attr." + key
                self.out.append((value.strip(), "metadata", channel))
        if tag in _SKIP:
            self.skip = tag
        if tag == "a" and a.get("href", "").startswith(("http://", "https://")):
            self.links.append(a["href"])
        elif tag == "a":
            self.links.append("")
        if tag not in _VOID:
            self.stack.append((tag, reason))
            self.buf_reason = self._reason()

    def handle_endtag(self, tag: str) -> None:
        if self.skip == tag:
            self.skip = None
        if tag == "a" and self.links:
            href = self.links.pop()
            if href and self.buf and not self._reason():
                self.buf.append(f"({href})")
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                before = self._reason()
                del self.stack[i:]
                if tag in _BLOCK or before != self._reason():
                    self._flush()
                break
        self.buf_reason = self._reason()

    def handle_data(self, data: str) -> None:
        if self.skip or not data.strip():
            return
        reason = self._reason()
        if reason != self.buf_reason:
            self._flush()
            self.buf_reason = reason
        self.buf.append(data)

    def handle_comment(self, data: str) -> None:
        if len(data.strip()) >= MIN_CHARS:
            self.out.append((" ".join(data.split()), "comment", "html.comment"))


def _html_units(html: str) -> list[tuple[str, str | None, str]]:
    walker = _HtmlWalker(_hidden_selectors(html))
    walker.feed(html)
    walker.close()
    walker._flush()
    return walker.out


def _split_long(text: str) -> list[str]:
    """Split a long paragraph at sentence ends so one bad sentence costs less."""
    if len(text) <= MAX_BLOCK_CHARS:
        return [text]
    parts: list[str] = []
    current = ""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if current and len(current) + len(sentence) > MAX_BLOCK_CHARS:
            parts.append(current)
            current = sentence
        else:
            current = f"{current} {sentence}".strip()
    if current:
        parts.append(current)
    return parts


class _Builder:
    """Collects segments and the ordered blocks that make up the output."""

    def __init__(self, source_type: SourceType) -> None:
        self.source_type: SourceType = source_type
        self.segments: list[Segment] = []
        self.blocks: list[str] = []
        self.anomalies: list[str] = []

    def add_block(self, text: str, channel: str = "visible_text", location: str = "") -> None:
        for piece in _split_long(text):
            index = len(self.blocks)
            self.blocks.append(piece)
            invisible = bool(_INVISIBLE.search(piece))
            if invisible and "unicode_invisible" not in self.anomalies:
                self.anomalies.append("unicode_invisible")
            if len(piece.strip()) >= MIN_CHARS:
                self._add(piece, channel, location or f"block {index + 1}", block=index)

    def add_hidden(self, text: str, channel: str, reason: str, location: str = "") -> None:
        self._add(text, channel, location, hidden=True, reason=reason)

    def _add(
        self,
        text: str,
        channel: str,
        location: str,
        *,
        block: int | None = None,
        hidden: bool = False,
        reason: str | None = None,
    ) -> None:
        self.segments.append(
            Segment(
                id=f"s{len(self.segments)}",
                text=text,
                source_type=self.source_type,
                channel=channel,
                location=location,
                hidden=hidden,
                hidden_reason=reason,
                block=block,
            )
        )

    def add_html(self, html: str, *, render: bool = True, prefix: str = "") -> None:
        for text, reason, channel in _html_units(html):
            if reason is None and render:
                self.add_block(text)
            elif reason is None:
                self.add_hidden(text, prefix + "html_body", "text_html_mismatch")
            elif len(text) >= MIN_CHARS:
                self.add_hidden(text, prefix + channel, reason)

    def build(self, declared: str | None = None) -> ExtractedDocument:
        return ExtractedDocument(
            source_type=self.source_type,
            declared_type=declared,
            segments=self.segments,
            anomalies=self.anomalies,
            payload={"blocks": self.blocks},
        )


def extract_html(content: str) -> ExtractedDocument:
    builder = _Builder("html")
    builder.add_html(content)
    return builder.build()


_MD_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_MD_LINK_TITLE = re.compile(r"(\]\(\s*<?[^)\s>]+>?)\s+(?:\"([^\"]*)\"|'([^']*)')\s*\)")
_MD_REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*\S+(?:\s+[\"'(](.*)[\"')])?\s*$")
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]*)[^)]*\)")
_TAG = re.compile(r"<[^>]+>")


def extract_markdown(content: str, source_type: SourceType = "markdown") -> ExtractedDocument:
    """Markdown and plain text: one block per paragraph."""
    builder = _Builder(source_type)
    for raw in re.split(r"\n\s*\n", content):
        if not raw.strip():
            continue
        for comment in _MD_COMMENT.findall(raw):
            if len(comment.strip()) >= MIN_CHARS:
                builder.add_hidden(" ".join(comment.split()), "markdown.comment", "comment")
        block = _MD_COMMENT.sub("", raw)
        if _HTML_TAG.search(block):
            shown: list[str] = []
            for text, reason, channel in _html_units(block):
                if reason is None:
                    shown.append(text)
                elif len(text) >= MIN_CHARS:
                    builder.add_hidden(text, "markdown.inline_html." + channel, reason)
            # Keep only what the inline HTML would display.
            block = "\n".join(shown)
        for match in _MD_LINK_TITLE.finditer(block):
            title = match.group(2) or match.group(3) or ""
            if len(title) >= MIN_CHARS:
                builder.add_hidden(title, "markdown.link_title", "metadata")
        block = _MD_LINK_TITLE.sub(r"\1)", block)
        kept_lines = []
        for line in block.splitlines():
            ref = _MD_REF_DEF.match(line)
            if ref:
                if ref.group(1) and len(ref.group(1)) >= MIN_CHARS:
                    builder.add_hidden(ref.group(1), "markdown.reference_def", "metadata")
                line = re.sub(r"(\s+[\"'(].*[\"')])\s*$", "", line)
            kept_lines.append(line)
        block = "\n".join(kept_lines).strip()
        if block:
            builder.add_block(block)
    return builder.build()


def extract_plain(content: str) -> ExtractedDocument:
    return extract_markdown(content, source_type="plain_text")


_OCR_GLYPHS = str.maketrans({"0": "o", "5": "s", "$": "s", "@": "a", "3": "e"})
_OCR_AMBIGUOUS = "1|!"  # each may be an "l" or an "i"
# Words an injected instruction is built from. Used only to choose between
# "l" and "i" when repairing an ambiguous glyph.
_OCR_LEXICON = frozenset(
    [
        "ignore",
        "all",
        "previous",
        "prior",
        "instructions",
        "instruction",
        "disregard",
        "forget",
        "override",
        "system",
        "prompt",
        "reveal",
        "print",
        "admin",
        "administrator",
        "password",
        "passwords",
        "credentials",
        "email",
        "mail",
        "file",
        "files",
        "delete",
        "assistant",
        "ai",
        "model",
        "reply",
        "with",
        "only",
        "confidential",
        "rules",
        "guidelines",
        "instead",
        "please",
        "will",
        "immediately",
        "silently",
        "click",
        "link",
        "login",
        "details",
        "list",
        "their",
        "this",
        "still",
        "until",
        "initial",
        "original",
        "hidden",
        "privileged",
        "policies",
        "policy",
        "comply",
        "compliance",
        "tell",
        "disclose",
        "limits",
        "limitations",
        "unrestricted",
        "jailbreak",
        "developer",
        "priority",
        "field",
        "including",
        "include",
        "display",
        "online",
        "similar",
        "while",
        "main",
        "bill",
        "billing",
        "verify",
        "verification",
        "critical",
    ]
)


def _repair_word(word: str) -> str:
    core = word.translate(_OCR_GLYPHS)
    slots = [i for i, c in enumerate(core) if c in _OCR_AMBIGUOUS]
    if not slots or len(slots) > 4:
        return core.replace("1", "l").replace("|", "l") if slots else core
    best = None
    for mask in range(2 ** len(slots)):
        chars = list(core)
        for bit, index in enumerate(slots):
            chars[index] = "i" if mask >> bit & 1 else "l"
        candidate = "".join(chars)
        if candidate.lower().strip(".,;:!?\"'()") in _OCR_LEXICON:
            return candidate
        if best is None:
            best = candidate
    return best or core


def repair_ocr(text: str) -> str:
    """Undo common OCR damage: broken words, letter spacing, look-alike glyphs."""
    fixed = re.sub(r"(\w)-\n\s*(\w)", r"\1\2", text)
    fixed = re.sub(
        r"(?<![A-Za-z])((?:[A-Za-z'.] ){4,}[A-Za-z.])(?![A-Za-z])",
        lambda m: m.group(1).replace(" ", ""),
        fixed,
    )
    words = []
    for word in re.split(r"( +)", fixed):
        letters = sum(c.isalpha() for c in word)
        glyphs = sum(c in "0153$@|!" for c in word)
        other_digits = sum(c.isdigit() and c not in "0153" for c in word)
        # Repair only tokens that read as a damaged word: at least one
        # letter, and nothing but letters, look-alike glyphs and punctuation.
        # Real numbers ("2026", "$41.50", "v2") are left alone.
        if letters >= 1 and glyphs >= 1 and other_digits == 0 and letters + glyphs >= 3:
            trailing = word[len(word.rstrip("!.,;:?")) :]
            word = _repair_word(word[: len(word) - len(trailing)]) + trailing
        words.append(word)
    fixed = "".join(words)
    fixed = re.sub(r"(?<=[a-z])rn(?=[a-z])", "m", fixed)
    return re.sub(r"[ \t]{2,}", " ", fixed)


def extract_ocr(content: str) -> ExtractedDocument:
    doc = extract_markdown(content, source_type="ocr_text")
    for segment in doc.segments:
        repaired = repair_ocr(segment.text)
        if repaired != segment.text:
            segment.alt_text = repaired
    return doc


def _header(value: Any) -> str:
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def _norm(text: str) -> str:
    return re.sub(r"\W+", " ", text).strip().lower()


def extract_email(content: str) -> ExtractedDocument:
    message = email.message_from_string(content, policy=email.policy.default)
    builder = _Builder("email")
    for name in ("From", "Reply-To", "To", "Subject"):
        value = message.get(name)
        if value:
            builder.add_block(f"{name}: {_header(value)}", f"email.header.{name.lower()}", name)
    texts: list[str] = []
    htmls: list[str] = []
    attachments: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            continue
        try:
            body = part.get_content()
        except Exception:
            builder.anomalies.append("unparseable_part")
            continue
        if not isinstance(body, str):
            continue
        (htmls if part.get_content_type() == "text/html" else texts).append(body)
    builder.add_block("")  # blank line between headers and body
    if texts:
        text_body = "\n\n".join(texts)
        for paragraph in re.split(r"\n\s*\n", text_body):
            if not paragraph.strip():
                continue
            quoted = all(line.lstrip().startswith(">") for line in paragraph.splitlines())
            builder.add_block(paragraph.strip(), "email.quoted" if quoted else "email.body_text")
        # The HTML alternative is not forwarded, but anything in it that the
        # text part does not say is content a reader would never see.
        text_norm = _norm(text_body)
        for html in htmls:
            for text, reason, channel in _html_units(html):
                if reason is not None:
                    if len(text) >= MIN_CHARS:
                        builder.add_hidden(text, "email." + channel, reason)
                elif len(text) >= MIN_CHARS and _norm(text) not in text_norm:
                    builder.add_hidden(text, "email.body_html", "text_html_mismatch")
                    if "text_html_mismatch" not in builder.anomalies:
                        builder.anomalies.append("text_html_mismatch")
    else:
        for html in htmls:
            builder.add_html(html, prefix="email.")
    for name in attachments:
        builder.add_block(f"[attachment not inspected: {name}]", "email.attachment_name")
        if "attachment_not_inspected" not in builder.anomalies:
            builder.anomalies.append("attachment_not_inspected")
    return builder.build()


def extract_json(content: str) -> ExtractedDocument:
    data = json.loads(content)
    segments: list[Segment] = []
    anomalies: list[str] = []

    def add(
        text: str, channel: str, path: str, *, hidden: bool = False, why: str | None = None
    ) -> None:
        segments.append(
            Segment(
                id=f"s{len(segments)}",
                text=text,
                source_type="json",
                channel=channel,
                location=path,
                hidden=hidden,
                hidden_reason=why,
            )
        )

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if len(str(key)) >= 24:
                    add(str(key), "json.key", f"{path}.{key}")
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        elif isinstance(node, str) and len(node.strip()) >= MIN_CHARS:
            if _HTML_TAG.search(node):
                # A string that is itself HTML: read it as a page, so text
                # hidden inside it is found and left out.
                for text, reason, channel in _html_units(node):
                    if len(text) < MIN_CHARS:
                        continue
                    if reason is None:
                        add(text, "json.string.html", path)
                    else:
                        add(text, "json.string." + channel, path, hidden=True, why=reason)
            else:
                add(node, "json.string", path)

    walk(data, "$")
    return ExtractedDocument(
        source_type="json", segments=segments, anomalies=anomalies, payload={"data": data}
    )


_C_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/|(?m:^\s*#[^\n]*)", re.S)
_C_STRING = re.compile(
    r"\"((?:[^\"\\\n]|\\.){%d,})\"|'((?:[^'\\\n]|\\.){%d,})'|`((?:[^`\\]|\\.){%d,})`"
    % (MIN_CHARS, MIN_CHARS, MIN_CHARS)
)


def extract_code(content: str) -> ExtractedDocument:
    """Source code: only comments, docstrings and string literals can carry
    an instruction to a model, so only those are scanned."""
    builder = _Builder("source_code")
    if _INVISIBLE.search(content):
        builder.anomalies.append("unicode_invisible")
    clean = _INVISIBLE.sub("", content)
    comments: list[str] = []
    strings: list[str] = []
    try:
        compile(clean, "<code>", "exec")
        for tok in tokenize.generate_tokens(io.StringIO(clean).readline):
            if tok.type == tokenize.COMMENT:
                comments.append(tok.string.lstrip("# "))
            elif tok.type == tokenize.STRING and len(tok.string) >= MIN_CHARS:
                strings.append(tok.string.strip("\"'rbfuRBFU \n"))
    except (SyntaxError, tokenize.TokenError, ValueError):
        comments = [
            re.sub(r"^\s*(?://|/\*|#!?)\s*|\s*\*/$", "", m.group())
            for m in _C_COMMENT.finditer(clean)
        ]
        strings = [next(g for g in m.groups() if g) for m in _C_STRING.finditer(clean)]
    # Adjacent comment lines read as one message, so scan them together.
    joined = "\n".join(c for c in comments if c.strip())
    if len(joined.strip()) >= MIN_CHARS:
        builder._add(joined, "code.comment", "comments")
    for index, literal in enumerate(strings):
        if len(literal.strip()) >= MIN_CHARS:
            builder._add(literal, "code.string", f"string {index + 1}")
    doc = builder.build()
    doc.payload = {"code": content}
    return doc


_EMAIL_HEAD = re.compile(r"^(?:From|To|Subject|Received|Return-Path|MIME-Version|Date): ", re.M)


def sniff(content: str) -> SourceType:
    """Guess the format from the content itself."""
    head = content.lstrip()[:2000]
    if head.startswith(("{", "[")):
        try:
            json.loads(content)
            return "json"
        except ValueError:
            pass
    lines = head.split("\n\n", 1)[0]
    if len(_EMAIL_HEAD.findall(lines)) >= 2:
        return "email"
    if head.startswith("<?xml") or re.match(r"<[A-Za-z][\w:.-]*(?:\s[^>]*)?>", head):
        return "html"  # XML reads the same way: element text, attributes, comments
    if re.search(r"<!doctype html|<html\b|<body\b|<head\b", head, re.I) or (
        len(re.findall(r"</?(?:div|p|span|table|section|article|ul|li|h[1-6])\b", content, re.I))
        >= 3
    ):
        return "html"
    return "plain_text"


_EXTRACTORS = {
    "plain_text": extract_plain,
    "markdown": extract_markdown,
    "html": extract_html,
    "email": extract_email,
    "json": extract_json,
    "source_code": extract_code,
    "ocr_text": extract_ocr,
}
# Formats whose structure can be recognised from the content. When one of
# these is recognised it wins over what the caller declared, so content
# cannot be mislabelled to get a weaker reading.
_STRUCTURAL = {"json", "email", "html"}


def extract(content: str, declared_type: str | None = None) -> ExtractedDocument:
    """Split ``content`` into segments. ``declared_type`` is a hint only."""
    sniffed = sniff(content)
    anomalies: list[str] = []
    if declared_type in _EXTRACTORS and not (
        sniffed in _STRUCTURAL and declared_type != sniffed and declared_type != "source_code"
    ):
        chosen: str = declared_type
    else:
        chosen = sniffed
        if declared_type and declared_type != sniffed:
            anomalies.append("declared_type_mismatch")
    try:
        doc = _EXTRACTORS[chosen](content)
    except Exception:
        # The declared format did not parse. Read it as what it looks like.
        anomalies.append("declared_type_mismatch")
        try:
            doc = _EXTRACTORS[sniffed if sniffed != chosen else "plain_text"](content)
        except Exception:
            doc = extract_plain(content)
            anomalies.append("unparseable")
    doc.declared_type = declared_type
    doc.anomalies = anomalies + [a for a in doc.anomalies if a not in anomalies]
    return doc


def render(doc: ExtractedDocument, removed: set[str]) -> str:
    """Rebuild the document without hidden text and without ``removed`` segments."""
    payload = doc.payload or {}
    if doc.source_type == "json":
        by_path: dict[str, list[Segment]] = {}
        for segment in doc.segments:
            by_path.setdefault(segment.location, []).append(segment)

        def rebuild(node: Any, path: str) -> Any:
            if isinstance(node, dict):
                out: dict[str, Any] = {}
                for index, (key, value) in enumerate(node.items()):
                    key_segs = [
                        s for s in by_path.get(f"{path}.{key}", []) if s.channel == "json.key"
                    ]
                    new_key = (
                        f"withheld_key_{index}" if any(s.id in removed for s in key_segs) else key
                    )
                    out[new_key] = rebuild(value, f"{path}.{key}")
                return out
            if isinstance(node, list):
                return [rebuild(value, f"{path}[{i}]") for i, value in enumerate(node)]
            if isinstance(node, str):
                segs = [s for s in by_path.get(path, []) if s.channel != "json.key"]
                if any(s.id in removed and not s.hidden for s in segs):
                    return VALUE_MARKER
                if any(s.channel.startswith("json.string.") for s in segs):
                    # HTML inside a string: forward only its visible text.
                    return " ".join(s.text for s in segs if not s.hidden)
            return node

        return json.dumps(
            rebuild(copy.deepcopy(payload["data"]), "$"), ensure_ascii=False, indent=2
        )
    if doc.source_type == "source_code":
        return str(payload.get("code", ""))
    blocks: list[str] = list(payload.get("blocks", []))
    gone = {s.block for s in doc.segments if s.id in removed and s.block is not None}
    out: list[str] = []
    for index, text in enumerate(blocks):
        if index in gone:
            if not out or out[-1] != GAP_MARKER:
                out.append(GAP_MARKER)
        else:
            clean = _INVISIBLE.sub("", text)
            # A page title repeated as its first heading is one line, not two.
            if not (out and clean and out[-1] == clean):
                out.append(clean)
    separator = "\n" if doc.source_type == "email" else "\n\n"
    return separator.join(out).strip()
