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

import contextvars
import copy
import email
import email.policy
import io
import json
import logging
import re
import tokenize
from dataclasses import dataclass
from email.header import decode_header, make_header
from html.parser import HTMLParser
from typing import Any

from kestral.ingest import css
from kestral.ingest.models import DocumentError, ExtractedDocument, Segment, SourceType

logger = logging.getLogger("kestral.ingest")

GAP_MARKER = "[… withheld by Kestral …]"
VALUE_MARKER = "[withheld by Kestral]"
MIN_CHARS = 12  # fragments shorter than this carry no instruction worth scanning
MAX_BLOCK_CHARS = 600
# JSON nested deeper than this is withheld ("nesting_too_deep"). Real API
# responses stay far below it; much deeper input exhausts Python's stack in
# the parser and in the code that walks and rebuilds the value.
MAX_JSON_DEPTH = 100

# Text a reader may or may not see. It is kept in the output, but the
# inspector judges it more strictly than plain visible text.
#   COLLAPSED     the closed part of a <details> element: seen after a click
#   LOW_CONTRAST  drawn in about the colour of its background, where one of
#                 the two colours may come from a stylesheet Kestral cannot
#                 see (the page links external CSS)
COLLAPSED = "collapsed_details"
LOW_CONTRAST = "css_low_contrast"
DOUBTFUL = frozenset({COLLAPSED, LOW_CONTRAST})
_TEXT_ATTRS = ("alt", "title", "aria-label", "placeholder", "value", "content", "summary")
_VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
    "source", "track", "wbr",
}  # fmt: skip
_BLOCK = {
    "p", "div", "li", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "td", "th",
    "table", "section", "article", "header", "footer", "nav", "main", "aside", "blockquote",
    "pre", "br", "hr", "title", "form", "body", "html", "dd", "dt", "figcaption", "option",
    "label", "button", "head", "details", "summary",
}  # fmt: skip
_NOT_RENDERED = {"template", "noscript"}
_SKIP = {"script", "style"}
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁩﻿\U000e0000-\U000e007f]")
_HTML_TAG = re.compile(
    r"<(?:!--|/?(?:html|body|div|span|p|a|img|script|style|br|h[1-6]|ul|ol|li|table|tr|td"
    r"|meta|input|form|section|article|template|noscript|details|summary|font)\b)",
    re.I,
)


@dataclass
class _View:
    """What is in effect inside an element on one screen (see css.PROFILES)."""

    # The hiding reason in effect inside it, inherited by everything within.
    layout: str | None
    # Text and background colour in effect, and the depth of the element that
    # declared each (-1: the browser default, or a value Kestral cannot be
    # sure of).
    colour: css.Colour
    colour_depth: int
    background: css.Colour
    background_depth: int
    # The background is painted through the text (gradient text): colour
    # says nothing about visibility.
    painted_text: bool
    variables: dict[str, str]
    # What a reader of this screen sees of text directly inside it.
    reason: str | None


_ROOT_VIEW = _View(None, css.BLACK, -1, css.WHITE, -1, False, {}, None)


@dataclass
class _Frame:
    """An open element and what is in effect inside it."""

    element: css.Element
    depth: int
    # Why the element itself is hidden by attributes, or COLLAPSED.
    own: str | None
    # COLLAPSED when inside the closed part of a <details>.
    doubt: str | None
    # One view per screen, in css.PROFILES order.
    views: tuple[_View, ...]
    # What a reader sees of text directly inside it: None = visible.
    effective: str | None
    summary_seen: bool = False


class _StyleCollector(HTMLParser):
    """First pass: the stylesheets a browser would apply, the screens each
    applies on, and whether the page links external stylesheets (whose rules
    Kestral cannot see)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sheets: list[tuple[str, frozenset[str]]] = []
        self.external = False
        self._media: frozenset[str] | None = None  # inside a <style> that applies
        self._inert = 0  # inside <template> or <noscript>, whose styles do not apply
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag in ("template", "noscript"):
            self._inert += 1
        elif tag == "style":
            media = css.media_profiles(a.get("media", ""))
            self._media = media if media and not self._inert else None
            self._buf = []
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower().split():
            self.external = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("template", "noscript"):
            self._inert = max(0, self._inert - 1)
        elif tag == "style":
            if self._media is not None:
                sheet = "".join(self._buf)
                self.sheets.append((sheet, self._media))
                if "@import" in sheet.lower():
                    self.external = True
            self._media = None

    def handle_data(self, data: str) -> None:
        if self._media is not None:
            self._buf.append(data)


class _HtmlWalker(HTMLParser):
    def __init__(self, rules: css.RuleIndex, external: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.rules = rules
        self.external = external
        # Keeping what is in effect per frame makes each lookup O(1), so
        # deeply nested markup costs linear time, not quadratic.
        self.stack: list[_Frame] = []
        self.root = css.Element(tag=css.ROOT)
        self.open_tags: dict[str, int] = {}
        self.skip: str | None = None
        self.buf: list[str] = []
        self.buf_reason: str | None = None
        self.links: list[str] = []
        # (text, hidden or doubtful reason or None, channel)
        self.out: list[tuple[str, str | None, str]] = []

    def _reason(self) -> str | None:
        return self.stack[-1].effective if self.stack else None

    def _flush(self) -> None:
        text = " ".join(" ".join(self.buf).split())
        if text:
            if self.buf_reason == COLLAPSED:
                channel = "html.collapsed"
            elif self.buf_reason == LOW_CONTRAST:
                channel = "html.low_contrast"
            elif self.buf_reason:
                channel = "html.hidden_element"
            else:
                channel = "visible_text"
            self.out.append((text, self.buf_reason, channel))
        self.buf = []

    def _view(
        self,
        tag: str,
        a: dict[str, str],
        rules: list[css.Rule],
        inline: css.Declarations,
        outer: _View,
        inherited: str | None,
        attribute_reason: str | None,
        depth: int,
    ) -> _View:
        """What is in effect inside an element on one screen."""
        values, variables, guessed = css.cascade(rules, inline, outer.variables, self.rules.budget)
        if inherited == "css_visibility_hidden" and values.get("visibility") == "visible":
            inherited = None  # unlike display, visibility can be set back by a child
        layout = inherited or css.layout_reason(values) or attribute_reason

        # Colours: the legacy attributes, then the cascade.
        colour, colour_depth = outer.colour, outer.colour_depth
        background, background_depth = outer.background, outer.background_depth
        painted = outer.painted_text
        text_prop = "-webkit-text-fill-color" if "-webkit-text-fill-color" in values else "color"
        text_value = values.get(text_prop)
        if text_value is None and tag == "font" and "color" in a:
            text_value = a["color"].lower()
        # A colour from a variable may be redefined by a stylesheet Kestral
        # cannot see (that is how pages switch themes): its origin is unknown.
        unsure = self.external and bool(guessed)
        declared = css.colour(text_value) if text_value else None
        if declared is not None:
            colour = declared
            colour_depth = -1 if unsure and text_prop in guessed else depth
        own_background = css.background_colour(values)
        if own_background is None and "bgcolor" in a:
            own_background = css.colour(a["bgcolor"])
        clipped_to_text = "text" in (
            values.get("background-clip"),
            values.get("-webkit-background-clip"),
        )
        if clipped_to_text:
            # Gradient text: the background is painted through the glyphs, so
            # it is the text's colour. A solid or uniform one is judged
            # against what lies behind; a varied one cannot be.
            painted = own_background is None or own_background == css.UNKNOWN
            if not painted and own_background is not None:
                colour, colour_depth = own_background, depth
        elif (
            own_background is not None
            and own_background != css.UNKNOWN
            and own_background[3] > 0.05
        ):
            if own_background[3] < 1 and background != css.UNKNOWN:
                # A translucent background is mixed with what lies behind it.
                alpha = own_background[3]
                own_background = (
                    alpha * own_background[0] + (1 - alpha) * background[0],
                    alpha * own_background[1] + (1 - alpha) * background[1],
                    alpha * own_background[2] + (1 - alpha) * background[2],
                    1.0,
                )
            background = own_background
            background_depth = (
                -1 if unsure and guessed & {"background", "background-color"} else depth
            )
        elif own_background == css.UNKNOWN:
            background = own_background
            background_depth = depth

        reason = layout
        if reason is None and not painted and css.contrast_too_low(colour, background):
            # Certain when both colours are known: the page has no stylesheet
            # Kestral cannot see, or the text colour is set on the page at or
            # inside the element that set the background. Text the page itself
            # makes transparent or near-white on the default white page is
            # also certain: one linked stylesheet must not be enough to bring
            # it back. Otherwise (the text colour is the default or comes from
            # a variable a stylesheet may redefine) it is only doubtful.
            set_on_page = colour_depth >= 0
            certain = (
                not self.external
                or (set_on_page and background_depth >= 0 and colour_depth >= background_depth)
                or (set_on_page and colour[3] <= 0.05)
                or (set_on_page and background_depth < 0 and css.luminance(colour) >= 0.9)
            )
            reason = "css_same_colour" if certain else LOW_CONTRAST
        return _View(
            layout, colour, colour_depth, background, background_depth, painted, variables, reason
        )

    def _frame(self, tag: str, a: dict[str, str]) -> _Frame:
        parent = self.stack[-1] if self.stack else None
        holder = parent.element if parent else self.root
        element = css.Element(
            tag=tag,
            id=a.get("id", ""),
            classes=frozenset(a.get("class", "").split()),
            attrs=a,
            parent=holder,
            index=len(holder.children),
            type_index=holder.type_counts.get(tag, 0),
        )
        holder.children.append(element)
        holder.type_counts[tag] = element.type_index + 1
        depth = parent.depth + 1 if parent else 0
        matched = self.rules.matching(element) if self.rules else []
        inline = css.declarations(a.get("style", ""))

        own: str | None = None
        if (
            "hidden" in a
            or a.get("aria-hidden") == "true"
            or (tag == "input" and a.get("type", "").lower() == "hidden")
        ):
            own = "attr_hidden"
        elif tag in _NOT_RENDERED:
            own = "non_rendered_element"
        elif tag == "details" and "open" not in a:
            own = COLLAPSED

        # What is inherited. The first <summary> of a closed <details> is
        # what the reader sees of it.
        outer_frame = parent
        doubt = parent.doubt if parent else None
        if (
            tag == "summary"
            and parent is not None
            and parent.own == COLLAPSED
            and not parent.summary_seen
        ):
            parent.summary_seen = True
            outer_frame = self.stack[-2] if len(self.stack) > 1 else None
            doubt = outer_frame.doubt if outer_frame else None
        if own == COLLAPSED:
            doubt = COLLAPSED
        attribute_reason = own if own != COLLAPSED else None

        views: list[_View] = []
        for index, profile in enumerate(css.PROFILES):
            outer = outer_frame.views[index] if outer_frame else _ROOT_VIEW
            # The first <summary> of a closed <details> takes what is in
            # effect around the details element, not inside it.
            inherited = outer.layout
            if index and not self.rules.by_screen and views:
                # No rule depends on the screen: every view is the same.
                views.append(views[0])
                continue
            rules = (
                matched if not self.rules.by_screen else [r for r in matched if profile in r.media]
            )
            views.append(
                self._view(tag, a, rules, inline, outer, inherited, attribute_reason, depth)
            )

        # Hidden only if hidden on every screen; text shown on one screen is
        # seen by its readers.
        reasons = [v.reason for v in views]
        if all(r is not None and r != LOW_CONTRAST for r in reasons):
            effective: str | None = reasons[-1]
        elif all(r is not None for r in reasons):
            effective = LOW_CONTRAST
        else:
            effective = doubt
        return _Frame(
            element=element,
            depth=depth,
            own=own,
            doubt=doubt,
            views=tuple(views),
            effective=effective,
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        frame = self._frame(tag, a)
        if tag in _BLOCK or frame.effective != self._reason():
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
            self.stack.append(frame)
            self.open_tags[tag] = self.open_tags.get(tag, 0) + 1
            self.buf_reason = self._reason()

    def handle_endtag(self, tag: str) -> None:
        if self.skip == tag:
            self.skip = None
        if tag == "a" and self.links:
            href = self.links.pop()
            if href and self.buf and (self._reason() is None or self._reason() in DOUBTFUL):
                self.buf.append(f"({href})")
        if self.open_tags.get(tag):  # skip the search for a tag that is not open
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i].element.tag == tag:
                    before = self._reason()
                    for closed in self.stack[i:]:
                        self.open_tags[closed.element.tag] -= 1
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


# The stylesheet work budget of the document being extracted. A document can
# hold many HTML fragments (JSON string values, Markdown blocks, email parts);
# they share one budget, so splitting a page into pieces gains nothing.
_BUDGET: contextvars.ContextVar[css.Budget | None] = contextvars.ContextVar(
    "kestral_css_budget", default=None
)


def _html_units(html: str) -> list[tuple[str, str | None, str]]:
    """(text, reason, channel) for every piece of text in a page, in order.

    Raises DocumentError("too_complex") when the page's stylesheets would
    need more work than one document may use.
    """
    styles = _StyleCollector()
    styles.feed(html)
    styles.close()
    try:
        rules: list[css.Rule] = []
        for sheet, media in styles.sheets:
            rules += css.stylesheet_rules(sheet, start=len(rules), media=media)
        budget = _BUDGET.get() or css.Budget(max(css.MAX_WORK, 2 * len(html)))
        walker = _HtmlWalker(css.RuleIndex(rules, budget), styles.external)
        walker.feed(html)
        walker.close()
    except css.TooComplex as exc:
        raise DocumentError("too_complex") from exc
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

    def add_block(
        self,
        text: str,
        channel: str = "visible_text",
        location: str = "",
        reason: str | None = None,
    ) -> None:
        for piece in _split_long(text):
            index = len(self.blocks)
            self.blocks.append(piece)
            invisible = bool(_INVISIBLE.search(piece))
            if invisible and "unicode_invisible" not in self.anomalies:
                self.anomalies.append("unicode_invisible")
            if len(piece.strip()) >= MIN_CHARS:
                self._add(
                    piece, channel, location or f"block {index + 1}", block=index, reason=reason
                )

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
            if reason in DOUBTFUL and render:
                self.add_block(text, prefix + channel, reason=reason)
            elif reason is None and render:
                self.add_block(text)
            elif reason is None or reason in DOUBTFUL:
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
        doubtful: list[tuple[str, str, str]] = []
        if _HTML_TAG.search(block):
            shown: list[str] = []
            for text, reason, channel in _html_units(block):
                if reason is None:
                    shown.append(text)
                elif reason in DOUBTFUL:
                    doubtful.append((text, reason, "markdown.inline_html." + channel))
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
        for text, reason, channel in doubtful:
            builder.add_block(text, channel, reason=reason)
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
                if reason is not None and reason not in DOUBTFUL:
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


def _too_deep(data: Any, limit: int) -> bool:
    """True if ``data`` nests containers more than ``limit`` levels deep."""
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def load_json(content: str) -> Any:
    """``json.loads`` with a nesting limit. Raises DocumentError("nesting_too_deep")."""
    try:
        data = json.loads(content)
    except RecursionError as exc:
        raise DocumentError("nesting_too_deep") from exc
    if _too_deep(data, MAX_JSON_DEPTH):
        raise DocumentError("nesting_too_deep")
    return data


def extract_json(content: str) -> ExtractedDocument:
    data = load_json(content)
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
                    elif reason in DOUBTFUL:
                        add(text, "json.string." + channel, path, why=reason)
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
        except RecursionError:
            return "json"  # too deep to parse here; extract_json withholds it
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
    """Split ``content`` into segments. ``declared_type`` is a hint only.

    Raises :class:`DocumentError` when the content exceeds a structural
    limit (JSON nested more than ``MAX_JSON_DEPTH`` levels).
    """
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
    # Larger documents may use proportionally more work, within the time limit.
    token = _BUDGET.set(css.Budget(max(css.MAX_WORK, 2 * len(content))))
    try:
        return _extract(content, declared_type, chosen, sniffed, anomalies)
    finally:
        _BUDGET.reset(token)


def _extract(
    content: str, declared_type: str | None, chosen: str, sniffed: str, anomalies: list[str]
) -> ExtractedDocument:
    try:
        doc = _EXTRACTORS[chosen](content)
    except DocumentError:
        raise
    except Exception:
        # The declared format did not parse. Read it as what it looks like.
        logger.warning(
            "Extractor %s failed; reading the content as %s", chosen, sniffed, exc_info=True
        )
        anomalies.append("declared_type_mismatch")
        try:
            doc = _EXTRACTORS[sniffed if sniffed != chosen else "plain_text"](content)
        except DocumentError:
            raise
        except Exception:
            logger.warning(
                "Extractor %s failed; reading the content as plain text", sniffed, exc_info=True
            )
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
