"""Text normalization pipeline implementation."""

from __future__ import annotations

import re
import unicodedata
from array import array
from dataclasses import dataclass, field

from . import arabic

# Zero-width and invisible control characters commonly used in token smuggling.
_ZERO_WIDTH_CHARS = (
    "​"  # ZERO WIDTH SPACE
    "‌"  # ZERO WIDTH NON-JOINER
    "‍"  # ZERO WIDTH JOINER
    "⁠"  # WORD JOINER
    "﻿"  # ZERO WIDTH NO-BREAK SPACE
    "­"  # SOFT HYPHEN
    "͏"  # COMBINING GRAPHEME JOINER
    "⁡"  # FUNCTION APPLICATION
    "⁢"  # INVISIBLE TIMES
    "⁣"  # INVISIBLE SEPARATOR
    "⁤"  # INVISIBLE PLUS
)
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]")
_WHITESPACE_RUN_RE = re.compile(r"[ \t]{2,}")

# Cyrillic letters that visually match Latin letters in many fonts.
_CYRILLIC_TO_LATIN = {
    "а": "a",
    "А": "A",  # CYRILLIC SMALL/CAPITAL LETTER A
    "е": "e",
    "Е": "E",  # E
    "о": "o",
    "О": "O",  # O
    "р": "p",
    "Р": "P",  # ER
    "с": "c",
    "С": "C",  # ES
    "х": "x",
    "Х": "X",  # HA
    "у": "y",
    "У": "Y",  # U
    "ұ": "h",
    "Ұ": "H",  # STRAIGHT U → loosely h/H
    "і": "i",
    "І": "I",  # BYELORUSSIAN-UKRAINIAN I
    "ј": "j",
    "Ј": "J",  # JE
    "к": "k",
    "К": "K",  # KA
    "м": "m",
    "М": "M",  # EM
    "н": "n",
    "Н": "H",  # EN → looks like H in capital
    "в": "v",
    "В": "B",  # VE → looks like B capital
    "т": "t",
    "Т": "T",  # TE
    "б": "b",
    "Б": "B",  # BE
}


@dataclass(frozen=True)
class NormalizationResult:
    """The output of running the normalization pipeline on a text input."""

    text: str
    """The normalized text — what detectors that don't need raw input will see."""

    original: str
    """The original text — preserved for detectors that need the raw form."""

    changes: tuple[str, ...]
    """Names of stages that actually modified the text. Useful for diagnostics."""

    pipeline: NormalizationPipeline | None = field(default=None, repr=False, compare=False)
    """The pipeline that produced this result, used to map positions back."""

    _map: list[_SpanMap] = field(default_factory=list, repr=False, compare=False)

    @property
    def modified(self) -> bool:
        return len(self.changes) > 0

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map ``[start, end)`` in :attr:`text` to the span of :attr:`original` it came from.

        Stages remove and merge characters, so a position in the normalized
        text is not a position in the original. Callers that cut or point
        into the original text (redaction, line numbers) need this mapping.
        The span covers every original character that produced the selected
        characters, so cutting it never leaves part of a match behind.
        """
        if not self.modified:
            return start, end
        if not self._map:
            if self.pipeline is None:
                return 0, len(self.original)
            self._map.append(self.pipeline._track(self.original, self.text))
        return self._map[0].span(start, end, len(self.original))


class _SpanMap:
    """For each normalized character, the original span ``[start, end)`` it came from."""

    __slots__ = ("ends", "starts")

    def __init__(self, starts: array[int], ends: array[int]) -> None:
        self.starts = starts
        self.ends = ends

    def span(self, start: int, end: int, original_length: int) -> tuple[int, int]:
        size = len(self.starts)
        if size == 0:
            return 0, original_length
        start = min(max(start, 0), size)
        end = min(max(end, start), size)
        if start == end:
            at = self.starts[start] if start < size else self.ends[size - 1]
            return at, at
        return self.starts[start], max(self.ends[start:end])


class _Units:
    """Text as characters, each with the original span it came from."""

    __slots__ = ("chars", "ends", "starts")

    def __init__(self, chars: list[str], starts: list[int], ends: list[int]) -> None:
        self.chars = chars
        self.starts = starts
        self.ends = ends

    @classmethod
    def of(cls, text: str) -> _Units:
        return cls(list(text), list(range(len(text))), list(range(1, len(text) + 1)))

    def text(self) -> str:
        return "".join(self.chars)


class NormalizationPipeline:
    """Run a configurable text normalization pipeline before detector dispatch.

    All stages are idempotent: running the pipeline twice produces the same
    result as running it once. This guarantees that downstream re-normalization
    (e.g. inside a chained detector) is a no-op.
    """

    def __init__(
        self,
        *,
        nfkc: bool = True,
        strip_zero_width: bool = True,
        homoglyph_map: bool = True,
        arabic: bool = True,
        collapse_whitespace: bool = True,
    ) -> None:
        self.nfkc = nfkc
        self.strip_zero_width = strip_zero_width
        self.homoglyph_map = homoglyph_map
        self.arabic = arabic
        self.collapse_whitespace = collapse_whitespace

    def normalize(self, text: str) -> NormalizationResult:
        """Apply all enabled stages to `text` and return the result."""
        if not isinstance(text, str):
            return NormalizationResult(text=text, original=text, changes=())

        original = text
        changes: list[str] = []

        if self.nfkc:
            after = unicodedata.normalize("NFKC", text)
            if after != text:
                changes.append("nfkc")
                text = after

        if self.strip_zero_width:
            after = _ZERO_WIDTH_RE.sub("", text)
            if after != text:
                changes.append("zero_width")
                text = after

        if self.homoglyph_map:
            after = text.translate(_HOMOGLYPH_TABLE)
            if after != text:
                changes.append("homoglyph")
                text = after

        if self.arabic:
            after = arabic.fold(text)
            if after != text:
                # Removing a mark or direction control can bring a letter
                # and its combining accent together; compose them now so a
                # second pass changes nothing.
                if self.nfkc:
                    after = unicodedata.normalize("NFKC", after)
                changes.append("arabic")
                text = after

        if self.collapse_whitespace:
            after = _WHITESPACE_RUN_RE.sub(" ", text).strip()
            if after != text:
                changes.append("whitespace")
                text = after

        return NormalizationResult(
            text=text, original=original, changes=tuple(changes), pipeline=self
        )

    def _track(self, original: str, expected: str) -> _SpanMap:
        """Run the stages again, recording where each output character came from.

        Only called when a caller needs positions in the original, so scans
        without matches pay nothing. If the tracked run does not reproduce
        ``expected`` (it always should), every character maps to the whole
        original: a wider cut is safe, a wrong one is not.
        """
        units = _Units.of(original)
        if self.nfkc:
            units = _track_nfkc(units)
        if self.strip_zero_width:
            units = _track_drop(units, _ZERO_WIDTH_CHARS)
        if self.homoglyph_map:
            units.chars = [_CYRILLIC_TO_LATIN.get(ch, ch) for ch in units.chars]
        if self.arabic and arabic.has_arabic(units.text()):
            folded = _track_fold(units)
            if folded.chars != units.chars and self.nfkc:
                folded = _track_nfkc(folded)
            units = folded
        if self.collapse_whitespace:
            units = _track_whitespace(units)
        if units.text() != expected:
            whole = len(original)
            return _SpanMap(array("q", [0] * len(expected)), array("q", [whole] * len(expected)))
        return _SpanMap(array("q", units.starts), array("q", units.ends))

    @classmethod
    def from_config(cls, config: dict[str, object]) -> NormalizationPipeline:
        """Build a pipeline from a `normalization` config block."""

        def as_bool(key: str, default: bool) -> bool:
            v = config.get(key, default)
            return bool(v) if isinstance(v, (bool, int)) else default

        return cls(
            nfkc=as_bool("nfkc", True),
            strip_zero_width=as_bool("strip_zero_width", True),
            homoglyph_map=as_bool("homoglyph_map", True),
            arabic=as_bool("arabic", True),
            collapse_whitespace=as_bool("collapse_whitespace", True),
        )


_HOMOGLYPH_TABLE = str.maketrans(_CYRILLIC_TO_LATIN)


def _track_nfkc(units: _Units) -> _Units:
    """NFKC one cluster at a time: a starter and the combining marks after it.

    Composition happens inside a cluster, so each output character maps to
    the cluster it came from. The rare compositions across clusters (Hangul
    jamo, some Indic letters) are handled by aligning the differing middle.
    """
    whole = unicodedata.normalize("NFKC", units.text())
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i = 0
    size = len(units.chars)
    while i < size:
        j = i + 1
        while j < size and unicodedata.combining(units.chars[j]):
            j += 1
        cluster = "".join(units.chars[i:j])
        out = cluster if cluster.isascii() else unicodedata.normalize("NFKC", cluster)
        start, end = units.starts[i], max(units.ends[i:j])
        for ch in out:
            chars.append(ch)
            starts.append(start)
            ends.append(end)
        i = j
    if "".join(chars) == whole:
        return _Units(chars, starts, ends)
    return _align(_Units(chars, starts, ends), whole)


def _align(units: _Units, target: str) -> _Units:
    """Map ``target`` onto ``units`` by their common prefix and suffix.

    The differing middle of ``target`` maps to the span of the differing
    middle of ``units``.
    """
    have = units.text()
    prefix = 0
    limit = min(len(have), len(target))
    while prefix < limit and have[prefix] == target[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < limit - prefix and have[len(have) - 1 - suffix] == target[len(target) - 1 - suffix]
    ):
        suffix += 1
    lo = units.starts[prefix] if prefix < len(have) else (units.ends[-1] if have else 0)
    hi_index = len(have) - suffix
    middle_ends = units.ends[prefix:hi_index]
    hi = max(middle_ends) if middle_ends else lo
    middle = len(target) - prefix - suffix
    return _Units(
        list(target),
        units.starts[:prefix] + [lo] * middle + units.starts[hi_index:],
        units.ends[:prefix] + [hi] * middle + units.ends[hi_index:],
    )


def _track_drop(units: _Units, dropped: str) -> _Units:
    keep = [i for i, ch in enumerate(units.chars) if ch not in dropped]
    return _Units(
        [units.chars[i] for i in keep],
        [units.starts[i] for i in keep],
        [units.ends[i] for i in keep],
    )


def _track_fold(units: _Units) -> _Units:
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for ch, start, end in zip(units.chars, units.starts, units.ends, strict=True):
        out = arabic.FOLD.get(ch, ch)
        if out:
            chars.append(out)
            starts.append(start)
            ends.append(end)
    return _Units(chars, starts, ends)


def _track_whitespace(units: _Units) -> _Units:
    """Collapse runs of two or more spaces or tabs to one space, then strip."""
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i = 0
    size = len(units.chars)
    while i < size:
        if units.chars[i] in " \t":
            j = i
            while j < size and units.chars[j] in " \t":
                j += 1
            if j - i >= 2:
                chars.append(" ")
                starts.append(units.starts[i])
                ends.append(max(units.ends[i:j]))
                i = j
                continue
        chars.append(units.chars[i])
        starts.append(units.starts[i])
        ends.append(units.ends[i])
        i += 1
    lo = 0
    while lo < len(chars) and chars[lo].isspace():
        lo += 1
    hi = len(chars)
    while hi > lo and chars[hi - 1].isspace():
        hi -= 1
    return _Units(chars[lo:hi], starts[lo:hi], ends[lo:hi])
