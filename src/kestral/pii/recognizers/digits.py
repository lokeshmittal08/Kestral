"""Fold digits and invisible characters so number patterns see one spelling.

A phone number or Emirates ID can be written in Arabic-Indic, Persian,
full-width or mathematical digits, with no-break spaces between the groups,
or with invisible format characters inside. A model reads all of them as the
number; so must the recognizers. The folded text keeps a map back to the
original so a redaction cuts the right characters.
"""

from __future__ import annotations

from dataclasses import dataclass

from kestral.normalization.arabic import DIGITS

# Format characters that render as nothing: soft hyphen, Arabic letter mark,
# Mongolian vowel separator, zero-width characters and direction marks,
# direction embeddings and isolates, invisible operators, BOM, and the
# interlinear annotation marks.
_INVISIBLE = frozenset(
    chr(c)
    for r in (
        (0x00AD, 0x00AD),
        (0x061C, 0x061C),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
    )
    for c in range(r[0], r[1] + 1)
)

# Spaces that separate digit groups as an ordinary space does: no-break,
# figure, narrow no-break, and the fixed-width spaces.
_SPACES = frozenset(chr(c) for c in (0x00A0, 0x2007, 0x202F, *range(0x2000, 0x200B)))


@dataclass(frozen=True)
class Folded:
    text: str
    origin: tuple[int, ...]
    """For each folded character, its index in the original text."""

    def span(self, start: int, end: int) -> tuple[int, int]:
        """The original span of folded characters ``[start, end)``."""
        if start >= end:
            at = self.origin[start] if start < len(self.origin) else len(self.origin)
            return at, at
        return self.origin[start], self.origin[end - 1] + 1


def fold(text: str) -> Folded:
    chars: list[str] = []
    origin: list[int] = []
    for index, ch in enumerate(text):
        if ch in _INVISIBLE:
            continue
        chars.append(" " if ch in _SPACES else DIGITS.get(ch, ch))
        origin.append(index)
    return Folded("".join(chars), tuple(origin))
