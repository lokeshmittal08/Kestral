"""Arabic-script folding for detection.

Spelling variation in Arabic script is large and free: diacritics (tashkeel),
the stretching tatweel, hamza seats, ta marbuta, alef maqsura, Persian and
Urdu keyboard letters, invisible direction marks and Arabic-Indic digits all
change the code points without changing what a reader sees or what a model
understands. A phrase list written in one spelling misses the others, so the
detectors see one folded spelling instead.

The folding applies to the detection copy only; callers always get their own
text back. It touches a text only when it contains an Arabic-script
character, so text in any other script is returned unchanged.

All tables are frozen code-point lists rather than ``unicodedata`` lookups:
CI runs Python 3.10 to 3.13, which ship different Unicode versions, and the
results must not depend on which one is used.
"""

# The tables hold Arabic letters on purpose.
# ruff: noqa: RUF001

from __future__ import annotations

# Unicode blocks of the Arabic script: Arabic, Arabic Supplement, Arabic
# Extended-B and -A, and the two presentation-form blocks (which NFKC folds
# to base letters before this stage runs).
_ARABIC_BLOCKS = (
    (0x0600, 0x06FF),
    (0x0750, 0x077F),
    (0x0870, 0x08FF),
    (0xFB50, 0xFDFF),
    (0xFE70, 0xFEFF),
)


def _span(first: int, last: int) -> range:
    return range(first, last + 1)


# Marks that change no letter: tashkeel, superscript alef, honorifics,
# Quranic annotation marks, the extended-block marks, spacing dot symbols and
# the number signs that prefix digits.
_MARKS = frozenset(
    chr(c)
    for r in (
        _span(0x064B, 0x065F),
        _span(0x0670, 0x0670),
        _span(0x0610, 0x061A),
        _span(0x06D6, 0x06DC),
        _span(0x06DD, 0x06DD),
        _span(0x06DF, 0x06E4),
        _span(0x06E7, 0x06E8),
        _span(0x06EA, 0x06ED),
        _span(0x0898, 0x089F),
        _span(0x08CA, 0x08E1),
        _span(0x08E3, 0x08FF),
        _span(0xFBB2, 0xFBC1),
        _span(0x0600, 0x0605),
    )
    for c in r
)

TATWEEL = "\u0640"

# Direction controls. An RLM between two words is invisible but breaks a
# pattern that expects a space there. (ZWJ and ZWNJ are already removed for
# all text by the zero-width stage.)
_BIDI = frozenset(
    chr(c)
    for r in (
        _span(0x200E, 0x200F),
        _span(0x061C, 0x061C),
        _span(0x202A, 0x202E),
        _span(0x2066, 0x2069),
    )
    for c in r
)

_HAMZA = "ء"

# Letter folds: alef with hamza or madda, alef wasla -> alef; hamza on waw and
# on ya -> waw and ya; alef maqsura -> ya; ta marbuta -> ha; Persian and Urdu
# keyboard kaf, ya and ha forms -> the Arabic letters.
_LETTERS: dict[str, str] = {
    "أ": "ا",
    "إ": "ا",
    "آ": "ا",
    "ٱ": "ا",
    "ؤ": "و",
    "ئ": "ي",
    "ى": "ي",
    "ة": "ه",
    "ک": "ك",
    "ی": "ي",
    "ۀ": "ه",
    "ہ": "ه",
    "ھ": "ه",
    "ە": "ه",
}

# The zero of every Unicode decimal-digit run (Unicode 15.1). Each run holds
# the digits 0-9 at consecutive code points.
DIGIT_ZEROS: tuple[int, ...] = (
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66,
    0xCE6, 0xD66, 0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810,
    0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620,
    0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10, 0x104A0, 0x10D30,
    0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50,
    0x16A60, 0x16AC0, 0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6,
    0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950, 0x1FBF0,
)  # fmt: skip

DIGITS: dict[str, str] = {
    chr(zero + i): str(i) for zero in DIGIT_ZEROS if zero != 0x30 for i in range(10)
}

# One character in, at most one out: deletions map to "" and everything else
# to a single character, which keeps position tracking simple.
FOLD: dict[str, str] = {
    **{ch: "" for ch in _MARKS},
    **{ch: "" for ch in _BIDI},
    TATWEEL: "",
    _HAMZA: "",
    **_LETTERS,
    **DIGITS,
}

_TABLE = str.maketrans({ch: (out or None) for ch, out in FOLD.items()})


def is_arabic_char(ch: str) -> bool:
    """True for a character in one of the Arabic-script blocks."""
    code = ord(ch)
    return any(first <= code <= last for first, last in _ARABIC_BLOCKS)


def has_arabic(text: str) -> bool:
    """True when ``text`` contains at least one Arabic-script character."""
    return any(is_arabic_char(ch) for ch in text)


def fold(text: str) -> str:
    """Fold ``text`` to its detection spelling; unchanged if it has no Arabic script.

    Idempotent: folding a folded text changes nothing.
    """
    if not has_arabic(text):
        return text
    return text.translate(_TABLE)


__all__ = ["DIGITS", "DIGIT_ZEROS", "FOLD", "TATWEEL", "fold", "has_arabic", "is_arabic_char"]
