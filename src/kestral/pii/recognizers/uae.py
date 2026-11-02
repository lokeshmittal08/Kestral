"""Recognizers for UAE identifiers: Emirates ID, IBAN and UAE phone numbers.

Each runs on digit-folded text (see :mod:`.digits`), so Arabic-Indic digits,
no-break spaces and invisible characters inside a number do not hide it, and
maps what it finds back to the original text.

Patterns use bounded repetition with at most one separator between digit
groups, so their cost grows linearly with the text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import regex

from kestral.pii.recognizers.base import Span
from kestral.pii.recognizers.digits import fold

if TYPE_CHECKING:
    from collections.abc import Iterable

# Seconds one recognizer may spend on one text before it gives up loudly
# (regex raises TimeoutError, and callers fail closed).
TIMEOUT = 1.0

_LANGS = frozenset({"en", "ar"})


def luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------- Emirates ID

# 784 (the UAE's ISO country number), a four-digit year, seven digits and a
# check digit; written 784-YYYY-NNNNNNN-C or without the dashes. The check
# digit follows the Luhn scheme (Microsoft Purview's definition and public
# validators agree; ICP publishes no specification).
_EID = regex.compile(r"(?<![0-9])784([- ]?)((?:19|20)[0-9]{2})\1([0-9]{7})\1([0-9])(?![0-9])")
# Words near an ID that make it more certain.
_EID_CONTEXT = regex.compile(
    r"(?:emirates\s+id|\beid\b|id\s+(?:card\s+)?(?:no|number)|identity\s+card"
    r"|رقم\s+الهوية|الهوية|بطاقة\s+الهوية)",
    regex.IGNORECASE,
)


class EmiratesId:
    entity = "emirates_id"
    version = "1.0"
    languages = _LANGS

    def find(self, text: str) -> Iterable[Span]:
        folded = fold(text)
        for m in _EID.finditer(folded.text, timeout=TIMEOUT):
            digits = "784" + m.group(2) + m.group(3) + m.group(4)
            valid = luhn(digits)
            if not valid and m.group(1) != "-":
                # Fifteen undashed digits that fail the check digit are as
                # likely an account or reference number.
                continue
            before = folded.text[max(0, m.start() - 40) : m.start()]
            score = 0.95 if valid else 0.6
            if _EID_CONTEXT.search(before, timeout=TIMEOUT):
                score = min(1.0, score + 0.05)
            start, end = folded.span(m.start(), m.end())
            yield Span(start, end, self.entity, score, valid)


# ----------------------------------------------------------------------- IBAN

# Total IBAN length per country (ISO 13616 registry). An IBAN-shaped string
# from a country not listed is not reported.
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "OM": 23,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24,
    "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23,
    "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}  # fmt: skip

_IBAN_START = regex.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2})([0-9]{2})")


def mod97(iban: str) -> bool:
    moved = iban[4:] + iban[:4]
    number = "".join(str(int(ch, 36)) for ch in moved)
    return int(number) % 97 == 1


class Iban:
    entity = "iban"
    version = "1.0"
    languages = _LANGS

    def find(self, text: str) -> Iterable[Span]:
        folded = fold(text)
        t = folded.text
        for m in _IBAN_START.finditer(t, timeout=TIMEOUT):
            length = IBAN_LENGTHS.get(m.group(1).upper())
            if length is None:
                continue
            # Walk forward: letters and digits, with at most one space
            # between characters, until the country's length is reached.
            compact = m.group(1).upper() + m.group(2)
            i = m.end()
            while len(compact) < length and i < len(t):
                if t[i] == " " and i + 1 < len(t) and t[i + 1].isascii() and t[i + 1].isalnum():
                    i += 1
                    continue
                if not (t[i].isascii() and t[i].isalnum()):
                    break
                compact += t[i].upper()
                i += 1
            if len(compact) != length or (i < len(t) and t[i].isascii() and t[i].isalnum()):
                continue
            if not mod97(compact):
                continue
            start, end = folded.span(m.start(), i)
            yield Span(start, end, self.entity, 0.95, True)


# ---------------------------------------------------------------- UAE phones

# Mobile network prefixes after the leading 0 (050 ... 058), and landline
# area codes (02 Abu Dhabi, 03 Al Ain, 04 Dubai, 06 Sharjah/Ajman/UAQ,
# 07 Ras Al Khaimah, 08 Al Dhafra, 09 Fujairah). Kept as data: operators add
# prefixes.
MOBILE_PREFIXES = frozenset({"50", "52", "53", "54", "55", "56", "57", "58"})
AREA_CODES = frozenset({"2", "3", "4", "6", "7", "8", "9"})

_SEP = r"[- ]?"
# +971 / 00971 (optionally followed by the trunk 0 people keep), or a 0.
_PHONE = regex.compile(
    r"(?<![0-9+])"
    r"(?:(?:\+|00)971[- ]?(?:\(?0\)?[- ]?)?|0)"
    r"(5[0-9]|[2-9])"
    rf"((?:{_SEP}[0-9]){{7}})"
    r"(?![0-9])"
)


class UaePhone:
    """UAE mobile and landline numbers. Reported as ``phone``, like other phones."""

    entity = "phone"
    version = "1.0"
    languages = _LANGS

    def find(self, text: str) -> Iterable[Span]:
        folded = fold(text)
        for m in _PHONE.finditer(folded.text, timeout=TIMEOUT):
            prefix = m.group(1)
            if len(prefix) == 2 and prefix not in MOBILE_PREFIXES:
                continue
            if len(prefix) == 1 and prefix not in AREA_CODES:
                continue
            start, end = folded.span(m.start(), m.end())
            yield Span(start, end, self.entity, 0.9, True)


# 800 toll-free (3 to 7 more digits) and 600 shared-cost (6 more digits).
# Public company numbers: off by default, since masking "call 800 4444" in a
# reply protects nobody.
_SERVICE = regex.compile(
    r"(?<![0-9+])(?:800[- ]?[0-9]{3,7}|600[- ]?[0-9]{2}[- ]?[0-9]{4})(?![0-9])"
)


class UaeServicePhone:
    entity = "phone_ae_service"
    version = "1.0"
    languages = _LANGS

    def find(self, text: str) -> Iterable[Span]:
        folded = fold(text)
        for m in _SERVICE.finditer(folded.text, timeout=TIMEOUT):
            start, end = folded.span(m.start(), m.end())
            yield Span(start, end, self.entity, 0.7, False)
