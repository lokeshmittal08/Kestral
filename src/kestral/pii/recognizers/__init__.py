"""Pluggable personal-data recognizers.

A recognizer finds one kind of value and says whether a checksum or
numbering plan confirmed it. Built in: the original regex table, and UAE
recognizers for Emirates ID, IBAN and phone numbers. Other packages add
recognizers under the ``kestral.recognizers`` entry point.

``PIIRedactor()`` without recognizers keeps its original six entity types;
callers opt in with ``PIIRedactor(recognizers=uae_set())``.
"""

from __future__ import annotations

from kestral.pii.recognizers.base import (
    ENTRY_POINT_GROUP,
    Recognizer,
    Span,
    check_names,
    discover,
    find_all,
    resolve,
)
from kestral.pii.recognizers.legacy import BOUNDED_EMAIL, PatternTable
from kestral.pii.recognizers.uae import (
    AREA_CODES,
    IBAN_LENGTHS,
    MOBILE_PREFIXES,
    EmiratesId,
    Iban,
    UaePhone,
    UaeServicePhone,
    luhn,
    mod97,
)

BUILT_IN: dict[str, type] = {
    "emirates_id": EmiratesId,
    "iban": Iban,
    "phone_ae": UaePhone,
    "phone_ae_service": UaeServicePhone,
}
"""Built-in recognizers by the name used in configuration."""

DEFAULT_UAE = ("emirates_id", "iban", "phone_ae")


def uae_set(names: tuple[str, ...] = DEFAULT_UAE, plugins: bool = True) -> list[Recognizer]:
    """The original patterns plus the named UAE recognizers and any installed plugins."""
    unknown = [n for n in names if n not in BUILT_IN]
    if unknown:
        raise ValueError(f"unknown recognizers: {unknown}; known: {sorted(BUILT_IN)}")
    chosen: list[Recognizer] = [PatternTable()]
    chosen += [BUILT_IN[name]() for name in names]
    if plugins:
        chosen += discover()
    return chosen


__all__ = [
    "AREA_CODES",
    "BOUNDED_EMAIL",
    "BUILT_IN",
    "DEFAULT_UAE",
    "ENTRY_POINT_GROUP",
    "IBAN_LENGTHS",
    "MOBILE_PREFIXES",
    "EmiratesId",
    "Iban",
    "PatternTable",
    "Recognizer",
    "Span",
    "UaePhone",
    "UaeServicePhone",
    "check_names",
    "discover",
    "find_all",
    "luhn",
    "mod97",
    "resolve",
    "uae_set",
]
