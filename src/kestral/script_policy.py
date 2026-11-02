"""What an ML verdict is worth on text in a script the model was not validated on.

The bundled classifiers are English DeBERTa models. On Arabic script they
react to the script rather than the meaning: in testing they flagged 11 of
12 harmless Arabic banking questions as injections. A detection the model
cannot vouch for is kept in the report but marked *downgraded*; on its own
it does not block, remove or flag anything. It counts again when a precise
rule-based detector agrees.

The classifier itself decides what to mark (see ``d022_semantic_classifier``):
it scores the text again with the Arabic-script runs removed, so an English
attack padded or interleaved with Arabic is still caught on its English part.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import regex

from kestral.models import DetectionResult, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable

Policy = Literal["corroborate", "score"]
POLICIES: tuple[Policy, ...] = ("corroborate", "score")
ARABIC_SCRIPT = "arabic_script"

# Marker in DetectionResult.metadata. Kept in metadata so report schemas do
# not change.
DOWNGRADED = "downgraded"
REASON = "classifier_not_validated_for_script"
# A phrase that is an attack in one reading and ordinary text in another
# (after folding, "انس كل شيء" also reads "Anas, everything ...").
AMBIGUOUS = "ambiguous_phrase"

# Rule-based detectors precise enough to confirm a downgraded verdict at
# HIGH or CRITICAL severity. The same set the inspector trusts on its own
# (inspector.PRECISE). ML and statistical detectors (d021 embeddings, d022,
# d027 stylometry) and format noise never confirm.
CORROBORATORS = frozenset(
    {
        "d008_base64_payload",
        "d009_rot13_substitution",
        "d024_multilingual_injection",
        "d025_multi_encoding",
        "d034_honeypot_tool",
        "d036_credential_theft",
    }
)

_ARABIC_WORD = regex.compile(r"\p{Arabic}+")
# Arabic letters plus the marks Unicode files under the common script but
# only Arabic text uses (comma, semicolon, question mark, percent and decimal
# signs, full stop, tatweel, direction marks), with any punctuation glued to
# either side: "اليوم." leaves no stray "." between the words around it.
_ARABIC_CHARS = r"\p{Arabic}\u060c\u061b\u061f\u0640\u066a-\u066d\u06d4\u200e\u200f\u061c"
# A run starts only where a punctuation run starts: trying every position
# inside a long one would take time quadratic in its length.
_ARABIC_RUN = regex.compile(
    rf"(?<![^\p{{L}}\p{{N}}\s])[^\p{{L}}\p{{N}}\s]*[{_ARABIC_CHARS}]+(?:[^\p{{L}}\p{{N}}\s]*[{_ARABIC_CHARS}]+)*"
    r"[^\p{L}\p{N}\s]*"
)
_OTHER_LETTER = regex.compile(r"(?!\p{Arabic})[\p{L}\p{N}]")
_OTHER_ALPHA = regex.compile(r"(?!\p{Arabic})\p{L}")
_SPACES = regex.compile(r"[ \t]{2,}")


def unvalidated_script(text: str) -> str | None:
    """The unvalidated script ``text`` substantially uses, or None.

    Substantial means at least three Arabic-script words, or at least a fifth
    of the letters. Arabic script includes Persian and Urdu, on which the
    classifiers are not validated either.
    """
    words = len(_ARABIC_WORD.findall(text))
    if words >= 3:
        return ARABIC_SCRIPT
    if not words:
        return None
    letters = sum(1 for ch in text if ch.isalpha())
    arabic = sum(len(w) for w in _ARABIC_WORD.findall(text))
    return ARABIC_SCRIPT if letters and arabic * 5 >= letters else None


def residual(text: str) -> str:
    """``text`` with every Arabic-script run replaced by a space.

    Line breaks are kept: the classifier reads them, and the text left over
    should be scored as it was written.
    """
    rest: str = _SPACES.sub(" ", _ARABIC_RUN.sub(" ", text))
    return rest.strip()


def other_letters(text: str) -> int:
    """Letters and digits in any script but Arabic: Latin, Devanagari, Han and so on.

    Digits count so that an encoded payload (hex, base64) is scored too.
    """
    return len(_OTHER_LETTER.findall(text))


def other_alpha(text: str) -> int:
    """Letters in any script but Arabic, without digits."""
    return len(_OTHER_ALPHA.findall(text))


def is_downgraded(detection: DetectionResult) -> bool:
    return DOWNGRADED in detection.metadata


def downgrade(detection: DetectionResult, reason: str = REASON) -> DetectionResult:
    return detection.model_copy(update={"metadata": {**detection.metadata, DOWNGRADED: reason}})


def corroborated(detections: Iterable[DetectionResult]) -> bool:
    return any(
        d.detector_id in CORROBORATORS
        and d.severity in (Severity.CRITICAL, Severity.HIGH)
        and not is_downgraded(d)
        for d in detections
    )


def effective(detections: list[DetectionResult]) -> list[DetectionResult]:
    """The detections a decision may rest on.

    Downgraded detections are dropped unless a precise detector agrees.
    """
    if not any(is_downgraded(d) for d in detections) or corroborated(detections):
        return detections
    return [d for d in detections if not is_downgraded(d)]


def policy_for(config: object, script: str) -> Policy:
    """Read ``unvalidated_scripts`` from a detector config: one policy for all
    unvalidated scripts, or a mapping from script to policy."""
    value = config.get(script) if isinstance(config, dict) else config
    if value in POLICIES:
        return value
    if value is None:
        return "corroborate"
    raise ValueError(f"unvalidated_scripts: unknown policy {value!r}; use one of {POLICIES}")


__all__ = [
    "AMBIGUOUS",
    "ARABIC_SCRIPT",
    "CORROBORATORS",
    "DOWNGRADED",
    "POLICIES",
    "REASON",
    "corroborated",
    "downgrade",
    "effective",
    "is_downgraded",
    "other_alpha",
    "other_letters",
    "policy_for",
    "residual",
    "unvalidated_script",
]
