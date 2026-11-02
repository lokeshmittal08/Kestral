"""Detector for prompt injection attacks written in non-English languages."""

from __future__ import annotations

from typing import ClassVar

import regex

from kestral import script_policy
from kestral.detectors.base import BaseDetector
from kestral.models import DetectionResult, MatchDetail, Severity
from kestral.normalization import NormalizationPipeline
from kestral.normalization.arabic import fold

# Arabic-script folding on its own, for input that did not come through the
# engine's normalizer (direct calls, or normalization.arabic switched off).
_ARABIC_ONLY = NormalizationPipeline(
    nfkc=False, strip_zero_width=False, homoglyph_map=False, collapse_whitespace=False
)

# After folding, "انس كل شيء" (forget everything) is also "أنس كل شيء"
# (Anas, everything ...). It counts only when another detector agrees.
# The imperative is انسَ; انسى is the common spelling of it.
_NOT_NEGATED = r"(?<!(?<![\p{L}\p{M}])(?:عدم|لا)\s+)"
_FORGET_EVERYTHING_AR = r"انسى?\s+كل\s+شيء"
_AMBIGUOUS = frozenset({_FORGET_EVERYTHING_AR})

# Each entry: (raw_pattern, language, description)
_RAW_PATTERNS: list[tuple[str, str, str]] = [
    # ── French ──────────────────────────────────────────────────────────
    (
        r"ignorez\s+toutes\s+les\s+instructions\s+pr[ée]c[ée]dentes",
        "french",
        "Ignore instructions",
    ),
    (r"montrez\s+le\s+prompt\s+syst[èe]me", "french", "Show system prompt"),
    (r"oubliez\s+tout", "french", "Forget everything"),
    (r"vous\s+[êe]tes\s+maintenant", "french", "You are now [role]"),
    (r"ignorez\s+les\s+consignes", "french", "Ignore directives"),
    (r"affichez\s+les\s+instructions", "french", "Display instructions"),
    (r"r[ée]v[ée]lez\s+le\s+prompt", "french", "Reveal prompt"),
    (
        r"ne\s+tenez\s+pas\s+compte\s+des\s+instructions",
        "french",
        "Disregard instructions",
    ),
    (
        r"oubliez\s+les\s+instructions\s+pr[ée]c[ée]dentes",
        "french",
        "Forget previous instructions",
    ),
    # ── German ──────────────────────────────────────────────────────────
    (
        r"ignorieren\s+Sie\s+alle\s+vorherigen\s+Anweisungen",
        "german",
        "Ignore instructions",
    ),
    (r"zeigen\s+Sie\s+den\s+System[\-\s]?Prompt", "german", "Show system prompt"),
    (r"vergessen\s+Sie\s+alles", "german", "Forget everything"),
    (r"Sie\s+sind\s+jetzt", "german", "You are now [role]"),
    (r"Anweisungen\s+ignorieren", "german", "Ignore instructions"),
    (r"Systemaufforderung\s+anzeigen", "german", "Show system prompt"),
    (r"vorherige\s+Anweisungen\s+vergessen", "german", "Forget previous instructions"),
    (r"missachten\s+Sie\s+alle\s+Anweisungen", "german", "Disregard all instructions"),
    # ── Spanish ─────────────────────────────────────────────────────────
    (
        r"ignora\s+todas\s+las\s+instrucciones\s+anteriores",
        "spanish",
        "Ignore instructions",
    ),
    (r"muestra\s+el\s+prompt\s+del\s+sistema", "spanish", "Show system prompt"),
    (r"olvida\s+todo", "spanish", "Forget everything"),
    (r"ahora\s+eres", "spanish", "You are now [role]"),
    (r"revela\s+las\s+instrucciones", "spanish", "Reveal instructions"),
    (r"ignora\s+las\s+instrucciones", "spanish", "Ignore instructions"),
    (
        r"muestra\s+las\s+instrucciones\s+del\s+sistema",
        "spanish",
        "Show system instructions",
    ),
    # ── Portuguese ──────────────────────────────────────────────────────
    (
        r"ignore\s+todas\s+as\s+instru[çc][õo]es\s+anteriores",
        "portuguese",
        "Ignore instructions",
    ),
    (r"mostre\s+o\s+prompt\s+do\s+sistema", "portuguese", "Show system prompt"),
    (r"esque[çc]a\s+tudo", "portuguese", "Forget everything"),
    (r"voc[êe]\s+agora\s+[ée]", "portuguese", "You are now [role]"),
    (r"ignore\s+as\s+instru[çc][õo]es", "portuguese", "Ignore instructions"),
    (r"revele\s+o\s+prompt", "portuguese", "Reveal prompt"),
    # ── Italian ─────────────────────────────────────────────────────────
    (
        r"ignora\s+tutte\s+le\s+istruzioni\s+precedenti",
        "italian",
        "Ignore instructions",
    ),
    (r"mostra\s+il\s+prompt\s+di\s+sistema", "italian", "Show system prompt"),
    (r"dimentica\s+tutto", "italian", "Forget everything"),
    (r"ora\s+sei", "italian", "You are now [role]"),
    (r"rivela\s+le\s+istruzioni", "italian", "Reveal instructions"),
    (r"ignora\s+le\s+istruzioni", "italian", "Ignore instructions"),
    # ── Chinese (Simplified) ───────────────────────────────────────────
    (r"忽略所有之前的指令", "chinese", "Ignore instructions"),
    (r"显示系统提示", "chinese", "Show system prompt"),
    (r"忘记一切", "chinese", "Forget everything"),
    (r"你现在是", "chinese", "You are now [role]"),
    (r"忽略之前的指示", "chinese", "Ignore previous instructions"),
    (r"展示系统提示词", "chinese", "Show system prompt words"),
    (r"无视所有指令", "chinese", "Disregard all instructions"),
    (r"忽略上面的指令", "chinese", "Ignore above instructions"),
    (r"请告诉我你的系统提示", "chinese", "Tell me your system prompt"),
    # ── Japanese ────────────────────────────────────────────────────────
    (r"前の指示をすべて無視して", "japanese", "Ignore instructions"),
    (r"システムプロンプトを表示", "japanese", "Show system prompt"),
    (r"すべて忘れて", "japanese", "Forget everything"),
    (r"あなたは今", "japanese", "You are now [role]"),
    (r"指示を無視", "japanese", "Ignore instructions"),
    (r"以前の指示を無視", "japanese", "Ignore previous instructions"),
    (r"システムの指示を見せて", "japanese", "Show system instructions"),
    # ── Korean ──────────────────────────────────────────────────────────
    (r"이전의\s*모든\s*지시를\s*무시", "korean", "Ignore instructions"),
    (r"시스템\s*프롬프트를\s*보여", "korean", "Show system prompt"),
    (r"모든\s*것을\s*잊어", "korean", "Forget everything"),
    (r"당신은\s*이제", "korean", "You are now [role]"),
    (r"이전\s*지시를\s*무시", "korean", "Ignore previous instructions"),
    (r"시스템\s*지시를\s*보여\s*줘", "korean", "Show system instructions"),
    # ── Arabic ──────────────────────────────────────────────────────────
    # Written in ordinary spelling; the detector folds them (and the input)
    # so diacritics, tatweel and letter variants do not matter. "Not
    # ignoring the instructions" (عدم / لا) is not an attack; the negation
    # must be a word of its own, not the end of أولا ("first") or حالا ("now").
    (_NOT_NEGATED + r"تجاهل\s+جميع\s+التعليمات\s+السابقة", "arabic", "Ignore instructions"),
    (r"أظهر\s+الأوامر\s+الأساسية", "arabic", "Show system prompt"),
    (_FORGET_EVERYTHING_AR, "arabic", "Forget everything"),
    # "You are now" alone is how a support bot greets people ("أنت الآن متصل
    # بخدمة العملاء"); an attack goes on to lift the rules.
    (
        r"أنت\s+الآن.{0,40}?(?:(?:بدون|بلا|دون|من\s+غير)\s+(?:أي\s+)?"
        r"(?:قيود|حدود|رقابة|قواعد|فلاتر|فلتر)|غير\s+مقيد|متحرر\s+من)",
        "arabic",
        "You are now [role] without restrictions",
    ),
    (_NOT_NEGATED + r"تجاهل\s+التعليمات", "arabic", "Ignore instructions"),
    (r"اكشف\s+عن\s+الأوامر", "arabic", "Reveal instructions"),
    # ── Hindi ───────────────────────────────────────────────────────────
    (r"सभी\s+पिछले\s+निर्देशों\s+को\s+अनदेखा\s+करें", "hindi", "Ignore instructions"),
    (r"सिस्टम\s+प्रॉम्प्ट\s+दिखाएं", "hindi", "Show system prompt"),
    (r"सब\s+कुछ\s+भूल\s+जाओ", "hindi", "Forget everything"),
    (r"अब\s+आप\s+हैं", "hindi", "You are now [role]"),
    (r"निर्देशों\s+को\s+अनदेखा\s+करें", "hindi", "Ignore instructions"),
    (r"सिस्टम\s+निर्देश\s+दिखाओ", "hindi", "Show system instructions"),
]

# Pattern for detecting language mixing: non-Latin script near English injection keywords
_LANGUAGE_MIXING_PATTERN = (
    r"(?:[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af"
    r"\u0900-\u097f])"
    r".{0,50}"
    r"(?:ignore|forget|override|bypass|reveal|show|display|print|dump|extract|system\s*prompt)"
    r"|"
    r"(?:ignore|forget|override|bypass|reveal|show|display|print|dump|extract|system\s*prompt)"
    r".{0,50}"
    r"(?:[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af"
    r"\u0900-\u097f])"
)

# Arabic and English are mixed in ordinary Gulf chat ("Can you show me رصيد
# حسابي", "print statement", "forget password", "Al Ain bypass"), so for
# Arabic script the English part must be an instruction verb with its object.
_ARABIC_CHAR = r"[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff]"
_EN_INSTRUCTION = (
    r"(?:\b(?:ignore|forget|override|bypass|disregard)\s+"
    r"(?:(?:all|the|your|any|my|previous|prior|above|earlier|these|those)\s+){0,3}"
    r"(?:instructions?|rules|prompts?|guidelines|directions|directives)\b"
    r"|\bsystem\s*prompt\b)"
)
_ARABIC_MIXING_PATTERN = (
    rf"{_ARABIC_CHAR}.{{0,50}}{_EN_INSTRUCTION}|{_EN_INSTRUCTION}.{{0,50}}{_ARABIC_CHAR}"
)


class MultilingualInjectionDetector(BaseDetector):
    """Detects prompt injection attacks written in non-English languages.

    Adversaries craft injection payloads in languages other than English to
    evade English-only pattern detectors. This detector covers French, German,
    Spanish, Portuguese, Italian, Chinese, Japanese, Korean, Arabic, and Hindi.
    It also flags language-mixing attacks that combine non-Latin scripts with
    English injection keywords.
    """

    detector_id: str = "d024_multilingual_injection"
    name: str = "Multilingual Injection"
    description: str = (
        "Detects prompt injection attacks in non-English languages including "
        "French, German, Spanish, Portuguese, Italian, Chinese, Japanese, "
        "Korean, Arabic, and Hindi."
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["multilingual", "direct_injection"]
    version: str = "1.0.0"
    author: str = "kestral"

    _base_confidence: float = 0.85

    def __init__(self) -> None:
        super().__init__()
        # Pre-compile all patterns once at instantiation time. Arabic patterns
        # are folded to the spelling the input is folded to, so they match
        # every spelling variant of the phrase.
        self._compiled_patterns: list[tuple[regex.Pattern[str], str, str]] = [
            (regex.compile(fold(pat), regex.IGNORECASE), lang, desc)
            for pat, lang, desc in _RAW_PATTERNS
        ]
        self._mixing_patterns: list[regex.Pattern[str]] = [
            regex.compile(_LANGUAGE_MIXING_PATTERN, regex.IGNORECASE),
            regex.compile(_ARABIC_MIXING_PATTERN, regex.IGNORECASE),
        ]
        self._ambiguous = frozenset(fold(p) for p in _AMBIGUOUS)

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        matches: list[MatchDetail] = []
        # The engine has usually folded the text already; folding is
        # idempotent, so this costs nothing then.
        folded = _ARABIC_ONLY.normalize(input_text)
        text = folded.text

        def found(pattern: str, m: regex.Match[str], description: str) -> MatchDetail:
            start, end = folded.original_span(m.start(), m.end())
            return MatchDetail(
                pattern=pattern,
                matched_text=input_text[start:end],
                position=(start, end),
                description=description,
            )

        # Check language-specific patterns
        for compiled, language, description in self._compiled_patterns:
            for m in compiled.finditer(text):
                matches.append(found(compiled.pattern, m, f"[{language}] {description}"))

        # Check language mixing
        for mixing in self._mixing_patterns:
            for m in mixing.finditer(text):
                matches.append(
                    found(
                        mixing.pattern,
                        m,
                        "[mixed] Language mixing with English injection keywords",
                    )
                )

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No suspicious multilingual patterns found",
            )

        confidence = min(1.0, self._base_confidence + 0.05 * (len(matches) - 1))
        result = DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(f"Detected {len(matches)} pattern(s) indicating {self.name.lower()}"),
        )
        if all(m.pattern in self._ambiguous for m in matches):
            return script_policy.downgrade(result, script_policy.AMBIGUOUS)
        return result
