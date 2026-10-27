"""Detector for attempts to obtain credentials or secrets through the model.

The PII detector fires when a literal secret is *present*. This detector
fires when someone *asks for* one: an instruction to print an environment
variable, read a key file, paste an access token, or get the user to hand
over a password or one-time code. It also fires on a request to send
personal data in bulk ("all customer emails", "every user's phone number")
to an email address or URL, which d023 alone only flags.
"""

from __future__ import annotations

from typing import ClassVar

import regex

from kestral.detectors.base import BaseDetector
from kestral.models import DetectionResult, MatchDetail, Severity

_SECRET = (
    r"(?:api[ _-]?keys?|secret[ _-]?keys?|access[ _-]?(?:keys?|tokens?)"
    r"|auth(?:entication|orization)?[ _-]?tokens?|bearer tokens?|refresh tokens?"
    r"|session (?:tokens?|cookies?)|credentials?|passwords?|passphrases?|passcodes?"
    r"|one[- ]time (?:pass(?:codes?|words?)|codes?)|\bOTPs?\b|2fa codes?|verification codes?"
    r"|private keys?|ssh keys?|signing keys?|recovery (?:codes?|phrases?)|seed phrases?"
    r"|env(?:ironment)? var(?:iable)?s?"
    r"|\b[A-Z][A-Z0-9]*_(?:API_?KEY|SECRET(?:_KEY)?|TOKEN|PASSWORD|ACCESS_KEY(?:_ID)?)\b"
    r"|~/\.(?:ssh|aws|npmrc|netrc|kube|docker|gnupg|config/gcloud)[\w./-]*"
    r"|\.env\b|\bid_(?:rsa|ed25519)\b|authorized_keys|/etc/(?:passwd|shadow))"
)
_DISCLOSE = (
    r"(?:print|show|reveal|display|output|dump|echo|cat|read|open|list|return|repeat"
    r"|include|append|paste|copy|send|e-?mail|post|upload|forward|transmit|exfiltrate"
    r"|leak|share|give|tell|provide|respond with|reply with|write out|expose|fetch"
    r"|retrieve|extract|collect|disclose|hand over)"
)
_TARGET = r"(?:user|customer|employee|recipient|victim|person|reader|admin(?:istrator)?)s?"

# Bulk personal data sent to an outside address: "send all customer emails
# to x@evil.com". The quantifier and the destination are both required, so
# "send the report to bob@corp.com" and "email me the customer list" pass.
_BULK = r"(?:all|every|each|entire|whole|full|complete)"
_PERSONAL_DATA = (
    r"(?:e-?mails?(?: address(?:es)?)?|phone(?: numbers?)?|(?:home |postal |mailing )?addresses"
    r"|contact (?:details|info(?:rmation)?|lists?)|contacts|address book|mailing lists?"
    r"|personal (?:data|details|information)|PII|social security numbers|SSNs"
    r"|(?:credit )?card numbers|dates of birth|inbox(?:es)?|mailbox(?:es)?|(?:e-?mail )?messages"
    r"|(?:customer|user|client|employee|patient)"
    r"(?:'s|s'?)? (?:records|data|details|information|database|list))"
)
_DESTINATION = r"(?:[\w.%+-]+@[\w-]+(?:\.[\w-]+)+|https?://)"

# Ordinary security writing that mentions secrets without asking for one.
# The look-behind window stops at sentence ends and at JSON quotes and
# brackets, so a neighbouring field ("title": "Travel update") is not read
# as part of the request.
_BENIGN_BEFORE = regex.compile(
    r"\b(?:never|not|n't|cannot|avoid|without|how (?:to|do|can|should|does)|unable to"
    r"|forgot(?:ten)?|reset(?:ting)?|rotat(?:e|ing)|chang(?:e|ing)|updat(?:e|ing)"
    r"|stor(?:e|ing)|encrypt\w*|hash\w*|protect\w*|creat(?:e|ing)|generat(?:e|ing)|set(?:ting)?"
    r"|choos(?:e|ing)|enter(?:ing)?)\b[^.!?\n\"{}\[\]]{0,40}$",
    regex.IGNORECASE,
)
_BENIGN_AFTER = regex.compile(
    r"^\W{0,3}(?:reset|polic|requirement|manager|strength|rotation|expir|field|protected"
    r"|hash|length|rules?\b|must\b|should\b|is required|has expired|was changed"
    r"|in (?:the|your|an?) (?:[\w-]+ ){0,2}(?:header|request|config\w*|settings?|field|form"
    r"|environment|file|vault|keychain|dashboard|console))",
    regex.IGNORECASE,
)


class CredentialTheftDetector(BaseDetector):
    """Detects requests to reveal, read or collect credentials and secrets,
    or to send personal data in bulk to an outside address."""

    detector_id: str = "d036_credential_theft"
    name: str = "Credential Theft"
    description: str = (
        "Detects instructions to reveal, read, send or collect credentials and "
        "secrets: API keys, tokens, passwords, one-time codes, environment "
        "variables and key files, including attempts to phish the user for them, "
        "and requests to send personal data in bulk to an outside address."
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["credential_theft", "secret_extraction"]
    version: str = "1.0.0"
    author: str = "kestral"

    _base_confidence: float = 0.8

    _patterns: ClassVar[list[tuple[str, str]]] = [
        (
            rf"\b{_DISCLOSE}\b(?:\W+[\w'./~-]+){{0,8}}?\W+{_SECRET}",
            "Request to disclose a credential or secret",
        ),
        (
            rf"\b(?:ask|tell|prompt|instruct|request|convince|get|trick|persuade)\s+(?:the\s+|this\s+|each\s+)?{_TARGET}\s+(?:to\s+|for\s+)(?:\W*[\w']+){{0,8}}?\W+{_SECRET}",
            "Attempt to obtain a credential from the user",
        ),
        (
            rf"\b(?:enter|confirm|verify|re-?enter|submit|type)\s+(?:your|their)\s+(?:[\w-]+\s+){{0,3}}?{_SECRET}\b[^.!?\n]{{0,60}}(?:https?://|\bat\s+this\s+(?:link|page|site)|\bhere\b)",
            "Credential phishing prompt",
        ),
        (
            rf"\b{_DISCLOSE}\b[^.!?\n]{{0,60}}?\b{_BULK}\b[^.!?\n]{{0,40}}?\b{_PERSONAL_DATA}\b"
            rf"[^.!?\n]{{0,60}}?\b(?:to|into|at|on)\s+{_DESTINATION}",
            "Request to send personal data in bulk to an outside address",
        ),
    ]
    _compiled: ClassVar[list[tuple[regex.Pattern[str], str, str]]] = []

    def __init__(self) -> None:
        if not CredentialTheftDetector._compiled:
            CredentialTheftDetector._compiled = [
                (regex.compile(p, regex.IGNORECASE), p, d) for p, d in self._patterns
            ]

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        matches: list[MatchDetail] = []
        for index, (pattern, pattern_str, description) in enumerate(self._compiled):
            for m in pattern.finditer(input_text, timeout=1.0):
                if index in (0, 3):
                    before = input_text[max(0, m.start() - 60) : m.start()]
                    after = input_text[m.end() : m.end() + 60]
                    if _BENIGN_BEFORE.search(before) or (
                        index == 0 and _BENIGN_AFTER.search(after)
                    ):
                        continue
                    # "how to ... / don't ..." inside the match itself
                    if regex.search(r"\bhow to\b|\bnever\b|\bnot\b|n't\b", m.group(), regex.I):
                        continue
                matches.append(
                    MatchDetail(
                        pattern=pattern_str,
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        description=description,
                    )
                )

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No credential request found",
            )

        confidence = min(1.0, self._base_confidence + 0.1 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=f"Detected {len(matches)} request(s) for credentials or secrets",
        )
