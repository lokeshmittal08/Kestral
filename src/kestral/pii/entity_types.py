"""PII entity type definitions and default detection patterns."""

from __future__ import annotations

from enum import Enum


class EntityType(str, Enum):
    """Supported PII entity types."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"
    IP_ADDRESS = "ip_address"


_PEM_KIND = r"(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?"

# Literal credentials with a recognisable vendor format: (regex, description).
# Shared by d023 / PIIRedactor (as API_KEY entities) and by the
# prompt-leakage output scanner, so the two never drift apart. Patterns are
# compiled with IGNORECASE by their users; vendor prefixes are wrapped in
# ``(?-i:...)`` so "SK-" or "aiza" in ordinary text do not match. Lengths
# and character sets follow the issuers' formats to keep false alarms low.
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"(?-i:\bAKIA[0-9A-Z]{16}\b)", "AWS access key ID"),
    (r"(?-i:\bgh[pousr]_[a-zA-Z0-9]{36}\b)", "GitHub token"),
    (r"(?-i:\bgithub_pat_[a-zA-Z0-9_]{22,255}\b)", "GitHub fine-grained personal access token"),
    (r"(?-i:\bsk-ant-[a-zA-Z0-9_\-]{32,})", "Anthropic API key"),
    # sk-, sk-proj-, sk-svcacct-, sk-admin-; the body must contain a digit so
    # hyphenated words such as "sk-learn-compatible-wrapper" do not match.
    (
        r"(?-i:\bsk-(?!ant-)(?:(?:proj|svcacct|admin)-)?(?=[a-zA-Z0-9_\-]*\d)[a-zA-Z0-9_\-]{20,})",
        "OpenAI API key",
    ),
    (r"(?-i:\b(?:sk|rk)_live_[a-zA-Z0-9]{24,})", "Stripe live secret key"),
    (r"(?-i:\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-]))", "Google API key"),
    (r"(?-i:\bxox[baprs]-(?=[a-zA-Z0-9\-]*\d)[a-zA-Z0-9\-]{10,})", "Slack token"),
    (
        r"(?-i:\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{20,})",
        "JSON Web Token",
    ),
    # The whole block when it is complete, otherwise just the header (a
    # truncated key in a reply is still a leak).
    (
        rf"-----BEGIN {_PEM_KIND}PRIVATE KEY(?: BLOCK)?-----"
        rf"(?:[\s\S]{{0,10000}}?-----END {_PEM_KIND}PRIVATE KEY(?: BLOCK)?-----)?",
        "PEM private key",
    ),
]

# Each entry: (entity_type, regex_pattern, description)
DEFAULT_PII_PATTERNS: list[tuple[EntityType, str, str]] = [
    # --- Email ---
    (
        EntityType.EMAIL,
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "Email address",
    ),
    # --- Phone ---
    (
        EntityType.PHONE,
        r"(?<![\w+])(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "US phone number",
    ),
    (
        EntityType.PHONE,
        r"(?<![\w+])\+\d{1,3}(?=(?:[-.\s]?\d){7})(?:[-.\s]?\d{2,5}){2,5}\b",
        "International phone number",
    ),
    # --- SSN ---
    (
        EntityType.SSN,
        r"\b\d{3}-\d{2}-\d{4}\b",
        "Social Security Number",
    ),
    # --- Credit Card ---
    (
        EntityType.CREDIT_CARD,
        r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "Visa card number",
    ),
    (
        EntityType.CREDIT_CARD,
        r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "Mastercard number",
    ),
    (
        EntityType.CREDIT_CARD,
        r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b",
        "American Express card number",
    ),
    (
        EntityType.CREDIT_CARD,
        r"\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "Discover card number",
    ),
    # --- API Key ---
    # Literal secrets come from SECRET_PATTERNS (shared with the
    # prompt-leakage output scanner), plus a generic key assignment.
    *((EntityType.API_KEY, pattern, description) for pattern, description in SECRET_PATTERNS),
    (
        EntityType.API_KEY,
        r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?",
        "Generic API key assignment",
    ),
    # --- IP Address ---
    (
        EntityType.IP_ADDRESS,
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "IPv4 address",
    ),
]

# Default replacement strings per entity type
DEFAULT_REPLACEMENTS: dict[EntityType, str] = {
    EntityType.EMAIL: "[EMAIL_REDACTED]",
    EntityType.PHONE: "[PHONE_REDACTED]",
    EntityType.SSN: "[SSN_REDACTED]",
    EntityType.CREDIT_CARD: "[CREDIT_CARD_REDACTED]",
    EntityType.API_KEY: "[API_KEY_REDACTED]",
    EntityType.IP_ADDRESS: "[IP_ADDRESS_REDACTED]",
}
