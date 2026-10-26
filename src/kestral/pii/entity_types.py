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
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "US phone number",
    ),
    (
        EntityType.PHONE,
        r"\+\d{1,3}[-.\s]?\d{4,14}",
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
    (
        EntityType.API_KEY,
        r"\bAKIA[0-9A-Z]{16}\b",
        "AWS access key ID",
    ),
    (
        EntityType.API_KEY,
        r"\bghp_[a-zA-Z0-9]{36}\b",
        "GitHub personal access token",
    ),
    (
        EntityType.API_KEY,
        r"\bgho_[a-zA-Z0-9]{36}\b",
        "GitHub OAuth token",
    ),
    (
        EntityType.API_KEY,
        r"\bghu_[a-zA-Z0-9]{36}\b",
        "GitHub user-to-server token",
    ),
    (
        EntityType.API_KEY,
        r"\bxox[bpras]-[a-zA-Z0-9\-]+",
        "Slack token",
    ),
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
