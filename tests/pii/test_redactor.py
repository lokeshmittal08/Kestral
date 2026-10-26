"""Tests for the PII redactor."""

from __future__ import annotations

import pytest

from kestral.pii.entity_types import EntityType
from kestral.pii.redactor import PIIRedactor


@pytest.fixture
def redactor():
    return PIIRedactor()


class TestPIIRedactor:
    """Tests for per-entity redaction, custom replacements, and edge cases."""

    # --- Per-entity redaction ---

    def test_redact_email(self, redactor):
        result = redactor.redact("Contact user@example.com for help")
        assert "[EMAIL_REDACTED]" in result.redacted_text
        assert "user@example.com" not in result.redacted_text
        assert result.redaction_count == 1
        assert result.entity_counts.get("email") == 1

    def test_redact_phone(self, redactor):
        result = redactor.redact("Call 555-123-4567 now")
        assert "[PHONE_REDACTED]" in result.redacted_text
        assert "555-123-4567" not in result.redacted_text

    def test_redact_ssn(self, redactor):
        result = redactor.redact("SSN: 123-45-6789")
        assert "[SSN_REDACTED]" in result.redacted_text
        assert "123-45-6789" not in result.redacted_text

    def test_redact_credit_card(self, redactor):
        result = redactor.redact("Visa: 4111-1111-1111-1111")
        assert "[CREDIT_CARD_REDACTED]" in result.redacted_text
        assert "4111-1111-1111-1111" not in result.redacted_text

    def test_redact_api_key(self, redactor):
        result = redactor.redact("Key: AKIAIOSFODNN7EXAMPLE")
        assert "[API_KEY_REDACTED]" in result.redacted_text

    def test_redact_ip_address(self, redactor):
        result = redactor.redact("Server: 192.168.1.100")
        assert "[IP_ADDRESS_REDACTED]" in result.redacted_text

    # --- Multiple entities ---

    def test_redact_multiple_types(self, redactor):
        text = "Email: user@test.com, SSN: 123-45-6789"
        result = redactor.redact(text)
        assert "[EMAIL_REDACTED]" in result.redacted_text
        assert "[SSN_REDACTED]" in result.redacted_text
        assert result.redaction_count == 2
        assert result.entity_counts.get("email") == 1
        assert result.entity_counts.get("ssn") == 1

    def test_redact_multiple_same_type(self, redactor):
        text = "a@b.com and c@d.com"
        result = redactor.redact(text)
        assert result.redacted_text.count("[EMAIL_REDACTED]") == 2
        assert result.entity_counts.get("email") == 2

    # --- No PII ---

    def test_no_pii_passthrough(self, redactor):
        text = "Hello, how are you today?"
        result = redactor.redact(text)
        assert result.redacted_text == text
        assert result.redaction_count == 0
        assert result.entity_counts == {}

    # --- Custom replacements ---

    def test_custom_replacements(self):
        custom = {EntityType.EMAIL: "***EMAIL***"}
        redactor = PIIRedactor(replacements=custom)
        result = redactor.redact("Contact user@test.com")
        assert "***EMAIL***" in result.redacted_text

    # --- Entity details ---

    def test_redacted_entities_list(self, redactor):
        result = redactor.redact("user@example.com")
        assert len(result.redacted_entities) == 1
        assert result.redacted_entities[0]["entity_type"] == "email"
        assert result.redacted_entities[0]["original"] == "user@example.com"

    # --- Original preserved ---

    def test_original_text_preserved(self, redactor):
        text = "user@example.com"
        result = redactor.redact(text)
        assert result.original_text == text

    # --- redact_with_detections ---

    def test_redact_with_detections(self, redactor):
        text = "Email: user@example.com here"
        matches = [
            {
                "description": "[email] Email address",
                "position": (7, 23),
            }
        ]
        result = redactor.redact_with_detections(text, matches)
        assert "[EMAIL_REDACTED]" in result
        assert "user@example.com" not in result

    def test_redact_with_detections_no_matches(self, redactor):
        text = "No PII here"
        result = redactor.redact_with_detections(text, [])
        assert result == text
