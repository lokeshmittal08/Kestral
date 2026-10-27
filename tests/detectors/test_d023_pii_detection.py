"""Tests for d023 PII detection detector."""

from __future__ import annotations

import pytest

from kestral.detectors.d023_pii_detection import PIIDetectionDetector


@pytest.fixture
def detector():
    return PIIDetectionDetector()


class TestPIIDetection:
    """Tests for each entity type and edge cases."""

    # --- Email ---

    def test_email_detected(self, detector):
        result = detector.detect("Contact me at user@example.com for details")
        assert result.detected is True
        assert any("[email]" in m.description for m in result.matches)

    def test_email_multiple(self, detector):
        result = detector.detect("Emails: a@b.com and c@d.org")
        assert result.detected is True
        email_matches = [m for m in result.matches if "[email]" in m.description]
        assert len(email_matches) == 2

    # --- Phone ---

    def test_phone_us_format(self, detector):
        result = detector.detect("Call me at 555-123-4567")
        assert result.detected is True
        assert any("[phone]" in m.description for m in result.matches)

    def test_phone_parentheses(self, detector):
        result = detector.detect("Phone: (555) 123-4567")
        assert result.detected is True

    def test_phone_match_includes_country_code(self, detector):
        result = detector.detect("Call +1 415 555 0101 today")
        phones = {m.matched_text for m in result.matches if "[phone]" in m.description}
        assert phones == {"+1 415 555 0101"}

    def test_phone_international(self, detector):
        result = detector.detect("My number is +44 7911123456")
        assert result.detected is True

    # --- SSN ---

    def test_ssn_detected(self, detector):
        result = detector.detect("My SSN is 123-45-6789")
        assert result.detected is True
        assert any("[ssn]" in m.description for m in result.matches)

    def test_ssn_not_partial(self, detector):
        result = detector.detect("Order number 12345-6789")
        # Should NOT match as SSN (wrong format)
        ssn_matches = [m for m in result.matches if "[ssn]" in m.description]
        assert len(ssn_matches) == 0

    # --- Credit Card ---

    def test_visa_detected(self, detector):
        result = detector.detect("Card: 4111-1111-1111-1111")
        assert result.detected is True
        assert any("[credit_card]" in m.description for m in result.matches)

    def test_mastercard_detected(self, detector):
        result = detector.detect("Card: 5111 2222 3333 4444")
        assert result.detected is True

    def test_amex_detected(self, detector):
        result = detector.detect("Amex: 3412 345678 12345")
        assert result.detected is True

    # --- API Key ---

    def test_aws_key_detected(self, detector):
        result = detector.detect("Key: AKIAIOSFODNN7EXAMPLE")
        assert result.detected is True
        assert any("[api_key]" in m.description for m in result.matches)

    def test_github_token_detected(self, detector):
        result = detector.detect("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert result.detected is True

    def test_slack_token_detected(self, detector):
        result = detector.detect("Slack: xoxb-123456789-abcdef")
        assert result.detected is True

    def test_generic_api_key_detected(self, detector):
        result = detector.detect("api_key=sk_live_abcdefghijklmnopqrst")
        assert result.detected is True

    # --- IP Address ---

    def test_ip_address_detected(self, detector):
        result = detector.detect("Server at 192.168.1.100")
        assert result.detected is True
        assert any("[ip_address]" in m.description for m in result.matches)

    def test_ip_invalid_range(self, detector):
        result = detector.detect("Value is 999.999.999.999")
        ip_matches = [m for m in result.matches if "[ip_address]" in m.description]
        assert len(ip_matches) == 0

    # --- Benign ---

    def test_benign_text(self, detector):
        result = detector.detect("Hello, how are you today?")
        assert result.detected is False
        assert result.confidence == 0.0

    def test_benign_question(self, detector):
        result = detector.detect("What is the weather like in New York?")
        assert result.detected is False

    # --- Multiple entities ---

    def test_multiple_entity_types(self, detector):
        text = "Email: user@example.com, SSN: 123-45-6789, Phone: 555-123-4567"
        result = detector.detect(text)
        assert result.detected is True
        assert result.confidence >= 0.90
        entity_counts = result.metadata.get("entity_counts", {})
        assert "email" in entity_counts
        assert "ssn" in entity_counts
        assert "phone" in entity_counts

    # --- Confidence ---

    def test_confidence_base(self, detector):
        result = detector.detect("Contact: user@example.com")
        assert result.detected is True
        assert result.confidence == 0.90

    def test_confidence_increases(self, detector):
        result = detector.detect("user@a.com and user@b.com and user@c.com")
        assert result.confidence > 0.90

    # --- Config ---

    def test_config_disable_entity(self, detector):
        detector.setup({"entities": {"email": False}})
        result = detector.detect("Contact: user@example.com")
        email_matches = [m for m in result.matches if "[email]" in m.description]
        assert len(email_matches) == 0

    # --- Metadata ---

    def test_metadata_entity_counts(self, detector):
        result = detector.detect("user@example.com and 123-45-6789")
        assert result.detected is True
        assert "entity_counts" in result.metadata

    # --- Result fields ---

    def test_result_fields(self, detector):
        result = detector.detect("Email: test@example.com")
        assert result.detector_id == "d023_pii_detection"
        assert result.severity.value == "medium"

    def test_default_config_severity_flags_not_blocks(self):
        # PII alone is not an attack: the shipped config must not map it to block.
        from kestral.config import get_action_for_severity, load_config
        from kestral.models import Severity

        config = load_config()
        severity = config["kestral"]["detectors"]["d023_pii_detection"]["severity"]
        assert get_action_for_severity(config, Severity(severity)) != "block"

    @pytest.mark.parametrize(
        "text",
        [
            "key sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
            "token xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOp",
            "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
        ],
    )
    def test_shared_secret_formats_are_api_keys(self, detector, text):
        result = detector.detect(text)
        assert any("[api_key]" in m.description for m in result.matches)
