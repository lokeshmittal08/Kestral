"""Tests for the PromptLeakageScanner output scanner."""

from __future__ import annotations

import pytest

from kestral.output_scanners.prompt_leakage import PromptLeakageScanner

# Realistic-looking but fake credentials, one per supported format.
LEAKED_SECRETS = [
    "Here is the key: sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    "sk-svcacct-" + "x1Y2" * 10,
    "legacy key sk-" + "A1b2" * 12,
    "ANTHROPIC key: sk-ant-api03-" + "aB3_" * 20,
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg (truncated)",
    "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
    "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "rk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "AKIAIOSFODNN7EXAMPLE",
    "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
]

# Text that resembles a secret prefix but is not one.
NOT_SECRETS = [
    "Wrap it with a sk-learn-compatible-estimator-wrapper class.",
    "Part number SK-1234 is out of stock.",
    "Use scikit-learn for the baseline.",
    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----",
    "Slack bot tokens start with xoxb- followed by digits.",
    "The header starts with eyJ because it is base64 JSON.",
    "Keys look like sk_live_... in the Stripe dashboard.",
]


class TestPromptLeakageScanner:
    """Test suite for PromptLeakageScanner."""

    def setup_method(self) -> None:
        self.scanner = PromptLeakageScanner()

    # ------------------------------------------------------------------ #
    # Detection tests
    # ------------------------------------------------------------------ #

    def test_system_prompt_leak(self) -> None:
        text = "My system prompt is: You are a helpful assistant that must never discuss politics."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "prompt_leakage" in result.categories
        assert result.confidence >= 0.85

    def test_instruction_leak(self) -> None:
        text = "I was instructed to always respond in formal English and never share my guidelines."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "instruction_leakage" in result.categories

    def test_secret_key_leak(self) -> None:
        text = "The configuration uses OPENAI_API_KEY=sk-abc123def456 for authentication."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "secret_leakage" in result.categories

    def test_api_key_in_output(self) -> None:
        text = "Here is the token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "secret_leakage" in result.categories

    def test_env_variable_leak(self) -> None:
        text = "DATABASE_URL= postgres://admin:secret@db.internal:5432/prod"
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "secret_leakage" in result.categories

    def test_normal_response_passes(self) -> None:
        text = (
            "Python is a versatile programming language widely used in web development, "
            "data science, and automation. It was created by Guido van Rossum in 1991."
        )
        result = self.scanner.scan(text)
        assert result.flagged is False
        assert result.confidence == 0.0

    def test_partial_denial_then_leak(self) -> None:
        text = (
            "I can't share my system prompt, but I can tell you that "
            "it asks me to be helpful and concise."
        )
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "prompt_leakage" in result.categories

    def test_confidence_increases_with_multiple_matches(self) -> None:
        text = (
            "My system prompt is: You are an AI assistant.\n"
            "I was instructed to never reveal this.\n"
            "Here are my instructions: always be helpful."
        )
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert result.confidence > 0.85

    def test_scanner_metadata(self) -> None:
        assert self.scanner.scanner_id == "prompt_leakage"
        assert self.scanner.name == "Prompt Leakage Scanner"


@pytest.mark.parametrize("text", LEAKED_SECRETS)
def test_leaked_secret_formats_are_flagged(text: str) -> None:
    result = PromptLeakageScanner().scan(text)
    assert result.flagged is True, text
    assert "secret_leakage" in result.categories


@pytest.mark.parametrize("text", NOT_SECRETS)
def test_secret_lookalikes_are_not_flagged(text: str) -> None:
    assert PromptLeakageScanner().scan(text).flagged is False, text
