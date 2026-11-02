"""UAE recognizers: Emirates ID, IBAN and phone numbers in any digit script."""

# Arabic text and Arabic-Indic digits are the subject of these tests.
# ruff: noqa: RUF001

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from kestral.pii import PIIRedactor
from kestral.pii.recognizers import (
    EmiratesId,
    Iban,
    PatternTable,
    Span,
    UaePhone,
    UaeServicePhone,
    check_names,
    find_all,
    luhn,
    mod97,
    resolve,
    uae_set,
)

ROOT = Path(__file__).resolve().parents[2]
NBSP, RLM, SHY = chr(0xA0), chr(0x200F), chr(0xAD)


def _jsonl(name: str) -> list[dict]:
    path = ROOT / "eval" / "arabic" / name
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _found(recognizer, text: str) -> list[str]:
    return [text[s.start : s.end] for s in recognizer.find(text)]


class TestChecksums:
    def test_luhn(self) -> None:
        assert luhn("784199012345676") and not luhn("784199012345677")
        assert luhn("4111111111111111")

    def test_mod97(self) -> None:
        assert mod97("AE070331234567890123456")
        assert not mod97("AE080331234567890123456")


class TestEmiratesId:
    def test_dashed_and_compact(self) -> None:
        eid = EmiratesId()
        assert _found(eid, "ID 784-1990-1234567-6 on file") == ["784-1990-1234567-6"]
        assert _found(eid, "ID 784199012345676.") == ["784199012345676"]

    def test_failed_check_digit(self) -> None:
        # The dashed shape is still personal data if mistyped; fifteen bare
        # digits that fail the check are likely some other number.
        dashed = list(EmiratesId().find("784-1990-1234567-1"))
        assert len(dashed) == 1 and not dashed[0].validated
        assert _found(EmiratesId(), "ref 784199012345671") == []

    def test_any_digit_script_and_invisible_characters(self) -> None:
        arabic = "رقم الهوية ٧٨٤-١٩٩٠-١٢٣٤٥٦٧-٦"
        assert _found(EmiratesId(), arabic) == ["٧٨٤-١٩٩٠-١٢٣٤٥٦٧-٦"]
        hidden = f"784-19{SHY}90-123{RLM}4567-6"
        assert _found(EmiratesId(), hidden) == [hidden]

    def test_year_must_be_plausible(self) -> None:
        assert _found(EmiratesId(), "784-1850-1234567-1") == []


class TestIban:
    @pytest.mark.parametrize(
        "iban",
        ["AE070331234567890123456", "AE07 0331 2345 6789 0123 456", "ae070331234567890123456"],
    )
    def test_forms(self, iban) -> None:
        assert _found(Iban(), f"Pay to {iban} today") == [iban]

    def test_bad_checksum_or_length_is_ignored(self) -> None:
        assert _found(Iban(), "AE080331234567890123456") == []
        assert _found(Iban(), "AE07033123456789012345") == []
        assert _found(Iban(), "AE0703312345678901234567") == []

    def test_arabic_digits(self) -> None:
        text = "الآيبان AE٠٧٠٣٣١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦ شكرا"
        assert _found(Iban(), text) == ["AE٠٧٠٣٣١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦"]


class TestUaePhone:
    @pytest.mark.parametrize(
        "number",
        [
            "+971 50 123 4567",
            "+971501234567",
            "00971 55 123 4567",
            "+971 0 56 123 4567",
            "050 123 4567",
            "0581234567",
            "04 123 4567",
            "+971 2 123 4567",
            f"050{NBSP}123{NBSP}4567",
            "٠٥٠١٢٣٤٥٦٧",
            "۰۵۵۱۲۳۴۵۶۷",
        ],
    )
    def test_numbers(self, number) -> None:
        assert _found(UaePhone(), f"call {number} now") == [number]

    def test_number_glued_to_arabic(self) -> None:
        assert _found(UaePhone(), "رقمي و0501234567") == ["0501234567"]

    @pytest.mark.parametrize(
        "text", ["0511234567", "05 1234 56", "PO 4500123456", "AED 1234567890"]
    )
    def test_not_a_uae_number(self, text) -> None:
        assert _found(UaePhone(), text) == []

    def test_reported_as_phone(self) -> None:
        assert {s.entity for s in UaePhone().find("050 123 4567")} == {"phone"}

    def test_service_numbers_are_a_separate_entity(self) -> None:
        assert _found(UaeServicePhone(), "call 800 4444 or 600 52 2222") == [
            "800 4444",
            "600 52 2222",
        ]
        redacted = PIIRedactor(recognizers=uae_set()).redact("call 800 4444").redacted_text
        assert "800 4444" in redacted


class TestEvaluationSet:
    def test_every_synthetic_value_is_found_exactly(self) -> None:
        redactor = PIIRedactor(recognizers=uae_set())
        for item in _jsonl("pii_uae.jsonl"):
            want = {
                ("phone" if e["entity"] == "phone_ae" else e["entity"], e["start"], e["end"])
                for e in item["expected"]
                if e["entity"] != "phone_ae_service"
            }
            assert set(redactor.redact(item["text"]).spans) == want, item["id"]

    def test_no_new_entity_in_business_text(self) -> None:
        new = [EmiratesId(), Iban(), UaePhone()]
        for item in _jsonl("business_negatives.jsonl"):
            assert find_all(new, item["text"]) == [], item["id"]


class TestOverlapsAndDefaults:
    def test_validated_span_wins(self) -> None:
        loose = Span(0, 12, "phone", 0.8, False)
        checked = Span(4, 22, "emirates_id", 0.95, True)
        assert resolve([loose, checked]) == [checked]

    def test_same_choice_as_checking_every_pair(self) -> None:
        import random

        rng = random.Random(7)
        for _ in range(300):
            spans = []
            for _ in range(rng.randint(0, 12)):
                start = rng.randint(0, 40)
                spans.append(Span(start, start + rng.randint(1, 10), "x", 0.5, rng.random() < 0.3))
            chosen: list[Span] = []
            by_start = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
            for span in [s for s in by_start if s.validated] + [
                s for s in by_start if not s.validated
            ]:
                if not any(span.start < c.end and c.start < span.end for c in chosen):
                    chosen.append(span)
            assert resolve(spans) == sorted(chosen, key=lambda s: s.start)

    def test_disabled_entity_does_not_hide_an_enabled_one(self) -> None:
        text = "reach me at 0501234567@gmail.com"
        spans = find_all(uae_set(), text, {"email"})
        assert [text[s.start : s.end] for s in spans] == ["0501234567@gmail.com"]

    def test_legacy_order_among_unvalidated_spans_is_unchanged(self) -> None:
        text = "host 10.0.0.255 555 1234"
        before = PIIRedactor().redact(text).redacted_text
        assert before == "host [IP_ADDRESS_REDACTED] 555 1234"
        assert PIIRedactor(recognizers=uae_set()).redact(text).redacted_text == before

    def test_eid_is_no_longer_cut_up_as_a_phone(self) -> None:
        result = PIIRedactor(recognizers=uae_set()).redact("ID 784-1990-1234567-6")
        assert result.redacted_text == "ID [EMIRATES_ID_REDACTED]"

    def test_default_redactor_keeps_its_six_types(self) -> None:
        result = PIIRedactor().redact("IBAN AE070331234567890123456")
        assert result.redaction_count == 0

    def test_plugin_names_are_checked(self) -> None:
        class Bad:
            entity = "Bad Name;DROP"
            version = "1"
            languages = frozenset({"en"})

            def find(self, text):
                return []

        with pytest.raises(ValueError):
            check_names(Bad())

    def test_unknown_recognizer_name(self) -> None:
        with pytest.raises(ValueError):
            uae_set(("passport",))


class TestCost:
    @pytest.mark.parametrize(
        "make",
        [
            lambda n: "7" * n,
            lambda n: "784-1990-" * (n // 9),
            lambda n: "AE07 " * (n // 5),
            lambda n: "0 " * (n // 2),
            lambda n: "a@" + "a." * (n // 2),
            # Thousands of values: overlap resolution must not be quadratic.
            lambda n: "a@b.co " * (n // 7),
        ],
    )
    def test_linear_on_adversarial_input(self, make) -> None:
        recognizers = [EmiratesId(), Iban(), UaePhone(), UaeServicePhone(), PatternTable()]

        def cost(n: int) -> float:
            text = make(n)
            start = time.perf_counter()
            find_all(recognizers, text)
            return time.perf_counter() - start

        small, large = cost(25_000), cost(100_000)
        # About 0.06 s on a laptop; shared CI runners are many times slower,
        # so the absolute bound only catches a pathological case.
        assert large < 5.0
        # Four times the input: well under sixteen times the time.
        assert large < 8 * small + 0.05


def test_gateway_pii_reply_mode_masks_uae_values(tmp_path) -> None:
    from kestral.engine import KestralEngine
    from kestral.gateway import Gateway
    from kestral.inspector import Inspector

    engine = KestralEngine(
        config_dict={"kestral": {"vault": {"enabled": False}}}, data_dir=str(tmp_path)
    )
    gateway = Gateway(engine, Inspector(engine), redact_replies="pii")
    reply = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Transfer to AE07 0331 2345 6789 0123 456, ID 784-1990-1234567-6",
                }
            }
        ]
    }
    assert gateway.redact_response(reply) == 2
    content = reply["choices"][0]["message"]["content"]
    assert content == "Transfer to [IBAN_REDACTED], ID [EMIRATES_ID_REDACTED]"
