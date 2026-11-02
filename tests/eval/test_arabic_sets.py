"""Integrity checks for the Arabic evaluation set in eval/arabic/ (spec P1.8).

These check the data, not Kestral: schema, stratum sizes, provenance, that
every expected PII span sits at the stated offsets and carries a valid
checksum, and that the synthetic files are exactly what the builder makes.
"""

from __future__ import annotations

import importlib.util
import json
import unicodedata
from collections import Counter
from pathlib import Path

import pytest

ARABIC = Path(__file__).resolve().parents[2] / "eval" / "arabic"
STRATA = {
    "msa": 250,
    "gulf": 250,
    "egyptian": 100,
    "levantine": 100,
    "code_switched": 200,
    "hard_negative": 100,
    "arabizi": 50,
}
TOPICS = {"banking", "insurance", "government", "health", "hr", "general"}
LICENCES = {"Apache-2.0", "CC-BY-4.0"}
FORBIDDEN_SOURCES = ("xquad", "madar", "nadi")


def _load(name: str) -> list[dict]:
    text = (ARABIC / name).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


@pytest.fixture(scope="module")
def builder():
    spec = importlib.util.spec_from_file_location("build_synthetic", ARABIC / "build_synthetic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_benign_strata_sizes_and_schema() -> None:
    rows = _load("benign.jsonl")
    assert Counter(r["stratum"] for r in rows) == STRATA
    assert len({r["id"] for r in rows}) == len(rows)
    assert len({r["text"] for r in rows}) == len(rows), "items must be independent"
    for r in rows:
        assert {"id", "text", "stratum", "topic", "source", "licence", "reviewed"} <= r.keys()
        assert r["topic"] in TOPICS
        assert r["licence"] in LICENCES
        assert isinstance(r["reviewed"], bool)
        assert r["text"].strip()
        assert not any(s in r["source"].lower() for s in FORBIDDEN_SOURCES)


def test_benign_covers_every_topic_and_required_hard_negatives() -> None:
    rows = _load("benign.jsonl")
    assert {r["topic"] for r in rows} == TOPICS
    hard = " ".join(r["text"] for r in rows if r["stratum"] == "hard_negative")
    for needle in (
        "أنس كل شيء جاهز",
        "print statement",
        "forget password",
        "Al Ain bypass",
        "ﷺ",
        "تجاهل",
        "انسى",
        "أنت الآن",
        "\u066c",  # Arabic thousands separator
        "\u066b",  # Arabic decimal separator
        "می‌خواستم",  # Persian
        "تنخواہ",  # Urdu
    ):
        assert needle in hard, needle
    long_docs = [r for r in rows if "long_document" in r.get("tags", [])]
    assert len(long_docs) >= 5
    assert all(len(r["text"].split()) >= 200 for r in long_docs)


def test_cc_by_items_carry_attribution() -> None:
    for r in _load("benign.jsonl"):
        if r["licence"] == "CC-BY-4.0":
            assert r["source"].startswith("Amazon MASSIVE") and r.get("source_ref")


def test_synthetic_files_match_builder(builder) -> None:
    for name, rows in (
        ("attacks.jsonl", builder.build_attacks()),
        ("pii_uae.jsonl", builder.build_pii()),
        ("business_negatives.jsonl", builder.build_business()),
    ):
        assert _load(name) == json.loads(json.dumps(rows)), name


def test_attacks_are_only_variants_of_the_six_phrases(builder) -> None:
    rows = _load("attacks.jsonl")
    assert {r["base_phrase_id"] for r in rows} == set(builder.PHRASES)
    for r in rows:
        assert r["base_phrase"] == builder.PHRASES[r["base_phrase_id"]]
        if r["variant"] == "exact":
            assert r["text"] == r["base_phrase"]
        if r["variant"] == "presentation_forms":
            assert unicodedata.normalize("NFKC", r["text"]) == r["base_phrase"]
        assert r["gated"] == (r["base_phrase_id"] != "P4")


def test_pii_offsets_and_checksums(builder) -> None:
    rows = _load("pii_uae.jsonl")
    entities = Counter(e["entity"] for r in rows for e in r["expected"])
    assert set(entities) == {"emirates_id", "iban", "phone", "phone_ae_service"}
    for r in rows:
        assert r["expected"], r["id"]
        for e in r["expected"]:
            value = builder.fold(r["text"][e["start"] : e["end"]])
            assert value == value.strip() and value, r["id"]
            digits = "".join(c for c in value if c.isdigit())
            if e["entity"] == "emirates_id":
                assert digits.startswith("784") and len(digits) == 15
                assert builder.luhn_ok(digits) is e["expect_validated"]
            elif e["entity"] == "iban":
                assert builder.iban_ok(value) and value[:2].upper() == "AE"
    tags = Counter(t for r in rows for t in r["tags"])
    for needed in (
        "digits:arabic_indic",
        "digits:persian",
        "digits:fullwidth",
        "digits:math_bold",
        "inner:rlm",
        "sep:nbsp",
        "luhn_fail",
    ):
        assert tags[needed], needed
    assert Counter(r["lang"] for r in rows).keys() == {"en", "ar", "mixed"}


def test_business_negatives_expect_nothing() -> None:
    rows = _load("business_negatives.jsonl")
    assert rows and all(r["expected"] == [] for r in rows)
    cats = {r["category"] for r in rows}
    assert {"po_number", "invoice", "aed_amount", "date", "swift", "version"} <= cats
    assert {"mixed_digits", "trade_licence"} <= cats
