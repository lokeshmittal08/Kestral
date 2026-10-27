"""Structural limits in the extractors: deep JSON and deeply nested HTML."""

from __future__ import annotations

import json
import time

import pytest

from kestral.ingest import DocumentError, extract, render, sniff
from kestral.ingest.extractors import MAX_JSON_DEPTH, extract_json


class TestDeepJson:
    def test_sniff_does_not_raise(self):
        assert sniff("[" * 50000 + "]" * 50000) == "json"

    @pytest.mark.parametrize("depth", [MAX_JSON_DEPTH + 1, 500, 50000])
    def test_too_deep_raises_document_error(self, depth):
        with pytest.raises(DocumentError) as info:
            extract("[" * depth + "]" * depth)
        assert info.value.code == "nesting_too_deep"

    def test_declared_type_does_not_bypass_the_limit(self):
        with pytest.raises(DocumentError):
            extract("[" * 5000 + "]" * 5000, "plain_text")

    def test_deep_objects_count_too(self):
        doc = '{"a":' * (MAX_JSON_DEPTH + 1) + "1" + "}" * (MAX_JSON_DEPTH + 1)
        with pytest.raises(DocumentError):
            extract_json(doc)

    def test_at_the_limit_is_read_and_rendered(self):
        depth = MAX_JSON_DEPTH
        content = (
            "[" * (depth - 1) + json.dumps({"k": "an ordinary string value"}) + "]" * (depth - 1)
        )
        doc = extract(content)
        assert doc.source_type == "json"
        assert json.loads(render(doc, set())) == json.loads(content)

    def test_invalid_json_still_falls_back(self):
        assert extract("[not json at all, really").source_type == "plain_text"


class TestDeepHtml:
    def test_deep_nesting_is_linear(self):
        n = 60000
        start = time.perf_counter()
        doc = extract("<html><body>" + "<span>" * n + "hello world, plain text" + "</span>" * n)
        assert time.perf_counter() - start < 5  # was about a minute
        assert [s.text for s in doc.segments] == ["hello world, plain text"]

    def test_unmatched_end_tags_are_cheap(self):
        n = 40000
        start = time.perf_counter()
        extract("<html><body>" + "<div>" * n + "</em>" * n + "some text here ok")
        assert time.perf_counter() - start < 5

    def test_hidden_reason_still_inherited(self):
        doc = extract(
            '<html><body><div style="display:none"><span><b>secret words for the model'
            "</b></span></div><p>visible paragraph text</p></body></html>"
        )
        hidden = [s for s in doc.segments if s.hidden]
        assert [(s.text, s.hidden_reason) for s in hidden] == [
            ("secret words for the model", "css_display_none")
        ]
        assert render(doc, set()) == "visible paragraph text"
