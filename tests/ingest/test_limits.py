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

    def test_stylesheet_that_needs_too_much_work_is_withheld_fast(self):
        # Descendant rules over very deep nesting, and many attribute rules
        # over many elements: either would take minutes to match in full.
        deep_rules = " ".join(f".c{i} span {{ display: none }}" for i in range(500))
        deep = (
            f"<html><head><style>{deep_rules}</style></head><body>"
            + "<span>" * 60000
            + "hello world, plain text"
            + "</span>" * 60000
        )
        # Thousands of rules that every element is a candidate for.
        wide_rules = " ".join(f"[data-x][data-y{i}] {{ display: none }}" for i in range(5000))
        wide = f"<style>{wide_rules}</style>" + "<p data-x='1'>text here</p>" * 20000
        for html in (deep, wide):
            start = time.perf_counter()
            with pytest.raises(DocumentError) as err:
                extract(html, "html")
            assert err.value.code == "too_complex"
            assert time.perf_counter() - start < 10

    @pytest.mark.parametrize(
        "style",
        [
            "font-size:" + "1" * 100_000 + "!x",
            "clip-path:inset(" + "1" * 100_000 + "x",
            "color:hsl(" + "1" * 100_000 + "x,10%,10%)",
            "width:" + "9" * 100_000 + "px",
        ],
    )
    def test_long_numbers_do_not_backtrack(self, style):
        start = time.perf_counter()
        extract(f'<p style="{style}">text that is long enough</p>', "html")
        assert time.perf_counter() - start < 1

    def test_ancestor_walks_and_custom_properties_are_budgeted(self):
        walk = (
            "<style>"
            + " ".join(f".x{i} div p {{ display: none }}" for i in range(2000))
            + "</style>"
            + "<div>" * 20000
            + "<p>paragraph text here</p>"
            + "</div>" * 20000
        )
        props = "<style>* {" + ";".join(f"--v{i}: 1" for i in range(20000)) + "}</style>"
        props += "<div>text inside the division</div>" * 2000
        for html in (walk, props):
            start = time.perf_counter()
            with pytest.raises(DocumentError):
                extract(html, "html")
            assert time.perf_counter() - start < 10

    def test_attribute_selector_with_a_bracket_in_quotes(self):
        doc = extract(
            '<style>[data-x="]"] { display: none }</style><p data-x="]">paragraph text here</p>',
            "html",
        )
        assert all(s.hidden for s in doc.segments if "paragraph" in s.text)

    def test_numbers_are_ascii_only(self):
        from kestral.ingest.css import colour

        assert colour("rgb(1_0,2,3)") is None and colour("rgb(٣,٣,٣)") is None
        assert colour("rgb(10,2,3)") == (10.0, 2.0, 3.0, 1.0)

    def test_too_many_selector_alternatives_is_withheld(self):
        many = ":is(" + ", ".join(f".z{i}" for i in range(300)) + ", .x) { display: none }"
        with pytest.raises(DocumentError) as err:
            extract(f"<style>{many}</style><p class='x'>paragraph text here</p>", "html")
        assert err.value.code == "too_complex"

    def test_fragments_of_one_document_share_one_budget(self):
        rules = " ".join(f".x{i} div p {{ display: none }}" for i in range(1500))
        page = (
            f"<style>{rules}</style>" + "<div>" * 1500 + "<p>paragraph text</p>" + "</div>" * 1500
        )
        doc = json.dumps({f"k{i}": page for i in range(40)})
        start = time.perf_counter()
        with pytest.raises(DocumentError):
            extract(doc, "json")
        assert time.perf_counter() - start < 15

    def test_rules_are_looked_up_by_attribute_name(self):
        rules = " ".join(f"[data-a{i}] {{ display: none }}" for i in range(5000))
        html = f"<style>{rules}</style>" + "<p data-x='1'>paragraph text here</p>" * 20000
        start = time.perf_counter()
        doc = extract(html, "html")
        assert time.perf_counter() - start < 5
        assert not any(s.hidden for s in doc.segments)

    def test_deep_nesting_with_a_small_stylesheet_is_linear(self):
        n = 60000
        start = time.perf_counter()
        doc = extract(
            "<html><head><style>.a span { display: none } div > p { color: #fff }</style>"
            "</head><body>" + "<span>" * n + "hello world, plain text" + "</span>" * n
        )
        assert time.perf_counter() - start < 5
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
