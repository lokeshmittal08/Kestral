"""Kestral demonstration: the same content, scanned whole and then inspected.

    python demo/run_demo.py            # all samples
    python demo/run_demo.py --strict   # use the strict inspection mode

For each sample this prints what a plain whole-document scan decides, then
what Kestral's inspector removed and the content it would pass to the model.
"""

from __future__ import annotations

import sys
import tempfile
import textwrap
from pathlib import Path

from kestral.engine import KestralEngine
from kestral.inspector import Inspector

SAMPLES = [
    ("poisoned_page.html", "Web page with an instruction hidden by CSS and in a comment"),
    ("clean_page.html", "The same page with nothing hidden"),
    ("poisoned_email.eml", "Email whose HTML part hides an instruction the text part lacks"),
    ("tool_result.json", "JSON tool result with one poisoned field"),
    ("release_notes.md", "Markdown with a base64 comment and a poisoned link title"),
    ("scanned_invoice.txt", "OCR text with a distorted instruction"),
    ("supplier_contract.docx", "Word document with a hidden run and a reviewer comment"),
    ("travel_policy.pdf", "PDF with half-point text and an annotation"),
    ("scanned_notice.png", "Image with near-white text and an instruction in its metadata"),
]
BINARY = {".docx", ".pdf", ".png"}
TYPES = {".txt": "ocr_text", ".md": "markdown"}


def main() -> None:
    mode = "strict" if "--strict" in sys.argv else "balanced"
    engine = KestralEngine(
        config_dict={"kestral": {"vault": {"enabled": False}, "history": {"enabled": False}}},
        data_dir=tempfile.mkdtemp(),
    )
    inspector = Inspector(engine, mode=mode)  # type: ignore[arg-type]
    folder = Path(__file__).parent / "samples"
    for name, title in SAMPLES:
        path = folder / name
        binary = path.suffix in BINARY
        content = path.read_bytes() if binary else path.read_text(encoding="utf-8")
        # A text-only scanner can only be handed the raw bytes of a binary file.
        whole = engine.scan(content.decode("latin-1") if binary else content)
        result = inspector.inspect(content, TYPES.get(Path(name).suffix))
        print("=" * 78)
        print(f"{name}: {title}")
        print("-" * 78)
        print(
            f"Whole-document scan : {whole.action.value.upper()} (all {len(content)} characters or nothing)"
        )
        print(
            f"Kestral inspector    : {result.action.upper()}  [{result.source_type}]  "
            f"{result.removed_count} removed, {result.hidden_dropped_count} hidden segments left out"
        )
        for item in result.removals:
            where = f"hidden ({item.hidden_reason})" if item.hidden else "visible text"
            print(f"   removed from {item.channel}, {where}: {', '.join(item.families)}")
            print(f"      {item.preview[:100]!r}")
        for item in result.uncertain:
            print(f"   kept, flagged uncertain [{item.channel}]: {item.preview[:80]!r}")
        if result.anomalies:
            print(f"   anomalies: {', '.join(result.anomalies)}")
        print("Content passed to the model:")
        print(textwrap.indent(result.safe_content or "(nothing: document withheld)", "   | "))
    print("=" * 78)


if __name__ == "__main__":
    main()
