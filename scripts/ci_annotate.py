"""Turn failed tests in a JUnit report into GitHub Actions error annotations.

Annotations show on the run page next to the failing job, so a failure can
be read without downloading logs.

Usage: python scripts/ci_annotate.py junit.xml [limit]
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    limit = int(argv[2]) if len(argv) > 2 else 20
    shown = 0
    for case in ET.parse(argv[1]).getroot().iter("testcase"):
        problem = case.find("failure")
        if problem is None:
            problem = case.find("error")
        if problem is None:
            continue
        shown += 1
        if shown > limit:
            break
        title = f"{case.get('classname', '')}.{case.get('name', '')}"
        detail = (problem.get("message") or "") + "\n" + (problem.text or "")[-1500:]
        print(f"::error title={_escape(title)}::{_escape(detail.strip())}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
