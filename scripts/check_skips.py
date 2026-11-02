"""Fail when pytest skipped a test that is not on the allowed list.

A green run must mean the tests ran. Optional integrations skip themselves
when their package is missing, which would otherwise hide a broken install.

Usage: python scripts/check_skips.py junit.xml tests/allowed_skips.txt
Each non-comment line of the allowed list is a regular expression matched
against "<test id> :: <skip reason>".
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET


def skipped(junit_path: str) -> list[str]:
    found = []
    for case in ET.parse(junit_path).getroot().iter("testcase"):
        skip = case.find("skipped")
        if skip is None:
            continue
        test_id = f"{case.get('classname', '')}.{case.get('name', '')}"
        found.append(f"{test_id} :: {skip.get('message', '')}")
    return found


def allowed(list_path: str) -> list[re.Pattern[str]]:
    with open(list_path, encoding="utf-8") as handle:
        lines = [line.strip() for line in handle]
    return [re.compile(line) for line in lines if line and not line.startswith("#")]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    patterns = allowed(argv[2])
    unexpected = [s for s in skipped(argv[1]) if not any(p.search(s) for p in patterns)]
    for entry in unexpected:
        print(f"unexpected skip: {entry}")
    if unexpected:
        print(f"{len(unexpected)} test(s) skipped without being on {argv[2]}")
        return 1
    print("no unexpected skips")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
