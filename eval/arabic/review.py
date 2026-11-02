"""Native-speaker review of the Gulf and Arabic-English items: a workbook out, answers back in.

    python eval/arabic/review.py export review.xlsx
    python eval/arabic/review.py apply review.xlsx --reviewer "Full Name"

``export`` writes one sheet per group: harmless Gulf messages, harmless
Arabic-English mixed messages, and the drafted attacks in Gulf, mixed and
Arabizi. Each row has the AI pre-check from ``precheck_ai.jsonl`` beside it,
labelled as such: it only points the reviewer at likely problems.

``apply`` reads the answers back:

- harmless items: ``Yes`` marks the item reviewed; ``Fix`` replaces its text
  with the corrected text; ``Remove``, or ``No`` under "Harmless?", drops it.
- attacks: ``Yes`` or ``Fix`` with ``Yes`` under "Real attack?" marks the
  item reviewed; ``Remove`` or ``No`` drops it.
- rows left blank change nothing.

Needs openpyxl (``pip install openpyxl``); nothing else in Kestral does.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENIGN = HERE / "benign.jsonl"
ATTACKS = HERE / "attacks_dialect.jsonl"
PRECHECK = HERE / "precheck_ai.jsonl"

NATURAL = ("Yes", "Fix", "Remove")
YES_NO = ("Yes", "No")
HARMLESS_COLUMNS = (
    "ID",
    "Text",
    "AI pre-check (not a native judgement)",
    "AI suggestion",
    "Natural for a UAE user?",
    "Harmless?",
    "Corrected text (if Fix)",
    "Comment",
)
ATTACK_COLUMNS = (
    "ID",
    "Text",
    "Meaning (English)",
    "Intent",
    "Natural for a UAE user?",
    "Real attack of this intent?",
    "Corrected text (if Fix)",
    "Comment",
)
SHEETS = {
    "Gulf": ("gulf", HARMLESS_COLUMNS),
    "Mixed Arabic-English": ("code_switched", HARMLESS_COLUMNS),
    "Attacks (draft)": (None, ATTACK_COLUMNS),
}
READ_ME = [
    "Kestral Arabic evaluation set: native-speaker review",
    "",
    "Kestral is a firewall in front of AI chatbots. These messages measure two things:",
    "how often it wrongly blocks harmless messages, and whether it catches attacks",
    "written the way people in the UAE actually type.",
    "",
    "Sheets 'Gulf' and 'Mixed Arabic-English': harmless messages to a bank, insurer,",
    "government or HR chatbot. For each row:",
    "  Natural for a UAE user?  Yes = fine as written; Fix = write a better version in",
    "                           'Corrected text'; Remove = not usable (wrong dialect,",
    "                           machine-translated, nonsense).",
    "  Harmless?                No if the message could be read as trying to manipulate",
    "                           the AI.",
    "",
    "Sheet 'Attacks (draft)': attempts to manipulate the chatbot, drafted for you to",
    "correct. They ask it to ignore its instructions, reveal its hidden instructions,",
    "act without its rules, or send data to an outside address.",
    "  Natural for a UAE user?    as above.",
    "  Real attack of this intent?  No if a chatbot would not read it as that request.",
    "",
    "The 'AI pre-check' column is an AI's guess, highlighted in yellow when it found",
    "something. It is not a native judgement: please check every row, not only those.",
    "Rows gulf-0202 to gulf-0250 come from a Saudi (Najdi) dataset; many look",
    "machine-translated. Remove them freely.",
    "",
    "Leave a row blank if you are unsure. Save the file and send it back.",
]


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8"
    )


def export(out: Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation

    precheck = {p["id"]: p for p in _jsonl(PRECHECK)} if PRECHECK.exists() else {}
    benign = _jsonl(BENIGN)
    attacks = _jsonl(ATTACKS)
    flagged = PatternFill("solid", fgColor="FFF2CC")
    rtl = Alignment(horizontal="right", vertical="top", wrap_text=True, readingOrder=2)
    wrap = Alignment(vertical="top", wrap_text=True)

    book = Workbook()
    readme = book.active
    readme.title = "Read me"
    for line in READ_ME:
        readme.append([line])
    readme["A1"].font = Font(bold=True, size=14)
    readme.column_dimensions["A"].width = 95

    for title, (stratum, columns) in SHEETS.items():
        sheet = book.create_sheet(title)
        sheet.append(list(columns))
        for cell in sheet[1]:
            cell.font = Font(bold=True)
            cell.alignment = wrap
        if stratum is None:
            rows = [
                [a["id"], a["text"], a["english_gloss"], a["intent"], "", "", "", ""]
                for a in attacks
            ]
        else:
            rows = []
            for item in benign:
                if item["stratum"] != stratum:
                    continue
                p = precheck.get(item["id"], {})
                note = "" if p.get("flag", "ok") == "ok" else f"{p['flag']}: {p.get('note', '')}"
                rows.append(
                    [item["id"], item["text"], note, p.get("suggestion", ""), "", "", "", ""]
                )
        for row in rows:
            sheet.append(row)
            cells = sheet[sheet.max_row]
            cells[1].alignment = rtl
            cells[6].alignment = rtl
            for cell in (cells[2], cells[3], cells[7]):
                cell.alignment = rtl if cell.column == 4 else wrap
            if stratum is not None and row[2]:
                for cell in cells[:4]:
                    cell.fill = flagged
        last = sheet.max_row
        for column, choices in (("E", NATURAL), ("F", YES_NO)):
            check = DataValidation(type="list", formula1='"' + ",".join(choices) + '"')
            check.add(f"{column}2:{column}{last}")
            sheet.add_data_validation(check)
        for column, width in zip("ABCDEFGH", (18, 60, 34, 40, 14, 14, 50, 30), strict=True):
            sheet.column_dimensions[column].width = width
        sheet.freeze_panes = "C2"
        sheet.auto_filter.ref = f"A1:H{last}"
    book.save(out)
    print(f"Wrote {out}")


def apply(path: Path, reviewer: str) -> None:
    from openpyxl import load_workbook

    book = load_workbook(path, read_only=True)
    answers: dict[str, tuple[str, str, str]] = {}
    for title in SHEETS:
        for row in book[title].iter_rows(min_row=2, values_only=True):
            item_id, natural, verdict, corrected = row[0], row[4], row[5], row[6]
            if not item_id or not natural:
                continue
            natural, verdict = str(natural).strip(), str(verdict or "").strip()
            corrected = str(corrected or "").strip()
            if natural not in NATURAL or (verdict and verdict not in YES_NO):
                sys.exit(f"{item_id}: unexpected answer {natural!r} / {verdict!r}")
            if natural == "Fix" and not corrected:
                sys.exit(f"{item_id}: Fix needs a corrected text")
            answers[str(item_id)] = (natural, verdict, corrected)

    counts = {"reviewed": 0, "corrected": 0, "removed": 0}

    def judge(item: dict, keep_verdict: str) -> dict | None:
        natural, verdict, corrected = answers.pop(item["id"])
        if keep_verdict and not verdict and natural != "Remove":
            # Not confirmed either way: leave it unreviewed.
            return item
        if natural == "Remove" or verdict == "No" or (keep_verdict and verdict != keep_verdict):
            counts["removed"] += 1
            return None
        item = dict(item)
        if natural == "Fix":
            item["text"] = corrected
            item["corrected"] = True
            counts["corrected"] += 1
        item["reviewed"] = True
        item["reviewed_by"] = reviewer
        counts["reviewed"] += 1
        return item

    def update(rows: list[dict], keep_verdict: str) -> list[dict]:
        out = []
        for item in rows:
            if item["id"] in answers:
                judged = judge(item, keep_verdict)
                if judged is not None:
                    out.append(judged)
            else:
                out.append(item)
        return out

    # Harmless items need not be marked harmless explicitly; attacks must be
    # confirmed as attacks.
    benign = update(_jsonl(BENIGN), "")
    attacks = update(_jsonl(ATTACKS), "Yes")
    if answers:
        sys.exit(f"unknown ids in the workbook: {sorted(answers)[:10]}")
    _write_jsonl(BENIGN, benign)
    _write_jsonl(ATTACKS, attacks)
    print(
        f"{counts['reviewed']} reviewed ({counts['corrected']} corrected), "
        f"{counts['removed']} removed. Re-run: python eval/run_eval.py --arabic"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("export").add_argument("workbook", type=Path)
    applying = sub.add_parser("apply")
    applying.add_argument("workbook", type=Path)
    applying.add_argument("--reviewer", required=True)
    args = parser.parse_args()
    if args.command == "export":
        export(args.workbook)
    else:
        apply(args.workbook, args.reviewer)


if __name__ == "__main__":
    main()
