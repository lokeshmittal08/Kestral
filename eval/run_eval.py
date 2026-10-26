"""Reproducible evaluation of Kestral on its development sets.

Run from the repository root:

    python eval/run_eval.py            # prints a summary, writes eval/results.json

Usage: add ``--quick`` to skip the raw-engine baseline on the carrier set, and
``--second-opinion`` to also measure the optional second classifier (it
downloads a further model).

Three measurements:

1. Engine on chat-style text: 120 attacks and 120 hard benign inputs.
2. Format set: 70 hand-built documents (39 with an injection, 31 benign)
   across eight input sources, scanned raw and through the inspector.
3. Carrier set: every one of the 120 attacks placed into five document
   channels, and every benign input into three, then inspected.

These are development sets: the detectors and rules were tuned while
looking at sets 1 and 2. Set 3 reuses the payload wording of set 1 inside
carriers written afterwards. None of this is a sealed test set.
"""

from __future__ import annotations

import collections
import json
import re
import sys
import tempfile
import time
from math import sqrt
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "data"))

import format_samples  # noqa: E402

from kestral.engine import KestralEngine  # noqa: E402
from kestral.inspector import Inspector, SecondOpinion  # noqa: E402

TYPE = {
    "user_message": "plain_text", "web_page": "html", "html": "html", "markdown": "markdown",
    "email": "email", "api_response": "json", "source_code": "source_code", "ocr_text": "ocr_text",
}  # fmt: skip


def norm(text: str | None) -> str:
    return re.sub(r"\W+", "", text or "").lower()


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    z, p = 1.96, k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * (c - h), 1), round(100 * (c + h), 1))


def rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "pct": round(100 * k / n, 1) if n else 0.0, "ci95": [lo, hi]}


ARTICLE = (
    "<html><head><title>Harbour bridge reopens after repairs</title></head><body>"
    "<h1>Harbour bridge reopens after repairs</h1>"
    "<p>The harbour bridge reopened to traffic on Monday morning after six weeks of repair work.</p>"
    "<p>Engineers replaced forty expansion joints and resurfaced both carriageways.</p>"
    "{slot}"
    "<p>The council said bus routes would return to their normal timetable from Tuesday.</p>"
    "<p>A second phase of work on the footpath is planned for the spring.</p>"
    "</body></html>"
)
MAIL = (
    "From: Morgan Lee <morgan.lee@example.org>\nTo: team@example.org\n"
    "Subject: Notes from the planning meeting\nMIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Hi all,\n\nThanks for joining the planning meeting this morning.\n\n{slot}\n\n"
    "The next meeting is on the second Thursday of the month.\n\nRegards,\nMorgan\n"
)
NOTES = "# Release notes\n\nThis release improves start-up time and fixes two export bugs.\n\n{slot}\n\nUpgrade with the usual package command.\n"


def carriers_attack(payload: str) -> dict[str, tuple[str, str]]:
    esc = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return {
        "html_hidden": (ARTICLE.format(slot=f'<div style="display:none">{esc}</div>'), "html"),
        "html_visible": (ARTICLE.format(slot=f"<p>{esc}</p>"), "html"),
        "json_field": (
            json.dumps(
                {
                    "query": "bridge reopening",
                    "results": [
                        {
                            "title": "Harbour bridge reopens",
                            "snippet": "The bridge reopened on Monday after six weeks of repairs.",
                        },
                        {"title": "Travel update", "snippet": payload},
                        {
                            "title": "Council notice",
                            "snippet": "Bus routes return to the normal timetable on Tuesday.",
                        },
                    ],
                }
            ),
            "json",
        ),
        "email_body": (MAIL.format(slot=payload), "email"),
        "markdown_comment": (
            NOTES.format(slot=f"<!-- {payload.replace('-->', '')} -->"),
            "markdown",
        ),
    }


def carriers_benign(text: str) -> dict[str, tuple[str, str]]:
    all_ = carriers_attack(text)
    return {k: all_[k] for k in ("html_visible", "json_field", "email_body")}


def run_mode(engine, mode, probe, cache, second=None):
    inspector = Inspector(engine, mode=mode, second_opinion=second)
    inspector._cache = cache  # verdicts do not depend on the mode; share them
    fmt = collections.Counter()
    for s in format_samples.S:
        r = inspector.inspect(s["content"], TYPE[s["source"]])
        if s["label"] == "mal":
            p = norm(s["payload"])[:60]
            fmt["mal_n"] += 1
            fmt["neutralised"] += r.action == "quarantine" or (
                bool(p) and p not in norm(r.safe_content)
            )
        else:
            fmt["ben_n"] += 1
            fmt["disrupted"] += r.action == "quarantine" or any(not x.hidden for x in r.removals)
            fmt["false_alarm"] += r.band == "block"
    ch_att = collections.defaultdict(lambda: [0, 0])
    type_att = collections.defaultdict(lambda: [0, 0])
    ch_ben = collections.defaultdict(lambda: [0, 0, 0])
    half = {"tune": collections.Counter(), "check": collections.Counter()}
    latencies = []
    for index, item in enumerate(probe):
        h = half["tune" if index % 2 == 0 else "check"]
        key = norm(item["text"])[:50]
        if item["label"] == "attack":
            for channel, (doc, typ) in carriers_attack(item["text"]).items():
                r = inspector.inspect(doc, typ)
                latencies.append(r.latency_ms)
                ok = r.action == "quarantine" or key not in norm(r.safe_content)
                for bucket in (ch_att[channel], type_att[item["category"]]):
                    bucket[1] += 1
                    bucket[0] += ok
                h["att_n"] += 1
                h["att_ok"] += ok
        else:
            for channel, (doc, typ) in carriers_benign(item["text"]).items():
                r = inspector.inspect(doc, typ)
                latencies.append(r.latency_ms)
                lost = r.action == "quarantine" or key not in norm(r.safe_content)
                ch_ben[channel][2] += 1
                ch_ben[channel][0] += lost
                ch_ben[channel][1] += r.band == "block"
                h["ben_n"] += 1
                h["ben_lost"] += lost
    visible = [c for c in ch_att if c in ("html_visible", "json_field", "email_body")]
    hidden = [c for c in ch_att if c not in visible]
    return {
        "format_set": {
            "malicious_neutralised": rate(fmt["neutralised"], fmt["mal_n"]),
            "benign_disrupted": rate(fmt["disrupted"], fmt["ben_n"]),
            "benign_false_alarm": rate(fmt["false_alarm"], fmt["ben_n"]),
        },
        "carrier_set": {
            "attacks_neutralised": rate(
                sum(v[0] for v in ch_att.values()), sum(v[1] for v in ch_att.values())
            ),
            "hidden_channels": rate(
                sum(ch_att[c][0] for c in hidden), sum(ch_att[c][1] for c in hidden)
            ),
            "visible_channels": rate(
                sum(ch_att[c][0] for c in visible), sum(ch_att[c][1] for c in visible)
            ),
            "by_channel": {k: rate(*v) for k, v in ch_att.items()},
            "by_attack_type": {k: rate(*v) for k, v in sorted(type_att.items())},
            "benign_text_lost": rate(
                sum(v[0] for v in ch_ben.values()), sum(v[2] for v in ch_ben.values())
            ),
            "benign_false_alarm": rate(
                sum(v[1] for v in ch_ben.values()), sum(v[2] for v in ch_ben.values())
            ),
            "tuning_half": {
                "attacks_neutralised": rate(half["tune"]["att_ok"], half["tune"]["att_n"]),
                "benign_text_lost": rate(half["tune"]["ben_lost"], half["tune"]["ben_n"]),
            },
            "check_half": {
                "attacks_neutralised": rate(half["check"]["att_ok"], half["check"]["att_n"]),
                "benign_text_lost": rate(half["check"]["ben_lost"], half["check"]["ben_n"]),
            },
            "latency_ms_uncached_p95": sorted(latencies)[int(len(latencies) * 0.95)],
        },
    }


def main() -> None:
    engine = KestralEngine(
        config_dict={
            "kestral": {
                "vault": {"enabled": False},
                "feedback": {"enabled": False},
                "history": {"enabled": False},
            }
        },
        data_dir=tempfile.mkdtemp(),
    )
    probe = [
        json.loads(line)
        for line in (HERE / "data" / "probe.jsonl").read_text().splitlines()
        if line.strip()
    ]
    out: dict = {"generated": time.strftime("%Y-%m-%d %H:%M:%S")}

    # 1. engine on chat-style text
    by_cat: dict = collections.defaultdict(lambda: [0, 0])
    benign_blocked = benign_n = 0
    for item in probe:
        action = engine.scan(item["text"]).action.value
        if item["label"] == "attack":
            by_cat[item["category"]][1] += 1
            by_cat[item["category"]][0] += action == "block"
        else:
            benign_n += 1
            benign_blocked += action == "block"
    out["engine_chat"] = {
        "attacks_blocked": rate(
            sum(v[0] for v in by_cat.values()), sum(v[1] for v in by_cat.values())
        ),
        "benign_blocked": rate(benign_blocked, benign_n),
        "by_attack_type": {k: rate(*v) for k, v in sorted(by_cat.items())},
    }

    # Baseline: what a caller gets by passing the whole document to the engine.
    raw = collections.Counter()
    for s in format_samples.S:
        action = engine.scan(s["content"]).action.value
        if s["label"] == "mal":
            raw["fmt_mal_n"] += 1
            raw["fmt_mal_detected"] += action in ("block", "flag")
        else:
            raw["fmt_ben_n"] += 1
            raw["fmt_ben_hit"] += action in ("block", "flag")
    if "--quick" not in sys.argv:
        for item in probe:
            if item["label"] == "attack":
                for doc, _ in carriers_attack(item["text"]).values():
                    raw["car_att_n"] += 1
                    raw["car_att_blocked"] += engine.scan(doc).action.value == "block"
            else:
                for doc, _ in carriers_benign(item["text"]).values():
                    raw["car_ben_n"] += 1
                    raw["car_ben_blocked"] += engine.scan(doc).action.value == "block"
    out["raw_engine_on_documents"] = {
        "format_set": {
            "malicious_blocked_or_flagged": rate(raw["fmt_mal_detected"], raw["fmt_mal_n"]),
            "benign_blocked_or_flagged": rate(raw["fmt_ben_hit"], raw["fmt_ben_n"]),
        },
        "carrier_set": {
            "attack_documents_blocked": rate(raw["car_att_blocked"], raw["car_att_n"]),
            "benign_documents_blocked": rate(raw["car_ben_blocked"], raw["car_ben_n"]),
        },
    }

    cache: collections.OrderedDict = collections.OrderedDict()
    out["inspector"] = {
        mode: run_mode(engine, mode, probe, cache) for mode in ("balanced", "cautious", "strict")
    }
    if "--second-opinion" in sys.argv:
        second = SecondOpinion()
        out["inspector"]["balanced+second"] = run_mode(engine, "balanced", probe, cache, second)
        out["inspector"]["cautious+second"] = run_mode(engine, "cautious", probe, cache, second)
        out["second_opinion_model"] = second.model_name
    (HERE / "results.json").write_text(json.dumps(out, indent=2))

    def show(r):
        return f"{r['k']}/{r['n']} ({r['pct']}%)"

    e = out["engine_chat"]
    print(
        f"Engine on chat text:  attacks blocked {show(e['attacks_blocked'])}   benign blocked {show(e['benign_blocked'])}"
    )
    b = out["raw_engine_on_documents"]
    print(
        f"Raw engine, format set:  flagged/blocked malicious {show(b['format_set']['malicious_blocked_or_flagged'])}   benign {show(b['format_set']['benign_blocked_or_flagged'])}"
    )
    if b["carrier_set"]["attack_documents_blocked"]["n"]:
        print(
            f"Raw engine, carrier set: attack docs blocked {show(b['carrier_set']['attack_documents_blocked'])}   benign docs blocked {show(b['carrier_set']['benign_documents_blocked'])}"
        )
    for mode, r in out["inspector"].items():
        f, c = r["format_set"], r["carrier_set"]
        print(f"Inspector [{mode}]")
        print(
            f"  format set:  neutralised {show(f['malicious_neutralised'])}   benign disrupted {show(f['benign_disrupted'])}"
        )
        print(
            f"  carrier set: neutralised {show(c['attacks_neutralised'])}  hidden {show(c['hidden_channels'])}  visible {show(c['visible_channels'])}"
        )
        print(
            f"               benign text lost {show(c['benign_text_lost'])}   check half: {show(c['check_half']['attacks_neutralised'])} / lost {show(c['check_half']['benign_text_lost'])}"
        )
    print("Wrote", HERE / "results.json")


if __name__ == "__main__":
    main()
