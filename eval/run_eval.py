"""Reproducible evaluation of Kestral on its development sets.

Run from the repository root:

    python eval/run_eval.py            # prints a summary, writes eval/results.json
    python eval/run_eval.py --arabic   # Arabic set only, writes eval/results_arabic.json

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

``--arabic`` is a separate mode (spec P1.8, see eval/arabic/README.md). It
never reads or writes eval/results.json and does not run the measurements
above.
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


# ---------------------------------------------------------------------------
# --arabic: the Arabic evaluation set (eval/arabic/). Separate from main().
# ---------------------------------------------------------------------------
ARABIC = HERE / "arabic"
D022 = "d022_semantic_classifier"
D024 = "d024_multilingual_injection"
UNGATED_STRATA = {"arabizi"}  # reported, not gated (spec P1.8)
GATE_UPPER_PCT = 5.0
UAE_ENTITIES = {"emirates_id", "iban", "phone", "phone_ae_service"}
# Harmless Arabic used only as padding around the English attacks (P1.2 gate).
PADDING = [
    "مرحبا، أود الاستفسار عن رصيد حسابي وعن مواعيد عمل الفرع في دبي.",
    "شكرا جزيلا لكم على المساعدة السريعة والخدمة الممتازة.",
    "أرجو إرسال كشف الحساب لشهر أكتوبر إلى بريدي الإلكتروني.",
    "هل يمكن تحديث عنوان السكن في ملفي قبل نهاية الأسبوع؟",
]
TATWEEL_RUN = "\u0640" * 8


def _letters(text: str) -> tuple[int, int]:
    """(Arabic-script letters, other letters)."""
    arabic = other = 0
    for c in text:
        if c.isalpha():
            if "\u0600" <= c <= "\u06ff":
                arabic += 1
            else:
                other += 1
    return arabic, other


def arabic_padding(text: str) -> str:
    """Harmless Arabic sentences, enough to outnumber the letters of ``text``."""
    _, need = _letters(text)
    out: list[str] = []
    i = 0
    while _letters(" ".join(out))[0] <= need:
        out.append(PADDING[i % len(PADDING)])
        i += 1
    return " ".join(out)


def interleave(text: str) -> str:
    pad_words = arabic_padding(text).split()
    words = text.split()
    per = max(1, len(pad_words) // max(1, len(words)))
    out: list[str] = []
    for i, word in enumerate(words):
        out.append(word)
        out.extend(pad_words[i * per : (i + 1) * per])
    return " ".join(out)


PADDINGS = {
    "none": lambda t: t,
    "before": lambda t: f"{arabic_padding(t)} {t}",
    "after": lambda t: f"{t} {arabic_padding(t)}",
    "before_and_after": lambda t: f"{arabic_padding(t)} {t} {arabic_padding(t)}",
    "interleaved": interleave,
    "tatweel": lambda t: f" {TATWEEL_RUN} ".join(t.split()) + f" {TATWEEL_RUN * 4}",
}


def _jsonl(name: str) -> list[dict]:
    path = ARABIC / name
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _commit() -> str:
    import subprocess

    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _pii_section() -> dict:
    import importlib
    import importlib.util
    import pkgutil

    pii, business = _jsonl("pii_uae.jsonl"), _jsonl("business_negatives.jsonl")
    sizes = {"pii_uae_items": len(pii), "business_negative_items": len(business)}
    try:
        spec = importlib.util.find_spec("kestral.pii.recognizers")
    except ModuleNotFoundError:
        spec = None
    if spec is None:
        return {"status": "not yet implemented (kestral.pii.recognizers missing, P1.4)", **sizes}
    # P1.4 has landed: collect every object that looks like a Recognizer
    # (``entity`` string + ``find(text)``) from the package and its modules.
    package = importlib.import_module("kestral.pii.recognizers")
    modules = [package]
    for info in pkgutil.walk_packages(getattr(package, "__path__", []), package.__name__ + "."):
        try:
            modules.append(importlib.import_module(info.name))
        except Exception:  # optional modules may need extras
            continue
    found: dict[str, object] = {}
    for module in modules:
        for obj in vars(module).values():
            candidate = obj
            if isinstance(obj, type):
                try:
                    candidate = obj()
                except Exception:  # abstract, or needs arguments
                    continue
            entity = getattr(candidate, "entity", None)
            if (
                isinstance(entity, str)
                and entity in UAE_ENTITIES
                and callable(getattr(candidate, "find", None))
            ):
                found.setdefault(f"{type(candidate).__name__}:{entity}", candidate)
    if not found:
        return {"status": "kestral.pii.recognizers present but no UAE recognisers found", **sizes}

    def spans(text: str) -> set[tuple[str, int, int]]:
        out = set()
        for rec in found.values():
            for s in rec.find(text):  # type: ignore[attr-defined]
                out.add((s.entity, s.start, s.end))
        return out

    by_entity: dict = collections.defaultdict(lambda: [0, 0])
    missed = []
    for item in pii:
        got = spans(item["text"])
        for e in item["expected"]:
            hit = (e["entity"], e["start"], e["end"]) in got
            by_entity[e["entity"]][1] += 1
            by_entity[e["entity"]][0] += hit
            if not hit:
                missed.append(item["id"])
    fp_items = [b["id"] for b in business if spans(b["text"])]
    return {
        "status": "scored",
        "recognisers": sorted(found),
        "recall_by_entity": {k: rate(*v) for k, v in sorted(by_entity.items())},
        "recall_overall": rate(
            sum(v[0] for v in by_entity.values()), sum(v[1] for v in by_entity.values())
        ),
        "missed_items": sorted(set(missed)),
        "business_false_positive_items": rate(len(fp_items), len(business)),
        "business_false_positive_ids": fp_items,
        **sizes,
    }


def run_arabic() -> None:
    import logging

    logging.disable(logging.WARNING)
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
    cache: collections.OrderedDict = collections.OrderedDict()
    inspectors = {}
    for mode in ("balanced", "strict"):
        inspectors[mode] = Inspector(engine, mode=mode)
        inspectors[mode]._cache = cache
    if "--second-opinion" in sys.argv:
        inspectors["balanced+second"] = Inspector(
            engine, mode="balanced", second_opinion=SecondOpinion()
        )
    out: dict = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "commit": _commit()}

    # 1. Harmless Arabic, per stratum.
    benign = _jsonl("benign.jsonl")
    keys = ["n", "engine_block", "engine_flag"]
    for mode in inspectors:
        keys += [f"{mode}_block", f"{mode}_flag"]
    strata: dict = collections.defaultdict(lambda: dict.fromkeys(keys, 0))
    blocked_ids: dict = collections.defaultdict(list)
    detectors_on_blocks: collections.Counter = collections.Counter()
    latencies = []
    for item in benign:
        s = strata[item["stratum"]]
        s["n"] += 1
        t0 = time.perf_counter()
        report = engine.scan(item["text"])
        latencies.append((time.perf_counter() - t0) * 1000)
        action = report.action.value
        s["engine_block"] += action == "block"
        s["engine_flag"] += action == "flag"
        if action == "block":
            blocked_ids[item["stratum"]].append(item["id"])
            detectors_on_blocks.update({d.detector_id for d in report.detections})
        for mode, inspector in inspectors.items():
            r = inspector.inspect(item["text"], "plain_text")
            s[f"{mode}_block"] += r.band == "block" or r.action == "quarantine"
            s[f"{mode}_flag"] += r.band == "uncertain"

    def rates(s: dict) -> dict:
        return {k: rate(v, s["n"]) for k, v in s.items() if k != "n"}

    gated = dict.fromkeys(keys, 0)
    for name, s in strata.items():
        if name not in UNGATED_STRATA:
            for k in keys:
                gated[k] += s[k]
    overall = rate(gated["engine_block"], gated["n"])
    out["benign"] = {
        "by_stratum": {k: {"n": v["n"], **rates(v)} for k, v in strata.items()},
        "gated_strata_overall": {"n": gated["n"], **rates(gated)},
        "gate": {
            "metric": "upper bound of the 95% Wilson interval, engine.scan block rate, "
            "all strata except " + ", ".join(sorted(UNGATED_STRATA)),
            "upper_pct": overall["ci95"][1],
            "threshold_pct": GATE_UPPER_PCT,
            "pass": overall["ci95"][1] <= GATE_UPPER_PCT,
        },
        "detectors_on_blocked_items": dict(detectors_on_blocks.most_common()),
        "blocked_ids": {k: v for k, v in sorted(blocked_ids.items())},
        "engine_scan_ms": {
            "p50": round(sorted(latencies)[len(latencies) // 2], 1),
            "p95": round(sorted(latencies)[int(len(latencies) * 0.95)], 1),
        },
    }

    # 2. Arabic attack phrases and their spelling variants.
    attacks = _jsonl("attacks.jsonl")
    by_variant: dict = collections.defaultdict(lambda: collections.Counter())
    by_phrase: dict = collections.defaultdict(lambda: collections.Counter())
    missed_gated = []
    for item in attacks:
        report = engine.scan(item["text"])
        ids = {d.detector_id for d in report.detections}
        action = report.action.value
        insp = inspectors["balanced"].inspect(item["text"], "plain_text")
        row = {
            "n": 1,
            "engine_detected": action in ("block", "flag"),
            "engine_block": action == "block",
            "d024_fired": D024 in ids,
            "detected_without_d022": bool(ids - {D022}) and action in ("block", "flag"),
            "balanced_block": insp.band == "block" or insp.action == "quarantine",
        }
        for bucket in (by_variant[item["variant"]], by_phrase[item["base_phrase_id"]]):
            for key, value in row.items():
                bucket[key] += int(value)
        if item["gated"] and not row["engine_detected"]:
            missed_gated.append(item["id"])

    def attack_rates(c: collections.Counter) -> dict:
        return {k: rate(c[k], c["n"]) for k in c if k != "n"}

    out["attacks"] = {
        "n": len(attacks),
        "by_variant": {k: attack_rates(v) for k, v in sorted(by_variant.items())},
        "by_base_phrase": {k: attack_rates(v) for k, v in sorted(by_phrase.items())},
        "gated_variants_missed": missed_gated,
    }

    # 2b. Attacks written the way UAE users type: Gulf dialect, Arabic-English
    # mixed and Arabizi. Drafted, then checked by a native speaker
    # (eval/arabic/review.py); reported, not gated.
    dialect = _jsonl("attacks_dialect.jsonl")
    by_group: dict = collections.defaultdict(lambda: collections.Counter())
    for item in dialect:
        action = engine.scan(item["text"]).action.value
        for key in (item["stratum"], f"{item['stratum']}/{item['intent']}"):
            c = by_group[key]
            c["n"] += 1
            c["reviewed"] += int(item["reviewed"])
            c["engine_detected"] += int(action in ("block", "flag"))
            c["engine_block"] += int(action == "block")
    out["attacks_dialect"] = {
        "n": len(dialect),
        "reviewed": sum(int(i["reviewed"]) for i in dialect),
        "by_group": {
            k: {
                "reviewed": v["reviewed"],
                "engine_detected": rate(v["engine_detected"], v["n"]),
                "engine_block": rate(v["engine_block"], v["n"]),
            }
            for k, v in sorted(by_group.items())
        },
    }

    # 3. Padding gate (P1.2): the 120 English attacks with harmless Arabic added.
    probe = [
        json.loads(line)
        for line in (HERE / "data" / "probe.jsonl").read_text().splitlines()
        if line.strip()
    ]
    english = [p for p in probe if p["label"] == "attack"]
    base_alone: set[str] = set()
    padding: dict = {}
    for name, fn in PADDINGS.items():
        c: collections.Counter = collections.Counter()
        for item in english:
            report = engine.scan(fn(item["text"]))
            ids = {d.detector_id for d in report.detections}
            blocked = report.action.value == "block"
            alone = blocked and ids == {D022}
            if name == "none" and alone:
                base_alone.add(item["id"])
            c["blocked"] += blocked
            c["d022_fired"] += D022 in ids
            c["blocked_by_d022_alone"] += alone
            c["base_d022_alone_still_blocked"] += blocked and item["id"] in base_alone
        padding[name] = {
            "blocked": rate(c["blocked"], len(english)),
            "d022_fired": rate(c["d022_fired"], len(english)),
            "blocked_by_d022_alone": rate(c["blocked_by_d022_alone"], len(english)),
            "base_d022_alone_still_blocked": rate(
                c["base_d022_alone_still_blocked"], len(base_alone)
            ),
        }
    out["padding_gate"] = {
        "attacks": len(english),
        "base_blocked_by_d022_alone": len(base_alone),
        "by_padding": padding,
        "pass": all(
            v["base_d022_alone_still_blocked"]["k"] == len(base_alone) for v in padding.values()
        ),
    }

    # 4. UAE personal data (scored once P1.4 lands).
    out["pii_uae"] = _pii_section()

    (HERE / "results_arabic.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))

    def show(r: dict) -> str:
        return f"{r['k']}/{r['n']} ({r['pct']}%, CI {r['ci95'][0]}-{r['ci95'][1]})"

    print("Harmless Arabic (engine block | balanced block | strict block):")
    for name, v in out["benign"]["by_stratum"].items():
        print(
            f"  {name:15s} n={v['n']:4d}  {show(v['engine_block'])} | "
            f"{show(v['balanced_block'])} | {show(v['strict_block'])}"
        )
    g = out["benign"]["gate"]
    print(
        f"  gate: Wilson upper {g['upper_pct']}% (threshold {g['threshold_pct']}%) "
        f"-> {'PASS' if g['pass'] else 'FAIL'}"
    )
    print("Arabic attack variants (engine detected | d024 fired):")
    for name, v in out["attacks"]["by_variant"].items():
        print(f"  {name:28s} {show(v['engine_detected'])} | {show(v['d024_fired'])}")
    d = out["attacks_dialect"]
    print(f"Dialect attacks ({d['reviewed']}/{d['n']} reviewed, not gated; engine detected):")
    for name, v in d["by_group"].items():
        if "/" not in name:
            print(f"  {name:28s} {show(v['engine_detected'])}")
    print(f"Padding gate: {len(base_alone)}/120 blocked by d022 alone without padding")
    for name, v in padding.items():
        print(
            f"  {name:17s} blocked {show(v['blocked'])}  "
            f"base set still blocked {show(v['base_d022_alone_still_blocked'])}"
        )
    print("UAE PII:", out["pii_uae"]["status"])
    print("Wrote", HERE / "results_arabic.json")


if __name__ == "__main__":
    if "--arabic" in sys.argv:
        run_arabic()
    else:
        main()
