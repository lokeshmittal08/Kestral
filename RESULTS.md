# Kestral evaluation results

Produced by `python eval/run_eval.py --second-opinion` on 2026-10-27. Raw output is in [eval/results.json](eval/results.json). Intervals are Wilson 95%.

## Read this first

- **These are development sets.** They were written by the team. Detector rules were tuned while looking at the engine set and the format set. The carrier set is split in two: rules were tuned looking at failures in one half only, and the other half is reported separately as a check.
- **The benign texts are deliberately hard:** role-play requests, text about prompt injection, security instructions, code, short fragments. Rates on them are stress figures, not estimates for ordinary traffic.
- **No adaptive attacker was used.** Published research shows that detection-based defences lose most of their effect against an attacker who adapts to them.
- **Samples are not independent in the carrier set:** each of 120 payloads appears in five carriers.

## Definitions

| Term | Meaning |
|---|---|
| Neutralised | The document was withheld, or the injected text does not appear in the content passed to the model |
| Benign text lost | A benign text placed in a document does not appear in the content passed to the model |
| Benign disrupted | A benign document was withheld or had visible text removed |
| False alarm | A benign document was reported as containing an attack |
| Hidden channel | Text a person viewing the rendered item cannot see: a CSS-hidden element, a comment |
| Visible channel | An ordinary paragraph, JSON field or email body |

## 1. Carrier set

120 attack payloads across the nine attack types, each placed into five channels (600 documents). 120 benign texts, each placed into three visible channels (360 documents). Carriers are a news article page, a JSON search result, an email and Markdown release notes.

### Whole-document scanning versus the inspector

| Approach | Attack documents stopped | Benign documents affected |
|---|---|---|
| Whole-document scan | 468/600 (78.0%, 74.5 to 81.1) blocked whole | 156/360 (43.3%, 38.3 to 48.5) blocked whole |
| Inspector, `balanced` | 359/600 (59.8%, 55.9 to 63.7) neutralised | 39/360 (10.8%, 8.0 to 14.5) lose the passage |
| Inspector, `cautious` | 458/600 (76.3%, 72.8 to 79.6) neutralised | 59/360 (16.4%, 12.9 to 20.6) lose the passage |
| Inspector, `strict` | 500/600 (83.3%, 80.1 to 86.1) neutralised | 90/360 (25.0%, 20.8 to 29.7) lose the passage |

The two rows of each kind are not the same harm. A whole-document block removes the entire page from the agent. The inspector removes the one passage and passes the rest of the document.

The whole-document figures are lower than in the previous run (525/600, 87.5%, and 260/360, 72.2%) because personal data no longer blocks on its own. Every email carrier has addresses in its headers, so before this change every email document was blocked whatever its body said.

### With the optional second classifier

Measured with `python eval/run_eval.py --second-opinion`. The second model is `deepset/deberta-v3-base-injection`; confirm its licence on its model page before shipping it.

| Configuration | Attacks neutralised | Visible channels | Benign text lost | Check half: neutralised / lost |
|---|---|---|---|---|
| `balanced` | 359/600 (59.8%) | 119/360 | 39/360 (10.8%) | 178/300, 21/180 |
| `balanced` + second opinion | 497/600 (82.8%) | 257/360 | 78/360 (21.7%) | 248/300, 45/180 |
| `strict` | 500/600 (83.3%) | 260/360 | 90/360 (25.0%) | 251/300, 54/180 |

The second classifier brings `balanced` up to the protection of `strict` while losing 12 fewer benign passages out of 360. On the format set it disrupts 17 of 31 benign documents, about the same as `strict` (18). It is a better operating point than `strict`, not a fix: the second model is itself quick to flag benign text.

### By channel

| Channel | `balanced` | `cautious` | `strict` |
|---|---|---|---|
| HTML, hidden by CSS | 120/120 | 120/120 | 120/120 |
| Markdown comment | 120/120 | 120/120 | 120/120 |
| **Hidden channels** | **240/240** | **240/240** | **240/240** |
| **Visible channels** (HTML paragraph, JSON field, email body) | **119/360 (33.1%)** | **218/360 (60.6%)** | **260/360 (72.2%)** |

### By attack type (all five channels)

| Attack type | `balanced` | `cautious` | `strict` |
|---|---|---|---|
| Instruction override | 35/65 | 51/65 | 61/65 |
| Role change | 44/65 | 56/65 | 58/65 |
| Secret extraction | 35/65 | 55/65 | 58/65 |
| Tool abuse | 31/65 | 43/65 | 45/65 |
| Credential theft | 41/65 | 44/65 | 52/65 |
| Context poisoning | 30/65 | 52/65 | 58/65 |
| Multi-step jailbreaks | 30/60 | 36/60 | 39/60 |
| Encoded instructions | 68/80 | 72/80 | 75/80 |
| Indirect prompt injection | 45/70 | 49/70 | 54/70 |

Every type scores at least 2 in 5 because two of the five channels are hidden and are always removed. The spread between types comes from the visible channels.

### Tuning half and check half

| Mode | Tuning half: neutralised | Check half: neutralised | Check half: benign text lost |
|---|---|---|---|
| `balanced` | 181/300 | 178/300 (59.3%) | 21/180 (11.7%) |
| `cautious` | 226/300 | 232/300 (77.3%) | 30/180 (16.7%) |
| `strict` | 249/300 | 251/300 (83.7%) | 54/180 (30.0%) |

The two halves agree closely, so the rules did not overfit the half they were tuned on. Both halves were written by the same author in the same style, so this is weaker evidence than a sealed test set.

## 2. Format set

70 hand-built documents, three to five per cell, across user messages, web pages, HTML fragments, Markdown, email, API responses, source code and OCR text. Injections are placed the way an attacker would: in hidden elements, comments, attributes, link titles, headers, JSON fields, code comments and distorted OCR text.

| Approach | Malicious (39) | Benign (31) |
|---|---|---|
| Whole-document scan | 39 flagged or blocked | 24 flagged or blocked (77.4%) |
| Inspector, `balanced` | 39 neutralised | 2 disrupted (6.5%) |
| Inspector, `cautious` | 39 neutralised | 13 disrupted (41.9%) |
| Inspector, `strict` | 39 neutralised | 18 disrupted (58.1%) |

Rules were tuned on this set, so 39/39 is a development result. The carrier set is the better guide to what to expect on new content.

## 3. Detection engine on chat-style text

120 attacks and 120 hard benign inputs sent as single messages to the engine, with no document structure.

| Measure | Result |
|---|---|
| Attacks blocked | 95/120 (79.2%, 71.1 to 85.5) |
| Benign blocked | 31/120 (25.8%, 18.8 to 34.3) |

| Attack type | Blocked |
|---|---|
| Instruction override | 13/13 |
| Role change | 12/13 |
| Secret extraction | 12/13 |
| Tool abuse | 7/13 |
| Credential theft | 10/13 |
| Context poisoning | 12/13 |
| Multi-step jailbreaks | 5/12 |
| Encoded instructions | 15/16 |
| Indirect prompt injection | 9/14 |

The benign block rate on chat text is high. Most of it comes from the ML classifier firing alone on ordinary sentences, and its confidence does not separate those from real attacks. Replacing or retraining that classifier, and fusing detector outputs with a calibrated model instead of letting one detector block alone, is the next item on the roadmap.

## What the results support

1. Reading structure removes a whole class of attack. Instructions in hidden channels were removed in every case across the formats covered, independent of wording, language or encoding.
2. Segment-level neutralisation keeps legitimate content that whole-document blocking throws away.
3. The remaining weakness is specific and known: an instruction written as ordinary visible prose with no trigger wording.

## What the results do not support

- Any claim that Kestral prevents prompt injection.
- Any rate for PDFs, Word documents or images. These are read and covered by unit tests on generated files, but are not in any evaluation set.
- Any claim about the gateway against a live provider. It is tested against a stub.
- Any claim about real-world false-positive rates, which need real traffic to measure.

## Latency

Measured on an Apple Silicon laptop, CPU only, with the ML classifier dominating. A single message scanned on its own takes about 40 ms. In a document, new segments are scored by the classifier in batches, about 20 ms per segment the first time it is seen; a page with forty new segments takes about one second, against about 1.7 seconds when each segment is scored separately. Verdicts are cached by content, so a repeated segment costs under 1 ms.

Each inspection has a budget: a document with more than 2,000 segments, or one still being scanned after 30 seconds, is withheld with reason `budget_exceeded` instead of holding the service for minutes. No document in the evaluation sets comes near either limit.
