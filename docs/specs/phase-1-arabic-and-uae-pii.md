# Phase 1: Arabic support and UAE personal-data redaction

Status: draft v2, revised after review (regression, Arabic NLP, security) · Base: commit `69aa6ea` · Date: 2026-11-02

## 1. Why

On 2026-11-02, reviewers tested Kestral against two proposed capabilities: B1, an Arabic-first personal-data redaction gateway, and B2, Arabic red-teaming. Neither exists. The tests also found that Kestral handles Arabic badly today:

| Finding (measured at 69aa6ea) | Effect |
|---|---|
| The ML classifier d022 (English-only DeBERTa) scores harmless Arabic near 1.0. It blocked 11 of 12 harmless Arabic banking questions and 15 of 27 harmless UAE customer-service prompts. | Arabic users get blocked. |
| d024 has 6 exact Arabic phrases. One diacritic, a tatweel (letter-stretching mark) or a dropped hamza defeats it (0 of 25 variants caught). | With the classifier off, Arabic attacks pass. |
| The PII redactor does not recognise Emirates ID, IBAN, UAE landlines, `00971` numbers or passports. An Emirates ID is partly masked as a "phone". | It cannot handle UAE data. |
| The gateway never redacts what is sent to the model, only the reply. | Personal data reaches foreign AI services. |
| `/pii/redact` returns the original values (contradicting README:213). CrewAI `pii_redact` never masks what the model receives. | Bugs. |
| `tool_guard/_sanitize.py` and `hooks.py` apply match positions measured on normalised text to the raw text. Text with repeated spaces before an email leaves the email unmasked. | An existing leak. Arabic normalisation would make it routine. |

There is a binding legal basis for B1. CBUAE's outsourcing rule restricts sharing customer data outside the UAE. Federal Law 2/2019, Art. 13, keeps health data in the UAE. The PDPL (Art. 20(1)(a)) names pseudonymisation as a security measure. Masking reduces exposure and produces evidence. It does **not** make offshore AI use lawful, and nothing in this phase may be described as making a customer compliant.

Phase 1 delivers the parts that bring the most value for the least risk. It also lays the foundation that Phase 2 (names, dialects) and Phase 3 (B2) build on.

## 2. Ground rules

1. **Nothing existing changes unless section 6 lists it.** Every new feature is either off by default or affects only text in Arabic script, which the current evaluation contains none of. The reviewers confirmed there is no Arabic, Persian or Urdu in `eval/data/probe.jsonl` or `format_samples.py`.
2. **The gates in section 7 must pass before merge.**
3. **Detection always sees the original text.** Redaction runs afterwards and only changes what is forwarded, so it can never weaken detection.
4. **Fail closed.** If redaction or restoring fails, or runs out of budget, the request is refused. The unredacted text is never forwarded instead.
5. **Each new part sits behind an interface,** so Phase 2 extends it rather than rewriting it (section 5).
6. **No new required dependencies.** All tables (Unicode ranges, phone prefixes, IBAN lengths) are frozen in the repo, so results are identical on Python 3.10–3.13, which use different Unicode versions.

"Arabic script" means the Arabic Unicode blocks. It includes Persian and Urdu, which the classifier has not been validated on either.

## 3. Scope

| # | Item | Size |
|---|---|---|
| P1.0 | CI green, with real model tests and no hidden skips (prerequisite) | S |
| P1.1 | Arabic-script normalisation, with match positions mapped back to the original text | M |
| P1.2 | The English classifier can't block Arabic on its own (residual scoring) | M |
| P1.3 | d024 Arabic precision and robustness | S |
| P1.4 | Pluggable recognisers, plus Emirates ID, IBAN and UAE phone | M |
| P1.5 | Redaction before the model in the gateway (opt-in): masks or reversible tokens | L |
| P1.6 | Redaction evidence log (opt-in) | M |
| P1.7 | Bug fixes: `/pii/*` originals, CrewAI `pii_redact` | S |
| P1.8 | Arabic evaluation set (about 1,000 harmless items) and gates | M |

Estimate: about 6–7 weeks for one engineer, plus native-speaker time for P1.8.

Not in Phase 1 (see section 9): person names, passport and other UAE identifiers, dialect and Arabizi phrase tables, a multilingual classifier, the `phonenumbers` library, a general limit on request body size, B2 red-teaming, and CBUAE/DIFC mapping.

## 4. Work items

### P1.0 CI green
- **Install:** `.[dev,ml,fastapi,documents,mcp,openai,anthropic,observability,language,sentiment,langchain,haystack,pydantic-ai]`. `ml` is required: `tests/detectors/test_d022_batch.py:110` imports `transformers` without a guard, and P1.2 must be tested against the real model. The three framework extras are included so their tests run instead of skipping.
- **Found while doing this** (fixed in the same step):
  - `rapidocr-onnxruntime` has no build for Python 3.13 or later, so `pip install kestral[documents]` failed there. It is now installed only on 3.10–3.12. On 3.13, images are withheld with `ocr_support_not_installed`, which the README states.
  - The CSS stress tests allowed exactly the 10-second limit they exercise and failed at 10.01 s on shared runners. They now allow the limit plus a margin.
- **Failures are readable without logs:** failed tests, a failed install and unexpected skips are reported as annotations on the run page.
- **Matrix:** `fail-fast: false`.
- **Models:** cache Hugging Face models at their pinned revisions. Set `HF_HUB_OFFLINE=1` after warm-up.
- **Skips:** check in an allowed-skip list. CI fails on any skip not on it, so "all tests pass" means they actually ran.
- **Weekly job:** a separate weekly job installs `.[all]` and reports which extra breaks.
- **Acceptance:** CI is green on 3.10–3.13 with no unexpected skips.

### P1.1 Arabic-script normalisation
**Where:** a new `arabic` stage in `normalization/pipeline.py`, on by default. Stage order: NFKC → zero-width → homoglyph → **arabic** → whitespace. NFKC must run first, because it composes alef + U+0654 into أ before marks are removed.

**The stage runs only if the text contains an Arabic-script character.** Otherwise it returns the input unchanged. Within the stage:

| Action | Characters |
|---|---|
| Remove marks | U+064B–065F, U+0670, U+0610–061A, U+06D6–06DC, U+06DD, U+06DF–06E4, U+06E7–06E8, U+06EA–06ED, U+0898–089F, U+08CA–08E1, U+08E3–08FF; spacing dot symbols U+FBB2–FBC1; number signs U+0600–0605 |
| Remove tatweel | U+0640 |
| Remove bidi controls | U+200E, U+200F, U+061C, U+202A–202E, U+2066–2069. Today an RLM between two words breaks every `\s+` in d024. ZWJ/ZWNJ are already removed for all text. |
| Fold alef | أ إ آ ٱ → ا |
| Fold hamza seats | ؤ → و; ئ → ي; standalone ء removed |
| Fold ya and ta marbuta | ى → ي; ة → ه |
| Fold Persian/Urdu keyboard letters | ک → ك; ی → ي; ۀ ہ ھ ە → ه |
| Map digits | every Unicode decimal digit → ASCII, from the same frozen table as P1.4 |

Presentation forms (U+FB50–FDFF, U+FE70–FEFF) need no rule: NFKC already folds them, including lam-alef. All tables are frozen code-point tables, not `unicodedata.category()`.

**Positions:** every stage that changes length returns a position map. The arabic stage does; so do the existing whitespace and zero-width stages. The engine maps `MatchDetail.position` and `matched_text` back to the original text before returning them. This fixes the existing leak in `tool_guard/_sanitize.py:37-48` and `hooks.py:169`, and stops the new stage from making it worse. One position mapper is shared with P1.4.

**Who sees the normalised text:** every keyword detector, and d022 (`engine.py:255, :446`). Callers, `input_hash`, `scan_history` and the Inspector cache keep using the original text, and the reviewers verified this.

**Switch:** `normalization.arabic: false`.

**Acceptance:**
- property test: every non-Arabic string in the tests and evaluation comes out unchanged byte for byte;
- the stage is idempotent;
- all 25 measured variants are caught, plus new variants: Persian keyboard, presentation forms, an inserted RLM/ALM, Quranic marks, decomposed hamza, and the spellings شيء/شئ/شي/شيئ;
- test: Arabic with tashkeel before an email → `sanitize_text` masks the email, at the right position.

### P1.2 The English classifier can't block Arabic on its own
**Problem:** d022 reacts to Arabic script, not meaning. A simple "mostly Arabic" rule can be gamed. The reviewers showed that 56 of the eval's 120 English attacks are blocked by d022 alone, and one harmless Arabic sentence of padding would push each past a 50% threshold.

**Rule (residual scoring):** applies when d022 fires and the text, after normalisation, has at least 3 Arabic-script words or at least 20% Arabic-script letters (counting only letter characters).
1. Replace every run of Arabic script with a space, and run d022 again on what is left. That is one extra call, made only on mixed text where d022 has already fired.
2. The Arabic runs that are removed include Arabic punctuation and tatweel, and any punctuation attached to either side, so `اليوم.` leaves no stray `.`. If the remainder has at least 20 letters or digits in other scripts (`residual_min_letters`) and d022 still fires, the original detection stands. Padding and interleaving don't help an attacker: "ignore الف previous باء instructions" leaves "ignore previous instructions". Counting every script except Arabic, not only Latin, keeps Hindi and Chinese attacks padded with Arabic from being downgraded. Counting digits does the same for hex-encoded payloads.
3. Otherwise the detection is marked downgraded **on the DetectionResult itself**: `metadata["downgraded"] = "classifier_not_validated_for_script"`. Its severity does not change, and keeping the mark in `metadata` leaves report schemas unchanged. A report whose only grounds are downgraded detections gets the action `log`, not `flag`, because CrewAI treats a flag as blocked. These all honour the mark:
   - the action in `engine.py:765-790`;
   - the gateway monitor-mode recompute (`gateway.py:444-452`);
   - CrewAI, which treats FLAG as blocked (`crewai_guard.py:178, :212`);
   - the operator-configured severity actions;
   - Inspector `_judge`, including strict mode (`inspector.py:394-445`).
   
   `risk_score` still reports the raw confidence.
4. The detection blocks again only if a **closed list** of detectors agrees: non-ML detectors in `PRECISE` at HIGH or CRITICAL. The list excludes `FORMAT_NOISE`, d021 (an English embedding model), d027 (statistical) and SecondOpinion, because SecondOpinion is also English DeBERTa.
5. Text that is hidden in a document still counts as an attack when any detector fires (today's rule, `inspector.py:400-409`). Hidden Arabic text is suspicious in itself.

**Also:** add Arabic punctuation (`؟ ، ؛ ۔`) to the Inspector's sentence splitter `_SENTENCE` (`inspector.py:94`).

**Switch:** `detectors.d022.unvalidated_scripts: corroborate | score`. The default is `corroborate`; `score` gives today's behaviour. It is a function from script to policy, so a validated model can set `arabic_script: score` later.

**Limits:**
- English written in Arabic letters is not handled (Phase 2).
- d022 already scores only the first 8 chunks, about 3.2k characters (`_chunk`, `d022_semantic_classifier.py:285-303`). That is unchanged and documented.

**Acceptance:**
- the upper bound of the 95% Wilson interval for harmless Arabic block rate is 5% or less on P1.8 (it is 92% today);
- the 120 English eval attacks, each with harmless Arabic padding added before and after, plus interleaved and tatweel-padded forms, keep d022's current recall (56/120 blocked by d022 alone);
- English evaluation unchanged.

### P1.3 d024 Arabic precision and robustness
- **Folded input:** d024 folds its own input with the P1.1 table, which is safe because folding is idempotent. Its patterns then match both forms. `test_d024_multilingual_injection.py:131` (unfolded "أنت الآن") still passes unedited, and turning normalisation off doesn't lose the hamza phrases.
- **"You are now":** bare `أنت الآن` is replaced by `انت الان.{0,40}<role cue>`, for example "without restrictions".
- **"Forget everything":** `انس كل شيء` can collide with the name أنس (Anas) after folding. It is changed to corroborate-only: a d024 result whose only matches are this phrase carries `metadata["downgraded"] = "ambiguous_phrase"` and counts only when another detector agrees.
- **Negation:** "عدم / لا تجاهل التعليمات" ("not ignoring the instructions") no longer matches the ignore-instructions patterns.
- **Language mixing:** Arabic script is taken out of the shared language-mixing regex and gets its own pattern. That pattern needs `\b`-bounded verb + object, either ignore/forget/override/bypass + previous/all/your + instructions/rules/prompt/guidelines, or "system prompt". Bare show/print/forget no longer count. The reviewers checked all 10,612 string literals in tests, eval and src: the split changes none of them. Other scripts keep today's pattern.
- **Acceptance:**
  - the measured false positives pass;
  - hard negatives in P1.8 pass ("print statement", "forget password", "Al Ain bypass", the Anas sentence);
  - 5 of the 6 existing phrases and their variants are still caught;
  - bare "أنت الآن" is intentionally no longer caught.

### P1.4 Recogniser framework and UAE recognisers
**Interface** (`pii/recognizers/base.py`):

```python
class Recognizer(Protocol):
    entity: str              # validated against ^[a-z0-9_.-]{1,64}$ on registration
    version: str             # same pattern; recorded in evidence
    languages: frozenset[str]
    def find(self, text: str) -> Iterable[Span]: ...   # Span(start, end, entity, score, validated)
```

**Registry:** built-in recognisers, plus an entry-point group `kestral.recognizers`, the same mechanism as `kestral.detectors` (`registry.py:124`). An adapter wraps today's `DEFAULT_PII_PATTERNS` unchanged.

**What stays the same:** `PIIRedactor()` with no arguments keeps exactly today's six types as a frozen default. These callers are therefore unaffected: the pre-commit hook, `OutputPIIScanner`, CLI, `tool_guard`, CrewAI and d023. New recognisers are switched on only by explicit argument, and only in three places:
- `/pii/*`;
- reply redaction in `pii` mode;
- P1.5.

d023 and `sanitize_text` still see an Emirates ID as a phone number. That is a documented limit.

**Digit folding:**
- every Unicode decimal digit (Arabic-Indic, Persian, full-width, mathematical, and so on) maps to ASCII;
- every format character (category Cf) is removed;
- NBSP and similar spaces count as separators;
- positions are mapped back through the shared mapper.

**Boundaries:** on folded text, use digit lookarounds `(?<![0-9])…(?![0-9])`, not `\b`, because Arabic letters count as `\w` (as in "و0501234567"). `،` and `؛` separate list items, never digits.

**Recognisers:**

| Entity (label) | Rule | Validation |
|---|---|---|
| `emirates_id` | `784`, then a 4-digit year (19xx or 20xx), 7 digits and a check digit; dashes optional | Luhn pass → `validated`, high score. The exact dashed shape still redacts at a lower score when Luhn fails (a mistyped ID is still personal data). Arabic or English context words (e.g. رقم الهوية) raise the score. Luhn is from Microsoft Purview's definition and libraries, not from ICP, so it is not treated as official. |
| `iban` | 2 letters, 2 check digits, then the national part; spaces allowed; any letter case | ISO 13616 mod-97 plus a frozen per-country length table (AE = 23: bank code of 3 digits + 16 digits, per CBUAE) |
| `phone` (UAE rule, keeps today's label and placeholder) | `+971`, `00971` or `0`, also `+971 0`; mobile 50/52/53/54/55/56/57/58 (10 digits nationally); landline 2/3/4/6/7/8/9 (9 digits nationally) | Prefixes are in a config table |
| `phone_ae_service` | 800 / 600 / 200 service numbers | Off by default; public company numbers |

Cards that pass Luhn become `validated`. Card matches that fail Luhn are still masked as today.

**Overlaps:** validated spans win first. Among unvalidated spans, today's rule stays exactly as is (earliest start, then longest).

**Cost limits:**
- quantifiers are bounded and never nested;
- at most one separator character between digit groups;
- every recogniser gets the `regex` module's `timeout=`;
- redaction uses an email pattern with bounded lengths (`{1,64}@{1,253}`). Today's email pattern is quadratic: 200 KB takes 1.9 s.

**Acceptance:**
- 100% recall on the synthetic UAE set, covering Arabic, English and mixed text; ASCII, Arabic-Indic, full-width and mathematical digits; and RLM, NBSP or Cf characters inside numbers;
- 0 new false positives on the business set. That set includes PO numbers, invoice numbers, AED amounts with `٬ ٫` separators, mixed-digit strings, dates, SWIFT codes, version strings and service numbers;
- every recogniser processes 100 KB of adversarial input in under 100 ms on a laptop (measured worst: IBAN, 62 ms), and time grows linearly with length;
- at least one Emirates ID in the real format, confirmed by a person, is in the tests, so the check is not circular.

### P1.5 Redaction before the model in the gateway (opt-in)
**Settings:**
- `KESTRAL_REDACT_REQUESTS = off | mask | tokenize`. The default is `off`: no change, no new headers.
- `KESTRAL_REDACT_ENTITIES`, default `emirates_id,iban,phone,email,credit_card,api_key`.

**What is redacted** when the mode is not `off`: every string in `messages[*]`:
- user text and parts;
- **all system messages, including the first.** Apps often put customer data into it, and redaction only replaces values, so the instructions stay the same;
- tool results and later system messages: the Inspector's `safe_content` is redacted **before** it is wrapped (`gateway.py:477-478`);
- assistant `content`, `refusal`, `reasoning_content` and `name`. This keeps restored values from returning upstream as history;
- text extracted from files;
- tool-call arguments.

**Tool-call arguments** are handled as parsed JSON: string values, numbers that look like identifiers (which become strings, a documented change) and object keys. They are written back with `json.dumps(ensure_ascii=False)`. Arguments that are not JSON are redacted as text, using tokens that are safe inside a JSON string.

**Not redacted:** `tools[].function.description`, `metadata`, and the other top-level fields. This is a documented limit.

**Monitor mode:** request redaction is a data-residency control. It runs even when `mode: monitor`. Today `prepare()` returns the body unchanged (`gateway.py:586-592`), and that needs changing for this case.

**Modes:**
- `mask`: a typed placeholder such as `[EMIRATES_ID]`. It cannot be undone.
- `tokenize`: `[EMIRATES_ID_1#7f3a9c2e]`, with a random per-request nonce (`secrets.token_hex(4)`). The token alphabet excludes `< > " \` and newline.
  - Inbound text that already looks like a token is neutralised, the same way `wrap()` does (`inspector.py:284`).
  - The token map is returned by `prepare()` as a per-request object and handed to the reply stage. It is never stored on the shared `Gateway`, and its `__repr__` hides the values.
  - Each token records its source: user, tool, system or file.

**Reply processing with `tokenize`** (fixed order; without `tokenize` today's order is unchanged):
1. `redact_response`, run on the reply while it still contains tokens. This masks personal data the model invented. Tokens never match a recogniser.
2. **Restore** tokens that match this request's nonce, and only those whose source is allowed by `KESTRAL_RESTORE_FROM`. The default is `user`, so a CRM record from a tool result stays masked, just as `pii` mode masks it today.
3. **`filter_response`** (egress allowlist, `_unsafe_call`), run on the **restored** reply. That way a token can't smuggle an address past the egress check.

Two more rules apply to restoring:
- Tokens inside tool-call arguments are **not** restored unless `KESTRAL_RESTORE_TOOL_ARGS=true`. When restoring is on, it puts values into the parsed JSON, never into the raw string.
- Nothing is restored when the upstream returns status 400 or higher.

The gateway already reads the whole upstream reply (`api.py:826, :837-870`), so streaming replies are rebuilt after restoring.

**Errors:**
- redaction failure or budget exceeded → `GatewayRefusal(500, "redaction_failed")` or `(413, "redaction_budget_exceeded")`;
- restore failure → `GatewayRefusal(502, "restore_failed")`.

These are raised as refusals, not as `check_failed`.

**Budget:** when the mode is not `off`:
- `KESTRAL_MAX_BODY_BYTES`, default 4 MB, plus a cap per field;
- a deadline for redacting the whole request, after which it fails closed.

A general body limit for all traffic is left for Phase 2.

**Headers:** `X-Kestral-Redacted-Request: <count>`, sent only when the mode is not `off`.

**Acceptance:**
- with `off`, the upstream request and client response are byte-identical to today's on the golden tests;
- with `mask` or `tokenize`, a recording mock upstream receives no test value on turn 1 or turn 2 (with the history sent back), in normal and monitor mode;
- token forgery fails: a token in user or document text, a token with the wrong nonce, and tokens from another request are all left alone;
- the model sends a tool call with `to="[EMAIL_1#…]"` (from a retrieved document) → it is held back or left masked, never restored to a host outside the allowlist;
- tokens from tools are not restored by default;
- values are restored in normal and streaming replies.

### P1.6 Redaction evidence log (opt-in)
**When it writes:** only if `KESTRAL_EVIDENCE=on`, and only for request redaction (P1.5), reply redaction in `pii` mode, and `/pii/*`. The default `secrets` reply redaction writes nothing. If `history.enabled: false` is set, no evidence is written either.

**Table:** migration 2 adds `redaction_events`. Inserting the version row uses `INSERT OR IGNORE`, so replicas starting together are safe. Rows are aggregated as one row per (request, message role, entity, key_id), with a cap on rows per request. Columns:
- `id`, `request_id`, `timestamp`;
- `direction` (`request`, `reply` or `api`);
- `role`, `entity`, `count`;
- `recognizer_version`, `policy`, `key_id`;
- `value_digest`;
- `prev_hash`: a hash chain over the rows, so tampering shows.

**Digests:** opt-in (`KESTRAL_EVIDENCE_DIGEST=on`). Each is `HMAC-SHA-256(key, request_id ‖ entity ‖ value)`. It is tied to the request, so the same person cannot be linked across requests. This matters because phone numbers and Emirates IDs have few enough possible values to brute-force if the key leaks.
- Key: from a key ring with `key_id` and retirement dates, kept in a KMS or vault, never next to the SQLite file. Destroying a retired key makes its digests useless.
- Verification: a DPO checks "was value X masked in request R" through an admin-only, rate-limited, audited service call. Exports contain no digests.

**Request id:** generated by the server. It is passed through `prepare()` and the reply stage, and returned as `X-Kestral-Request-Id` on the gateway and on `/pii/*` when evidence is on.

**Operation:**
- `prune_redaction_events(retention_days)`;
- the database file is created with mode 0600;
- `KESTRAL_EVIDENCE_REQUIRED=on` refuses a request whose evidence row cannot be written;
- `kestral evidence export` writes an export-audit row and escapes CSV cells that start with `= + - @ \t \r`.

**Acceptance:**
- no test value appears in the database, logs or exports;
- counts match the headers;
- migration 2 applies to an existing version-1 database without losing data;
- the hash chain verifies.

### P1.7 Bug fixes
1. **`/pii/redact`** stops returning `redacted_entities[].original`, as README:213 already says it does.
2. **`/pii/scan`** returns `(entity_type, start, end)` positions instead of `original`. The caller already has the text. This is a **breaking API change**: `PIIScanEntity.original` is a required field in the schema today.
3. **CrewAI `pii_redact=True`** now scans the **original** text and forwards the **redacted** context and task description to the task, restoring the caller's description afterwards. That follows ground rule 3. Today it redacts before scanning (`crewai_guard.py:275-279`). Because CrewAI treats a flag as blocked, a personal-data finding (d023) alone does not block when `pii_redact` is on: that data is redacted before the model sees it. Every other detector decides on the original text, so an attack that redaction used to hide is now blocked.

### P1.8 Arabic evaluation set and gates
**Files:** `eval/arabic/benign.jsonl`, `attacks.jsonl` and `pii_uae.jsonl`. The last uses synthetic, checksum-valid fake values. Every item records its source and licence.

**Harmless set: about 1,000 independent items.** That size is needed because the gate uses the upper bound of the 95% Wilson interval. With 300 items, a 3% false-positive rate already reaches 5.6%.

| Stratum | Items |
|---|---|
| Modern Standard Arabic | 250 |
| Gulf / Emirati | 250 |
| Egyptian | 100 |
| Levantine | 100 |
| Arabic–English code-switched | 200 |
| Hard negatives | 100 |
| Arabizi (reported, not gated) | 50 |

The hard negatives include:
- harmless uses of تجاهل / انسى / أنت الآن;
- the Anas sentence;
- "print statement", "forget password";
- fully vowelled religious text;
- religious ligatures;
- Persian/Urdu expat messages;
- long Arabic document extracts.

Topics cover banking, insurance, government, health and HR.

**Sources:**
- Amazon MASSIVE ar-SA (CC BY 4.0);
- TyDi QA Arabic (Apache-2.0);
- Aya Dataset Arabic (Apache-2.0);
- XQuAD ar (CC BY-SA 4.0: ShareAlike applies if it is redistributed in the repo).

MADAR and NADI may not be committed. The Gulf, code-switched and Arabizi strata are written by native speakers, starting from the 39 prompts already measured.

**Attacks:** existing phrases and their spelling variants only. Dialect attacks come in Phase 2, after native-speaker review.

**Report:** `eval/run_eval.py --arabic` is a separate mode. It writes `eval/results_arabic.json`, never `results.json`, and reports each stratum separately.

## 5. How it extends

| Later need | Where it goes | What Phase 1 provides |
|---|---|---|
| Names (English and Arabic NER), passport, TRN, visa file number, UID, trade licence, Thiqa or health card | New `Recognizer` classes, possibly an optional extra `kestral[pii-ar]`. The ID types have no public checksum, so they need keyword gates. | Interface, registry, entry points, digit and position mapping, evidence log |
| Customer-specific identifiers | A third-party package in `kestral.recognizers` | Entry-point discovery, name validation |
| A validated multilingual classifier | Set `unvalidated_scripts.arabic_script: score` once it passes P1.8 | Per-script policy function |
| Dialect and Arabizi detection | New d024 tables, measured on P1.8 | Normalisation, the evaluation set |
| A shared token store across replicas | A `TokenVault` interface. A Redis version is keyed by (tenant, request_id, nonce), with a short lifetime and deletion after the reply. | In-memory implementation behind the interface |
| Signed evidence packs, CBUAE/DIFC mapping, B2 harness | Built on `redaction_events` and the evaluation framework | Table, hash chain, export, statistics |

## 6. Default behaviour that changes (everything else is opt-in)

| Change | Who notices | Why it is safe | Undo |
|---|---|---|---|
| Arabic-script normalisation (P1.1) | Arabic, Persian and Urdu input | Text without Arabic script comes out byte-identical | `normalization.arabic: false` |
| Match positions mapped back to the original text (P1.1) | `sanitize_text` / ToolResultGuard / AgentGuard and hook users whose text was changed by normalisation | Fixes an existing leak where the wrong text was cut | none needed (bug fix) |
| `sanitize_text` cuts every span at its position in the given text, in one pass (P1.1) | Same callers, when a PII value and another detection both match | Before, the PII placeholder was inserted first and shifted every later cut | none needed (bug fix) |
| d022 can't block Arabic-script text on its own; padding is closed by residual scoring (P1.2) | Arabic-script input | Ends the 92% false blocking; the English-attack gate shows no loss | `unvalidated_scripts: score` |
| Arabic sentence punctuation in the Inspector (P1.2) | Arabic documents | Splits sentences more precisely | none needed |
| d024 Arabic precision fixes; bare "أنت الآن" no longer matches (P1.3) | Arabic input | Removes the measured false positives | none needed |
| New recognisers in `/pii/*` and `pii` reply mode (P1.4) | Callers of those paths | Masks more UAE data; checksums keep false positives near zero | `redaction.entities` |
| `/pii/redact` and `/pii/scan` stop returning originals; scan returns positions (P1.7) | API clients that read `original` | The caller already has the text; this ends a leak | none (breaking change, noted in the changelog) |
| CrewAI `pii_redact` actually masks, and scans the original first (P1.7) | CrewAI users who set it | Does what the option promises; may newly block real attacks | turn the option off |

## 7. Gates before merge

1. CI green on Python 3.10–3.13 with real models and no unexpected skips (P1.0).
2. All existing tests pass unedited, except the tests named in P1.7, each updated with a note.
3. **Evaluation baseline:** first regenerate `eval/results.json` at `69aa6ea` (it was last written at e47d442). Then every step must reproduce it, ignoring the `generated` field and the latency fields. Run with `HF_HUB_OFFLINE=1` and `--second-opinion`.
4. Property tests: P1.1 leaves non-Arabic text unchanged and is idempotent.
5. With `KESTRAL_REDACT_REQUESTS=off`, gateway golden tests produce byte-identical upstream requests and client responses.
6. P1.2 padding gate: the English attacks with Arabic padding, interleaving and tatweel padding keep d022's recall.
7. Arabic targets (P1.8):
   - the upper bound of the 95% Wilson interval for harmless block rate is 5% or less;
   - all spelling variants are caught;
   - 100% UAE PII recall on the synthetic set;
   - 0 new false positives on the business set.
8. Performance:
   - English p95 scan latency stays within 2 ms of the baseline;
   - recognisers stay linear and under 100 ms per 100 KB of adversarial input.
9. Leak check: no test value appears in the database, logs, exports or responses (except restored tokens). Three known exceptions are listed and scheduled for Phase 2:
   - the `matched_text` for admins on `/scan`;
   - `Removal.preview`;
   - the unkeyed SHA-256 in `scan_history.input_hash`.
10. Security tests from P1.5: token forgery, a token in a tool call aimed at an outside host, history sent back on turn 2, monitor mode.
11. ruff, mypy and the coverage threshold pass.

## 8. Rollout

Each step is a separate commit that passes the gates on its own, and updates README and ARCHITECTURE.md, including the limits that remain:

1. P1.0 (CI);
2. P1.8 (the evaluation set, so every later step is measured);
3. P1.1 → P1.3 (Arabic detection);
4. P1.4 + P1.7;
5. P1.5 + P1.6.

## 9. Phase 2 and later

**Phase 2 (B1 complete):**
- Identifiers:
  - English and Arabic names: Presidio-style recognisers, plus an Arabic NER model such as CAMeLBERT once its licence and accuracy are checked;
  - passport, with the format from ICP;
  - TRN, visa file number, UID, trade licence, Thiqa;
  - `phonenumbers` for non-UAE numbers.
- Tightening:
  - a tighter IPv4 pattern;
  - a general request-body limit;
  - fixing the three leak-check exceptions.
- Infrastructure: the Redis token vault.
- Arabic detection:
  - dialect and Arabizi phrase tables reviewed by native speakers;
  - testing a multilingual classifier, such as Prompt-Guard after a licence check;
  - English written in Arabic letters.

**Phase 3 (B2):**
- Arabic red-teaming on an existing framework (garak, PyRIT or promptfoo), with the gateway recording traffic;
- bias tests with swapped names;
- signed evidence packs mapped to the CBUAE AI guidance note and DIFC Regulation 10, with clause references checked by Legal first.

## 10. Decisions

Decided on 2026-11-02, following the reviewers' recommendations:

1. **P1.2 default:** the English classifier stops blocking Arabic-script text on its own by default, with residual scoring.
2. **P1.7 API change:** `/pii/scan` returns positions instead of the original values in this release, noted as a breaking change.
3. **P1.5 first system prompt:** it is redacted whenever request redaction is on.
4. **P1.4 label:** UAE numbers keep today's `phone` label and placeholder.

Still open:

5. **P1.8 people:** who writes and checks the Gulf, code-switched and Arabizi items as native speakers? Which Presight product's real traffic should the set reflect? Until this is settled, items in those strata are marked `reviewed: false`. The gate counts them, but the set is not final.
