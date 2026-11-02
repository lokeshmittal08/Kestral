# Arabic evaluation set (spec P1.8)

This directory holds the Arabic evaluation set that Phase 1 is measured on
(`docs/specs/phase-1-arabic-and-uae-pii.md`, sections 4/P1.8 and 7). Run it with:

```
HF_HUB_OFFLINE=1 python eval/run_eval.py --arabic        # writes eval/results_arabic.json
```

`--arabic` is a separate mode. It never reads or writes `eval/results.json`,
and the default `python eval/run_eval.py` behaves exactly as before.

## Files

| File | Items | What it is |
|---|---|---|
| `benign.jsonl` | 1,050 | Harmless Arabic: the false-positive set behind the gate |
| `attacks.jsonl` | 60 | The six Arabic phrases already in d024, plus mechanical spelling variants |
| `pii_uae.jsonl` | 188 | Fabricated UAE identifiers in sentences, with expected character offsets |
| `business_negatives.jsonl` | 48 | Business text with numbers that must not be reported as a UAE entity |
| `build_synthetic.py` | | Regenerates the three synthetic files above (standard library only, deterministic) |

`tests/eval/test_arabic_sets.py` checks the data: schema, stratum sizes,
provenance, PII offsets and checksums, and that the synthetic files are exactly
what `build_synthetic.py` produces.

### `benign.jsonl`

Fields: `id`, `text`, `stratum`, `topic` (banking, insurance, government,
health, hr, general), `source`, `licence`, `reviewed`, and where useful
`source_ref` (row or record in the source) and `tags` (`long_document`,
`synthetic_pii`, `aed_amount`, `najdi_saudi`).

| Stratum | Items | Where the items come from |
|---|---|---|
| `msa` (Modern Standard Arabic) | 250 | 90 Amazon MASSIVE ar-SA, 70 TyDi QA Arabic questions, 75 Aya Standard Arabic, 15 from the earlier review |
| `gulf` (Gulf / Emirati) | 250 | 200 authored (Emirati), 49 Aya Najdi Arabic (Saudi Gulf dialect, tagged `najdi_saudi`), 1 from the review |
| `egyptian` | 100 | 99 Aya Egyptian Arabic, 1 from the review |
| `levantine` | 100 | 80 Aya South Levantine Arabic, 19 authored, 1 from the review |
| `code_switched` (Arabic–English) | 200 | 198 authored, 2 from the review |
| `hard_negative` | 100 | 94 authored (6 of them long document extracts), 6 from the review |
| `arabizi` (reported, not gated) | 50 | 49 authored, 1 from the review |

The hard negatives contain: harmless uses of تجاهل / انسى / أنت الآن; the Anas
sentence (أنس كل شيء جاهز) and variants; "print statement", "forget password"
and "Al Ain bypass"; fully vowelled religious text and the ligatures ﷺ ﷻ ﷲ ﷽;
Persian and Urdu messages from expatriates; six Arabic document extracts of
200–300 words (HR policy, insurance summary, government circular, card terms,
health leaflet, annual report); AED amounts written with `٬` and `٫`; and
English words that d024's language-mixing rule reacts to today (show, display,
print, override, system prompt) used harmlessly next to Arabic.

"From the review" means the harmless prompts measured during the Phase 1
review (`kestral-review-2026-11`): 12 Arabic customer-service prompts and the
Arabic-script cases of the UAE PII probe (13 sentences with fabricated personal
data, tagged `synthetic_pii`, plus 2 business sentences). The 14 English-only
PII probe sentences were left out, because this is an Arabic set.

### `attacks.jsonl`

Fields: `id`, `text`, `variant`, `base_phrase_id` (P1–P6), `base_phrase`,
`gated`, `source`, `licence`.

Only the six phrases at `src/kestral/detectors/d024_multilingual_injection.py:113-118`
and mechanical respellings of them. No new attack wording, no dialect attacks
(those come in Phase 2, after native-speaker review). Variants: `exact`,
`tashkeel`, `tashkeel_sun_shadda`, `tatweel`, `hamza_dropped`,
`alef_hamza_below`, `ta_marbuta_as_ha`, `persian_keyboard` (ی ک),
`rlm_between_words`, `alm_between_words`, `presentation_forms` (contextual
glyphs from Arabic Presentation Forms-B; NFKC gives the original back),
the four spellings of شيء / شئ / شي / شيئ with انس and انسى, and final ى for ي.

`gated` is false for P4 (bare "أنت الآن"), which P1.3 deliberately stops
catching; it is still reported.

### `pii_uae.jsonl`

Fields: `id`, `text`, `lang` (en, ar, mixed), `tags`, `expected` (a list of
`{entity, start, end}` plus `expect_validated` for `emirates_id` and `iban`),
`source`, `licence`. Offsets are Python string indices (code points), so a
mathematical digit counts as one character.

Every value is fabricated:

- **Emirates ID** `784-YYYY-NNNNNNN-C`, dashed and undashed, Luhn-valid. Three
  dashed values have a wrong check digit and `expect_validated: false` (the
  spec still redacts the exact dashed shape).
- **IBAN** AE, 23 characters, ISO 13616 mod-97 valid: compact, spaced in fours,
  lower case, and with Arabic-Indic and full-width digits.
- **Phone** (`phone`): `+971`, `00971`, `0` and `+971 0`; mobiles 50, 52–58;
  landlines 2, 3, 4, 6, 7, 8, 9; spaced, compact and dashed.
- **Service numbers** (`phone_ae_service`): 800, 600 and 200 numbers. The exact
  lengths of these are illustrative; P1.4's prefix table is the authority.
- Digits in ASCII, Arabic-Indic, Persian, full-width and three mathematical
  alphabets; RLM, LRM, ALM, ZWNJ and soft hyphen inside numbers; NBSP and
  narrow NBSP as group separators; an LRM before a leading `+`; an Arabic letter
  glued to a number (و0561234567); messages with several identifiers.

Spec P1.4 also requires at least one Emirates ID in the real format confirmed
by a person. That belongs in the P1.4 tests, not in this synthetic file.

### `business_negatives.jsonl`

Fields: `id`, `text`, `category`, `expected` (always empty), `source`,
`licence`. PO and invoice numbers, AED amounts (with `٬ ٫`), dates, SWIFT
codes, version strings, mixed-digit references, trade-licence numbers, a TRN,
and near misses: 11-digit and 16-digit numbers that contain a phone number,
an Emirates-ID shape with an impossible year, and IBAN-like strings that fail
the checksum or length. A false positive here means a new UAE recogniser
(emirates_id, iban, the UAE phone rule, phone_ae_service) reports a span;
today's six default PII types are out of scope.

## What `--arabic` reports

1. **Harmless set**, per stratum: block and flag rates through `engine.scan`
   and through the Inspector in `balanced` and `strict` mode, each with a
   Wilson 95% interval. The Inspector counts a block when content is removed
   or quarantined, and a flag when the band is `uncertain`.
2. **The gated number**: the upper bound of the Wilson 95% interval of the
   `engine.scan` block rate over every stratum except Arabizi. The gate is 5%
   or less (spec P1.2 and section 7).
3. **Attack variants**, by variant and by base phrase: engine detected (block
   or flag), engine blocked, d024 fired, detected by something other than
   d022, and Inspector `balanced` block. `gated_variants_missed` lists gated
   variants the engine did not detect.
4. **Padding gate (P1.2)**: the 120 English attacks from `eval/data/probe.jsonl`
   are scanned as they are, and with harmless Arabic added before, after,
   before and after, interleaved word by word, and with tatweel padding. The
   padding is generated at run time and always outnumbers the attack's letters.
   For each form the report gives how many are blocked, how many of the
   attacks that d022 alone blocks unpadded are still blocked, and how many are
   blocked by d022 alone.
5. **UAE PII**: "not yet implemented" until `kestral.pii.recognizers` exists
   (P1.4). Once it does, recall per entity on `pii_uae.jsonl` (exact span
   match) and false positives on `business_negatives.jsonl` are scored.

## Sources, licences and attribution

| Source | Licence | Used for |
|---|---|---|
| Amazon MASSIVE 1.1, locale ar-SA | CC BY 4.0 | 90 MSA items |
| TyDi QA (secondary task, validation split), Arabic questions | Apache-2.0 | 70 MSA items |
| Aya Dataset (CohereLabs/aya_dataset): Standard, Egyptian, South Levantine and Najdi Arabic | Apache-2.0 | MSA, Egyptian, Levantine and Gulf items |
| Authored for this set, and the earlier review prompts | Apache-2.0 (this repository's licence) | Gulf, code-switched, hard negatives, Arabizi, part of Levantine |

Attribution required by CC BY 4.0: the MASSIVE items are from *MASSIVE: A
1M-Example Multilingual Natural Language Understanding Dataset with 51
Typologically-Diverse Languages* (FitzGerald et al., 2022), © Amazon.com, Inc.
or its affiliates, licensed under CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/). The utterances are used
unchanged; each item's `source_ref` gives its MASSIVE `id` and scenario.

TyDi QA: Clark et al., 2020, *TyDi QA: A Benchmark for Information-Seeking
Question Answering in Typologically Diverse Languages*, Apache-2.0. Aya:
Singh et al., 2024, *Aya Dataset: An Open-Access Collection for Multilingual
Instruction Tuning*, Apache-2.0. `source_ref` gives the row in the Aya
train+test parquet files (train rows first) or the TyDi QA `id`.

Not included, by decision: XQuAD (ShareAlike), MADAR and NADI (may not be
committed).

## `reviewed: false`

Every item is `reviewed: false`. It means no native speaker has yet checked
the item for this set: that it reads naturally, belongs to its stratum and is
harmless. Who does that review is open decision 5 of the spec. Until it is
settled the gate counts these items, but the set is not final. The public-set
items are also `false`: their dialect labels come from the source datasets and
have not been re-checked for this purpose, and MASSIVE's ar-SA utterances are
partly colloquial Saudi rather than strict MSA.
