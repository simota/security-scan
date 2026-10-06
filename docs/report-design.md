# Report design direction

Status: decided 2026-10-07. Applies to `assessment.html` / `assessment.pdf` and
`dashboard.html` rendered by `skills/security-scan/scripts/render.py`.

## Brief

- **Request:** expert-review, academic design for both outputs.
- **Readers:** CISOs deciding priority and budget, engineering leads fixing
  findings, external auditors tracing claims. Japanese and English.
- **Adjectives:** rigorous · scholarly · sober · traceable · legible.
- **Must never read as:** a SaaS marketing dashboard; an alarm (red everywhere).
- **Fixed constraints:** self-contained and offline (no web fonts, no remote
  assets); PDF printed by headless Chrome on macOS (Hiragino) and Ubuntu CI
  (`fonts-noto-cjk`: Noto Sans/Serif CJK JP); existing dark mode in the
  dashboard; every report string and section already exists — this is a visual
  system, not a content change.
- **Standard:** the reader's experience of a peer-reviewed technical paper —
  numbered sections, captioned tables and listings, typographic hierarchy
  instead of boxes and colour. Judged by inspection (`inspected`); contrast is
  `measured`.

## Three directions considered

| Name | Thesis | Trades away |
|---|---|---|
| **A. Journal of record** *(chosen)* | Typeset like a journal article: serif text, numbered sections, booktabs tables, captioned listings, one ink colour plus severity inks | Glanceable colour blocks; executives read a statistics table instead of KPI tiles |
| B. Standards clause | Typeset like an ISO/NIST standard: numbered clauses, normative/informative labels, sans headings over serif text | Warmth and narrative; reads bureaucratic to executives |
| C. Audit working papers | Dense ledger grids, monospace references, tick-marked cross-reference codes | Readability for anyone but auditors |

A is chosen because the request names academic quality and A serves all three
readers: the abstract and Table 1 give the executive decision, numbered entries
give engineers stable addresses, captions and cross-references give auditors
traceability. B and C are not blended in (averaging references makes
directions generic); C's monospace references survive only for IDs, paths and
code, where they already exist.

## The six layers

**Voice.** Declarative, third person, hedged exactly as the record is. Labels
are nouns ("Verification basis"), not calls to action. Unchanged copy.

**Typography.**
- Text and headings: one mincho face that carries both scripts — `"Hiragino
  Mincho ProN", "Noto Serif CJK JP", "Yu Mincho"` (ground: `platform` — present
  on macOS and the CI image). A separate Latin serif was tried and refused:
  Chrome emits mixed-font lines as separate runs, and PDF text extraction then
  reorders Japanese and Latin, so copied or searched text no longer matches the
  record (`measured` by the PDF text tests).
- Labels, table heads, controls, metadata: the existing sans stack, small and
  letter-spaced, bold for Japanese (ground:
  `platform`). Sans is the apparatus; serif is the argument.
- Code, IDs, paths: existing monospace stack.
- PDF scale: body 10pt / 1.65 (Japanese mincho needs the extra leading; ground
  `ARBITRARY` within the 1.5–1.8 range used for CJK text), h1 20pt, h2 13pt,
  h3 11pt, captions and notes 8.5pt (`ARBITRARY`, a ~1.25 step).
- Lining tabular figures for every count.

**Colour.** Ink on paper; colour is reserved for severity and links. No fills
behind text except listing highlights.

| Role | Light | Ratio vs `#fff` | Dark | Ratio vs `#17171a` |
|---|---|---|---|---|
| ink | `#1b1b1b` | 17.22 | `#ece9e2` | 14.75 |
| muted | `#5a5a5a` | 6.90 | `#b3aea4` | 8.10 |
| High | `#8a1c1c` | 9.28 | `#f2a19a` | 8.81 |
| Medium | `#7a4800` | 7.62 | `#e8bf7a` | 10.36 |
| Low | `#24476e` | 9.54 | `#a9c3e6` | 9.91 |
| link | `#1f3f66` | 10.71 | `#a9c3e6` | 9.91 |

All `measured` (WCAG relative luminance); every pair clears AA 4.5:1, most AAA.
Hues are `ARBITRARY` within the role: deep, desaturated inks. In greyscale
they are told apart by the label text and by the entry's left rule weight
(High 2.4pt, Medium 1.2pt, Low 0.6pt), not by darkness.

**Composition.**
- PDF: A4, margins 22mm top, 24mm bottom, 22mm sides (text measure ≈ 166mm ≈
  47 Japanese characters at 10pt — within the 35–50 range for comfortable
  CJK text; ground `derived` from that range and the body size). Running
  footer: the fixed string `SECURITY ASSESSMENT` left, page `n / N` right; it
  stays fixed so page furniture can be stripped mechanically from extracted text.
- Case is never transformed by CSS: labels keep the recorded text, because
  `text-transform` changes what the browser and PDF extraction return.
- Sections numbered by CSS counters (1, 1.1); tables captioned "Table n" and
  source excerpts "Listing n" by counters.
- Title page: report type in small caps, title, project, a metadata table, then
  the executive summary set as an *Abstract* block between two rules.
- Dashboard: one centred column (max 1180px), the same serif headings and
  booktabs register; filters and controls stay sans and compact.

**Surface.** Booktabs tables: 1.2pt top and bottom rules, 0.6pt rule under the
head, no vertical rules, no zebra fills. No shadows, no rounded corners beyond
2px on interactive controls, no gradients. Severity shown as small letter-spaced text in
its ink with a weighted left rule on the finding entry — never a filled pill.

**Restraint (refused).** KPI tiles, card grids, coloured section backgrounds,
icons and emoji, decorative typefaces, more than one accent per severity,
uppercase body text, justified Japanese with uneven inter-character gaps
(text stays ragged-right).

## Not this

The closest look avoided is a law-firm memorandum (all-serif, no hierarchy,
no tables) — the report keeps structured tables and sans apparatus so it
stays scannable. It does not copy any journal's or standards body's identity:
the principles taken are numbering, captioning and booktabs rules, which are
conventions, not marks.

## Falsifiable

The direction fails if (a) an executive cannot find severity counts and the
top three actions on the first page, (b) an engineer cannot cite a finding by
section number and ID, (c) greyscale printing makes High and Low
indistinguishable, or (d) the Japanese PDF falls back to a sans face in body
text on either platform.
