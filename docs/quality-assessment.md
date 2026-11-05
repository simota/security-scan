# Quality assessment (SQI)

A repeatable rubric for the design, architecture, visual design and UI/UX of
this repository, with the baseline taken before the change set it accompanies.
The rubric, weights, evidence rules and measurement conditions below were fixed
before any code was changed; the "after" columns are filled in with the same
rubric once the changes are verified.

SQI is a rubric score, not a physical measurement. Measured values are listed
separately (see *Measurements*), and nothing here is a result from real users:
no user test was run, so task-completion rates and perceived difficulty are not
reported.

## Scope

- Design and architecture: `skills/security-scan/scripts/` (the vendored
  `scripts/scan_report_kit/` is excluded from change: `make check` pins it to
  its MANIFEST, so it can only be changed upstream) and `scripts/ci/`.
- Visual design and UI/UX: the two generated pages, `dashboard.html` and
  `assessment.html`, rendered from the five samples in `examples/`
  (`findings.sample.json`, `findings.sample.ja.json`,
  `findings.verification.sample.json`, `findings.workflow.sample.json`,
  `findings.three-pass.sample.json`). The PDF is the printed `assessment.html`.

## Formula

`SQI = 0.25 × DQI + 0.25 × AQI + 0.25 × VQI + 0.25 × UXQI` (equal weights, fixed
before the baseline). Each index is `Σ (weight × score ÷ 5)` over its items,
weights summing to 100, each item scored 0–5.

Evidence levels: E0 unverified (not scored), E1 inspection of code or
screenshots, E2 reproducible static analysis, automated tests or systematic
manual checks, E3 measured or independently corroborated.

## Measurement conditions

- Browser: headless Chrome for Testing 153 via Playwright; viewports
  1280×900 (desktop) and 390×844 (mobile); `prefers-color-scheme` light and
  dark; `prefers-reduced-motion: reduce`; language from each sample.
- Accessibility: axe-core 4.10.3, tags `wcag2a wcag2aa wcag21a wcag21aa
  wcag22aa best-practice`, on every page × viewport × scheme (20 runs per page).
- Keyboard: the first 40 Tab stops of each dashboard and assessment at desktop,
  counting stops whose computed outline and box-shadow are both absent.
- Layout: document horizontal overflow; interactive targets smaller than
  24×24 CSS px at mobile (inline links in running text counted, then checked by
  hand against the WCAG 2.5.8 inline and spacing exceptions).
- Import coupling: `python3 -B -c "import <tool>"` from the scripts directory,
  median of 9 runs, recording whether `render` and the PDF engine are loaded.
- Tests: `make check` (offline suite) and the browser interaction tests with
  `SECURITY_SCAN_BROWSER_TEST=1 CHROME=<chrome>`.

## Rubric

Each item names what earns each score. A score of 5 needs E2 or better evidence.

### DQI — software design

| Item | Weight | 5 | 4 | 3 | 2 | 1–0 |
|---|---:|---|---|---|---|---|
| D1 Separation of responsibilities | 20 | Every module has ≤2 change reasons and no module is imported for a responsibility other than its primary one | No such cross-responsibility import; ≤2 modules with ≥3 change reasons | One module imported for an unrelated responsibility, or ≥3 modules with ≥3 change reasons | ≥2 modules import a module for a responsibility unrelated to its primary one | Responsibilities mixed in most modules |
| D2 Cohesion | 15 | Every module's externally used names match its stated purpose, and no compatibility surface remains | As 5, but a module keeps re-exported names for compatibility | One module's externally used surface includes an unrelated responsibility | Two or more such modules | No discernible module purpose |
| D3 Interfaces and contracts | 15 | Documented, machine-checked contracts and typed public functions | Documented and machine-checked contracts (schema validation, contract checker), untyped | Documented, partly checked | Implicit contracts | None |
| D4 Ease of change | 15 | Every scenario below touches 1 module | Every scenario touches ≤2 modules | One scenario touches ≥3 modules | Several scenarios touch ≥3 modules | Most changes ripple widely |
| D5 Readability | 10 | Functions short and named for intent; no function >120 lines | ≤3 functions >120 lines, each internally sectioned | 4–8 functions >120 lines | >8 | Unreadable |
| D6 Testability | 15 | Regression suite covers normal, error and hostile cases offline, with injectable dependencies, and a structural rule is enforced by tests | Broad offline suite with injectable dependencies | Partial suite | Few tests | None |
| D7 Invariants and error handling | 10 | No swallowed exceptions; invariants raise typed errors with locations; failures leave outputs unchanged (tested) | As 5 with minor gaps | Some swallowed or untyped failures | Frequent | Errors ignored |

Change scenarios for D4: S1 add a validation verdict; S2 change a secret-masking
rule; S3 restyle the dashboard; S4 add a field check to the findings schema;
S5 add a dependency ecosystem.

### AQI — architecture

| Item | Weight | 5 | 4 | 3 | 2 | 1–0 |
|---|---:|---|---|---|---|---|
| A1 Module boundaries and dependency direction | 20 | 0 cycles, 0 record/tool → presentation imports, and the rule is enforced by a test | 0 cycles, 0 such imports | 0 cycles, 1–2 such imports | 0 cycles and ≥3 such imports, or 1 cycle | Multiple cycles |
| A2 Layering and data flow | 15 | record → validate → derive → present each in its own modules, one-way | One-way flow, one stage embedded in another stage's module | Two stages embedded | Flow loops back | No discernible flow |
| A3 Locality of change | 15 | Presentation module has 0 importing modules outside presentation | 1 | 2–3 | 4–5 | ≥6 |
| A4 Contracts and data integrity | 15 | Every entry point validates; writes are atomic and lock-protected; tested | Validated and atomic, gaps in locking | Validated, non-atomic writes | Partial validation | None |
| A5 Fault tolerance and isolation | 10 | Timeouts, signals and partial failures handled with actionable recovery, observed or tested | Handled, not all tested | Some handled | Few | None |
| A6 Security and privacy boundaries | 10 | Input validation, output escaping, secret redaction and a browser-enforced policy on generated pages, all tested | Validation, escaping and redaction tested; no browser-enforced policy | Two of these | One | None |
| A7 Observability and operability | 10 | Every step reports status and actionable errors and leaves an audit record, tested | Status and actionable errors, partial records | Errors reported, little guidance | Silent failures possible | Opaque |
| A8 Scalability | 5 | Large-input behaviour benchmarked against a stated budget | Large-input regression tests exist | Linear behaviour assumed | Known superlinear paths | Fails on large inputs |

### VQI — visual design

| Item | Weight | 5 | 4 | 3 | 2 | 1–0 |
|---|---:|---|---|---|---|---|
| V1 Visual hierarchy | 20 | Title, summary, priority queue and register read in task order on every sample and viewport | As 5 with one competing emphasis | Several competing emphases | Primary information hard to locate | No hierarchy |
| V2 Component and style consistency | 20 | One token set; every component state drawn the same way everywhere | Tokens used; ≤2 local overrides of shared components | 3–5 overrides or inconsistent states | Widespread | None |
| V3 Typography and legibility | 15 | No word in a data cell broken mid-word at tested viewports; body ≥13px; secondary ≥11px | No mid-word break of enumerated values; isolated minor issues | Recurring mid-word breaks in a primary table | Text clipped or overlapping | Illegible |
| V4 Layout and responsiveness | 15 | 0 horizontal overflow, 0 clipped values in controls at tested viewports | 0 overflow; current values of ≤2 controls truncated at one viewport | 0 overflow; wider truncation | Overflow at a tested viewport | Broken layout |
| V5 Interaction state visibility | 10 | Focus visible at every Tab stop; pressed, expanded and copied states shown | One state missing | Several | Focus invisible somewhere | None |
| V6 Colour, contrast and meaning | 10 | 0 axe contrast violations in light and dark; severity never colour-only | ≤2 contrast nodes | ≤10 | More | Unreadable |
| V7 Whitespace and density | 10 | Consistent rhythm; density suited to a working register | Minor inconsistencies | Crowded or sparse regions | Disorganised | — |

### UXQI — UI/UX

Representative tasks (start: the dashboard is open at the top; success as stated):
T1 identify the first open finding to act on (its card in *Start here* is
visible); T2 narrow the register to High findings (only High rows shown);
T3 open a finding's details and copy it for an LLM (clipboard holds the
Markdown); T4 reach the printable assessment (assessment.html open).

| Item | Weight | 5 | 4 | 3 | 2 | 1–0 |
|---|---:|---|---|---|---|---|
| U1 Task completion and efficiency | 25 | T1–T4 verified by real users | T1–T4 each ≤2 actions and covered by automated browser tests | Covered by inspection only | A task needs ≥4 actions | A task cannot be completed |
| U2 Discoverability and cognitive load | 15 | Every control's current state fully visible; labels self-explanatory | One minor issue | Two or more minor issues (e.g. truncated current values) | A primary control hard to find | — |
| U3 Predictability and consistency | 15 | Same control, same behaviour everywhere, tested | Consistent by inspection | Some inconsistency | Surprising behaviour | — |
| U4 Feedback | 10 | Live result counts, copy outcome and empty states announced, tested | One missing | Several | Actions silent | — |
| U5 Error prevention and recovery | 10 | Every filter state recoverable in one action; guidance in empty states; tested | Recoverable, guidance partial | Recovery needs several steps | Dead ends | — |
| U6 Accessibility | 15 | 0 axe violations, full keyboard operation, visible focus, plus a manual screen-reader pass | 0 axe violations, keyboard and focus verified; no screen-reader pass | ≤5 violation nodes | More | Unusable |
| U7 Perceived performance | 10 | Interactive in <100 ms on samples and large registers tested | <300 ms on samples | <1 s | Slower | — |

## Baseline (before changes)

Repository state: branch from `a9efdc4`, clean tree. Python 3.13 locally; CI
uses 3.9 and 3.12.

### Measurements

| Measure | Baseline |
|---|---|
| `make check` | 1105 tests OK, 26 skipped (browser/PDF opt-in) |
| Browser interaction tests (`SECURITY_SCAN_BROWSER_TEST=1`) | all non-PDF browser tests pass |
| PDF tests | fail in this container: the Chrome engine times out (120 s, as root with `--no-sandbox`); environment limitation, not a code regression, so PDF output is unverified here |
| axe violations (dashboard / assessment, 20 runs each) | 0 / 0 |
| Focus-invisible Tab stops | 0 of 290 (dashboard), 0 of 68 (assessment) |
| Horizontal overflow runs | 0 / 40 |
| Targets <24 px at mobile | 22 dashboard, 24 assessment — all inline links (headings, ID cells, footers); covered by the WCAG 2.5.8 inline/spacing exceptions on inspection |
| Register enum values broken mid-word (desktop 1280) | "Environment-dependent" → "Environmen/t-dependent" and "Unverified" → "Unverifie/d" in 4 of 5 samples (columns 96 px and 84 px wide; words need 84+24 and 65+24 px) |
| Truncated current values of filter selects (≥1100 px) | 2 (Records, Order) in en and ja |
| Record/tool modules importing `render` (presentation) | 4 direct (`findings`, `evidence_capture`, `expert_audit`, `scan_run`) + `deps_scan` transitively |
| `import findings` loads `render` and the PDF engine | yes; median 31.9 ms (`evidence_capture` 32.3, `expert_audit` 31.7, `scan_run` 32.8, `deps_scan` 34.9) |
| Import cycles among scripts | 0 |
| Functions >120 lines | 8 (`deps_scan.check_workflow` 477, `expert.derive_expert` 406, `render.render_assessment_html` 206, …) |
| Content-Security-Policy on generated pages | none |
| Dashboard DOMContentLoaded (samples) | 18–26 ms |

### Scores

| Item | W | Score | Evidence | Basis |
|---|---:|---:|---|---|
| D1 | 20 | 2 | E2 | `render.py` (2,684 lines) holds schema validation, secret masking, source excerpts, views, templates and the CLI; four record/tool modules import it for schema and secret checks |
| D2 | 15 | 3 | E2 | `render`'s externally used surface is mostly schema (`SchemaError`, `validate_data`, `json_depth`, `EXCLUDED`) and secret detection (`secret_in_source`) |
| D3 | 15 | 4 | E2 | `reference/findings-schema.md`, `validate_data`, `contract_check.py`; public functions untyped |
| D4 | 15 | 3 | E2 | S1 touches 8 modules (verdict names repeated); S2–S5 touch 1 each |
| D5 | 10 | 3 | E2 | 8 functions >120 lines |
| D6 | 15 | 4 | E2 | 1,105 offline tests, injectable SchemaError and patched engines; no structural rule enforced |
| D7 | 10 | 5 | E2 | 0 swallowed exceptions; typed `SchemaError` with field paths; outputs untouched on failure (tested) |
| **DQI** | | **66** | coverage 100 % | |
| A1 | 20 | 2 | E2 | 0 cycles; 4 record/tool → presentation imports |
| A2 | 15 | 4 | E1 | one-way flow; validation embedded in the presentation module |
| A3 | 15 | 2 | E2 | 4 direct importers of `render` outside presentation (5 with `deps_scan`) |
| A4 | 15 | 5 | E2 | validation on load, atomic writes via the kit, merge locks and concurrent-edit tests |
| A5 | 10 | 5 | E3 | observed here: PDF engine timeout reported with recovery steps, HTML kept |
| A6 | 10 | 4 | E2 | validation, escaping, redaction and hostile-text browser tests; no CSP |
| A7 | 10 | 4 | E2 | runner status and actionable errors |
| A8 | 5 | 4 | E2 | large-register and performance regression tests, no stated budget |
| **AQI** | | **71** | coverage 100 % | |
| V1 | 20 | 4 | E1 | screenshots: banner → cards → *Start here* → register; summary and cards compete slightly |
| V2 | 20 | 4 | E1 | shared kit tokens; local register/filter overrides in `DASHBOARD_CSS` |
| V3 | 15 | 3 | E2 | recurring mid-word breaks of enum values in the register |
| V4 | 15 | 4 | E2 | 0 overflow; 2 truncated select values at ≥1100 px |
| V5 | 10 | 5 | E2 | 358/358 Tab stops with visible focus; pressed/expanded/copied states |
| V6 | 10 | 5 | E2 | 0 contrast violations light and dark; severity also written as text |
| V7 | 10 | 4 | E1 | consistent rhythm |
| **VQI** | | **81** | coverage 100 % | |
| U1 | 25 | 4 | E2 | T1–T4 ≤2 actions each; browser tests cover facets, details, copy and links |
| U2 | 15 | 3 | E1 | truncated current filter values (2); enum values split mid-word in the register |
| U3 | 15 | 4 | E1 | consistent controls |
| U4 | 10 | 5 | E2 | `aria-live` result count, copy outcome, empty-state text, tested |
| U5 | 10 | 4 | E2 | *Clear filters*, empty-state guidance |
| U6 | 15 | 4 | E2 | 0 axe violations, keyboard and focus verified; no screen-reader pass |
| U7 | 10 | 4 | E3 | 18–26 ms DOMContentLoaded on samples; lazy details tested on large registers, no stated budget |
| **UXQI** | | **79** | coverage 100 % | |
| **SQI** | | **74.25** | | |
