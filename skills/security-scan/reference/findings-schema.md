# Findings file — the single source for every output

**Read when:** REPORT, before producing the dashboard or the assessment PDF.
Write the results and their verification limits to `findings.json` once. The
dashboard and assessment use the same recorded facts and derived verification
model; keep the chat summary consistent with them.

Render with (paths relative to this skill's directory):

```
python3 scripts/render.py findings.json --out <dir> [--lang ja|en] [--no-pdf] [--repo <audited-repo>]
```

It writes:

- `<dir>/dashboard.html` — interactive dashboard: totals, charts by severity,
  confidence, category and status, filterable findings table with expandable
  details, perspective coverage. Self-contained, works offline
- `<dir>/assessment.html` — the assessment document, print-styled for A4
- `<dir>/assessment.pdf` — the assessment document as PDF, printed by headless
  Chrome/Chromium (set `CHROME` to choose a binary) or WeasyPrint as a fallback

Exit codes: `0` done, `2` the file does not match the shape (the field is
named), `3` no PDF engine found (the HTML outputs are still written). A
sandboxed shell may block the browser; rerun outside it if `3` appears with
Chrome installed. Write `<dir>` outside the audited repository unless asked.

## Common report shape and legacy compatibility

The following fields apply to both formats. Omitting `schema_version` retains
legacy compatibility; the new structured format uses integer `schema_version: 2`
and the additional objects below. A legacy verdict is retained, not upgraded to
verified merely because it contains an evidence string.

```json
{
  "meta": {
    "project": "name of the system assessed",
    "date": "YYYY-MM-DD",
    "assessor": "who ran it",
    "scope": "what was in scope",
    "method": "static source review, read-only",
    "commit": "optional VCS revision",
    "source_url": "optional browse URL at that revision, e.g. https://github.com/org/repo/blob/<sha>"
  },
  "findings": [
    {
      "id": "F-001",
      "title": "one line",
      "severity": "High | Medium | Low | Info",
      "confidence": "Confirmed | Environment-dependent | Suspected",
      "category": "the perspective that surfaced it",
      "location": "path:line",
      "actor": "who can trigger it",
      "request": "method, path, parameter names",
      "impact": "what happens",
      "fix": "fix direction",
      "status": "Open | Fixed | Accepted",
      "references": [
        { "type": "advisory | fix | article | report | source | web | package",
          "url": "https://...", "title": "optional label" }
      ],
      "validation": {
        "verdict": "Valid | Likely | Unverified | Unlikely | FalsePositive | NotApplicable",
        "evidence": "why; required for Valid, FalsePositive, NotApplicable",
        "method": "auto | review | runtime"
      }
    }
  ],
  "perspectives": [
    { "name": "Actor and tenant", "result": "2 High, 1 Medium", "note": "" }
  ],
  "checked_ok": ["what was examined and held"],
  "decisions": ["questions a human must answer"],
  "limitations": ["what static reading could not show"],
  "next_steps": ["recommended order of work"]
}
```

`meta.project`, `meta.date` and every finding's `id`, `title`, `severity`,
`confidence` and `location` are required, and `id` must be unique. Every
`perspectives` entry needs a `name`; use the names in `reference/perspectives.md`.
Required text fields must be nonblank strings. Optional text fields may be
omitted or use an empty string; numbers, booleans, arrays, objects and `null`
are not converted to text. `meta.source_url` also accepts `null` as an absent
link. Report lists (`checked_ok`, `decisions`, `limitations`, `next_steps`)
contain strings. Present `validation` and `previous_validation` values must be
objects, `references` must be a list, and their documented text fields must be
strings. An invalid value exits `2` with its field path (including list index)
before creating report files. Text must be valid Unicode; locations cannot
contain control characters, and source line numbers must be parseable by the
Python runtime. Non-finite JSON numbers are rejected. Unknown extension fields
are retained if their values can be represented safely in UTF-8/JSON output;
this does not make them verification evidence. Derived verification labels are
computed by the renderer and cannot be set by an input flag.

`status` defaults to `Open`; `validation.verdict`
defaults to `Unverified`. Findings marked `FalsePositive` or `NotApplicable` are
left out of included totals and listed in a closing "excluded" section. The
validation distribution intentionally includes all records; verdict
rules are in `reference/validation.md`.

## Version 2: structured verification

Explicit integer `schema_version: 2` is the only opt-in to structured validation.
Omitted version and integer `1` remain legacy; other versions are rejected.
Legacy files retain arbitrary old extension fields, including root `assessment`,
`evidence`, `test_runs` and finding `verification`/`remediation`, without validating
or interpreting them as new proof. Existing common-field validation still applies.
All their findings remain `legacy` and cannot be fix-ready.

A mixed version-2 file may retain findings without `verification` or with a
historical string-valued verification note. Those findings also keep their
recorded verdict and receive `legacy` verification. In version 2, a structured
`remediation` requires structured `verification`.

The full, explicitly synthetic example is
`examples/findings.verification.sample.json` at the repository root. Its source,
commits, hashes, reviewers and test outcomes are invented fixtures, not evidence
of an executed assessment. The following describes the implemented fields;
there is no asset inventory, coverage matrix or automatic test runner.

### Assessment pin and evidence registry

`assessment` is required in version 2:

| Field | Required content |
|---|---|
| `repository` | Nonblank repository identity |
| `commit` | Full 40- or 64-character hexadecimal Git object ID |
| `worktree` | `clean` or `dirty` |
| `diff_sha256` | 64-character hexadecimal digest, required exactly when `worktree` is `dirty` |

If `meta.commit` is nonempty, it must match `assessment.commit`. A pin is the
commit plus optional worktree-diff digest. Current claims, checks, reviews and
applicability evidence must match the assessment pin. Historical and fixed-code
artifacts may be kept in the registry, but cannot stand in for current evidence.

`evidence` is a list of records. Each needs unique nonblank `id`, `kind` (`source`,
`runtime` or `environment`), `commit`, `location`, sanitized `summary` and a
64-character hexadecimal artifact `sha256`. Optional `diff_sha256` is part of
its pin. All IDs in `evidence_ids` must exist and may not be duplicated within
a reference list. Supported/contradicted claims must reference evidence;
`unknown` claims may have an empty list.

Artifact locations and digests are recorded, not opened, downloaded or checked
against file contents. The separate `--repo` source-excerpt feature does not
attest to the evidence registry's hashes or revision. Use a matching authorized
checkout and inspect the original artifacts before relying on them.

### Per-finding verification

`verification` is an object with these fields:

- `reviewer`: nonblank identity of the primary reviewer
- `claims`: the four required claim names below, each with `status`,
  nonblank `reason` and `evidence_ids`
  - `reachability`: the named actor can reach the relevant route and operation
  - `preconditions`: required feature, version, configuration and state hold
  - `defenses`: compensating controls do not neutralize the claimed issue
  - `impact`: the claimed data exposure, action or state change follows
- `falsification`: list of checks with nonblank `check` and `reason`, `result`
  (`clear`, `contradiction` or `unresolved`) and `evidence_ids`. A non-unresolved
  result requires evidence. Definitive verdicts require at least one check
- `reviews`: list of independent review records with `reviewer`, `conclusion`
  (`agree`, `disagree` or `unresolved`), nonblank `reason` and current
  `evidence_ids`. Every review requires evidence, regardless of conclusion
- `environment`: `status` (`not_required`, `verified` or `unknown`), nonblank
  `reason` and `evidence_ids`. `verified` requires current `environment`-kind
  evidence. `not_required` must explain the bounded claim being made, rather than
  hiding a deployment assumption
- `run_ids`: list of test-run IDs from the assessment pin, or an empty list for
  a static review

Claim statuses are `supported`, `contradicted` or `unknown`. A structured
`Valid` requires four supported, evidence-backed claims and at least one
falsification check, all `clear`; missing/contradictory claims or unresolved
falsification produce a schema error. To derive sufficient static support,
each of the four claims must include `source` evidence. Runtime-only assertions
cannot replace the source trace. `Unverified`, `Likely` and `Unlikely` always
derive `incomplete` with `verdict_unresolved`, even when all evidence fields
are complete. Derivation preserves the recorded verdict rather than upgrading it.

For a High definitive verdict (`Valid`, `FalsePositive`, `NotApplicable`),
sufficient verification requires a review by someone other than the primary
reviewer that covers every evidence ID used by the four claims. A missing review
or one that does not cover all claim evidence keeps verification incomplete.
Any reviewer disagreement/unresolved conclusion also keeps it incomplete, even
if several other reviewers agree. To resolve it, add that review's `resolution`
object with `reviewer` equal to the dissenting reviewer, nonblank `reason` and
current `evidence_ids`. The schema checks declared identities and references;
it cannot establish a person's actual independence.

For `FalsePositive` or `NotApplicable`, add `verification.exclusion` with
nonblank `reason`, current `evidence_ids`, and `basis` respectively
`condition_absent` or `not_applicable`. At least one of the four claims must be
`contradicted` with evidence. A mismatched/missing exclusion basis is rejected;
`exclusion` is not allowed on other verdicts. These records also require
falsification checks and the existing nonblank `validation.evidence` summary.

### Test-run records

`test_runs` is an optional list. Each record needs:

| Field | Content |
|---|---|
| `id`, `case_id` | Unique run ID and stable case ID |
| `commit`, optional `diff_sha256` | Assessed/fixed revision and optional worktree digest |
| `role` | `security`, `positive_control` or `regression` |
| `context.environment` | `local` or `throwaway` |
| `context.configuration`, `context.fixture`, `context.test_version` | Nonblank identities of the configuration, fixture and tests |
| `context.boundary` | `real`, `mocked` or `unknown`, for the control being tested |
| `result` | `pass`, `fail`, `not_run`, `blocked`, `unsupported`, `error` or `skip` |
| `failure_kind` | `none`, `assertion` or `infrastructure` |
| `exit_code` | Integer or `null`; use `null` when there was no process result |
| `expected`, `observed`, `command` | Nonblank sanitized descriptions; commands are never executed by the renderer |
| `recorded_at` | ISO-8601 timestamp with timezone |
| `evidence_ids` | Runtime evidence IDs matching the run's commit/worktree pin |

`pass` requires exit code `0` and failure kind `none`; `fail` requires a nonzero
exit code and a failure kind. Passed and failed runs require evidence. Other
outcomes remain incomplete, never pass. Record the secure expectation: a
legitimate vulnerable-case reproduction is a `security` run whose secure
assertion fails (`failure_kind: assertion`, positive exit code) through a `real`
boundary. Infrastructure failures, mocked/unknown boundaries, and an ordinary
successful process do not establish reproduction.

`runtime_supported` additionally requires `Valid`, sufficient source claims and
review, and such a legitimate failing security run in `verification.run_ids`.
Every run listed in `verification.run_ids` must support that reproduction; an
incomplete attempt prevents `runtime_supported` even if another listed run
legitimately reproduces the issue. Otherwise sufficient static evidence can
remain `static_supported`, with the runtime gap visible. A listed `security` run
that passes the secure assertion through a `real` boundary contradicts `Valid`.
A legitimate real-boundary failed security assertion instead contradicts
`FalsePositive` or `NotApplicable`. Either conflict adds `runtime_contradiction`
and derives `incomplete`, preserving the recorded verdict; it cannot be overruled
by another run or reviewer votes. Do not cherry-pick recorded runs. Post-fix and normal-control
runs belong to the remediation links, not the original reproduction list.
Unknown environment conditions derive `environment_unverified` unless other
blocking gaps already make verification `incomplete`; an isolated fixture does
not prove deployed behavior.

### Remediation and independent retest records

`status: Fixed` alone derives `fix_claimed`, not a verified retest. To record a
retest, add a `remediation` object with its intended fixed `commit` and optional
`diff_sha256`, plus these links:

- `before_run_id`: the current-assessment security run, also present in
  `verification.run_ids`, that legitimately fails its secure assertion
- `after_run_id`: a passing security run at the intended fixed pin
- `positive_control_run_ids`: one or more passing legitimate-use control runs
- `regression_run_ids`: one or more passing nearby-path regression runs

The fixed pin must differ from the assessment pin. Before/after must have the
same `case_id`, identical `expected` secure assertion, and matching environment,
configuration, fixture, test version and boundary. Controls/regressions must be
at the intended fixed pin, match the after-run context and have case IDs different
from the security case. Every counted run must exercise a `real` boundary with
the correct role. The original finding must remain `Valid` and
`runtime_supported`; static support alone is insufficient for a verified retest.
Thus a skipped/errored listed original run blocks verified retest even if the
selected before/after pair and its controls are otherwise complete.

Unknown run IDs or malformed records are errors. Missing links, wrong cases,
mismatched revisions/context, absent controls, failed/incomplete runs or
incomplete original verification derive retest `incomplete`; they never become
`verified`. A green post-fix run without legitimate before evidence is therefore
reported as incomplete. `Accepted` is a recorded response, not retest evidence.

### Derived states and limits

`scripts/verification.py` derives, per finding, `level`, `retest`, gap codes,
referenced `evidence_ids` and `run_ids`. `level` is one of `legacy`,
`incomplete`, `static_supported`, `runtime_supported` or `environment_unverified`.
`retest` is `not_requested`, `fix_claimed`, `incomplete` or `verified`. Input
`_verification` is replaced, never trusted. Do not hand-author these labels as
proof; supply the underlying records.

Schema checks establish structure and declared consistency only. They cannot
prove artifacts exist, verify their hashes, authenticate identities or execution,
check the truth of a claim, prove equivalent fixture semantics, or establish
that every relevant route was examined. The records grant no authorization to
run commands or use credentials. Runtime work remains explicitly authorized,
owned local/throwaway testing under `reference/fix-verification.md`.

## Reading the outputs

- Both summaries state recorded `Unverified`, insufficient-verification and
  excluded counts. A legacy `Valid` can therefore remain a recorded verdict
  while still requiring evidence. `Fixed` and `Accepted` statuses do not assert
  independent verification of remediation; retest state is displayed separately.
- The open-finding queue orders by severity, then fix readiness, then ID.
  Fix readiness needs `Valid` + `Confirmed` and sufficient structured static or
  runtime support. Missing independent review, unknown environment conditions
  and legacy evidence do not silently receive fix-ready priority.
- Scope, method, revision and limitations are visible before the finding
  details. Missing perspective coverage is unknown. No coverage percentage,
  all-clear verdict or risk score is inferred from missing data.
- Dashboard filters only affect the register, not report-wide counts. An
  explicit record selector switches between included, excluded and all
  findings. Selecting an excluded verdict switches to all records.
- Generated finding anchors link the queue, register and details. They are
  stable for the same sorted input; re-scans can change numbering.
- Source excerpts visibly identify truncation beyond 200 lines or 240
  characters per line. The full source remains the evidence of record.
- `previous_validation`, if present from a dependency re-scan, is shown as
  historical context. It cannot replace the current verdict or counts.

## References and source excerpts

Every finding should point the reader at evidence they can open:

- **Code in the audited repository** — give `location` as `path:line` or
  `path:start-end`, relative to the repository root. Render with
  `--repo <root>` to embed the lines around it (secret-looking values are
  masked), and set `meta.source_url` to a browse URL **pinned to a commit** so
  each location also becomes a link that will not drift
- **Third-party libraries** — `references` lists the advisory, the fix commit
  or pull request, and any write-up. `deps_scan.py` fills these from
  supported audit results; add an `article` entry by hand when a vendor post or analysis explains the issue
  better than the advisory
- Only absolute `http://` and `https://` URLs without credentials or control
  characters are accepted; anything else is rejected when rendering

Render with `--repo` only for the requester's own copy of the report: the
excerpts are source code, so the outputs carry the repository's confidentiality.

IDs starting with `D-` belong to `scripts/deps_scan.py`: `--into findings.json`
replaces them on each run, so do not hand-write findings with that prefix.

Same rules as the report: no working payloads, no secret values.
