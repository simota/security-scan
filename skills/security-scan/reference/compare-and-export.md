# Comparing assessments and exporting findings

**Read when:** asked what changed since an earlier assessment, whether fixes
landed, or to gate CI on new findings; or asked for SARIF (code scanning, IDE),
CSV (tracker, spreadsheet) or issue drafts from a finished `findings.json`.

Both tools read finished records only. They never take part in an assessment:
a run still never reads another run's outputs (*Run contract*, Independence),
and a comparison is made after both runs are complete. Both mask secret-looking
values the way the rendered reports do and write nothing inside the audited
repository.

## Comparing two runs

```
python3 scripts/compare.py <baseline-out>/findings.json <current-out>/findings.json \
  --markdown <scratch>/delta.md --json <scratch>/delta.json [--lang ja] [--fail-on High]
```

Either argument may be the output directory itself. IDs are numbered per run,
so findings are matched by what they describe, never by ID:

| Part | Matched by |
|---|---|
| Code (`F-*`) | Same file, CWE (a different recorded CWE counts against), perspective, line proximity and title similarity (word overlap; character pairs for Japanese). Different files match only with the same title |
| Dependencies (`D-*`) | Package plus a shared advisory ID; supply-chain checks without a package by file and scanner title |

Each finding lands in exactly one group:

| Group | Meaning |
|---|---|
| `new` | Included in the current run, not matched in the baseline |
| `reopened` | Ruled out (`FalsePositive`/`NotApplicable`) in the baseline, included now |
| `persisting` | Included in both, with any change of severity, confidence, verdict or status |
| `not_reported` | Included in the baseline, not repeated by the current run |
| `ruled_out` | Included in the baseline, ruled out in the current run |

`not_reported` is **not** "fixed". Two independent static reviews can differ,
so the comparison says whether the current run recorded that finding's
perspective as checked; a fix is confirmed by a regression test or retest
record (`reference/fix-verification.md`), not by absence. Say so wherever
the comparison is summarized.

`--fail-on SEVERITY` exits 1 when an open new or reopened finding is at that
severity or above, or an open persisting finding at that severity was raised
into that range or was recorded `Fixed` in the baseline (a regressed fix);
`Accepted` and `Fixed` findings never block. Exit 2 means unreadable or invalid
input, or an unsafe output path (a symlink or non-regular file).

## Exports

```
python3 scripts/export.py sarif  <out>/findings.json --out <scratch>/results.sarif
python3 scripts/export.py csv    <out>/findings.json --out <scratch>/findings.csv [--bom]
python3 scripts/export.py issues <out>/findings.json --out <scratch>/issues --lang ja [--all]
```

`--id F-001` (repeatable) limits any export to the named findings.

- **SARIF 2.1.0**: one rule per finding titled with the finding's title, level
  from severity (High `error`, Medium `warning`, Low and Info `note`), GitHub's
  `security-severity` (8.0 / 5.5 / 2.0; none for Info), the CWE help link, a
  repository-relative region, and `partialFingerprints.securityScanFinding/v1`,
  a digest of part, file, weakness class and title that ignores IDs and line
  drift so an alert follows its finding across rescans. Ruled-out findings are
  emitted with an external, accepted suppression carrying the exclusion
  evidence; `Accepted` ones with a risk-accepted suppression; `Fixed` ones are
  left out unless `--include-fixed`. Findings without a relative `path:line`
  (absolute or `..` paths, platform notes) are not emitted and are named on
  stderr and in `runs[0].properties.unlocatedFindings`
- **CSV**: one row per finding with ID, part, severity, confidence, verdict,
  status, derived verification and retest codes, category, CWE, location, the
  reproduction fields, reference URLs and the same fingerprint. Cells that
  start like a spreadsheet formula get a leading `'`. `--bom` helps Excel open
  UTF-8 Japanese text
- **Issue drafts**: one Markdown file per open, included finding (`--all`: every
  included finding) following `templates/issue.<lang>.md`, plus `index.md`.
  An open High or Medium is labelled for a private tracker or security
  advisory. Record text is escaped so a draft carries no markup, and no source
  excerpts are included. The directory must be new or empty. Filing is the
  requester's step (`SKILL.md`, *Decide first*)

Uploading SARIF to a code-scanning service sends the findings' titles, impact
and fix text to that service. That is the requester's decision, the same as
filing an issue: produce the file and name what it contains; do not upload it
yourself.

An export or comparison saved inside `<out>` is an extra output:
`contract_check.py <out> --allow NAME` names it. Prefer the scratch directory.
