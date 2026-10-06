# Findings file — the single source for every output

**Read when:** REPORT, before producing the dashboard or the assessment PDF.
Write the verified results to `findings.json` once; every output is rendered
from it, so they can never disagree.

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

## Shape

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
Other fields may be empty. `status` defaults to `Open`; `validation.verdict`
defaults to `Unverified`. Findings marked `FalsePositive` or `NotApplicable` are
left out of every count and listed in a closing "excluded" section; verdict
rules are in `reference/validation.md`.

## References and source excerpts

Every finding should point the reader at evidence they can open:

- **Code in the audited repository** — give `location` as `path:line` or
  `path:start-end`, relative to the repository root. Render with
  `--repo <root>` to embed the lines around it (secret-looking values are
  masked), and set `meta.source_url` to a browse URL **pinned to a commit** so
  each location also becomes a link that will not drift
- **Third-party libraries** — `references` lists the advisory, the fix commit
  or pull request, and any write-up. `deps_scan.py` fills these from
  osv-scanner, composer audit, npm audit, pip-audit and cargo audit; add an
  `article` entry by hand when a vendor post or analysis explains the issue
  better than the advisory
- Only `http://` and `https://` URLs are accepted; anything else is rejected
  when rendering

Render with `--repo` only for the requester's own copy of the report: the
excerpts are source code, so the outputs carry the repository's confidentiality.

IDs starting with `D-` belong to `scripts/deps_scan.py`: `--into findings.json`
replaces them on each run, so do not hand-write findings with that prefix.

Same rules as the report: no working payloads, no secret values.
