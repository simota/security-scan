# Report design direction

Moved: the design system for `assessment.html` / `assessment.pdf` and
`dashboard.html` (decided here 2026-10-07) is now the shared format of every
*-scan skill. It lives in the scan-report-kit repository (its design document
is `design.md` under that repository's docs directory), next to the
stylesheets it governs.

security-scan uses it as follows:

- `skills/security-scan/scripts/scan_report_kit/` is a vendored copy of the kit
  (stylesheets, PDF engine, safe writes). `make check` fails if it is edited in
  place; change the kit upstream, then run its `make vendor DEST=<this repo>/skills/security-scan/scripts`.
- `skills/security-scan/scripts/render.py` inlines the shared stylesheets first and
  appends only the rules for security-scan record types (verification,
  workflow, expert and three-pass records, evidence cells) in `ASSESSMENT_CSS`
  and `DASHBOARD_CSS`.
- The running footer is `SECURITY ASSESSMENT` (ja `セキュリティ診断`), passed to
  `document_css()` from the `a_running_footer` label.
