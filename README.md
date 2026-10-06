# security-scan

An agent skill for a **static, read-only security review of your own
application's source code**. It maps the application, reviews it from several
perspectives, verifies what it finds, and delivers the result three ways: a
chat summary, an interactive dashboard and an assessment PDF.

> Use it only on code you own or are authorized to assess. The skill reads
> source; it does not edit code and does not send traffic to deployed systems.

## What it does

```
RECON ─► CHECKLIST ─► REVIEW ─► VERIFY ─► REPORT
 map      tailor       one pass   re-read    findings.json
 routes,  perspectives per        High and   ├─ dashboard.html
 auth,    to this app  perspective Medium    ├─ assessment.pdf
 tenancy                          findings   └─ chat summary
```

- **Recon** builds the attack-surface map: stack and versions, every entry point
  with its auth and role guard, how tenant isolation is enforced and what escapes
  it, data sinks, config, dependencies
- **Perspectives** — fifteen review angles (actor and tenant, role and
  privilege, identity and session, input handling, data exposure, business
  rules, files, availability, configuration, secrets, dependencies, build and
  delivery, integrations, client side, privacy). Each one applied, not
  applicable, or not checked is recorded in the report
- **Dependencies and supply chain** — `scripts/deps_scan.py` inventories every
  manifest and lockfile and flags missing lockfiles, floating versions, git/URL
  sources, extra registries (dependency confusion), install-time scripts, CI
  actions not pinned to a SHA, risky workflow triggers and unpinned base images.
  With `--audit` it runs osv-scanner (including malicious-package reports),
  `composer audit` and `npm audit`, and lists every audit it could not run
- **Validation** — every finding gets a verdict (`Valid`, `Likely`,
  `Unverified`, `Unlikely`, `FalsePositive`, `NotApplicable`) with evidence.
  Dependency advisories are auto-triaged (runtime vs dev-only, direct vs
  transitive, referenced in source or not) and then confirmed per package.
  False positives stay in the record but drop out of the counts
- **Fix verification** *(on request)* — turn a confirmed finding into a local
  regression test that fails on the vulnerable code and passes once the fix
  lands, kept in the repo's own suite so the hole cannot reopen. Local, owned
  code only; asserts the secure outcome, never a working exploit
  (`reference/fix-verification.md`)
- **Verify** — every High and Medium finding is re-read end to end before it is
  reported; each carries severity and confidence separately
- **Report** — one `findings.json` renders every output, so they never disagree

Ask for "what should we check" and it stops after the checklist. Ask it to
check or audit and it runs all phases.

## Install

```sh
make link                 # symlink into every installed host's skills dir
make link AGENT=claude    # one host only
make status
make unlink
```

Then invoke `security-scan` (or `/security-scan`).

## Outputs

```sh
python3 skills/security-scan/scripts/render.py findings.json --out ./report --lang ja --repo /path/to/audited/repo
```

| File | Contents |
|---|---|
| `dashboard.html` | Totals, charts by severity / confidence / category / status, filterable findings table with details, perspective coverage. Self-contained, offline, light and dark |
| `assessment.html` | The assessment document, print-styled for A4 |
| `assessment.pdf` | Cover, summary, overview, perspectives, findings, sound items, decisions, limitations, next steps, excluded findings |

Each finding carries its evidence: code findings embed the lines around
`path:line` (with `--repo`, best-effort redaction) and link to the
source when `meta.source_url` is set; library findings link to the advisory,
the fix commit or pull request on GitHub, and related articles.

Sensitive paths (`.env*`, credential files and private keys), files containing
private-key blocks, and findings categorized as `Secrets` do not embed source
excerpts. URL credentials and common secret assignments are masked in other
excerpts, but redaction is heuristic, not a guarantee. Inspect reports before
sharing them; without `--repo`, source is not embedded. `source_link` and
`snippet` are derived fields and cannot be injected through input JSON. All
report links must be absolute HTTP(S) URLs without credentials or controls.

The PDF is printed with headless Chrome/Chromium (`CHROME=/path/to/binary` to
choose one), falling back to WeasyPrint. With neither available the HTML files
are still written and the script exits `3`. Exit `2` means `findings.json` does
not match the schema; the message names the field.

The format is documented in
`skills/security-scan/reference/findings-schema.md`.

Dependency and supply-chain scan:

```sh
python3 skills/security-scan/scripts/deps_scan.py /path/to/repo                 # static, offline
python3 skills/security-scan/scripts/deps_scan.py /path/to/repo --audit \
        --into findings.json                                                    # + advisory databases
make deps TARGET=/path/to/repo AUDIT=1
```

`--audit` sends the package list to public advisory databases. Install
[osv-scanner](https://github.com/google/osv-scanner) for every-ecosystem
coverage and malicious-package detection. Without it, installed Composer, npm,
Cargo and pip-audit tools provide limited fallbacks. Composer runs with
`--no-plugins --no-scripts`. The pip-audit fallback accepts only plain
`name==version` requirements, copied into a temporary input and audited with
`--no-deps --disable-pip`. Includes, URLs, options, extras, markers and floating
versions are reported as not run rather than resolved. No dependency code is
intentionally installed or built. Use trusted audit-tool installations.

Python lockfiles (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`) require
OSV coverage; the scanner never substitutes its own Python environment. Errors
and malformed results from fallback tools are recorded in `not_run`. Use
`--audit --strict` to exit `3` when any audit is incomplete (JSON output is still
written); the default remains exit `0` after a completed scan invocation.
`--strict` is a completeness check, not a vulnerability severity gate.

On `--into`, prior manual dependency verdicts are kept as `previous_validation`
only for the same location, package/version, title and advisory IDs. They do not
silently replace the new triage verdict: revalidate exclusions after every
scan because source and configuration may have changed.

Try it on the bundled sample:

```sh
make demo                       # Japanese, with PDF, into $TMPDIR/security-scan-demo
make demo LANG_OUT=en NO_PDF=1  # English, HTML only
```

## Layout

```
skills/security-scan/
  SKILL.md                     phases, decisions, rules, outputs
  reference/recon.md           building the attack-surface map
  reference/perspectives.md    the review perspectives
  reference/dependencies.md    dependency, vulnerability and supply-chain review
  reference/validation.md      verdicts and how each finding is validated
  reference/fix-verification.md local regression tests that lock a fix in
  reference/report.md          checklist and findings report formats
  reference/findings-schema.md findings.json and the render command
  scripts/deps_scan.py         dependency inventory, supply-chain checks, audits (stdlib only)
  scripts/render.py            findings.json -> dashboard / assessment PDF (stdlib only)
examples/findings.sample.json  fictional sample for make demo / make check
```

## Development

```sh
make test    # offline unit/regression tests; all audit subprocesses are mocked
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts compile, sample renders
```

Requirements: Python 3.9+; Chrome/Chromium or WeasyPrint for the PDF;
osv-scanner and/or the ecosystem audit tools for `--audit`.
