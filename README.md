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
  New structured records link four claims (reachability, preconditions, defenses
  and impact) to revision-pinned evidence, falsification checks and independent
  reviewer records. Static support, isolated runtime reproduction and unknown
  environment conditions remain distinct. Legacy verdicts are preserved but
  without structured evidence cannot become fix-ready. Dependency advisories
  remain auto-triaged and then reviewed per package; exclusions stay visible
- **Fix verification** *(on explicit request)* — record the same local case
  failing a secure assertion for the right reason before the fix, passing after,
  and passing positive-control and regression cases. Recorded `Fixed` remains
  separate from evidenced retest completion. Owned local or throwaway code only;
  synthetic fixtures and inert inputs, never a working exploit
  (`reference/fix-verification.md`)
- **Verify** — every High and Medium finding is re-read end to end before it is
  reported; each carries severity and confidence separately
- **Report** — one `findings.json` supplies the dashboard and assessment, with
  a shared verification model and explicit evidence limitations

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
| `dashboard.html` | Prioritized fix/validate queue, explicit uncertainty and coverage limits, report-wide totals, accessible searchable findings with included/excluded views and deep links. Self-contained, offline, light and dark |
| `assessment.html` | The assessment document, print-styled for A4 |
| `assessment.pdf` | Decision-ready first page, fix/validate queue, scope and limits, linked finding register, full evidence, excluded records and page numbers |

Both outputs distinguish potential severity, confidence, recorded validation
and evidence-derived verification. An open finding is ready to plan a fix only
when it is `Valid`, `Confirmed` and has sufficient structured verification;
legacy records or incomplete evidence call for validation first. The queue sorts
by severity, then readiness to fix, then ID. No risk score or deadline is invented.
`Fixed` and `Accepted` describe recorded status; the separately derived retest
state shows whether the required before/after and control records exist.

Unverified, insufficient-verification and excluded counts are explicit. Headline
totals include `Open`,
`Fixed` and `Accepted`, excluding `FalsePositive` and `NotApplicable`; the
validation distribution includes all records for traceability. Filters affect
only the finding register, with a visible result count and a reset button.
Choose Included, Excluded only, or All records, and open details with a keyboard
or a direct finding link. Missing coverage is unknown, and zero findings is
never presented as a guarantee of security.

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
Excerpts are capped at 200 lines and 240 characters per line; visible notes
identify shortened excerpts. Previous validation, when available, is labelled
as historical and never changes the current verdict or counts.

The PDF is printed with headless Chrome/Chromium (`CHROME=/path/to/binary` to
choose one), falling back to WeasyPrint. With neither available the HTML files
are still written and the script exits `3`. Exit `2` means `findings.json` does
not match the schema; the message names the field. Validation evidence must be
a string; `Valid`, `FalsePositive` and `NotApplicable` require a nonblank string.
Null, booleans, numbers, arrays and objects cannot justify an exclusion.
Required report text (including finding IDs, titles and locations) must be
nonblank strings; malformed types are rejected before output, rather than
coerced into text or allowed to cause a traceback. Optional text can be omitted
or empty. See the schema for object/list fields and the absent source-URL case.

### Structured verification records

New evidence-backed assessments use `schema_version: 2`, a pinned `assessment`,
a shared `evidence` registry, optional `test_runs`, and per-finding `verification`
and `remediation` records. Only explicit version `2` opts into the new rules.
Versionless and version-1 files keep their recorded verdicts, exclusions and
arbitrary old extension fields, including fields named `verification`, `evidence`
or `remediation`; these are not interpreted as structured proof. Their findings
remain legacy/insufficient. Findings without structured verification also remain
legacy inside version-2 files. No old field silently grants fix-ready or
runtime-confirmed status.

The verifier rejects broken evidence/run references, inconsistent revision pins
and unsupported definitive claims. It derives the verification basis and retest
state; a supplied label cannot certify itself. Missing independent High review,
unknown environment conditions and unresolved evidence remain visible. A skipped,
blocked, unsupported or errored run never counts as a pass. An incomplete listed
current-version run can leave static support intact, but prevents a runtime or
verified-retest label even if another run reproduced the issue. A listed
real-boundary security test already passing its secure assertion contradicts
`Valid`; a legitimate failing security assertion contradicts `FalsePositive` or
`NotApplicable`. Either keeps verification incomplete. `Unverified`, `Likely`
and `Unlikely` also stay incomplete even with complete evidence fields; recorded
verdicts are never automatically upgraded. A verified retest requires
runtime-supported original reproduction.

This is a record-and-report MVP. It does not add scanners, execute stored
commands, retrieve evidence files, verify their hashes, use credentials or extend
runtime authorization. Hashes identify declared artifacts; structural validation
is not proof that the evidence is true or that all paths were examined. Runtime
work still requires explicit permission for owned local or throwaway code. Broader
asset/coverage inventories and automated application-test execution are outside
this format's implemented scope.

The format and exact rules are documented in
`skills/security-scan/reference/findings-schema.md`. The explicitly synthetic
`examples/findings.verification.sample.json` demonstrates the version-2 records;
its invented commits, evidence and run outcomes are not real assessment results.
Render it with:

```sh
python3 skills/security-scan/scripts/render.py examples/findings.verification.sample.json --out /tmp/security-scan-verification-demo --no-pdf
```

Dependency and supply-chain scan:

```sh
python3 skills/security-scan/scripts/deps_scan.py /path/to/repo                 # static, offline
python3 skills/security-scan/scripts/deps_scan.py /path/to/repo --audit \
        --into findings.json                                                    # + advisory databases
make deps TARGET=/path/to/repo AUDIT=1
```

`--audit` sends the package list to public advisory databases. Install
[osv-scanner](https://github.com/google/osv-scanner) for every-ecosystem
coverage and malicious-package detection. Without it, installed Composer, npm
and pip-audit tools provide limited fallbacks. Automatic `cargo audit` execution
is disabled: Cargo lockfiles require OSV coverage, otherwise the audit is
recorded in `not_run` rather than running Cargo against the target checkout.

npm explicitly includes prod, dev, optional and peer dependencies, even when
`.npmrc` or the environment omits them, and disables lifecycle scripts.
Composer runs with `--no-plugins --no-scripts` against a temporary copy of the
lockfile, an auditor-owned manifest and an empty Composer home. Project/global
exclusions and `COMPOSER*` environment overrides are not inherited; abandoned
packages are explicitly reported. Custom repository configuration is not copied,
and its advisory coverage is recorded as incomplete. The original project files
are unchanged. See `AUDIT_SAFETY.md` for the boundaries of these fallbacks.

The pip-audit fallback accepts only plain `name==version` requirements, copied
into a temporary input and audited with `--no-deps --disable-pip`. Includes,
URLs, options, extras, markers and floating versions are reported as not run
rather than resolved. No dependency code is intentionally installed or built.
Use trusted audit-tool installations.

Python lockfiles (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`) require
OSV coverage; the scanner never substitutes its own Python environment. Errors
and malformed results from fallback tools are recorded in `not_run`. Use
`--audit --strict` to exit `3` when any audit is incomplete (JSON output is still
written); the default remains exit `0` after a completed scan invocation.
`--strict` is a completeness check, not a vulnerability severity gate.

Shared lockfiles are associated with explicitly declared Cargo and npm/Yarn
workspace members, respecting exclusions and nested workspace boundaries.
Cargo workspace TOML parsing requires Python 3.11+; on Python 3.9/3.10, missing
parser support is recorded as incomplete. Implicit Cargo path-dependency
membership, explicit `package.workspace` pointers and pnpm YAML membership are
not guessed: unresolved ownership is listed in `not_run`.

Workflow interpolation checks distinguish ordinary block-style `steps[*].run`
scalars from `env` and `with` data. Safe environment-variable handoffs are not
reported as direct shell interpolation. This is a conservative YAML subset;
aliased/tagged steps and flow-style structures require manual review and are
recorded as incomplete when recognized.

On `--into`, prior manual dependency verdicts are kept as `previous_validation`
only for the same location, package/version, title and advisory IDs. They do not
silently replace the new triage verdict: revalidate exclusions after every
scan because source and configuration may have changed.

Try it on the bundled sample:

```sh
make demo                       # Japanese, with PDF, into $TMPDIR/security-scan-demo
make demo LANG_OUT=en NO_PDF=1  # English, HTML only
make demo DEMO_INPUT=/path/to/findings.json  # custom data
```

The default Japanese demo uses `examples/findings.sample.ja.json`, an explicitly
fictional report with confirmed, uncertain, fixed, accepted and excluded records.
The English demo uses `examples/findings.sample.json`.

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
  scripts/verification.py      evidence consistency and derived verification/retest states
examples/findings.sample.json  fictional legacy sample for make demo / make check
examples/findings.verification.sample.json  synthetic structured-verification example
```

## Development

```sh
make test    # offline unit/regression tests; all audit subprocesses are mocked
make check   # tests plus citations resolve, references headed, frontmatter valid,
             # scripts compile, sample renders
```

Requirements: Python 3.9+ (Python 3.11+ for Cargo workspace ownership parsing);
Chrome/Chromium or WeasyPrint for the PDF; osv-scanner and/or the supported
ecosystem audit tools for `--audit`.

GitHub CI also requires real Chromium interaction and Japanese/English PDF
checks with zero skipped tests. See [CI checks and local reproduction](docs/ci.md)
for the pinned tooling, synthetic artifacts and stricter test command.
