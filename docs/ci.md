# Offline report CI

`.github/workflows/ci.yml` runs on pushes to `main`, all pull requests and manual
dispatches. Feature branches use their PR run rather than duplicating every job
for both the branch push and pull-request event.
Independent jobs run `make check` on Python 3.9 and 3.12, plus the complete
Python 3.12 test suite with real Chromium and PDF generation required. No advisory service, target system or external audit
command is called. Browser interaction tests abort page network requests; PDF
inputs are the self-contained, synthetic report fixtures.

## Required coverage

A CI-only preflight first prints a tiny synthetic HTML file using the renderer's
exact Chromium command-line flags. It stops within roughly 25 seconds and saves
the browser version, command, stdout and stderr in the synthetic artifact. A
failure prints the diagnostics and stops the job before four slow PDF retries.
Only the selected browser is tried: there are no alternate binaries, flag variants
or PDF-engine fallbacks that can turn a failing probe into a passing check.
The probe does not change renderer flags or browser sandbox protections.

`scripts/ci/run_required_tests.py` enables browser/PDF tests before discovery,
requires all named integration tests to remain present, and fails on **any
skipped test**, expected failures, an empty suite, errors or assertion failures. Missing Playwright,
Chromium, Japanese fonts or Poppler cannot count as a successful CI result.
The older smoke test's dependency skips are also caught by this runner.

- Real Tab navigation, visible focus, Enter/Space expansion, filtering, reset,
  excluded categories and hash navigation in English and Japanese.
- Both report HTML outputs at 375 px with long unbroken and HTML-like text.
  Tests assert no horizontal document overflow, no injected elements and no
  browser script errors.
- The real renderer CLI generates English/Japanese sample PDFs and a long PDF
  in each language. It must report Chromium as its engine; a missing output or
  fallback to WeasyPrint fails this check.
- Poppler extracts text from every PDF. Sample titles and validation evidence,
  including excluded findings and historical evidence, must survive. Each long
  PDF must span at least three pages and retain every one of its 120 evidence
  paragraphs and 60 remediation paragraphs, including Japanese text.
- The structured-verification fixture is rendered to an additional PDF in each
  language. Every displayed claim, reviewer, countercheck, execution record and
  referenced evidence item must survive text extraction. All input records are
  fictional; the report renderer does not execute their recorded commands.
- Verification states, retest gaps, report-wide counts and redacted proof details
  are checked in the real browser in both languages at 375 px. HTML-like proof
  remains inert text, and the new checks are mandatory in the zero-skip runner.
- Staged-verification reports are checked in both languages and at 375 px in
  the real browser. Pending, held and stale handoffs cannot become fix-ready
  through earlier evidence. Stage status, next manual stage, gaps, evidence
  lineage and recorded history remain visible. Secret-bearing identifiers and
  hostile text are redacted and inert, and raw stage output patches/extensions
  are excluded from the dashboard payload.
- Two additional workflow PDFs (English and Japanese) retain every curated stage,
  lineage and history entry, including interrupted and resumed verification.
  Fixtures advance through the actual manual submission helpers. They do not
  execute AI agents, recorded commands or application tests, and neither
  completion nor a digest authenticates artifacts or reviewers.

The `synthetic-report-evidence` Actions artifact retains the generated HTML,
PDFs, extracted UTF-8 text, page metadata and browser screenshots for seven days.
Only the designated synthetic-output directory is uploaded; no checkout,
credentials or real audit reports are included. Artifact retention does not
change repository access or branch-protection settings.

## Reproduce locally

The default `make check` still requires only the Python standard library and
skips browser/PDF integrations explicitly. Python 3.9 also explicitly skips the
two stdlib `tomllib` ownership tests, which run on Python 3.12. For the required CI suite, use Python
3.12 and a supported non-root Linux desktop or runner:

```sh
python3 -m venv /tmp/security-scan-ci-venv
. /tmp/security-scan-ci-venv/bin/activate
python -m pip install --only-binary=:all: -r scripts/ci/requirements.txt
# Debian/Ubuntu: install Poppler and Japanese fonts if they are not present.
sudo apt-get install --yes --no-install-recommends fonts-noto-cjk poppler-utils
fc-cache -f
# CI requires the runner-provided Google Chrome 154.0.8037.57 distribution.
export CHROME="/usr/bin/google-chrome"
export SECURITY_SCAN_REPORT_ARTIFACTS="/tmp/security-scan-report-artifacts"
python scripts/ci/run_required_tests.py
```

For other local runs, `CHROME` may point to another installed Chrome/Chromium;
that does not replace CI's exact distribution/version guard. Output is written
outside the checkout. A runtime that blocks browser process creation
cannot verify the integration suite; use the GitHub-hosted runner or another
permitted browser-capable environment. Do not describe a stdlib-only pass as a
browser/PDF pass, and do not disable system sandbox protections to hide failures.
The Ubuntu 22.04 runner avoids newer Ubuntu AppArmor restrictions on downloaded
Chromium user namespaces without changing security-sensitive host settings.

## Dependency provenance and maintenance

The workflow grants only `contents: read`, disables checkout credential
persistence, uses `pull_request` rather than a privileged PR trigger, and does
not consume repository secrets. All actions are pinned to full commit SHAs
verified against their official release repositories:

- [actions/checkout v7.0.1](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1)
- [actions/setup-python v7.0.0](https://github.com/actions/setup-python/commit/5fda3b95a4ea91299a34e894583c3862153e4b97)
- [actions/upload-artifact v7.0.1](https://github.com/actions/upload-artifact/commit/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a)

CI-only Python dependencies and all their runtime transitive dependencies have
exact versions in `scripts/ci/requirements.txt`, verified against PyPI:

- [Playwright 1.62.0](https://pypi.org/project/playwright/1.62.0/)
- [pyee 13.0.1](https://pypi.org/project/pyee/13.0.1/)
- [greenlet 3.5.5](https://pypi.org/project/greenlet/3.5.5/)
- [typing_extensions 4.16.0](https://pypi.org/project/typing-extensions/4.16.0/)

The workflow uses the GitHub runner's already-installed official **Google Chrome
154.0.8037.57**, launched through `/usr/bin/google-chrome` and its normal package
wrapper. It requires the exact browser identification/version and records the
installed `google-chrome-stable` package version as evidence without assuming a
Debian revision suffix. It records SHA-256 hashes of the package wrapper and browser executable in
the synthetic evidence. No alternative browser is downloaded or installed.
Playwright provides the pinned Python API and OS-library installation only.

This is an explicit image-version guard rather than a reproducible browser
archive install. When GitHub updates the runner image, CI deliberately fails if
the installed browser version changes. Revalidate the new distribution with the
unchanged preflight and complete real browser/PDF suite before updating the guard.
Do not silently switch browsers, remove the version guard or alter sandbox settings.

During diagnosis, Chrome for Testing 151.0.7922.34 and 154.0.8037.57 both failed the
bounded production-flag CLI PDF probe. The runner's standard Google Chrome
154.0.8037.57 passed with those same flags and retained English/Japanese text.
This demonstrates a distribution/launch-path difference, not a proven underlying
cause. The selected browser must pass the preflight and full required suite on
every run; the PR's checks and linked CI runs record the observed pass/fail status.
Production renderer flags and all report assertions are unchanged.

Ubuntu system packages come from the runner's configured distribution sources.
The installed Google Chrome package already supplies its runtime libraries.
CI installs only the extra Japanese fonts and PDF inspection tools, with bounded
APT network timeouts and a five-minute setup-step limit.
Those packages and the Python 3.12 patch version receive upstream updates rather
than being a byte-for-byte locked operating-system image. The application itself
remains standard-library-only. When updating a pin, verify the official source
again, update the corresponding documentation, and run the required suite.

References:
- [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [Playwright Python CI setup](https://playwright.dev/python/docs/ci)
- [Playwright browser installation](https://playwright.dev/python/docs/browsers)

## Synthetic reproduction evidence

The offline suite executes the generated SQLite owner-scope model twice from a
clean owned fixture, comparing semantic hashes and both security/control cases.
It also rejects stale input, altered scripts, unsafe fixture paths, unsupported
plans and incomplete runs. The strict reports job retains the generated bundle,
fictional input and separate run/evidence JSON under `reproduction-evidence/` in
the existing artifact. This is actual execution of a synthetic model only, not
an assessment of application code or a verified target remediation.


## Evidence-byte verification and CI artifacts

The report-artifact review established that specific retained CI files contained
actual bytes and the expected rendered text. Those manual artifact inspections
(including the earlier PR #11 review) are distinct from the repeatable local
`scripts/evidence_integrity.py` check documented in
[local evidence integrity](../skills/security-scan/reference/evidence-integrity.md).
No past artifact review is automatically imported as verification credit.

The new command reads local artifacts, compares declared SHA-256 values and,
for source records, compares an explicit source path with a committed blob in an
explicitly supplied owned local repository. It writes a separate receipt and can
be repeated by report/workflow/reproduction consumers. Required-integrity policy
can prevent insufficient evidence from receiving structured support or verified
retest; a copied receipt is never authoritative.

Tests and demonstrations for this boundary use newly created synthetic local
Git repositories and artifact files. They do not assess a real application,
fetch a repository, execute recorded commands or run a deployed-system scan.
Even a matching runtime artifact cannot authenticate its logged events, original
conditions or claimed application revision. Existing generated-bundle code and
input-hash checks continue independently of these evidence-file checks.
