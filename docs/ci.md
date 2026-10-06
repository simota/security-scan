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
failure prints the diagnostics and compares the runner's already installed
Google Chrome using identical production flags and a fresh profile. An absent
system Chrome is recorded as an unavailable comparison, not a success. A second
diagnostic uses the originally selected Chromium with plain `--headless` and
without the legacy `--disable-gpu` flag. Each probe keeps the same roughly
25-second outer bound, with at most three probes total. No browser is installed
or security setting changed by these comparisons. Even if a diagnostic succeeds, the baseline
failure stops the job before four slow PDF retries. It does not change the renderer, browser sandbox protections or PDF engine.

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
python -m playwright install --with-deps chromium
# Debian/Ubuntu: install Poppler and Japanese fonts if they are not present.
sudo apt-get install --yes --no-install-recommends fonts-noto-cjk poppler-utils
fc-cache -f
export CHROME="$(python -c 'from playwright.sync_api import sync_playwright; p = sync_playwright().start(); print(p.chromium.executable_path); p.stop()')"
export SECURITY_SCAN_REPORT_ARTIFACTS="/tmp/security-scan-report-artifacts"
python scripts/ci/run_required_tests.py
```

`CHROME` may instead point to an already installed Chrome/Chromium. Output is
written outside the checkout. A runtime that blocks browser process creation
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

Playwright installs the Chromium revision associated with that package release.
Ubuntu system packages come from the runner's configured distribution sources;
those packages and the Python 3.12 patch version receive upstream updates rather
than being a byte-for-byte locked operating-system image. The application itself
remains standard-library-only. When updating a pin, verify the official source
again, update the corresponding documentation, and run the required suite.

References:
- [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [Playwright Python CI setup](https://playwright.dev/python/docs/ci)
- [Playwright browser installation](https://playwright.dev/python/docs/browsers)
