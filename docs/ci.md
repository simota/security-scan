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
python -m pip install --only-binary=:all: --require-hashes -r scripts/ci/requirements.txt
# Debian/Ubuntu: install Poppler and Japanese fonts if they are not present.
sudo apt-get install --yes --no-install-recommends fonts-noto-cjk poppler-utils
fc-cache -f
# CI accepts only the listed runner-provided Google Chrome distributions.
export CHROME="/usr/bin/google-chrome"
export SECURITY_SCAN_REPORT_ARTIFACTS="/tmp/security-scan-report-artifacts"
python scripts/ci/check_chromium_pdf.py
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
exact versions and the SHA-256 hash of every wheel PyPI publishes for that
version in `scripts/ci/requirements.txt`, installed with `--require-hashes`, so
a file added to an existing release cannot be installed. When updating a
version, replace its hash list from the release's PyPI JSON
(`https://pypi.org/pypi/<name>/<version>/json`, every `bdist_wheel` digest):

- [Playwright 1.62.0](https://pypi.org/project/playwright/1.62.0/)
- [pyee 13.0.1](https://pypi.org/project/pyee/13.0.1/)
- [greenlet 3.5.5](https://pypi.org/project/greenlet/3.5.5/)
- [typing_extensions 4.16.0](https://pypi.org/project/typing-extensions/4.16.0/)

The workflow uses the GitHub runner's already-installed official **Google Chrome**,
launched through `/usr/bin/google-chrome` and its normal package wrapper. The
bounded version list contains **155.0.8059.39** from Ubuntu 22.04 image
20261012.322.1 and **156.0.8078.47**, observed on image 20261025.340.1 and listed
in the [official Ubuntu 22.04 image inventory](https://github.com/actions/runner-images/blob/2cdd82f39871ec1e98584ee64008bc1261ce427f/images/ubuntu/Ubuntu2204-Readme.md)
for image 20261026.341.1. The older Chrome 154 rollout entries have been retired.
Each selected version must pass the required suite below on its image. It requires an
exact browser identification/version match to that list and records the
installed `google-chrome-stable` package version as evidence without assuming a
Debian revision suffix. It records SHA-256 hashes of the package wrapper and browser executable in
the synthetic evidence. No alternative browser is downloaded or installed.
Playwright provides only the pinned Python API; no Playwright browser or
OS-dependency installation runs.

This is an explicit, bounded image-version guard rather than a reproducible
browser archive install. Unknown versions still fail. The selected distribution
must pass the unchanged preflight and complete zero-skip real browser/PDF suite
on every run; a version-list match alone is never a successful check. Record the
actual version from that run and do not imply that another listed version ran.
Review any version-list change, keep the list small during runner rollouts, and
retire the older entry when the rollout settles. Do not use a broad version
range, silently switch browsers, remove the guard or alter sandbox settings.

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

## Three-pass assurance regressions

`make benchmark` runs a deterministic, standard-library-only matrix from
`tests/fixtures/three_pass_cases.json`. To save exact expected/actual outcomes:

```sh
python3 scripts/ci/benchmark_three_pass.py --json > /tmp/three-pass-benchmark.json
```

The cases exercise the real workflow controller with invented observations:
supported findings, evidence-backed exclusions, benign scope cells, dropped
candidates, unreviewed scope, incomplete challenges, dissent and stale evidence.
A mismatch returns `1`; malformed benchmark input returns `2`. The unit suite
also runs this matrix, so regressions fail `make check` and the existing CI jobs.
TP/FP/TN/FN labels describe fixture intentions; these are assurance-gate tests,
not a detector benchmark, measured real-world accuracy, or reviewer evaluation.
No AI provider, recorded command or target application is executed.

The zero-skip report runner additionally requires the three-pass mobile browser
check and English/Japanese PDF checks. They verify aggregate state, all three
pass counts, gaps, claim labels, scope-countercheck reasons and evidence, and
redaction of hostile/secret-like fixture text. Missing workflows cannot reuse an
older finding's readiness, and negative-scope gaps remain visible even if an
individual finding is ready for a fix.

## Offline performance comparisons

`scripts/ci/benchmark_performance.py` measures eight synthetic workloads: workspace
lock discovery, shared source excerpts, both structured-verification HTML reports,
dependency triage without a source-reference model, reports with live evidence
results, and OSV result parsing with distinct groups, alias pairs, or no groups.
OSV and triage findings are generated in memory; the benchmark does not run an
auditor or query a service. The report fixtures repeat a finding from the existing
verification sample and never run its recorded commands or print PDFs.

The triage fixture contains Python source files whose contents cannot contribute
to the scanner's automatic reference inference. It measures the triage step only,
including its decision whether to read those files, not an online audit. The live
integrity fixture writes inert artifacts and checks their bytes before timing the
reports. It supplies no Git repository, so source revision checks remain explicitly
incomplete. `--triage-source-files`, `--triage-findings`, `--integrity-evidence`
(5–512) and `--integrity-findings` control these fixture sizes; `--source-lines`
also controls each triage source file's length.

Run the same harness against each revision's scripts, sequentially on the same
machine. For example, compare a local base worktree with the current checkout:

```sh
git worktree add --detach /tmp/security-scan-before <base-commit>
python3 scripts/ci/benchmark_performance.py \
  --scripts-dir /tmp/security-scan-before/skills/security-scan/scripts \
  --repeats 5 --osv-records 5000 --report-findings 400 > /tmp/security-scan-before.json
python3 scripts/ci/benchmark_performance.py \
  --repeats 5 --osv-records 5000 --report-findings 400 > /tmp/security-scan-after.json
```

Fixture setup, report validation, initial evidence-file checks, input copies,
warmup and output hashing are outside the timed regions; OSV parsing includes its
normal input validation. The timed live-integrity reports still perform the normal
declaration validation, stale-result checks and selected-result copying. Each workload
reports every sample, its median and an output SHA-256;
compare both the medians and the hashes between revisions. Results that change
between repetitions cause an error. The hashes include complete findings or HTML,
so the comparison also detects changed ordering, references and displayed text.
These timings describe the specified local workloads, not end-to-end audits or
network/PDF latency. They are diagnostic measurements rather than CI time limits.
The offline regression suite instead checks bounded record traversal, repeated
redaction and verification work, selective evidence copying and source loading
without relying on machine speed. Derived report states and source indexes are
reused only within a render or triage call; later calls must observe changed
records and source files. Evidence-result indexes remain bound to their checked
declarations, which are validated again on every selection.

### Pipeline workloads and paired comparisons

`scripts/ci/benchmark_pipeline.py` adds full offline scans for Compose files,
remote-only workflows, workflows with a local composite action, and mixed source
trees. It also measures the complete output contract checker, finding renumbering,
and both HTML reports with larger evidence/run catalogs. `--size small`, `normal`
and `high` select recorded dimensions; `--workloads` selects named cases. The two
`git_object_*` controls use an in-memory cat-file response to isolate object
validation and hashing. They do not represent Git subprocess or disk latency.
All fixtures use invented input; no target or recorded command is executed.
The `url_plain`, `url_dense` and `url_symbols` cases additionally cover ordinary
field values, 500 URLs on one source line, and long non-URL lines ending in a
colon or percent sign. This separates the benefit for ordinary prose from costs
on URL-bearing or delimiter-bearing input.

For a direct before/after comparison, use the current harness for both script
directories. This avoids differences in fixture generation or measurement code:

```sh
PYTHONHASHSEED=0 python3 scripts/ci/compare_performance.py \
  --before /tmp/security-scan-before/skills/security-scan/scripts \
  --after skills/security-scan/scripts --samples 21 --memory \
  -- --size normal --workloads compose workflow_remote workflow_local source_tree contract renumber verification_catalog \
  > /tmp/security-scan-paired.json

# Run the original eight workloads through the same comparison protocol.
PYTHONHASHSEED=0 python3 scripts/ci/compare_performance.py \
  --before /tmp/security-scan-before/skills/security-scan/scripts \
  --after skills/security-scan/scripts --suite existing --samples 21 \
  -- --workspaces 150 --findings 100 --source-lines 1000 \
     --osv-records 1000 --report-findings 100 \
     --triage-findings 50 --triage-source-files 100 \
     --integrity-findings 80 --integrity-evidence 100 \
  > /tmp/security-scan-existing-paired.json
```

The comparison starts one interpreter per revision to keep imported modules and
regular-expression caches separate. After three warmups, it alternates which
revision runs first in each pair, and never overlaps timed operations. Each full
result hash must match both within and across revisions. Copies, fixture setup,
IPC and result serialization/hashing remain outside timing. The scripts must
come from trusted checkouts: this is a measurement utility, not a sandbox for
untrusted Python code. `--cpu N` can pin the parent and both workers to one
available CPU on platforms supporting `sched_setaffinity`; omit it elsewhere.

The comparison records every wall and process CPU sample, mean, median, nearest-rank
P95/P99 and the inverse of mean time as serial operations per second. It also
reports a deterministic paired bootstrap 95% interval for the ratio of mean
times (3,000 resamples). These intervals help distinguish repeatable changes
from noise; they do not establish equivalence or replace workload-specific
review. With 21 samples, P99 is the maximum observed sample and is not a reliable
estimate of production tail latency. Repeat noisy cases and preserve their
earlier samples instead of selecting only favorable runs.

`--memory` adds three separately traced, untimed executions per workload. Their
`traced_peak_bytes` measure Python allocations made during the operation,
including its result, but exclude inputs prepared beforehand. They are neither
total resident memory nor a count of every allocation. RSS values are process
high-water marks including imports and fixtures; later workloads also inherit
earlier high-water marks, including any earlier tracing. Use one workload per
invocation without `--memory` when investigating uninstrumented process RSS.
Unsupported RSS platforms return `null` rather than an assumed unit.

For standalone `benchmark_performance.py`, the additional diagnostics are
opt-in through `--metrics` or `--memory`; its original default result fields are
preserved. Performance measurements do not verify online audit latency, physical
disk I/O, production concurrency, GC pause distributions, browser interaction
or PDF layout. Those require their own environments and tests.
