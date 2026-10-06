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
- **Local evidence integrity** *(opt-in)* — read safe local artifact files,
  compare their actual SHA-256 digests, and compare source artifacts with a blob
  at the declared commit in an explicitly supplied owned local Git repository.
  Separate receipts and report provenance distinguish checked bytes from declared
  records; no hashes certify the claim, reviewer or execution
  (`reference/evidence-integrity.md`)
- **Fix verification** *(on explicit request)* — record the same local case
  failing a secure assertion for the right reason before the fix, passing after,
  and passing positive-control and regression cases. Recorded `Fixed` remains
  separate from evidenced retest completion. Owned local or throwaway code only;
  synthetic fixtures and inert inputs, never a working exploit
  (`reference/fix-verification.md`)
- **Reproducibility bundles** *(on explicit request)* — generate deterministic
  synthetic seed data, reproduction and cleanup scripts, a hash-bound manifest,
  and two-run evidence. The first supported template models SQLite owner
  scoping locally; it does not execute the assessed application or verify its
  fix. Unsupported cases receive a manual-adaptation scaffold
  (`reference/reproduction-bundles.md`)
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

### Optional three-pass assurance

For a recorded **discovery → conditions → independent challenge and decision**
sequence, add the schema-version-2 `three_pass` profile. It requires an explicit
perspective/target coverage plan, evidence-backed discovery (including N/A and
zero-candidate cells), three distinct declared actors, four claim-specific
negative checks, and independent review covering every claim's evidence at all
severities. Existing findings and reports without this profile keep their
existing interpretation.

Use the existing manual workflow handoffs, then run:

```sh
python3 skills/security-scan/scripts/verification_workflow.py audit findings.json --require-complete
python3 skills/security-scan/scripts/render.py findings.json --out /tmp/three-pass-report --lang ja
```

The audit and English/Japanese dashboard, HTML assessment and PDF show per-pass
counts and remaining gaps. Aggregate completion covers every planned scope cell
and every current candidate workflow; missing workflows and changed inputs block
readiness. Zero candidates stays held. Distinct actor names are declarations,
not authenticated identities, and three passes imply no accuracy percentage,
security guarantee or complete vulnerability detection. The CLI accepts review
records and does not call AI providers or execute target tests.

See [the profile and handoff guide](skills/security-scan/reference/three-pass-check.md)
for the schema, scope-challenge aggregation, safe local workflow and limitations.
`make benchmark` checks deterministic synthetic acceptance/hold cases; its results
measure these record-handling rules, not vulnerability detection accuracy.

### Ordered verification handoffs

The optional local workflow splits verification into **conditions → independent
falsification → evidence-based decision**. Reviewers receive a structured
handoff and submit their observations; the CLI validates the result and advances
only the permitted next stage. It records progress and input/output lineage,
holds unresolved work, and makes an old review stale when its inputs change.

This coordinates submitted review work. It does not launch AI reviewers, require
an API key, execute evidence commands or run tests against an application.
Different reviewer labels separate responsibilities but do not authenticate
people. The existing evidence rules still decide whether a result is sufficient;
a completed stage or several agreeing reviewers cannot certify it by themselves.
See `skills/security-scan/reference/verification-workflow.md` for the commands,
stage contract and resuming interrupted work.

### 再現スクリプトとシードデータを生成する

明示的に依頼した場合だけ、finding に結び付いた再現バンドルを生成できます。
現在の実行テンプレートは、架空の owner と resource を使う SQLite の所有者境界モデルです。
実際のアプリケーション、その認証・認可層、修正コミットは実行しません。
以下は同梱の架空データを使った、ネットワーク不要の例です。

```sh
work=$(mktemp -d "${TMPDIR:-/tmp}/security-scan-repro.XXXXXX")
python3 skills/security-scan/scripts/reproduction.py generate \
  examples/findings.workflow.sample.json --finding F-001 \
  --plan examples/reproduction.plan.sample.json --out "$work/bundle"
python3 skills/security-scan/scripts/reproduction.py verify \
  "$work/bundle" --findings examples/findings.workflow.sample.json
python3 skills/security-scan/scripts/reproduction.py run \
  "$work/bundle" --findings examples/findings.workflow.sample.json \
  --out "$work/results"
```

生成先・結果の保存先には、親ディレクトリが存在する未使用のパスを指定します。
結果は results/results.json、results/records.json、results/evidence/ に保存されます。
バンドルには seed・再現・cleanup・反復実行用のスクリプトが入ります。
固定 seed で初期化し、修正前モデルでは安全な期待値の assertion が失敗、
修正後モデルでは成功すること、正当な所有者のアクセスと存在しない resource の
対照ケースが成功することを確認します。cleanup を挟んで 2 回実行し、
fixture と観測結果の意味的な hash が一致することも調べます。

成功時の results.json は `status: completed`、`repeatable: true` になります。
生成・整合性検証だけでは `not_run` のままです。実行エラーや未対応を成功とみなしません。

manifest は finding、評価対象の revision、選択した証拠レコード、設定と生成コードを
結び付けます。元の findings が変わった場合や生成コードが改変された場合は、
再検証で拒否します。結果は findings とは別に保存し、自動で `Valid`、
`Fixed`、runtime 検証済みへ昇格させません。記録された対象コミットや証拠の hash は、
対象コードを実際に実行した証明にはなりません。

`verification_workflow.py bundle` からも同じ生成ができます。
実アプリへの適用には別途、対象・権限・隔離方法を確認し、そのアプリのテスト基盤で
本物の境界を通るテストを作ります。詳細と未対応ケースの扱いは
`skills/security-scan/reference/reproduction-bundles.md` を参照してください。

### 証拠ファイルの実体・hash・コミットを照合する

記録された hash だけでなく、手元の証拠ファイルを毎回読み直して照合できます。
`evidence.location` は証拠ルートからの相対ファイルパス、`source_path` は
明示したローカル Git リポジトリ内のファイルパスにします。
source は宣言した完全なコミット ID の blob とも照合します。行番号付きの
表示用 location や URL は、証拠ファイルのパスとして使いません。

```sh
python3 skills/security-scan/scripts/evidence_integrity.py verify findings.json \
  --root /path/to/local-evidence --repository /path/to/owned-local-repo \
  --out /path/to/new-receipt.json
python3 skills/security-scan/scripts/render.py findings.json \
  --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repo \
  --out /path/to/new-report --lang ja --no-pdf
```

receipt は findings と別ファイルです。findings や判定は書き換えません。
レポート・workflow・再現バンドルで使うときも、同じ証拠ルートとリポジトリを
指定して再照合します。古い receipt を読み込むだけでは検証済みになりません。
既存データは従来どおり宣言として扱い、過去の証拠に検証済みの信用を追加しません。
`schema_version: 2` のトップレベルに `"evidence_integrity": {"required": true}` を
設定すると、新しい照合が足りない finding は構造化検証・再テストの条件を満たしません。

source は clean なコミットへの対応付けのみ検証でき、dirty source pin は未対応です。
ネットワーク取得、Git hook、対象アプリや記録されたコマンドは実行しません。
runtime・environment の hash が一致しても、ログの出来事、実行したコードや
環境条件が真実だとは証明できません。source の一致も脆弱性の存在を証明しません。
[安全上の制約と、新しい架空 Git リポジトリだけで試す例](skills/security-scan/reference/evidence-integrity.md)
を参照してください。同梱サンプルの架空 hash は実ファイルの検証には使えません。

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

Structural verification checks declared records; it does not by itself read
artifacts or verify their hashes. The separate opt-in local evidence check reads
actual bytes and, for source, checks the explicitly supplied local repository's
commit blob. Required-integrity policy can gate structured support and retest;
without it, existing record-level behavior remains, with provenance identifying
what was declared and what was freshly checked. Neither route authenticates
reviewers, proves recorded execution or establishes that all paths were examined.
No scanners, network retrieval, credentials or application-test execution are
added by this check. The separate reproduction runner continues to verify its
own generated files and run only its synthetic local template; it never executes
application code or stored evidence commands. Runtime work against an application
still requires explicit permission for owned local or throwaway code. Broader
asset/coverage inventories remain outside this implementation's scope.

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
  reference/verification-workflow.md conditions, falsification and decision handoffs
  reference/three-pass-check.md optional discovery/conditions/challenge coverage profile
  reference/evidence-integrity.md local artifact bytes, source commits and safety limits
  reference/fix-verification.md local regression tests that lock a fix in
  reference/reproduction-bundles.md deterministic synthetic seed/repro bundles and limits
  reference/report.md          checklist and findings report formats
  reference/findings-schema.md findings.json and the render command
  scripts/deps_scan.py         dependency inventory, supply-chain checks, audits (stdlib only)
  scripts/render.py            findings.json -> dashboard / assessment PDF (stdlib only)
  scripts/verification.py      evidence consistency and derived verification/retest states
  scripts/evidence_integrity.py read-only local evidence verification and separate receipts
  scripts/verification_workflow.py ordered local review handoffs, progress and lineage
  scripts/reproduction.py      generate, verify and run isolated synthetic bundles
  scripts/reproduction_runtime.py trusted standalone seed/repro/cleanup runtime
examples/findings.sample.json  fictional legacy sample for make demo / make check
examples/findings.verification.sample.json  synthetic structured-verification example
examples/reproduction.plan.sample.json      deterministic SQLite owner-scope demo plan
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
