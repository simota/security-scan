# Reproducibility bundles — deterministic local preparation

**Read when:** the requester explicitly wants seed-data registration scripts,
reproduction scripts, or a repeatable local case tied to a finding. Read
`reference/fix-verification.md` before adapting a case to an actual application.

## Scope and limits

`scripts/reproduction.py` generates a portable bundle of data, reviewed-template
scripts and instructions from a schema-version-2 findings file and an explicit
plan. It can verify that bundle against the current findings and run the
supported synthetic fixture twice. Generating or running it does not modify the
findings file or the assessed application's code, database or configuration.

The MVP supports one executable template: `sqlite-owner-scope-v1`. It uses
Python's standard library and SQLite to model two query policies over synthetic
owners and resources. It does **not** import application code, check out the
named commits, execute the application's authentication or authorization
layers, install dependencies, execute commands recorded in evidence, use
credentials or send network requests. There is no target-host, live-system or
network option. A declared target revision is a reference, not proof that the
revision was executed. Optional source-evidence checks can establish a blob's
correspondence with a local commit, but do not execute that revision.

Only explicitly requested owned-local or throwaway work is in scope. A static
review or report-rendering request does not authorize execution. Never use real
customer records, secrets, working exploit inputs, shared/staging/production
databases or third-party targets. The synthetic bundle uses only its own known
scratch files. Project-specific tests need the separate authorization and
boundary requirements in `reference/fix-verification.md`.

## Generate, verify and run

Start with the fictional sample below to learn the format. Its finding, commits
and source-evidence hash are invented; successful execution says nothing about
an actual application's security.

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

Use new output directories with existing parent directories. Keep results outside
the bundle; neither output path may contain the other. Symlinks are rejected. Review
the manifest, generated scripts and case instructions before executing them.
The `run` entry point rechecks current findings and trusted template code before
execution, then checks again before publishing evidence. `verify` provides the
integrity check without running the case.
If the finding or other bound inputs change, prepare a new bundle against the
new inputs and review it. Do not patch hashes just to silence a stale-input or
code-integrity error.

The ordered-review CLI offers the same generator as a convenience:

```sh
python3 skills/security-scan/scripts/verification_workflow.py bundle \
  examples/findings.workflow.sample.json --finding F-001 \
  --plan examples/reproduction.plan.sample.json --out "$work/another-bundle"
```

This alias neither runs a case nor advances conditions, falsification or
decision stages. See `reference/verification-workflow.md` for those handoffs.

## Check the evidence behind a bundle

Generated-script and findings-input hash verification remains mandatory. It is
separate from optional verification of the registered evidence files themselves.
For actual local artifacts, add these flags to `generate`, `verify` and `run`:

```sh
python3 skills/security-scan/scripts/reproduction.py generate findings.json \
  --finding F-001 --plan plan.json --out /path/to/new-bundle \
  --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repository
python3 skills/security-scan/scripts/reproduction.py verify /path/to/new-bundle \
  --findings findings.json --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repository
python3 skills/security-scan/scripts/reproduction.py run /path/to/new-bundle \
  --findings findings.json --out /path/to/new-results \
  --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repository
```

Use actual records with safe artifact paths and source `source_path` fields;
the bundled fictional sample is not suitable for successful artifact checks.
See `reference/evidence-integrity.md` for a synthetic Git setup and safety limits.
A required-integrity assessment refuses generation or execution without the
necessary successful fresh checks. A bundle generated with evidence checks
binds their deterministic receipt hash as `evidence_receipt_sha256`. Later
`verify` and `run` must recheck the same sources even if the assessment's policy
is optional. Supplying a saved receipt cannot replace those reads.

For checked bundles, use this repository's `reproduction.py` entry point to
seed or execute the model. Generated standalone `seed.py`, `reproduce.py` and
`run.py` cannot independently recheck external evidence and refuse such bundles.
Standalone `cleanup.py` is deliberately allowed without fresh external evidence,
so a missing artifact does not prevent safe removal of an owned fixture. Cleanup
still requires unchanged findings, valid integrity policy, manifest identity,
generated-file hashes, and the exact owned fixture inventory/database hash.
It grants no evidence credit and never relaxes those ownership checks.

Unchanged findings, checked source bytes and trusted generated code are separate
requirements. Manifest identity is recomputed; removing receipt metadata cannot
silently turn a checked bundle into an unchecked one. If bindings become stale,
investigate and regenerate; do not patch the manifest or use standalone
execution to bypass checks.

A source match establishes that the artifact equals a blob at the declared
commit. A runtime/environment hash match establishes only the artifact bytes.
Neither proves a logged event, executes the original application or upgrades
synthetic observations from `mocked` to `real`. Checked synthetic bundles still
cannot establish runtime-supported findings or verified application fixes.

## Plan contract

The minimal supported plan is `examples/reproduction.plan.sample.json`:

```json
{
  "plan_version": 1,
  "template": "sqlite-owner-scope-v1",
  "case_id": "owner-boundary",
  "seed": 42,
  "before": {"policy": "unscoped"},
  "after": {
    "policy": "owner_scoped",
    "commit": "2222222222222222222222222222222222222222"
  },
  "fixture": {"owners": 2, "resources_per_owner": 2},
  "evidence_ids": ["source-before"]
}
```

- `plan_version` selects the supported plan schema; do not infer compatibility
  with future versions.
- `template` is an explicit template choice, not an arbitrary module, command,
  path or URL. The generator does not infer a runnable test from finding prose.
- `case_id` names the same security expectation before and after.
- `seed` fixes synthetic fixture generation. Keep it, the fixture configuration
  and test/template version unchanged when comparing equivalent cases.
- `before.policy` and `after.policy` configure the local model. The sample
  intentionally contrasts an unscoped read with an owner-scoped read. Merely
  declaring the policies does not establish the real application's behavior.
- The before revision comes from the current assessment pin; `after.commit`
  declares the intended fixed revision. Neither field makes the runner fetch
  or execute that revision. Optional evidence checks only verify source artifacts
  explicitly registered with a source path and local commit.
- `fixture` describes synthetic owners and resources per owner. Provide enough
  independent owners to test an ownership boundary. Do not substitute real data.
- `evidence_ids` selects existing evidence records to bind to the manifest.
  Their declared hashes and descriptions need source review. Optional local
  checks below read actual artifact bytes and source commit blobs; the runner
  never retrieves remote artifacts or authenticates their claims.

The plan accepts exactly the fields above; no commands, SQL, URLs or extra
keys. The current bounds are:

- `seed`: integer 0 through 2147483647; booleans are not integers here.
- `fixture.owners` and `fixture.resources_per_owner`: integers 2 through 10.
- Finding, case and selected evidence IDs: 1–64 characters, starting with an
  ASCII letter, followed by ASCII letters, digits, hyphens or underscores.
- `after.commit`: full lowercase 40- or 64-character hexadecimal commit ID.
- `evidence_ids`: 1–50 unique IDs identifying source evidence pinned to the same
  assessment commit and worktree diff. The sample's hash is fictional.
- Policies are fixed to `unscoped` before and `owner_scoped` after. This schema
  does not accept arbitrary model policies, including for manual scaffolds.

Secret-category findings and detected secret-bearing identifiers are rejected;
arbitrary finding prose is not copied into generated files. This is not a
substitute for reviewing inputs and artifacts for sensitive data. The CLI
rejects invalid inputs instead of turning an unknown template or malformed
fixture into a passed check.

## What is bound, and what is produced

The manifest is immutable **input data for the run**, separate from changing
scratch state and results. Its bindings include the selected finding digest,
the byte hash of the entire findings input, current assessment revision pin,
selected evidence identities and hashes,
template/version and generated-file hashes, deterministic seed and fixture
configuration, and the secure expectations. Verification checks those bindings
against current findings and the trusted generator/template implementation.
Even a whitespace-only or unrelated change to the findings file makes its byte
hash stale. Changing generated code and updating its declared hash is not an
approved way to introduce a new adapter.

Hash consistency detects changed bytes and declared inputs. It is not a digital
signature, an identity check, proof that recorded events happened or proof that
the assessment is complete. Without fresh evidence checks, application commits
and source locations in a manifest remain declared references. With them, only
the supported local artifact/source-blob correspondence is additionally checked.

The generated standalone entry points are:

- `seed.py`: register only deterministic synthetic fixture data in bundle-owned
  local scratch storage.
- `reproduce.py`: exercise the synthetic model and report the secure expectation
  with the actual observation and control cases.
- `cleanup.py`: remove only known bundle-owned scratch artifacts.
- `run.py`: orchestrate repeatable runs and emit result JSON to standard output.

The bundle also contains `manifest.json`, `manifest.sha256.json` and the
non-executable `adapter.todo.json` review contract. The runtime's `.fixture`
directory holds only `owner.json` and `fixture.sqlite3` while seeded. Seeding an
already identical owned fixture and cleaning an absent fixture are idempotent;
changed database bytes or unexpected scratch data are refused. An exclusive
fixture lock prevents cooperating commands from overlapping; a lock left after
a killed process needs manual inspection before removal. These are accidental-
misuse guards, not protection against a malicious same-user process racing the
filesystem.

Fixture paths used by the scripts are relative to their bundle, not the
caller's working directory. Every standalone command requires the unchanged
source findings. The full sequence below is for unchecked default bundles;
checked bundles require the repository runner for seeding and execution. The
`cleanup.py` command also works for checked bundles without rechecking external
evidence, subject to all manifest and owned-fixture checks above. Use isolated
mode and disable site startup hooks:

```sh
findings="$PWD/examples/findings.workflow.sample.json"
python3 -I -S "$work/bundle/seed.py" --findings "$findings"
# Expected exit 1: the original model violates the secure assertion.
python3 -I -S "$work/bundle/reproduce.py" --findings "$findings"
python3 -I -S "$work/bundle/cleanup.py" --findings "$findings"
python3 -I -S "$work/bundle/run.py" --findings "$findings"
```

The direct reproduce command intentionally exits `1` for the original-model
assertion failure, so do not place that demonstration in a fail-fast shell block
that would skip cleanup. Use the full runner for automated execution and cleanup.

Prefer the repository's `reproduction.py run ... --findings ...` entry point:
it validates generated bytes against the trusted template and exports artifacts.
Standalone scripts check the manifest, file hashes and supplied findings byte
hash, but cannot establish their own authenticity. Review them before use.
Python `-I -S` reduces inherited import/environment and startup-hook effects;
it is not an operating-system security sandbox. Do not run an untrusted bundle
just because it contains hashes or a familiar filename.

The repository runner writes a new results directory containing:

- `results.json`: complete run status, each cycle and step, expected/actual case
  outcomes, semantic hashes, repeatability, timeout and tool-version metadata.
- `records.json`: separate evidence/test-run records for manual review/import,
  exported only for a `completed`, repeatable run. A stale, errored, timed-out
  or `incomplete` run exports no records. The child runtime stops one second
  before the `--timeout` deadline and reports `timeout` itself.
- `evidence/`: one sanitized JSON observation per completed case, referenced by
  hash from the exported records. Unsupported cases have no invented observations.

The manifest retains generation-time Python/SQLite/runtime versions; results
record execution-time versions, `generation_tools` and `tool_versions_match`.
A match across two cycles proves semantic repeatability within that run, not a
byte-identical execution environment across machines. Changed tool versions are
reported rather than silently described as identical.

### Status and exit codes

- Generate and verify exit `0` with `status: not_run`. Verification additionally
  reports `integrity: checked`; neither command has run the case.
- A full run exits `0` only when it reports `status: completed` and
  `repeatable: true`. That means the model's expected outcomes matched.
- Incomplete, unsupported, timed-out or stale runs exit `3`; inspect both
  top-level and per-cycle results. No such result counts as a pass.
- Invalid input, integrity failure or a refused output write exits `2`.
- Standalone seed/cleanup exit `0` on success; reproduce exits `1` when a secure
  assertion fails, including the sample's intended original red case. Standalone
  `run.py` exits `0` only for completed repeats. All manual-template entry points
  exit `3` with `unsupported`.

`run --timeout SECONDS` sets the outer subprocess limit, default 10 seconds,
allowed range 1–60. The standalone repeat runner also has its own bounded
execution. A hard timeout cannot guarantee that cleanup completed; rerun the
verified cleanup command against unchanged inputs and inspect any refusal.
Never convert a timeout into successful red evidence.

## What counts as repeatable

A full supported run performs clean → seed → reproduce → cleanup twice. Both
cycles use the same template, seed, fixture and secure expectation. For the
sample policy pair, inspect all of the following:

1. The before-model security assertion **fails because another owner's resource
   is returned**. This is the intended red observation, not a runner error.
2. The after-model security assertion passes: another owner's resource is not
   returned.
3. The legitimate owner can read its own resource. This positive control guards
   against a model that simply rejects every request.
4. A request for a missing resource returns no resource. This negative control
   checks a nearby non-success path.
5. Fixture and semantic-observation hashes match between the two clean runs.
   Timestamps and other execution metadata may differ; a whole result file need
   not have the same byte hash.

A successful overall reproduction records both the expected red and green. Do
not interpret the before assertion failure as an unexpected infrastructure
failure, or convert it into a passing secure assertion. Conversely, a timeout,
setup error or missing test is not evidence of a security assertion failure.

Run results preserve expected and actual outcomes, timestamps, runtime/tool
versions, timeouts and errors. `not_run`, `unsupported`, `error` and a completed
assertion are distinct. Inspect the structured results rather than treating a
created directory or a command invocation as proof of completion. A mismatch
between repetitions, failed control or incomplete cycle cannot establish
repeatability. Cleanup refuses symlinks and unexpected scratch contents rather
than recursively deleting whatever it finds; investigate the blocker, and do
not broaden cleanup to unrelated user files.

## Unsupported cases and project adapters

For findings outside this model, set `template` to `manual-target-v1` while
retaining the same plan shape. The generated `adapter.todo.json` scaffold records
what a reviewer must adapt and reports `unsupported`; it does not silently run a
placeholder, access a target or fabricate a successful reproduction. Template
support is intentionally narrow: injection, session, role, upload and arbitrary
framework cases do not become tested because the bundle names them.

A downstream adapter must be reviewed as a separate project test. Before writing
or running it:

1. Confirm ownership, explicit permission, the local/throwaway target, permitted
   actions, resource limits and stop conditions.
2. Use the project's test framework, factories and local client. Pin the actual
   before/after source, dependencies, test and fixture versions, configuration
   and deterministic seed. Keep real credentials and external services out.
3. Exercise the real route/handler and relevant authentication, authorization
   and tenancy layers. Stub unrelated side effects only; record all stubs.
4. Require a legitimate red secure assertion before, the same case green after,
   and passing normal/positive-control and regression cases. Retain failed,
   blocked, unsupported and contrary observations.
5. Restrict seeding and cleanup to explicitly owned disposable fixtures. Do not
   implement a generic URL/host runner, arbitrary shell command, destructive
   database reset or exploit-payload generator.
6. Export sanitized evidence for independent review, preserving the exercised
   boundary and limitations. Do not auto-promote the finding or remediation.

The trusted runtime template is now version 2. Its checked-evidence standalone
guard changes generated code; regenerate and review bundles from version 1
against the current trusted template. The plan and bundle schemas are unchanged.

The current trusted runner rejects manually edited generated code; it is not a
plugin loader for adapters. Run a reviewed project adaptation through that
project's authorized test harness. Adding a new trusted template requires an
implementation and safety review, not only editing its manifest.

## Evidence export and reporting

Generated evidence is a separate review input. It never automatically rewrites
`findings.json`, changes a verdict, marks a workflow complete or sets `Fixed`.
The synthetic template's exported test records declare the assessed boundary as
`mocked`: they cannot satisfy real-boundary runtime support or verified-retest
requirements. A deterministic model can help explain an ownership mistake and
prepare a real regression; it cannot prove that the named application has that
mistake or that its fix works.

Before incorporating evidence into a schema-version-2 assessment, a reviewer
must inspect the source, relevance, real boundary and before/after pairing under
`reference/findings-schema.md` and `reference/fix-verification.md`. Preserve all
limits and counterevidence. Integrity checks, repeated results and matching
reviewer opinions do not substitute for those checks.
