# Audit safety and completeness

The scanner is intended for an owned, **unchanged local checkout** and trusted
installations of the audit tools. Its path checks are not a filesystem sandbox
against concurrent modifications or arbitrary behavior of external tools.

## Report data

Generated dependency results remove URL user information, query strings and
fragments from string fields, including titles, references, inventory and retained
review history. Requirements and Gemfile checks report a location rather than
copying arbitrary source lines. This does not guarantee removal of every secret
format (for example a credential embedded in a URL path). Inspect reports before
sharing them. The renderer still rejects credential-bearing reference URLs from
manual input rather than treating HTML escaping as URL validation.

Validation evidence must be a string. `Valid`, `FalsePositive` and
`NotApplicable` additionally require nonblank evidence before a finding can be
accepted or excluded. Null, booleans, numbers, arrays and objects are rejected
with a schema error rather than coerced into an apparently valid justification.

## Files and audit tools

File and directory symlinks, broken links and non-regular files are skipped and
recorded in `not_run`. This includes links whose targets are inside the checkout.
A symlink does not satisfy a missing-lockfile check. Audit operands are rechecked
before invocation, and the npm/Composer fallbacks also reject symlinked project
configuration. No skipped path is reported as audited. Use a stable checkout;
these checks do not claim protection against a concurrent path-swap race.

OSV runs once per explicit dependency input and receives an auditor-owned empty
configuration through `--config`. Repository `osv-scanner.toml` exclusions and
package overrides are deliberately not applied or modified. Record reviewed
exclusions in `findings.json` with evidence instead. Subprocess exit codes, JSON
structure and result source paths are checked before coverage is granted. Invalid
or inconsistent output is recorded in `not_run`; partial findings from that input
are rolled back, while other inputs can still be audited. Raw tool stderr is not
copied into the report because it can contain credentials.

Both `bun.lock` and legacy `bun.lockb` satisfy the Bun lockfile check and appear in
the inventory. The text format is submitted to OSV; a missing or incompatible OSV
installation, or an unsupported legacy format, is recorded as incomplete. Known
inputs without a supported audit cannot silently disappear. `--audit --strict`
returns `3` for incomplete audits, **not** for vulnerability severity; complete
audits with findings still return `0`.

## Independent fallback boundaries

The scanner never automatically invokes `cargo audit`. A trusted Cargo
installation alone does not make executing Cargo inside an unreviewed checkout
safe. `Cargo.lock` requires OSV coverage; otherwise the Cargo audit is explicitly
incomplete. No Cargo lockfile generation or target toolchain invocation is used
as a fallback.

npm uses `--package-lock-only` and `--package-lock=true`, explicitly includes
prod/dev/optional/peer packages and sets `--ignore-scripts`. This prevents
production-only `omit` settings from silently narrowing the dependency kinds
under review. The fallback is limited to single-project locks: workspace
declarations, workspace lock entries and linked-package entries require OSV and
are explicitly incomplete without it. npm has no supported CLI reset for
inherited workspace selection, and disabling workspaces on a shared lock would
silently omit members. Single-project invocations pin `--prefix` to the lock's
directory and reset the workspace mode with `--workspaces=null`, avoiding the
root-only dependency filter applied by `--workspaces=false`. An inherited
workspace selection cannot match members in these validated single-project
inputs and fails the audit rather than narrowing it. The audit runs on an
isolated copy of the lock (and `package.json`) against the public npm
registry, with empty user and global npmrc files and every inherited
`npm_config_*` variable removed, so project or user registry and auth
configuration cannot redirect the advisory request. Private packages are
therefore not matched against a private registry's advisories. This is not a
general sandbox for npm. A version that rejects the required flags is a failed audit, not a
clean result.

Composer audits a temporary copy of `composer.lock` with an auditor-owned
manifest and an empty `COMPOSER_HOME`. The scanner strips inherited `COMPOSER`
and `COMPOSER_*` settings, disables plugins/scripts, includes development
packages and explicitly requests abandoned-package reports. Project/global
ignore lists and policy exclusions are not copied. Custom repository
configuration is deliberately not copied either: the fallback uses public
Packagist and records custom-repository advisory coverage as incomplete. Original
project files are not rewritten. A Composer version that rejects the required
options is a failed audit, not a clean result.

## Workspace and workflow parsing

Shared locks are associated only after checking explicit Cargo or npm/Yarn
workspace membership, exclusions and nested workspace boundaries. Matching an
unrelated ancestor's filename is not sufficient. Cargo TOML ownership requires
Python 3.11+ (`tomllib`); Python 3.9/3.10 remain usable, but unresolved ownership
is recorded in `not_run`. Implicit Cargo path-dependency membership, explicit
`package.workspace` pointers and pnpm YAML membership need manual validation.

Shell interpolation checks inspect each ordinary block-style `steps[*].run`
scalar separately, including multiline expressions and static dot/bracket access
inside functions or wildcard paths. Neighboring `env`/`with` values and examples
inside non-run scalar blocks are not direct shell interpolation. Dynamic event
selectors, unresolved event subtrees and quoted YAML escapes are recorded in
`not_run` when the scanner cannot establish their meaning. The parser is a
conservative YAML subset, not a complete YAML implementation. Recognized aliases,
tags and flow-style step structures are marked incomplete rather than treated as
proof that the workflow is safe.

## Regression tests

```sh
make test
# Run only the independent boundary regressions:
python3 -m unittest discover -s tests -p 'test_audit_boundaries.py' -v
# Optional real-browser smoke test (Playwright + installed Chrome/Chromium):
SECURITY_SCAN_BROWSER_TEST=1 make test
# Set CHROME=/absolute/path/to/chrome if it is not on PATH.
# Optional trusted-npm lock parser test (no advisory queries or network):
python3 scripts/ci/check_npm_audit_scope.py -v
```

Default tests mock advisory subprocesses. The optional npm test invokes a
trusted installed npm, mocks its advisory layer, blocks network calls and
checks the actual package payload for lockfile versions 1, 2 and 3, captured
from the advisory request body. It also checks that inherited workspace
selectors cannot narrow that payload, since the audit runs on an isolated copy.
The optional browser test aborts network
requests and renders only an inert local fixture. It verifies that HTML-like
finding titles and source snippets survive JSON decoding and that the dashboard
actually draws. The default tests require only Python's standard library.

OSV configuration and output contracts:
- https://google.github.io/osv-scanner/configuration/
- https://google.github.io/osv-scanner/output/

Fallback and workspace contracts:
- https://docs.npmjs.com/cli/v11/commands/npm-audit/
- https://getcomposer.org/doc/03-cli.md
- https://getcomposer.org/doc/06-config.md
- https://doc.rust-lang.org/cargo/reference/workspaces.html
