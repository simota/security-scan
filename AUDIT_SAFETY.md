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

npm uses `--package-lock-only`, explicitly includes prod/dev/optional/peer
packages and sets `--ignore-scripts`. This prevents production-only `omit`
settings from silently narrowing the dependency kinds under review. Registry
configuration is still used; this is not a general sandbox for npm or a guarantee
that a custom registry provides complete advisories.

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

Shell interpolation checks inspect ordinary block-style `steps[*].run` scalars,
not neighboring `env`/`with` values or examples inside non-run scalar blocks.
The parser is a conservative YAML subset, not a complete YAML implementation.
Recognized aliases, tags and flow-style step structures are marked incomplete
rather than treated as proof that the workflow is safe.

## Regression tests

```sh
make test
# Run only the independent boundary regressions:
python3 -m unittest discover -s tests -p 'test_audit_boundaries.py' -v
# Optional real-browser smoke test (Playwright + installed Chrome/Chromium):
SECURITY_SCAN_BROWSER_TEST=1 make test
# Set CHROME=/absolute/path/to/chrome if it is not on PATH.
```

All advisory subprocesses are mocked. The optional browser test aborts network
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
