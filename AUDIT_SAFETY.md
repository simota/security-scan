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

## Regression tests

```sh
make test
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
