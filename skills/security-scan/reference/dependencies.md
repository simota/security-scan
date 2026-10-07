# Dependencies and supply chain

**Read when:** RECON, to inventory every dependency source; REVIEW, for the
"Dependencies and platform" and "Build and delivery" perspectives. Run it on
every scan, not only when asked: third-party code is usually most of what ships.

## 1. Run the scanner

From this skill's directory:

```
python3 scripts/deps_scan.py <repo> --out deps.json            # static only, no network
python3 scripts/deps_scan.py <repo> --audit --out deps.json --into findings.json  # + vulnerability databases
```

`--into` replaces the `D-*` findings in `findings.json`, records every audit
that did not run under `limitations`, and stamps `dependency_scan` with the
count it wrote; `scripts/contract_check.py` rejects a file whose `D-*` count
differs, so `D-*` findings are never hand-written, merged or split. It covers, across npm, Composer, Python,
Bundler, Go, Cargo, Maven/Gradle (inventory), CI workflows and Dockerfiles:

| Check | Why it matters |
|---|---|
| Manifest without a lockfile | Every install can resolve different, possibly compromised, versions |
| Floating versions (`*`, `latest`, `dev-*`, unbounded `>`) | A newly published bad release is taken automatically |
| Dependencies from git, URLs or local paths | Outside registry integrity and advisory coverage |
| Non-default registries, `--extra-index-url`, lockfile hosts | Dependency confusion: a public name can shadow an internal one |
| Literal tokens in `.npmrc` | Publishing credentials in the repository |
| Install-time scripts, `allow-plugins: true` | Dependency code runs on every install, including CI |
| Actions not pinned to a commit SHA | A moved or hijacked tag runs with the pipeline's secrets |
| `pull_request_target`, event text inside `run:` | Outsider-controlled input reaches a privileged pipeline |
| Unpinned base images, `curl … \| sh` in builds | The build executes whatever is served that day |
| Known vulnerabilities (`--audit`) | Advisories matched against the exact locked versions |
| Malicious packages (`--audit` with osv-scanner) | OSV includes OpenSSF malicious-package reports (`MAL-` IDs), reported as High |
| Abandoned packages (Composer) | No fixes will come |

`--audit` prefers `osv-scanner` (every ecosystem, malicious-package data) and
also runs `composer audit` and `npm audit` for their severity and fix data.
Missing tools are listed under `not_run`; say so in the report rather than
implying the audit was complete. Audits query public advisory databases with
the package list, so they need network access; ask before running them if the
dependency list itself is confidential. osv-scanner is given each lockfile with
`-L` rather than a directory. A sandboxed shell whose proxy re-signs TLS makes
osv-scanner fail certificate checks; that appears in `not_run`, and the scan
needs rerunning outside the sandbox with the requester's agreement.

## 2. Judge what the scanner cannot

- **Platform end of life** — read the runtime and framework versions from the
  inventory (`platform`, `notable`) and compare with the vendor's support
  schedule. Check the current schedule rather than recalling it; an unsupported
  runtime or framework is High when it is internet-facing
- **Lockfile drift** — a lockfile older than the manifest, or a CI install that
  ignores it (`npm install` instead of `npm ci`, `composer update` in deploy)
- **Direct dependencies worth a second look** — names one character away from a
  popular package, very new or single-maintainer packages in sensitive roles
  (auth, crypto, HTTP), packages pulled only by a build step. Report these as
  `Suspected` with what would confirm them
- **Vendored or copied code** — third-party code committed into the repository
  is invisible to audit tools; list it as a limitation
- **Deploy artifacts** — whether build output, `.env` files or credentials end
  up inside images or bundles

## 3. Reporting

- Group many advisories for one package into one fix line in `next_steps`
  ("upgrade guzzlehttp/guzzle to ≥ the highest fixed version"), but keep each
  scanner finding as written so the dashboard counts stay true. Record the
  per-package review in the existing `D-*` findings' `validation`; do not add
  per-package findings under another prefix
- State application (`F-*`) and dependency (`D-*`) counts separately in the
  chat summary, so scanner volume does not hide the code findings; the
  dashboard and assessment already split the two parts by ID prefix
- A vulnerable package that is a dev-only dependency is still reported; say it
  is dev-only in `impact` and lower severity only with a reason
- Record in `perspectives`: lockfiles audited, tools run, tools not run
