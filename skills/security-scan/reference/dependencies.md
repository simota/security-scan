# Dependencies and supply chain

**Read when:** RECON, to inventory every dependency source; REVIEW, for the
"Dependencies and platform" and "Build and delivery" perspectives. Run it on
every scan, not only when asked: third-party code is usually most of what ships.

## 1. Run the scanner

From this skill's directory, writing into the run's output directory `<out>`:

```
python3 scripts/deps_scan.py <repo> --out <out>/deps.json            # static only, no network
python3 scripts/deps_scan.py <repo> --audit --out <out>/deps.json --into <out>/findings.json  # + vulnerability databases
```

`--into` needs the `findings.json` created by the first `findings.py merge`
(it exits 2 when the file is missing) and writes under the same writer lock.
Run it once, at the end of REVIEW, and record per-package review afterwards:
a rescan replaces each `D-*` validation with the scan's automatic triage
verdict (or `Unverified`) and keeps a prior manual review as
`previous_validation`.

`--into` replaces the `D-*` findings in `findings.json`, records every audit
that did not run under `limitations`, and stamps `dependency_scan` with the
count it wrote; `scripts/contract_check.py` rejects a file whose `D-*` count
differs, so `D-*` findings are never hand-written or split; `findings.py merge`
accepts only `validation`/`verification` on an existing `D-*` ID. It covers, across npm, Composer, Python,
Bundler, Go, Cargo, Maven/Gradle/NuGet (inventory and sources), CI workflows,
Dockerfiles and Compose files:

| Check | Why it matters |
|---|---|
| Manifest without a lockfile | Every install can resolve different, possibly compromised, versions |
| Floating versions (`*`, `latest`, `dev-*`, unbounded `>`) | A newly published bad release is taken automatically |
| Dependencies from git, URLs or local paths outside the checkout (`file:`/`link:`/`./` paths that resolve inside it are first-party) | Outside registry integrity and advisory coverage |
| Non-default registries, `--extra-index-url`, lockfile hosts | Dependency confusion: a public name can shadow an internal one |
| Literal tokens in `.npmrc`, `.yarnrc.yml`, `.pypirc` | Publishing credentials in the repository |
| Lockfile entries without integrity hashes, Composer `minimum-stability: dev`, pip `--find-links` | Downloads are not checked against a recorded hash, or unstable or unindexed packages are accepted |
| NuGet configs with several package sources and no `packageSourceMapping` | Any source can serve any package name |
| Package or submodule sources over `http://`/`git://` (Gradle: inside `repositories` blocks and `apply from:`), TLS checks off (`strict-ssl=false`, `--trusted-host`, `allowInsecureProtocol`) | A network attacker can substitute code that runs in builds |
| Install-time scripts, `allow-plugins: true` | Dependency code runs on every install, including CI |
| Actions not pinned to a commit SHA, or with no version at all | A moved or hijacked tag runs with the pipeline's secrets |
| `pull_request_target`, `workflow_run`, event text inside `run:` or `github-script` (also through an `env:` value read as `${{ env.X }}`, or a local action/reusable workflow input a caller fills with event text; `boolean`/`number` inputs are coerced and skipped, as is a whole expression that is one `contains`/`startsWith`/`endsWith` call) | Outsider-controlled input reaches a privileged pipeline |
| A privileged workflow (`pull_request_target`, `workflow_run`, `issue_comment`, or a local workflow/action it calls) checking out the PR head (with `actions/checkout` whose `ref`/`repository` names the head anywhere in its value, in block, quoted, flow or block-scalar form; `gh pr checkout`, `gh repo clone`, or `git checkout`/`switch`/`reset`/`pull`/`merge`/`rebase`/`worktree`/`clone` of the head, `FETCH_HEAD` or a fetched ref in the same `run:` step, double-quoted escapes decoded; a `git fetch` alone is data), including through `env:` maps (quoted keys and `{ A: x }` flow maps too), `$GITHUB_ENV`/`$GITHUB_OUTPUT` writes, shell variables of the same `run:` (`SHA=…`, `export REF=…`; `\` continuations joined), bracket reads (`github['head_ref']`) and a privileged local caller's `with:` value read as `inputs.X` in the callee's `ref`, `run:` or `env:`; a bare PR number (`github.event.number`, `issue.number`, directly or via env) counts only inside a `pull/<n>` ref or a `/pr/<n>` branch of a glob refspec fetch, so `checkout -b backport-<n>` is not flagged; a ref taken from another step or job output, matrix value, unresolved env variable or caller input is listed in `not_run` for manual review. Also downloading the triggering run's artifacts (`run-id:`, `gh run download`, github-script `downloadArtifact`) or running on a self-hosted runner (inline, block list or `labels:`); Confirmed when a later step builds or runs the checkout | The "pwn request": fork code runs with secrets and a write token |
| `permissions: write-all`, `secrets: inherit` in the same job as another repository's reusable workflow | One compromised step or repository gets every scope or secret |
| Unpinned base images (including `ARG` defaults), Compose images (also in `x-*` extension fields) and workflow `container:`/`services:`/`docker://` images, `ADD <url>` without `--checksum`, `curl … \| sh` in builds | The build executes whatever is served that day |
| Known vulnerabilities (`--audit`) | Advisories matched against the exact locked versions |
| Malicious packages (`--audit` with osv-scanner) | OSV includes OpenSSF malicious-package reports (`MAL-` IDs), reported as High |
| Abandoned packages (Composer) | No fixes will come |

`--audit` prefers `osv-scanner` (every ecosystem, malicious-package data).
`composer audit` always runs on `composer.lock` (only for abandoned packages
when OSV covered the lock). `npm audit` and `pip-audit` run only as fallbacks
for locks OSV did not cover: npm on single-project locks, pip-audit on plain
`name==version` requirements.
Generated-output directories (`build`, `dist`, `target`, `vendor`, `.next`,
`.nuxt`, `.cache*`) are not scanned; when one directly holds a manifest or
lockfile, `not_run` names it so a first-party package there can be scanned
separately. Files over 64 MiB are not read and are listed the same way.
Missing tools are listed under `not_run`; say so in the report rather than
implying the audit was complete. Only files directly in a `.github/workflows/`
directory are workflows (GitHub runs nothing in its subdirectories or in look-alike
directories such as `.github/workflows-archive/`); `uses:` text inside block
scalars is data, not a step. A UTF-8 byte-order mark is ignored in every input. Audits query public advisory databases with
the package list, so they need network access; ask before running them if the
dependency list itself is confidential. osv-scanner is given each lockfile with
`-L` rather than a directory. A sandboxed shell whose proxy re-signs TLS makes
osv-scanner fail certificate checks; that appears in `not_run`, and the scan
needs rerunning outside the sandbox with the requester's agreement.

## 2. Judge what the scanner cannot

- **Platform end of life** — read the runtime and framework versions from the
  manifests, lockfiles, Dockerfiles and CI files (the inventory's `platform` and
  `notable` fields are filled only for Composer) and compare with the vendor's
  support schedule. Check the current schedule rather than recalling it; an
  unsupported runtime or framework is High when it is internet-facing. When the
  schedule cannot be fetched (no network), do not decide from memory: add the
  limitation "platform end of life not checked: vendor schedule unavailable
  (<runtime and framework versions>)" instead of a finding
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
