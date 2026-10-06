# Validation — is each finding real and does it apply here?

**Read when:** VERIFY, for every finding before it reaches the report; and
whenever `findings.json` is re-rendered after a person has reviewed it.

A scanner hit or a reviewer's claim is a hypothesis. Validation turns it into a
verdict with evidence, recorded on the finding as `validation`
(`reference/findings-schema.md`). Nothing is deleted: a finding judged false is
kept, marked, excluded from the counts, and listed at the end of the assessment
so the next reader can see what was ruled out and why.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | Reproduced in reasoning end to end: reachable by the named actor, preconditions hold, impact follows | Agent or person, with evidence |
| `Likely` | Strong signals, one link not yet confirmed | Agent, person, or auto-triage |
| `Unverified` | Not yet examined | Default |
| `Unlikely` | Signals point away (dev-only, not referenced), but not ruled out | Agent, person, or auto-triage |
| `FalsePositive` | The claimed condition does not exist in this code | Agent or person, with evidence |
| `NotApplicable` | The condition exists but cannot be triggered here (feature unused, input never reaches it, compensating control) | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` require `evidence`; the renderer
refuses the file without it. Auto-triage never sets them.

## Code findings

For each finding, answer and record in `evidence`:

1. **Reachable** — the route exists, is registered, and the named actor passes
   its middleware/guards. Cite the route and guard lines
2. **Preconditions** — what state or configuration must hold, and whether it
   holds by default
3. **No compensating control** — no scope, policy, validation, framework
   default or upstream proxy rule neutralizes it. Check the layers the original
   reviewer did not read
4. **Impact follows** — the data or action named in `impact` is actually what
   the code returns or changes (check hidden fields, loaded relations, response
   shaping)
5. **Second look for High** — a High finding is re-read by a different
   reviewer (or the reporting agent, if a sub-reviewer found it) before it is
   `Valid`

Runtime confirmation on a local or throwaway environment, when the requester
has agreed to it, upgrades `Likely` to `Valid`; record what was run.

## Dependency findings

`scripts/deps_scan.py --audit` adds auto-triage to every advisory:

| Signal | Source |
|---|---|
| `exposure` runtime / dev-only / unknown | `packages` vs `packages-dev`, npm `dev` flags, `dependencies` vs `devDependencies` |
| `dependency` direct / transitive | the manifest next to the lockfile |
| `referenced` yes / no / unknown | first-party source searched for the package's namespaces or import paths |

and suggests `Likely` (runtime and used), `Unlikely` (dev-only and not
imported) or `Unverified`. Malicious-package reports are always `Likely`.
Then, for each package (not each advisory), the agent or person:

1. Reads the advisory's affected function, option or input
2. Searches the code for that function or option and for the input reaching it,
   including use through the framework (a transitive HTTP client used by the
   framework's own client is still reachable)
3. Sets the verdict on every advisory of that package with that evidence.
   Dev-only tooling is rarely `NotApplicable`: it runs in CI with secrets, so
   prefer `Unlikely` with the reason
4. Confirms the deployed version matches the lockfile when the deploy builds
   from it; if not, the verdict is `Unverified` with that note

Re-running `deps_scan.py --into` keeps any verdict whose `method` is not
`auto`, so reviews survive a re-scan.

## Reporting

- Headline counts and the dashboard's default view exclude `FalsePositive` and
  `NotApplicable`; the dashboard's validation filter shows them
- The summary states how many findings were excluded and how many remain
  `Unverified`. A report with many `Unverified` Highs says so in its first line
