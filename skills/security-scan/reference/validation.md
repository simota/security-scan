# Validation — is each finding real and does it apply here?

**Read when:** VERIFY, for every finding before it reaches the report; and
whenever `findings.json` is re-rendered after a person has reviewed it.

A scanner hit or a reviewer's claim is a hypothesis. Keep the recorded verdict
in `validation`, and its structured verification in `verification`
(`reference/findings-schema.md`). Severity, confidence, verdict, verification
basis and remediation status are separate axes. A verdict or a reviewer agreeing
with it is not, by itself, evidence.

Nothing is deleted: a finding judged false stays in the record, with the
exclusion and its evidence visible. Legacy records remain readable and retain
their verdicts, but without structured verification they are labelled as having
insufficient verification and are not promoted to the fix-ready queue. Only an
explicit `schema_version: 2` enables structured verification. Versionless/version-1
extension fields, including objects named `verification`, `evidence` or
`remediation`, remain uninterpreted legacy records.

## Ordered handoffs

Use `scripts/verification_workflow.py` when the review needs enforced stage order:
conditions, independent falsification, then the evidence-based decision. The
workflow accepts stage results and records their lineage; it does not call a
reviewer or execute a test. Changing relevant input requires a fresh round.
Unknown, conflicting, failed or unfinished work stays blocked. See
`reference/verification-workflow.md` for the CLI and exact handoff contract.

## Verdicts

| Verdict | Meaning | Who may set it |
|---|---|---|
| `Valid` | The named actor can reach the condition, its preconditions hold, compensating defenses do not block it, and the claimed impact follows | Agent or person, with the required evidence |
| `Likely` | Strong signals, at least one necessary link not yet confirmed | Agent, person, or auto-triage |
| `Unverified` | Not yet examined | Default |
| `Unlikely` | Signals point away, but the claim has not been ruled out | Agent, person, or auto-triage |
| `FalsePositive` | Evidence contradicts the claimed condition in this code | Agent or person, with evidence |
| `NotApplicable` | The condition is not applicable to the assessed version, path, configuration or control | Agent or person, with evidence |

`Valid`, `FalsePositive` and `NotApplicable` still require nonblank
`validation.evidence`. In the new schema, prose alone is insufficient: the
structured claims and evidence references must also meet the verdict's rules.
Auto-triage never sets these definitive verdicts. See
`reference/findings-schema.md` for the exact fields and validation rules.
Structured `Unverified`, `Likely` and `Unlikely` remain verification-incomplete
even if their evidence fields are complete: the recorded verdict is unresolved
and is not automatically upgraded.

## Four claims for every finding

State the finding as: who enters through which route, under which conditions,
crosses which protection boundary, and affects what. Record each claim as
`supported`, `contradicted` or `unknown`, and link the evidence used:

1. **Reachability** — the route exists and is registered; the named actor can
   pass its authentication and role guards. Trace route → middleware → handler
   → query/output, with source locations pinned to the assessed revision
2. **Preconditions** — the relevant feature, package version, configuration and
   state exist. Identify assumptions and environment conditions not checked
3. **Compensating defenses** — test the claim that no policy, tenant scope,
   input validation, serializer, DB constraint, framework default or upstream
   control blocks the issue. Read the layers the original reviewer missed
4. **Impact** — the data actually returned, state actually changed, or operation
   actually performed matches the reported impact. Check hidden fields, loaded
   relations and response shaping, rather than inferring exposure from a query

For a structured `Valid`, all four claims must have supporting evidence and
falsification checks must be clear. Unknown environment conditions or missing
independent review still prevent sufficient verification, even when the recorded
verdict remains `Valid`. For an exclusion, link the
specific contradictory evidence and explain why it rules out the claim or its
applicability. “Dev-only”, “no import found” or another reviewer's agreement is
not sufficient on its own.

## Evidence, falsification and independent review

- Pin evidence to the assessed revision. Record source locations and a
  sanitized observation, not just the conclusion. Historical evidence from a
  different revision must not silently establish the current finding
- Try to disprove the finding: look for alternate routing, authorization,
  default scopes, tenant constraints, output filtering and incompatible
  configuration. Record the check, what was observed, its evidence references,
  and any counterevidence or unresolved question
- Have a different reviewer re-read the evidence for a definitive High finding.
  Record their identity, the evidence they inspected, disagreements and how
  those disagreements were resolved. Reviewer count is not a vote; re-read the
  disputed path and keep the finding incomplete while a material issue remains
- On a host with no subagents or second reviewer, record `reviews: []`, keep
  each High finding verification-incomplete, and name that in the chat
  summary's first line. Never invent a reviewer identity or record the same
  agent under a second name
- Store only sanitized observations. Never store secrets, real credentials,
  unnecessary personal data or working exploit payloads in evidence or logs

## Static support, isolated reproduction and unknown environments

Static support can establish a finding without a runtime test when every
necessary claim is supported. Label that basis explicitly. It does not mean
that an exploit was run or that the deployed configuration was observed.

Runtime evidence can establish an **isolated local reproduction** only when its
recorded case, target revision, environment, expected/observed result and
successful execution support the claim. A runtime method label or a passing
command is not enough. Unknown deployment conditions stay explicit; a local
fixture does not prove production has the same state or configuration.

The review remains static by default. Runtime work needs an explicit go-ahead
for the requester's owned local or throwaway environment. Never extend it to a
shared, staging, production or third-party system. Use synthetic data and
inert inputs, preserve the controls being tested, and stub unrelated external
services. Do not use or validate real credentials. Agree resource limits and
stop conditions; no new scanner or automatic test runner is added by the record
format. For requested fix tests, use `reference/fix-verification.md`.

`not_run`, `blocked`, `unsupported`, `error` and `skip` are incomplete outcomes,
not passes and not proof that a finding is absent. An exception, timeout,
missing dependency or undiscovered test must not become successful validation.
Any incomplete run listed in the current finding's `verification.run_ids` blocks
runtime support and a verified retest, even if another listed run reproduced the
issue; otherwise sufficient static support may remain. A listed real-boundary
security run that passes its secure assertion contradicts `Valid` and makes
verification incomplete. Conversely, a legitimate real-boundary security
assertion failure contradicts `FalsePositive` or `NotApplicable` and makes that
exclusion's verification incomplete. Recorded verdicts stay unchanged. Inspect
and resolve conflicting evidence rather than cherry-picking a favorable run.
Post-fix runs are linked separately by remediation.

## Dependency findings

`scripts/deps_scan.py --audit` adds auto-triage to every advisory:

| Signal | Source |
|---|---|
| `exposure` runtime / dev-only / unknown | `packages` vs `packages-dev`, npm `dev` flags, `dependencies` vs `devDependencies` |
| `dependency` direct / transitive | the manifest next to the lockfile |
| `referenced` yes / no / unknown | first-party source searched for the package's namespaces or import paths |

It suggests `Likely` (runtime and used), `Unlikely` (dev-only and not imported)
or `Unverified`. Malicious-package reports are always `Likely`. For each package
(not just each advisory), the agent or person then:

1. Reads the advisory's affected function, option or input
2. Traces use through first-party code and framework/transitive calls
3. Records the affected version and the evidence of reachability, preconditions,
   defenses and impact. Dev-only tooling can run in CI with secrets; do not
   exclude it merely because it is absent from production dependencies
4. Checks whether the assessed build/deployment actually uses the lockfile
   version; an unverified deployed version remains an explicit limitation

Re-running `deps_scan.py --into` retains a matching manual review in
`previous_validation`, not as the current verdict. Matching includes normalized
location, package/version, title and advisory IDs. The new finding keeps its
auto-triage (or `Unverified`) verdict. Revalidate before excluding it again,
even at the same path. The previous review is history and cannot affect current
counts or replace new verification records.

## Reporting and limits

- Headline finding totals exclude recorded `FalsePositive` and `NotApplicable`
  verdicts; exclusions remain visible with their verification limitations
- State both the recorded `Unverified` count and the count with insufficient
  structured verification, including High findings. They are different measures
- A recorded `Fixed` or `Accepted` status is not proof of a successful retest
- Schema validation checks structure and declared consistency. It cannot prove
  an observation true, a reviewer independent in practice, an omitted path safe,
  or an authorization claim genuine. Actual evidence review and authorized tests
  remain necessary
