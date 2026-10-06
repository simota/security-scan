---
name: security-scan
description: "Static security review of an application's own source: maps routes, auth and tenancy, then checks authn/authz, cross-tenant access, API parameter tampering, injection, uploads, secrets, config, vulnerable/malicious dependencies, supply chain. Outputs a dashboard and a PDF report. Read-only. Use when asked to audit a codebase for vulnerabilities or data-isolation gaps, or to list what to check."
allowed-tools: Read, Grep, Glob, Bash
---

## Owns

Finding vulnerabilities in a codebase the requester owns or is authorized to
assess, **by reading it**. The output is a ranked list of findings, each with a
`file:line`, the actor who can trigger it, the request shape, what goes wrong and
how sure the finding is — or, when only a plan is asked for, a checklist tailored
to this application.

It does not fix code and does not send traffic to any deployed environment.
Fixing is a separate, later request.

Phases: `RECON → CHECKLIST → REVIEW → VERIFY → REPORT`.

## Before starting

- **Confirm scope and authorization in one line.** The repository is the
  requester's, the review is static, and no deployed system is touched. If the
  request implies live testing, see the dynamic row in *Decide first*
- **Name the actors before reading handlers**: anonymous, each role, and each
  tenant within a role. Most serious findings are one actor reaching another
  actor's data, and they are invisible until the actors are named
- **Name the crown jewels**: the data whose exposure or tampering would hurt
  most (other tenants' records, prices and contracts, credentials, PII, admin
  capability). Severity is judged against these
- **Size the run**: a handful of handlers is one careful pass. On a large
  codebase, split the review by resource domain plus one cross-cutting reviewer
  (auth, middleware, session, error handling), each read-only with the same
  output format, and merge before VERIFY

## Phases

| Phase | Do | Reference |
|---|---|---|
| RECON | Build the attack-surface map: stack, every entry point with its auth and role guard, how tenancy is enforced and which models escape it, data sinks, config; run `scripts/deps_scan.py` for the dependency inventory and supply-chain checks | `reference/recon.md`, `reference/dependencies.md` |
| CHECKLIST | Choose the perspectives that apply and turn the map into this app's checklist; attach early suspicions marked unverified | `reference/perspectives.md`, `reference/report.md` |
| REVIEW | One pass (or one independent reviewer) per perspective; handlers a low-privilege actor can reach first, admin-only handlers for the severe classes only; `deps_scan.py --audit` for known-vulnerable and malicious packages | `reference/perspectives.md`, `reference/dependencies.md` |
| VERIFY | Record evidence-linked reachability, preconditions, defenses and impact; try to falsify the claim; preserve unknown conditions and independent reviewer findings; distinguish static support from isolated runtime evidence | `reference/validation.md`, `reference/verification-workflow.md` |
| REPORT | Write `findings.json` with a `path:line` location for every code finding and `references` (advisory, fix commit, article) for every library finding; render the dashboard and the assessment PDF with `scripts/render.py --repo <audited-repo>` so code excerpts are embedded; then give the summary in chat | `reference/findings-schema.md`, `reference/report.md` |
| VERIFY-FIX *(on request)* | With explicit permission, test the same case before/after in owned local or throwaway code; require a legitimate secure-assertion failure before, pass after, plus passing positive control and regression. Record retest evidence separately from `Fixed` | `reference/fix-verification.md` |

## Outputs

| Output | What it is |
|---|---|
| Chat summary | First line status and counts, verified findings by severity, decisions for a human |
| `findings.json` | The single source every other output is rendered from |
| `dashboard.html` | Interactive, self-contained dashboard of the findings and perspective coverage |
| `assessment.pdf` | The formal assessment document: cover, summary, overview, perspectives, findings, sound items, limitations, next steps |

Skip the files when only a checklist was asked for. Render them in the
requester's language (`--lang ja|en`).

## Decide first

| Situation | How to proceed |
|---|---|
| Asked "what should we check" or "list the items" | RECON and CHECKLIST only, then stop and deliver the checklist |
| Asked to check, audit or scan | All five phases |
| Tenancy is enforced by a default/global scope or a base query | List every model **without** it and every query path that **bypasses** it. That list is the cross-tenant hunt list |
| A guard exists in one layer only (UI routes vs API routes, one middleware group vs another, list endpoint vs detail endpoint) | Check the other layer. Asymmetric guards are the most common real finding |
| A protection depends on a request header (client IP, host, forwarded proto) | Find where the header is set and which entry in it is trusted. Report as environment-dependent and name the setting to check |
| A finding's impact depends on deployment (debug flags, proxy, storage ACL) | Report it as `environment-dependent` with the exact setting, not as confirmed and not as dropped |
| The requester wants live confirmation | Only on a local or throwaway environment they own, only after an explicit go-ahead, never production, never a third party |
| Asked to confirm a fix, write a repro, or guard against regression | Write a local regression test that is red on the vulnerable code and green on the fix, in the repo's own suite (`reference/fix-verification.md`). Own code and local-only; not an attack tool |
| Two reviewers disagree | Re-read the disputed evidence and record the disagreement and its resolution. A vote is not verification; keep material unresolved disagreements incomplete |
| A secret is found in the repo | Report its location and kind only. Never print the value |

## Always / Never

- Always: anchor every finding to `file:line` and name the actor and the request
  shape (method, path, parameter names)
- Always: grade **severity** (High / Medium / Low) and **confidence**
  (Confirmed / Environment-dependent / Suspected) separately; also distinguish
  the recorded verdict, evidence-derived verification basis and remediation status
- Always: pin structured evidence to the assessed revision and record the four
  claims, falsification checks, reviewer evidence and unresolved conditions
- Always: retain legacy verdicts without promoting them to verified or fix-ready;
  label missing structured evidence as insufficient verification. Only explicit
  `schema_version: 2` opts into the new rules; versionless/version-1 extension
  fields remain historical, regardless of their names
- Always: list what was checked and found sound. A report with no negatives
  cannot be told apart from a report that did not look
- Always: say what static reading cannot show — deployed config, data actually
  present, the front end in production, infrastructure outside the repo
- Never: edit source, configs or dependencies during the review
- Never: send requests to deployed systems, or run scanners against hosts
- Never: write working exploit payloads into the report. Describe the weakness,
  the parameter and the fix direction
- Never: paste source or findings into external services. The one exception
  is a dependency audit, which sends the package list to public advisory
  databases — say so before running it
- Never: report a High or Medium finding you have not read end to end yourself
- Never: delete a finding judged false — mark it `FalsePositive` or
  `NotApplicable` with evidence so the exclusion is visible
- Never: produce a working exploit, a payload generator, or a scanner that
  varies hosts or targets. Fix verification is a local regression test on the
  requester's own code, asserting the secure outcome (`reference/fix-verification.md`)

## Verify with

- Every High and Medium finding is traced route → middleware → handler →
  query/response by the agent writing the report, not only by a reviewer
- Every claim that a field leaks is checked against the model's hidden/visible
  rules and the relations actually loaded
- Definitive High findings have a different reviewer inspect the supporting
  evidence; unresolved disagreements are not settled by majority vote
- Static support is never labelled runtime reproduction. Isolated runtime
  evidence does not establish deployed conditions; skipped, blocked, unsupported
  and errored runs never become passes. A listed incomplete current-version run
  blocks runtime/retest verification. A passing secure assertion contradicts
  `Valid`; a legitimate failing one contradicts an exclusion. Keep either
  conflict incomplete, and do not discard counterevidence
- `Unverified`, `Likely` and `Unlikely` remain verification-incomplete even with
  complete evidence fields; recorded verdicts are not automatically upgraded
- `Fixed` is a recorded claim. An independently evidenced retest requires the
  runtime-supported original case, matching before/after records and passing
  normal/positive-control and regression records
- For ordered reviewer handoffs, use `scripts/verification_workflow.py` and
  `reference/verification-workflow.md`: conditions → independent falsification →
  evidence-based decision. It accepts review outputs and controls stage order;
  it does not launch AI reviewers or application tests. A stale or unfinished
  opted-in workflow cannot become fix-ready
- `scripts/verification.py` checks record structure and declared consistency,
  not whether artifacts are truthful, test commands ran or all paths were covered
- Dependency findings come from `scripts/deps_scan.py` (static checks, plus
  audit tool output with `--audit`); every audit in its `not_run` list appears
  in the report's limitations, and platform end-of-life is checked against the
  vendor's current schedule, not recalled

## Done when

Every entry point reachable by a non-admin actor has been read, every
perspective in `reference/perspectives.md` is recorded as applied, N/A or not
checked, every High and Medium finding has a recorded verdict and explicit
verification basis (or the first line names the outstanding validation and
insufficient-evidence counts), and the report states its own blind spots. Record
uncertainty honestly; a completed report need not claim every finding is verified.
