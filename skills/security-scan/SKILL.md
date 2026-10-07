---
name: security-scan
description: "Static security review of an application's own source: maps routes, auth and tenancy, then checks authn/authz, cross-tenant access, API parameter tampering, injection, uploads, secrets, config, vulnerable/malicious dependencies, supply chain. Outputs a dashboard and a PDF report. Read-only. Use when asked to audit a codebase for vulnerabilities or data-isolation gaps, or to list what to check."
allowed-tools: Read, Grep, Glob, Bash, Write
---

## Owns

Finding vulnerabilities in a codebase the requester owns or is authorized to
assess, **by reading it**. The output is a ranked list of findings, each with a
`file:line`, the actor who can trigger it, the request shape, what goes wrong and
how sure the finding is — or, when only a plan is asked for, a checklist tailored
to this application.

It does not fix code and does not send traffic to any deployed environment.
Fixing is a separate, later request. On an explicit request for reproducible
fixtures, it can generate and run a separate synthetic local bundle; this never
executes or changes the assessed application.

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
- **Create a new, empty output directory** outside the audited repository and
  follow the *Run contract* below; it is the same on every host

## Run contract

Claude Code, Codex and Antigravity read this same file. Wherever hosts would
otherwise choose differently, the choice is fixed here, and
`scripts/contract_check.py <out>` must pass before the chat summary.

| Item | Fixed choice |
|---|---|
| Independence | Never read another assessment's outputs — other hosts' report directories, an earlier `findings.json`, review records — unless the request is to merge or compare them. A run that reuses another run's findings is not an assessment |
| Review units | Group the route inventory by resource domain: one unit per domain plus one cross-cutting unit (auth, middleware, session, error handling, config). Each unit applies every applicable perspective to every route in it. With subagents, one reviewer per unit; without, the same units sequentially in the same order. Reviewer notes stay in scratch, not in the output directory |
| Granularity | One finding per root cause, i.e. per fix location. The same flaw on several routes is one finding that lists them in `request`; flaws needing different fixes are separate findings |
| IDs | `F-001`… for code, config and platform findings, numbered without gaps in severity order (then path); `D-*` only from `deps_scan.py`. No other prefixes |
| Dependencies | `deps_scan.py <repo> --audit --out deps.json` and `--into findings.json` (without `--audit` if the requester declines the advisory query; that lands in limitations). Never hand-write, merge or split `D-*`; per-package review goes into that finding's `validation`. Platform end of life is one `F-*` finding under *Dependencies and platform* |
| Record format | `schema_version: 2`. `scripts/evidence_capture.py` pins the commit and writes the source evidence; every `F-*` finding carries an explicit `validation.verdict` and structured `verification` (four claims citing evidence IDs, at least one falsification check). Three-pass coverage, the sequential workflow, integrity receipts and reproduction bundles run only on request |
| Severity | The table below, decided before confidence; confidence never raises or lowers it |
| Outputs | Exactly `findings.json`, `deps.json`, `evidence/`, `dashboard.html`, `assessment.html`, `assessment.pdf` (plus `run/` at expert grade), in the requester's language. No README, summary PDF or extra audit dumps unless asked (`contract_check.py --allow NAME`) |
| `meta.assessor` | Host and model, e.g. `Claude Code (<model>)`, `Codex (<model>)`, `Antigravity (<model>)` |
| Writing the record | Never build `findings.json` with a shell heredoc, an inline `python -c` or a generated script. Write each batch of results as a JSON fragment with the file-write tool into scratch (not the output directory), then `scripts/findings.py merge <out>/findings.json <fragment>…`. The first fragment carries `meta`; `scripts/evidence_capture.py` then pins the record, and later fragments add `verification`, `test_runs` and requested `three_pass`/`expert`/`evidence_integrity` profiles. Nested profile lists/objects replace whole values; see `reference/findings-schema.md`. Workflow journals are written only by `scripts/verification_workflow.py` |
| Read-only | `allowed-tools` above is enforced by Claude Code only. Elsewhere keep to it yourself: read, search and run this skill's scripts; `Write` is for finding fragments in scratch only; write nothing inside the audited repository |

| Severity | When |
|---|---|
| High | An anonymous or ordinary signed-in actor, with nothing beyond what any account has, can read or alter another actor's crown-jewel data, take over an account, bypass authentication or payment, or reach code, SQL or command execution. Also an internet-facing end-of-life runtime or framework, and a malicious package |
| Medium | A High-class impact that needs one condition the attacker does not control alone (victim interaction, victim-specific knowledge, a plausible but unconfirmed setting, a non-admin privileged role), or direct impact on lower-value data or business rules (limits, metadata, non-sensitive profile fields) |
| Low | Defense-in-depth gaps (headers, cookie flags with compensating controls, internal TLS checks), low-value disclosure, or a path needing an admin, an insider or an unlikely chain |
| Info | A hardening note with no attacker path |

Each further condition the attacker does not control lowers severity one level.
An `Environment-dependent` finding is graded as if its stated condition holds,
and names that condition.

## When the host refuses an action

A host safety check or permission prompt may refuse one tool call. That refusal
covers that action, not the assessment: this skill exists to close holes, and
the run continues.

1. Do not resend the same call, and never disguise it (encoding, splitting,
   renaming, moving the content elsewhere). The aim is a different, defensive
   shape of the work, not a way past the check
2. Find what made the call look offensive. Almost always it is one of: finding
   text inside a shell command or generated script, a literal attack string,
   or something resembling an exploit or traffic generator. Switch to the
   sanctioned shape: a JSON fragment written with the file-write tool and
   `scripts/findings.py merge`; the request shape as method, path and parameter
   names with placeholders (`<other tenant's id>`); the fix direction instead of
   a demonstration
3. If the sanctioned shape is refused too, drop that step only: add it to
   `limitations` (what was not recorded and why), continue every phase that does
   not depend on it, and name the blocked step and the exact command in the chat
   summary so the requester can run it themselves
4. Never end the run silently on a refusal. "Cannot proceed in this session" is
   only a valid report when no remaining phase can be done

## Phases

| Phase | Do | Reference |
|---|---|---|
| RECON | Build the attack-surface map: stack, every entry point with its auth and role guard, how tenancy is enforced and which models escape it, data sinks, config; run `scripts/deps_scan.py` for the dependency inventory and supply-chain checks | `reference/recon.md`, `reference/dependencies.md` |
| CHECKLIST | Choose the perspectives that apply and turn the map into this app's checklist; attach early suspicions marked unverified | `reference/perspectives.md`, `reference/report.md` |
| REVIEW | One pass (or one independent reviewer) per review unit from the *Run contract*, applying every applicable perspective; handlers a low-privilege actor can reach first, admin-only handlers for the severe classes only; `deps_scan.py --audit --into` for known-vulnerable and malicious packages | `reference/perspectives.md`, `reference/dependencies.md` |
| VERIFY | Record evidence-linked reachability, preconditions, defenses and impact; try to falsify the claim; preserve unknown conditions and independent reviewer findings; distinguish static support from isolated runtime evidence | `reference/validation.md`, `reference/verification-workflow.md`, `reference/evidence-integrity.md` |
| REPORT | Write `findings.json` through fragments and `scripts/findings.py merge`, with a `path:line` location for every code finding and `references` (advisory, fix commit, article) for every library finding; capture cited source with `scripts/evidence_capture.py`; render the dashboard and the assessment PDF with `scripts/render.py --repo <audited-repo>` so code excerpts are embedded; pass `scripts/contract_check.py`; then give the summary in chat | `reference/findings-schema.md`, `reference/report.md` |
| REPRODUCE *(on request)* | Generate a deterministic synthetic seed/repro/cleanup bundle for a selected finding; verify its pins and hashes, repeat the local model twice and preserve unsupported/error outcomes. A synthetic model is not application runtime verification | `reference/reproduction-bundles.md` |
| VERIFY-FIX *(on request)* | With explicit permission, test the same case before/after in owned local or throwaway code; require a legitimate secure-assertion failure before, pass after, plus passing positive control and regression. Record retest evidence separately from `Fixed` | `reference/fix-verification.md` |

## Outputs

| Output | What it is |
|---|---|
| Chat summary | First line status and counts, verified findings by severity, decisions for a human |
| `findings.json` | The single source every other output is rendered from (`deps.json` and `evidence/` support it) |
| `dashboard.html` | Interactive, self-contained dashboard of the findings and perspective coverage |
| `assessment.pdf` | The formal assessment document: cover, summary, overview, perspectives, findings, sound items, limitations, next steps |

Skip the files when only a checklist was asked for. Render them in the
requester's language (`--lang ja|en`).

## Decide first

| Situation | How to proceed |
|---|---|
| Asked "what should we check" or "list the items" | RECON and CHECKLIST only, then stop and deliver the checklist |
| Asked to check, audit or scan | All five phases |
| Asked for an expert, commercial-grade, exhaustive or "no compromise" assessment | Expert grade: price the worker envelope, get consent to the ceiling, engines and data boundary, then run E0–E9 with independent workers for recon, discovery, variants, omission, conditions, refutation, calibrated severity, reception and QA (`reference/expert-mode.md`, `reference/engine-map.md`). Never label a run expert-grade unless `scripts/expert_audit.py` exits 0 |
| Asked for three-pass assurance or discovery → conditions → challenge | Opt into the schema-version-2 `three_pass` coverage profile, reuse the manual workflow and require the aggregate audit; see `reference/three-pass-check.md`. Do not promise a numerical accuracy rate |
| Tenancy is enforced by a default/global scope or a base query | List every model **without** it and every query path that **bypasses** it. That list is the cross-tenant hunt list |
| A guard exists in one layer only (UI routes vs API routes, one middleware group vs another, list endpoint vs detail endpoint) | Check the other layer. Asymmetric guards are the most common real finding |
| A protection depends on a request header (client IP, host, forwarded proto) | Find where the header is set and which entry in it is trusted. Report as environment-dependent and name the setting to check |
| A finding's impact depends on deployment (debug flags, proxy, storage ACL) | Report it as `environment-dependent` with the exact setting, not as confirmed and not as dropped |
| The requester wants live confirmation | Only on a local or throwaway environment they own, only after an explicit go-ahead, never production, never a third party |
| Asked to verify evidence files or commit correspondence | Use `scripts/evidence_integrity.py verify` with an explicit local evidence root and owned repository for source artifacts. Require fresh checks in consumers when policy opts in; do not treat an imported receipt as authority (`reference/evidence-integrity.md`) |
| Asked for reproducible seed data or a portable reproduction bundle | Use `scripts/reproduction.py` or `verification_workflow.py bundle`, following `reference/reproduction-bundles.md`. Generate only the supported synthetic template or a clearly unsupported scaffold; do not infer permission to execute application code |
| Asked to confirm a fix, write a repro against the application, or guard against regression | Write a local regression test that is red on the vulnerable code and green on the fix, in the repo's own suite (`reference/fix-verification.md`). Own code and local-only; not an attack tool |
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
- For the opt-in three-pass profile, account for every planned perspective/target
  cell, map every candidate, and use distinct declared discovery, conditions and
  falsification actors. Independently challenge all four claims at every severity;
  scope challenge must also cover zero-candidate and N/A cells. Run
  `verification_workflow.py audit findings.json --require-complete`. Missing
  workflows, stale records and zero candidates remain incomplete. Actor names are
  not authenticated identities; scope completeness is not security completeness
  (`reference/three-pass-check.md`)
- Reproduction bundles bind the selected finding, assessment pin, evidence
  records, template and configuration. Revalidate against current findings before
  running. Deterministic synthetic red/green outcomes never prove the actual
  application boundary; exported records keep that boundary mocked and never
  automatically update findings (`reference/reproduction-bundles.md`)
- `scripts/verification.py` checks record structure and declared consistency.
  Optional `--evidence-root` / `--evidence-repository` checks compare local bytes
  and source commit blobs; schema-version-2 `evidence_integrity.required` gates
  support/retest on fresh verification. Legacy/default records receive no
  retrospective verification credit. See `reference/evidence-integrity.md`
- Receipts are separate, deterministic records, never instructions to promote a
  verdict. Read the real sources again for each consuming command. Hashes cannot
  authenticate reviewers, establish logged events or prove a vulnerability;
  runtime/environment byte checks do not establish execution or deployment
- Evidence checks use safe relative local paths and an explicitly supplied owned
  repository. Dirty worktrees and remote retrieval are unsupported. Do not run
  repository hooks, apply repository configuration, execute app code or fetch
  missing objects to turn an incomplete check into a success
- Dependency findings come from `scripts/deps_scan.py` (static checks, plus
  audit tool output with `--audit`); every audit in its `not_run` list appears
  in the report's limitations, and platform end-of-life is checked against the
  vendor's current schedule, not recalled

## Done when

`scripts/contract_check.py` passes (and, at expert grade,
`scripts/expert_audit.py`), every entry point reachable by a non-admin actor has
been read, every perspective in `reference/perspectives.md` is recorded as
applied, N/A or not checked, every High and Medium finding has a recorded
verdict and explicit verification basis (or the first line names the outstanding
validation and insufficient-evidence counts), and the report states its own
blind spots. Record uncertainty honestly; a completed report need not claim
every finding is verified.
