# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many perspectives apply, and that suspicions are unverified
- One section per perspective from `reference/perspectives.md`, most important
  first; list the ones judged N/A with a reason
- Each item: the question, concrete routes/files, and an optional
  `initial note (unverified)`
- Close with the recommended starting point and one decision for the requester

## Findings report

1. **First line** — severity counts and review scope. State whether the work was
   static, or included explicitly authorized isolated tests. State recorded
   `Unverified` findings and insufficient-verification findings separately,
   highlighting High findings; do not call legacy verdicts execution-confirmed
2. **Evidence line** — assessed revision, what was read, which claims were
   checked, what the reporting agent re-read, and what remains environment-unknown
3. **Findings, by severity** — each includes:

   ```
   [High|Medium|Low][Confirmed|Environment-dependent|Suspected] one-line title
     location: path:line at the assessed revision
     actor and request shape: role, method, path, parameter names
     what happens: the code fact and bounded impact
     recorded verdict: Valid / Likely / Unverified / Unlikely / excluded verdict
     verification: static support / isolated runtime reproduction / incomplete
     evidence: IDs supporting reachability, preconditions, defenses and impact
     open questions: environment assumptions, counterevidence, reviewer disagreement
     remediation: recorded status; separately, whether a retest is evidenced
     fix direction: one line
     references: source; advisory / fix commit / article for libraries
   ```

   Keep exclusions visible with reasons. A legacy `Valid` may be retained as
   recorded while its verification is insufficient; do not silently rewrite it
   or promote it into the fix-ready queue. Only explicit schema version 2 enables
   structured verification; versionless/version-1 extension fields and plain
   legacy verification notes are historical, regardless of their names.
   `Unverified`, `Likely` and `Unlikely` remain incomplete even with complete
   evidence fields; do not upgrade their recorded verdicts.
4. **Checked and sound** — what was examined and held, without implying all
   paths or deployments were tested
5. **Decisions for a human** — specification questions, deployment settings to
   confirm, missing evidence and unresolved material disagreements
6. **Next step** — validation gaps first where necessary; otherwise a supported
   fix order. A local reproduction or fix test requires its own explicit scope
7. **Files** — link the dashboard and assessment rendered from `findings.json`
   using `reference/findings-schema.md`

Use the same recorded verdicts, confidence, verification basis and retest state
in chat, dashboard and PDF. `findings.json` is the record. Every chat finding
must exist there; output code derives verification labels rather than trusting
a caller-supplied “verified” flag.

A `Fixed` status means a fix was recorded. Retest verification needs the same
case on the before/after revisions, a legitimate secure-assertion failure
before, a pass after, and passing positive control and regression records.
`Accepted`, skipped tests and execution errors do not mean a successful retest.
The original case must be runtime-supported. An incomplete listed current-version
run prevents runtime/retest verification even if another run reproduced the issue;
a real-boundary secure assertion already passing contradicts `Valid`, while a
legitimate failure contradicts `FalsePositive` or `NotApplicable`. Either makes
verification incomplete without rewriting its verdict. Show those limits rather
than selecting only favorable runs.

State limitations prominently: static evidence is not runtime reproduction,
isolated reproduction is not proof of production conditions, and structural
schema checks are not semantic proof. Missing perspective coverage is unknown;
zero findings and passing repository CI are not evidence of an all-clear
assessment of the target application.

Describe weaknesses and parameters, not working payloads. Never print secret
values: use location and kind only. Evidence summaries and commands must be
sanitized before entry; heuristic output redaction is not a sharing guarantee.
