# Sequential verification workflow

**Read when:** VERIFY, when a finding needs a recorded handoff from conditions
review to independent falsification to an evidence-based decision.

## What this runs

`scripts/verification_workflow.py` coordinates three ordered, local review
handoffs for each finding:

1. **Conditions**: record reachability, preconditions, compensating defenses and
   impact, with revision-pinned evidence. State the environment assumptions.
2. **Falsification**: a different declared reviewer inspects the evidence and
   looks for a reason the finding does not hold. Record the checks,
   counterevidence and disagreements.
3. **Decision**: submit an explicit verdict and its evidence. Reuse the existing
   structured-verification rules before accepting a definitive result.

Reviewers perform the review and submit structured JSON. The CLI produces the
handoff, checks its input and output, applies the accepted stage result, records
the transition and identifies the next stage. It does not call an AI provider,
launch a reviewer, execute commands from evidence, run an application test or
send network traffic. Reviewer labels are declarations, not identity checks.
Multiple matching opinions do not establish a finding.

The workflow is opt-in for `schema_version: 2` findings. Old reports and findings
without a workflow retain their existing interpretation. For an opted-in
finding, fix readiness also requires completion of the current workflow; a
pre-existing `Valid` label cannot bypass an unfinished handoff.

## Run a review

Start with a schema-version-2 findings file, a pinned assessment and its evidence
registry. `examples/findings.workflow.sample.json` is an explicitly fictional
unverified candidate for trying the workflow. Work on a copy of that example.

```sh
cp examples/findings.workflow.sample.json /tmp/findings-workflow.json
python3 skills/security-scan/scripts/verification_workflow.py init /tmp/findings-workflow.json --finding F-001 --actor analyst
python3 skills/security-scan/scripts/verification_workflow.py next /tmp/findings-workflow.json --finding F-001 --out /tmp/conditions-handoff.json
```

The handoff identifies the stage, current input digest, evidence and expected
submission fields. The assigned reviewer reads the actual referenced source
and copies the handoff's `submission_template` object into a separate JSON file,
then replaces its placeholders with observations. Submit that object, not the
whole handoff packet. Do not treat the fictional example's
observations as a real assessment. Submit the completed file:

```sh
python3 skills/security-scan/scripts/verification_workflow.py submit /tmp/findings-workflow.json --finding F-001 --submission /tmp/conditions-result.json
python3 skills/security-scan/scripts/verification_workflow.py next /tmp/findings-workflow.json --finding F-001 --out /tmp/falsification-handoff.json
```

Use a different declared actor for falsification. After its accepted submission,
request the decision handoff, review its evidence and submit the decision. Every
submission carries the digest from its own handoff; do not reuse the conditions
digest for later stages.

```sh
python3 skills/security-scan/scripts/verification_workflow.py status /tmp/findings-workflow.json
python3 skills/security-scan/scripts/verification_workflow.py status /tmp/findings-workflow.json --require-complete
python3 skills/security-scan/scripts/render.py /tmp/findings-workflow.json --out /tmp/workflow-report --lang ja --no-pdf
```

Only init, submit, resume and invalidate update the findings file. Status and
next are read-only; next with `--out` creates a new handoff file and refuses to
replace an existing one. Mutations use an atomic replacement, a cooperative
sidecar lock and a final content check. Keep one active submitter per file;
parallel reviewers should submit through this CLI rather than saving whole-file
copies over one another.

Exit `0` means the command completed, not that the application is safe. Use
`status --require-complete` as a shell gate: it exits `3` if any selected finding
has no completed workflow. Invalid input, stage ordering and file-write conflicts
exit `2`. Read the JSON state and hold reason as well as the exit code.

## Submission contract

All submissions include `stage`, `actor`, `status`, `summary`, `evidence_ids` and
the handoff's `input_digest`. The stages are `conditions`, `falsification` and
`decision`. An actor label names responsibility but is not an authentication
credential. Status is `complete`, `held`, `error`, `unknown` or `conflict`;
incomplete outcomes cannot advance to the next stage.

Completed stages carry these additional results:

- Conditions: `claims` and `environment`, in the same format as structured
  verification. All four claims need observations and the relevant evidence
  IDs. The actor becomes the conditions reviewer. This starts an unverified
  assessment instead of inheriting a previous definitive verdict.
- Falsification: `checks` and `reviews`, using the existing falsification and
  reviewer record formats. Read the actual guards, scopes, output shaping and
  other controls, and preserve contrary evidence. A second actor label alone
  is insufficient.
- Decision: `validation` with `verdict`, `method` and `evidence`; `run_ids`; and
  `exclusion` when the verdict is `FalsePositive` or `NotApplicable`. The existing
  verifier evaluates the proposed result before accepting it. Confidence is
  preserved; this workflow never silently changes it to `Confirmed`.

See `reference/findings-schema.md` for the shared evidence, claim, environment,
falsification, reviewer and exclusion schemas. Evidence-backed negative claims
may support an exclusion. An unresolved contradiction is a hold, not an
automatic exclusion. No result is accepted solely because every reviewer agrees.

Current linked runtime observations and unresolved counterevidence are retained.
A new stage cannot make a prior skipped run, contradictory test or unresolved
review disappear simply by leaving it out. Resolve a dissent through its review
record, or explicitly correct the underlying source record and restart the
workflow. A withheld decision keeps any newly submitted run observations so a
retry cannot silently omit them.

## Resume or invalidate

After an interruption, status identifies the next stage. Request its handoff
again and submit against the current digest. A repeated identical submission is
handled safely; changing the result requires an explicit restart or invalidation
rather than rewriting history.

```sh
python3 skills/security-scan/scripts/verification_workflow.py resume /tmp/findings-workflow.json --finding F-001 --actor analyst --reason 'Missing source is now available; review the current input.'
python3 skills/security-scan/scripts/verification_workflow.py invalidate /tmp/findings-workflow.json --finding F-001 --actor analyst --reason 'The assessment input needs another review.'
```

Resume makes blocked work available for another attempt, or starts a fresh round
when the input is stale. Invalidation deliberately requires another review.
Previous submissions and the records they replaced remain in the history.

## Evidence and change handling

Each round has a fresh random identifier, included in its input digest. Even
when the source records are unchanged, an old round's submission cannot satisfy
a new round. Journal events also link their declared content digests; this
checks structural consistency, not authenticity.

Each accepted handoff is tied to the current assessment, finding and the evidence
and test-run records exposed in that round. The available catalog IDs are frozen
at initialization or restart. Newly added records need an explicit invalidate
and resume before they can be used; they do not silently appear in an already
issued handoff. A stage records the input and output digests so
the next reviewer can identify the exact result they received. These hashes
detect changes to the declared records; they do not themselves prove that an
evidence file exists, its declared hash matches actual bytes or a command ran.
Optional fresh local checks add byte/source-blob correspondence, never execution
or reviewer authentication.

Updating a relevant source record outside the workflow makes the current round
stale. Resume against the new input starts again at conditions while preserving
the previous history. Accepted stage-owned updates advance the digest chain.
Unrelated findings can be reviewed independently; the stages of one finding
remain ordered. Prepare and review handoffs in parallel, then submit using the
CLI's write protection rather than overwriting a shared JSON file by hand.

A skipped stage is not completion. Unknown conditions, unresolved disagreements,
infrastructure errors and stale input remain visible and block promotion.
Evidence-backed exclusions remain in the report. An unknown or failed check
does not mean the application is safe.

## Fresh local evidence checks

Use `reference/evidence-integrity.md` when a review depends on actual evidence
files. `init`, `next`, `status`, `submit`, `resume` and `invalidate` accept
`--evidence-root ROOT` and `--evidence-repository OWNED_LOCAL_REPO`. They read
current sources for that invocation; an old receipt cannot satisfy the check.
The separate `evidence` command aliases receipt generation without advancing a
stage or changing the findings. Its flags follow the standalone evidence CLI:

```sh
python3 skills/security-scan/scripts/verification_workflow.py evidence findings.json \
  --root /path/to/local-evidence --repository /path/to/owned-local-repository \
  --out /path/to/new-receipt.json
```

```sh
python3 skills/security-scan/scripts/verification_workflow.py next findings.json \
  --finding F-001 --out /path/to/new-handoff.json \
  --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repository
python3 skills/security-scan/scripts/verification_workflow.py submit findings.json \
  --finding F-001 --submission /path/to/stage-result.json \
  --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repository
```

Top-level version-2 `evidence_integrity: {"required": true}` makes fresh checks
an additional prerequisite for sufficient structured support and retest. Keep
supplying the evidence flags during the review; completing a workflow cannot
bypass an unmet integrity requirement. The policy and relevant declarations
are bound into the review context. Changed evidence, test records or policy
require current checks and, when the round is stale, explicit restart as above.
A matched source blob does not resolve unknown conditions, contrary runtime
observations or reviewer disagreements. Legacy/default records remain declared
unless actual sources are checked; do not retroactively certify historical work.

## Safety boundaries

Keep observations sanitized before storing them. Never include secret values,
real credentials, unnecessary personal data or working exploit payloads in
handoffs, submissions or history. Reports redact recognized patterns as a
best-effort safeguard; review them before sharing.

Runtime reproduction is separate and still requires explicit authorization for
owned local or throwaway code. The workflow does not expand that authorization.
Static support, an isolated recorded reproduction and deployed conditions remain
distinct. Fix verification continues to follow `reference/fix-verification.md`.

## Generate a reproducibility bundle

The bundle command is an alias for the separate reproduction generator:

```sh
python3 skills/security-scan/scripts/verification_workflow.py bundle \
  findings.json --finding F-001 --plan plan.json --out NEW_BUNDLE
```

It reads the finding and evidence records but does not advance a review stage,
change a verdict or run the assessed application. Use `scripts/reproduction.py`
to verify and run the generated synthetic model against the current findings
file.

See `reference/reproduction-bundles.md` for the plan, deterministic seed scripts,
two-run checks, unsupported scaffolds and evidence limits. A stale bundle must
be regenerated and reviewed; a successful synthetic run does not complete this
workflow or grant runtime verification.
