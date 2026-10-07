# Three-pass assurance profile

**Read when:** an assessment needs explicit discovery coverage, independent
conditions review and a recorded countercheck before declaring its review
sequence complete. This is an optional schema-version-2 profile; existing files
without it retain their interpretation.

## What the three passes mean

1. **Discovery:** plan the perspective × target cells to read, then record an
   evidence-backed outcome for each cell and map every candidate finding to at
   least one checked cell. Cells with no candidates remain in the plan. A
   `not_applicable` declaration also needs current source evidence; a missing
   or `not_checked` row is a visible gap.
2. **Conditions:** for each candidate, a different declared actor records the
   four claims: reachability, preconditions, defenses and impact, using the
   existing workflow's `conditions` stage. Discovery must be complete first.
3. **Challenge and decision:** a third declared actor independently rereads the
   supporting evidence and attempts to disprove every claim. The workflow's
   `falsification` stage records that challenge, followed by its existing
   evidence-based `decision` stage. Challenge is not an extra vote.

The three distinct actor labels are discovery, conditions and falsification.
The decision stage is not a fourth required identity. Labels and journal hashes
are declarations and consistency checks, not authentication of people, agents,
independence or events. No numerical accuracy or detection-rate claim follows
from three passes. Completion describes only the supplied records and declared
scope, not complete security coverage or proof that no vulnerability was missed.

The profile controls manually supplied review records. It does not invoke AI
provider APIs, launch autonomous reviewers, execute recorded commands, test the
application, or send traffic to a target. The existing static, read-only review
and explicitly authorized local-only test boundaries still apply.

## Opt in and record discovery

Use integer `schema_version: 2`, the existing assessment pin and evidence
registry, and this top-level object (IDs below are illustrative):

```json
{
  "three_pass": {
    "version": 1,
    "coverage": [
      {"id": "tenant-api", "perspective": "Actor and tenant", "target": "API detail routes"},
      {"id": "upload-api", "perspective": "Files and content", "target": "Upload routes and storage"}
    ],
    "discovery": {
      "actor": "discovery-reviewer",
      "summary": "Read the declared entry points and their guards at the assessment revision.",
      "checks": [
        {"coverage_id": "tenant-api", "status": "checked",
         "reason": "Traced the route, authorization middleware and data query.",
         "evidence_ids": ["source-before"], "finding_ids": ["F-001"]},
        {"coverage_id": "upload-api", "status": "not_applicable",
         "reason": "The scoped application exposes no upload endpoint; the route inventory is the evidence.",
         "evidence_ids": ["route-inventory"], "finding_ids": []}
      ]
    }
  }
}
```

Replace examples with observations and evidence from the owned repository.
The plan must be nonempty with unique IDs and nonblank perspective/target text.
Discovery needs a nonblank actor and summary. Check IDs must refer to unique
planned cells. `checked` and `not_applicable` need current source evidence;
`not_checked` may have no evidence but needs a reason. `not_applicable` cannot
contain candidate IDs. All referenced finding and evidence IDs must exist.
Every finding, including a later exclusion, must be mapped to checked discovery
coverage. Missing work holds the profile; it is not silently treated as a pass.
Profile objects use the documented fields only, so misspellings and unsupported
extensions cannot quietly become proof.

## Reuse the ordered workflow

After recording discovery, use the existing local CLI for each finding:

```sh
python3 skills/security-scan/scripts/verification_workflow.py init findings.json --finding F-001 --actor coordinator
python3 skills/security-scan/scripts/verification_workflow.py next findings.json --finding F-001 --out /tmp/conditions-handoff.json
# Read sources, complete the handoff's submission_template and save it separately.
python3 skills/security-scan/scripts/verification_workflow.py submit findings.json --finding F-001 --submission /tmp/conditions-result.json
python3 skills/security-scan/scripts/verification_workflow.py next findings.json --finding F-001 --out /tmp/challenge-handoff.json
```

The conditions actor must differ from discovery. The falsification actor must
differ from both. Use each handoff's current `input_digest`, never an earlier
stage's digest. See [verification-workflow.md](verification-workflow.md) for
submission, decision, resume and invalidation details.

A completed falsification submission adds two requirements:

- Every entry in `checks` declares `claim`, one of `reachability`,
  `preconditions`, `defenses` or `impact`. Together the negative checks cover all
  four claims, with explicit source-grounded reasoning and evidence. Preserve
  contradictory and unresolved results instead of dropping them.
- `coverage_checks` records the source-based countercheck of scope cells. Each
  item contains `coverage_id`, `result` (`clear`, `contradiction`, `unresolved`),
  `reason` and `evidence_ids`. Clear or contradictory results require current
  source evidence. Each finding's challenge must cover its associated discovery
  cells. Reviewers may also cover zero-candidate and N/A cells in these records.

For example, in the falsification submission:

```json
{
  "checks": [
    {"claim": "reachability", "check": "Could a route guard block the named actor?",
     "result": "clear", "reason": "Recorded the inspected guard and scoped conclusion.",
     "evidence_ids": ["source-before"]}
  ],
  "coverage_checks": [
    {"coverage_id": "tenant-api", "result": "clear",
     "reason": "Independently reread the scoped routes, guards and query paths.",
     "evidence_ids": ["source-before"]}
  ]
}
```

This fragment is intentionally incomplete: add the other three claim checks,
all required submission fields, independent `reviews`, and any additional scope
cells. Every severity, including Low and Info, needs the falsification actor's
independent review covering the complete union of all claim evidence IDs. The
existing agreement/disagreement resolution requirements continue to apply.

Scope challenge is aggregated across current finding workflows, so each reviewer
does not have to repeat the whole assessment. Their union must cover every
planned cell, including those with no finding and those marked N/A. An unresolved
or contradictory duplicate cannot be erased by another review marking the same
cell clear. A missing global scope cell holds the aggregate assessment without
removing an otherwise complete individual finding's fix readiness.

## Audit and report

```sh
python3 skills/security-scan/scripts/verification_workflow.py audit findings.json
python3 skills/security-scan/scripts/verification_workflow.py audit findings.json --require-complete --out /tmp/three-pass-audit.json
python3 skills/security-scan/scripts/render.py findings.json --out /tmp/three-pass-report --lang en --no-pdf
python3 skills/security-scan/scripts/render.py findings.json --out /tmp/three-pass-report-ja --lang ja
```

`audit` does not change findings. Optional `--out` creates a new audit JSON file
and refuses to overwrite an existing file. Its JSON reports overall state, reasons, per-pass completion
counts, discovery gaps, scope-challenge gaps and current per-finding workflow
states. `--require-complete` exits `3` unless the opted-in profile is complete;
invalid input exits `2`. Without that flag, a held assessment may still exit `0`
because the audit command itself completed. Inspect its state, not just success
of the process. Ordinary `status` remains the per-finding workflow view.

The dashboard, assessment HTML and PDF show the same English/Japanese aggregate
state, counts and gaps. Only named, redacted fields enter the public profile
view. Review reports before sharing: redaction is best effort. The reports never
embed the raw profile or arbitrary extension fields as proof.

Aggregate completion requires complete discovery, at least one candidate, a
complete current workflow for every candidate and full independent scope
challenge. Zero candidates stays held even when every discovery cell was checked;
it cannot establish the required candidate verification or security. Missing
workflows, incomplete reviews and stale inputs cannot borrow readiness from an
older `Valid` record. Excluded candidates remain visible and must complete their
current review sequence too.

Changing the coverage plan, discovery declarations or relevant assessment and
evidence inputs makes affected current work stale. Re-read and restart using the
existing workflow rather than relabeling history. Initialization and restart snapshots preserve previous discovery
declarations; reports label changed snapshots as historical, not current proof.
Fresh evidence checks remain
available through `--evidence-root` and `--evidence-repository`; when required by
policy they also gate profile completion. Hash matching establishes byte/source
correspondence, not that the observations or reviewer identity are true.


## Synthetic regression benchmark

Run `make benchmark` for deterministic fixture-based checks of profile gates.
The fixture outcomes test the implementation's acceptance and hold rules; they
are not a measured vulnerability detection rate and are not real assessment
results. No target application, provider API or external scanner is executed.
`make check` runs the broader offline suite; required Chromium/PDF checks are
separately enforced by the CI report runner.
