# Expert grade — a multi-agent assessment that spends workers instead of cutting corners

**Read when:** the requester asks for an expert, commercial-grade, exhaustive or
"no compromise" assessment, or approves spending many workers on one. Read
`reference/engine-map.md` with it; that file alone names host tools.

Expert grade wraps the ordinary phases. Nothing in the *Run contract* or
*Always / Never* relaxes: still static, still read-only, still no exploit
payloads. What changes is that every judgment a single reviewer would make
alone is made by workers that did not produce what they judge, and every gate
leaves a record that `scripts/expert_audit.py` recomputes. The deliverable is
labelled expert-grade only when that audit exits `0`.

It is expensive by design. Price it, get consent, then do not trade a gate for
budget: a run that cannot finish within the approved ceiling stops `held` and
says which gates remain, rather than shipping a cheaper process under the label.

## Run card

Each phase opens only when the previous phase's records exist. Records live in
the top-level `expert` object of `findings.json` (schema below) and in `run/`
beside the report. Before each spawn, write its prompt to
`run/spawns/S-NN.prompt.md`; save the raw return to `run/spawns/S-NN.return.md`
and add the `spawns` entry (`id`, `actor`, `role`, `engine`, `prompt`, `return`).
One actor label holds one role for the whole run.

| Phase | Do | Records |
|---|---|---|
| E0 Gate | Compute the envelope (below) and get the requester's approval of the ceiling, the engines, and the data boundary — any extra engine sends source to another provider. Run the spawn preflight for this host and the reachability preflight per extra engine (`reference/engine-map.md`). Exit 0 sets `mode: full`; a failed host preflight sets `single-agent`, which can only end `degraded` | `consent`, `preflight`, `mode`, `host`; `run/gate.md` |
| E1 Recon ×2 | Two recon workers build the attack-surface map independently (`reference/recon.md`). Reconcile the route inventories: every route one map has and the other lacks is re-read and resolved. Turn the reconciled map into `three_pass.coverage` cells: review unit × applicable perspective | `recon` (≥2 actors), `reconciliation` (`routes`, `disagreements`, `resolved` equal) |
| E2 Discovery ×3 | Per review unit, three discovery workers in isolation, one per angle: `entry-first` (walk each route to its sinks), `sink-first` (start at raw queries, templates, file and shell calls, outbound requests; trace back to callers), `control-first` (list every guard, scope and validator; find the paths that skip them). Each applies every perspective. No worker sees another's output. Consolidate candidates by root cause into `F-NNN` and write the consolidated `three_pass.discovery` record | `discovery` (`actor`, `angle`, `cells`, `candidates`, `raw_candidates`); every cell needs ≥2 actors and ≥2 angles, and ≥2 engines when more than one is approved |
| E3 Variants | For each High/Medium root cause, a variant worker writes the pattern, searches the whole repository for siblings and dispositions every hit: `finding:F-NNN` (new), `same:F-NNN` (already covered) or `safe` with a reason | `variants` (`hits` equals dispositions) |
| E4 Omission | One worker that discovered nothing reads the reconciled map, the checklist and the finding list and attacks the claim "no material vulnerability class is missing". Additions become findings and go through E5–E7 | `omission` |
| E5 Conditions | A verifier that did not discover the finding traces route → middleware → handler → query/response and records the four claims with `scripts/evidence_capture.py` evidence (three-pass `conditions` stage) | finding `verification.reviewer` (role `conditions`) |
| E6 Challenge | Three-pass `falsification` stage at every severity. For every High/Medium finding also a refutation panel: two or three skeptics, each a different angle (`defense-exists`, `unreachable`, `precondition-unrealistic`, `impact-overstated`, `not-shipped`), briefed to destroy the finding, single round, never shown another skeptic's return. Aggregate on evidence: a majority `refuted` makes the finding an exclusion or needs a written `resolution` naming the evidence the skeptics missed. `unproven` stays a named residual, not a refutation | `panels`; three-pass workflow |
| E7 Severity | Two rater workers first score the calibration anchors below; the audit recomputes `calibrated` from their scores. Each active finding is then rated by two calibrated raters who did not discover or verify it, without seeing the recorded severity or each other's rating, using the *Run contract* table; each also proposes the CWE. Any disagreement is re-read by the orchestrator and resolved in writing | `calibration`, `ratings`, `severity_resolutions`; finding `cwe` |
| E8 Report and reception | Render. Three persona workers read the rendered assessment cold — no run records, no findings file: `executive` (can I decide budget and priority from page one?), `engineer` (can I fix each High/Medium from its entry alone?), `auditor` (can I trace every claim to evidence and every limit?). Each returns the verbatim sentence where it stopped or doubted, and the fix. Apply fixes, re-render; the audit greps each span in the report | `reception` (`persona`, `actor`, `stop_span`, `disposition`) |
| E9 QA | A worker that held no other role opens `findings.json`, `run/` and the report, recomputes the counts, runs `expert_audit.py`, and returns `pass` or the imbalance. An imbalance is a phase that did not run: run it, never edit a count | `qa` |

Then `contract_check.py` and `expert_audit.py <out>` must both exit `0`.

When `evidence_integrity.required` is true, supply the explicit evidence root
and owned local Git repository to the expert audit, just as for rendering:

```sh
python3 scripts/expert_audit.py <out> --evidence-root <out> --evidence-repository <owned-repo>
# Add --no-pdf only when the PDF was intentionally skipped.
```

The audit checks artifact bytes and source/commit correspondence afresh and
passes that in-memory result into the gates. Missing roots or failed checks
hold required-integrity runs. A saved receipt or a previously completed journal
cannot replace the fresh check; never turn off the policy to pass the audit.

## Envelope

```
workers = 1 preflight + E extra-engine preflights + 2 recon
        + 3 × U discovery (U review units) + V variant (one per High/Medium root cause)
        + 1 omission + C conditions + C falsification (C findings; batch at most 5 per worker)
        + K × H skeptics (K = 2 or 3, H High/Medium findings) + 2 raters
        + 3 personas + 1 QA + retries
```

Present the computed number and a ceiling with headroom for retries and for
findings that E3/E4 add. The ceiling is the consent; spawns beyond it hold the
assessment (`spawns_over_ceiling`).

## Spawn discipline

- The prompt carries the task, the read-only rules from *Always / Never*, the
  exact output shape and a length budget, and only role-appropriate context:
  discovery gets its unit and the recon map; verifiers and skeptics get the
  finding and its evidence; raters get the finding without its severity;
  personas get the rendered report only
- Ask every worker to return file:line evidence for each claim; a return
  without locations is re-run, not paraphrased into a finding
- Keep each worker's return to one line per candidate (location, the missing
  control, parameter names, suggested severity, CWE), with longer working notes
  in scratch. A worker whose write is refused saves what it has, reports which
  candidates were not recorded, and stops; the orchestrator records that gap in
  `limitations` instead of re-briefing the same content
- Spend the high-reasoning tier (`reference/engine-map.md`) on verifiers,
  skeptics, raters and QA — the steps whose output is the judgment
- The orchestrator may consolidate, re-read and resolve; it never supplies a
  skeptic verdict, a rating or the QA result itself

## Calibration anchors

Raters receive exactly these nine cases and the severity table, nothing else,
and return one severity per anchor. The key is held in `scripts/expert.py`; a
rater passes when every anchor is scored, at most one differs, and none by two
levels. A failed rater is replaced, never coached on the key.

| Anchor | Case |
|---|---|
| A1 | `GET /api/invoices/{id}` needs no session and returns any tenant's invoice, including billing address and amounts |
| A2 | A signed-in user can change another user's display name through `PATCH /users/{id}`; no other field is writable |
| A3 | A comment body is stored unescaped and rendered to other signed-in users who open the thread; cookies are HttpOnly and there is no CSP |
| A4 | Application responses lack HSTS and `X-Content-Type-Options`; the load balancer redirects HTTP to HTTPS |
| A5 | A public search parameter is concatenated into a SQL `WHERE` clause on the main database |
| A6 | An admin-only CSV export writes user-supplied names without neutralising spreadsheet formulas |
| A7 | Password-reset tokens are written to the application log only when `DEBUG=true`; production config sets it false and log access is limited to operators |
| A8 | The internet-facing application runs a framework major version whose vendor security support has ended |
| A9 | A response header discloses the web server's product name without a version |

## Record schema

```json
"expert": {
  "version": 1, "mode": "full", "host": "claude-code",
  "consent": {"ceiling": 80, "engines": ["claude-code"], "data_boundary": "current host only", "record": "run/gate.md"},
  "preflight": [{"engine": "claude-code", "exit": 0, "record": "run/gate.md"}],
  "spawns": [{"id": "S-01", "actor": "recon-a", "role": "recon", "engine": "claude-code",
              "prompt": "run/spawns/S-01.prompt.md", "return": "run/spawns/S-01.return.md"}],
  "recon": [{"actor": "recon-a", "routes": 140}, {"actor": "recon-b", "routes": 133}],
  "reconciliation": {"routes": 142, "disagreements": 9, "resolved": 9},
  "discovery": [{"actor": "disc-a-entry", "angle": "entry-first", "cells": ["members-tenant"],
                 "candidates": ["F-003"], "raw_candidates": 4}],
  "variants": [{"actor": "variant-1", "findings": ["F-003"], "pattern": "…", "search": "…", "hits": 1,
                "dispositions": [{"location": "path:line", "result": "safe", "reason": "…"}]}],
  "omission": [{"actor": "omission-1", "added": [], "reason": "…"}],
  "panels": [{"finding": "F-003", "skeptics": [{"actor": "sk-1", "angle": "defense-exists",
              "result": "survived", "reason": "…", "evidence_ids": ["SRC-004"]}], "resolution": ""}],
  "calibration": [{"rater": "rater-1", "scores": {"A1": "High", "…": "…"}}],
  "ratings": [{"finding": "F-003", "rater": "rater-1", "severity": "High", "reason": "…"}],
  "severity_resolutions": [{"finding": "F-007", "reason": "…"}],
  "reception": [{"persona": "engineer", "actor": "persona-eng", "stop_span": "…", "disposition": "…"}],
  "qa": {"actor": "qa-1", "result": "pass"}
}
```

Roles are `recon`, `discovery`, `variant`, `conditions`, `falsification`,
`skeptic`, `rater`, `omission`, `persona` and `qa`. Engines named in spawns must
be approved and preflighted. Actor identities are compared after NFKC
normalization, removal of invisible characters, collapsing whitespace runs to
one space and case folding, consistently with the sequential workflow
(`Ann Lee` and `AnnLee` stay two identities).
Conditions and falsification actors in the effective workflow round, including
its recorded reviewers, must have the corresponding registered spawn roles.
QA must not appear in any other declared role or recorded workflow participation,
including retained historical rounds and coordinator/decision events. Reception
requires three distinct actors, one for each persona.

Each finding has at most one refutation panel, with two or three distinct,
registered independent skeptics and distinct angles. Duplicate panel entries,
actor rows or angles are schema errors, not additional votes. Only legitimate
members contribute votes. Skeptic evidence IDs use the shared evidence rules:
known, unique and pinned to the assessed revision; `refuted` and `survived`
require evidence, while `unproven` may have none. Required integrity applies to
panel evidence too.

The rendered report carries an *Assessment method
and assurance* section derived from these records, and each finding's CWE.
That section reports declaration-record gates only; it does not establish that
the final run-file audit passed. Missing prompts, returns or reception spans can
still hold `expert_audit.py` even when the report's declaration gates are complete.
Apply the expert-grade label only after that final audit exits `0`.

## What it does not prove

The audit recomputes declared records and opens the files they name. It cannot
tell a real worker from a written file, prove that labels are independent
minds, or show that a quiet panel was a diligent one. Same-engine workers share
priors; a single-engine run prints so. More workers raise the cost of a missed
or inflated finding; they do not produce a detection rate or a guarantee that
nothing was missed, and the report never claims one.
