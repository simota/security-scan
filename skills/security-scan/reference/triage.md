# Triage decisions: accept, assign, mark fixed, carry forward

**Read when:** the requester decides what happens to a finding after the
report: accepts a risk, assigns an owner or ticket, records that a fix landed,
reopens a finding, asks which decisions are overdue, or wants decisions from an
earlier assessment kept on a rescan.

Triage happens after the assessment is complete. It records the requester's
decisions; it never changes a verdict, confidence, evidence or the derived
verification and retest state. Ruled-out findings (`FalsePositive`,
`NotApplicable`) are not triaged: their validation decides them.

## The record

`scripts/triage.py` writes a finding's `status` together with a `triage` object:

```json
"status": "Accepted",
"triage": {
  "status": "Accepted",
  "reason": "Reachable only from the admin VPN; tracked for the Q1 auth rewrite",
  "owner": "payments-team",
  "decided": "2026-11-01",
  "review_by": "2027-01-31",
  "ticket": "https://tracker.example.com/SEC-12",
  "carried_from": {"baseline_id": "F-003", "date": "2026-10-06", "project": "…"},
  "history": [{"status": "Open", "decided": "2026-10-20", "owner": "payments-team"}]
}
```

| Decision | Requires |
|---|---|
| `Accepted` (risk acceptance) | `reason` and `review_by`, a date on or after `decided` |
| `Fixed` | `reason`: the change that fixed it (commit, pull request) |
| `Open` after `Fixed` or `Accepted` | `reason` for reopening |
| Assignment (no status change) | an `owner` or `ticket` that differs from the current one |

`triage.status` must equal the finding's `status`, so a fragment that changes
`status` alone is refused once a decision exists. Fragments cannot write
`triage` at all (`scripts/findings.py`). `owner` and `ticket` carry over to
the next decision unless replaced (an empty value clears them); the replaced
decision moves to `history`. `ticket` is an http(s) link without credentials
or token parameters. Text with a literal attack string or a secret-looking
value is refused, as for every other report field.

## Commands

```
python3 scripts/triage.py set <out>/findings.json F-003 --status Accepted \
  --reason "…" --review-by 2027-01-31 --owner payments-team --ticket https://…
python3 scripts/triage.py set <out>/findings.json F-001 F-002 --owner alice      # bulk assignment
python3 scripts/triage.py set <out>/findings.json F-002 --status Fixed --reason "PR 41 scopes the query"
python3 scripts/triage.py apply <out>/findings.json <scratch>/decisions.json
python3 scripts/triage.py summary <out>/findings.json [--markdown <scratch>/status.md] [--fail-on-overdue]
python3 scripts/triage.py carry <baseline-out> <current-out> [--dry-run] [--json <scratch>/carry.json]
```

`--date` sets the decision date (default today, UTC); `--as-of` sets the date
that decides expiry for `carry` and `summary`. Every decision in one call is
checked first: one refused decision writes nothing. Writes use the same writer
lock and atomic replace as `findings.py`; re-render afterwards
(`scan_run.py render <run>` or `render.py`) so the stamped reports show the
new state, then run `contract_check.py` as usual.

A decisions file is `{"decisions": [{"id", "status", "reason", "owner",
"review_by", "ticket"}, …]}` with only the keys a decision needs.

## Rescans

`carry` matches findings the way `scripts/compare.py` does (file, weakness
class, line proximity and title; package and advisory for `D-*`) and, for each
match, records in the later run:

| Baseline decision | Carried? |
|---|---|
| `Accepted`, review date not passed, severity not raised | Yes, unchanged, with `carried_from` naming the baseline finding |
| `Accepted`, review date passed | No: needs a new decision (owner and ticket are kept on the open finding) |
| `Accepted`, severity now higher | No: the accepted risk changed |
| `Accepted` without a recorded reason or review date | No: record the decision first |
| `Fixed`, reported again | No: a regressed fix stays Open (owner and ticket are kept) |
| `Open` with an owner or ticket | The assignment |

A finding that already has a decision or a non-`Open` status in the later run
keeps it. `carry` runs only after both runs are complete; it is not an input to
the assessment (*Run contract*, Independence). `deps_scan.py --into` keeps a
`D-*` finding's decision when it re-inventories the same package, version and
advisory.

## Expiry and gates

An acceptance whose `review_by` has passed counts as open again:

- `compare.py --fail-on` blocks on it at its severity, whether it is still
  recorded `Accepted` in the current run or the baseline acceptance expired and
  the rescan reports it `Open` (`--as-of` sets the date)
- `export.py sarif` emits it without a suppression, with
  `acceptanceExpired: true` (`--as-of` sets the date)
- the dashboard marks the review date as passed when it is viewed
- `triage.py summary --fail-on-overdue` exits 1 for CI or a scheduled check

## What the summary reports

Included findings by status and severity, open High/Medium without an owner,
acceptances past their review date, acceptances due within `--due-within` days
(default 30), `Accepted` records without a reason or review date, open work per
owner, and recorded `Fixed` findings with whether a retest verified them. A
recorded `Fixed` remains a claim until a retest record verifies it
(`reference/fix-verification.md`).
