# Invariants — derive this app's rules, then hunt their violations

**Read when:** end of RECON (derive the ledger), CHECKLIST (deliver it), REVIEW
(hunt each entry), REPORT (write reproduction steps). **Reader:** the agent
running the skill, cold. **Decision it supports:** which paths to read and what
counts as a violation in *this* application. As of 2026-10-07 · owner:
security-scan maintainers · review trigger: a missed finding that no ledger
entry would have predicted.

The findings that pattern-based tools miss are violations of rules that exist
only in this application: *an invoice belongs to one company*, *only an owner
can invite*, *an order cannot be refunded twice*, *a coupon applies once per
account*. No default rule knows them, so they must be written down before the
code is judged. This file is how: derive the rules (§1–§2), hunt every path that
touches each one (§3–§4), then use the perspectives as a coverage check (§6).

## 1. Derive invariants from where the app already states them

An invariant is a sentence that must stay true for every actor, on every entry
point, in every order of calls. Derive it from evidence in the repository, not
from what a typical app does. Sources, strongest first:

1. **Data model** — foreign keys to an owner or tenant, unique constraints,
   check constraints, enum columns, nullable vs required, soft-delete flags
2. **Declared authorization** — policy/permission classes, role enums, guard or
   middleware lists, row-level-security policies, scope definitions
3. **The majority of handlers** — if nine handlers filter by the caller's tenant
   and one does not, the nine state the rule and the one breaks it
4. **Tests and fixtures** — tests named "cannot", "forbidden", "only", "limit"
   state intended rules; seeded roles show the real role set
5. **Front end** — disabled buttons, hidden menu items, client-side validation
   and step wizards show the rule the server is supposed to enforce too
6. **Docs, comments, product copy** — pricing pages, plan limits, README
   statements of who can do what

Write each invariant with its source (`path:line`). An invariant inferred only
from sources 3–6 is marked `inferred`; if a violation of it would be a finding,
add the rule itself to `decisions` so a person can confirm the intent.

## 2. The seven families and the ledger

Derive at least one entry per family that the app has; a family the app lacks
is written `N/A` with the reason (no money, single-tenant, no workflow).

**Seed with baselines.** Before deriving, add each applicable family's *Typical
statement* below as a `baseline` entry (*Source*: `baseline`), filled in with
this app's nouns. A baseline is a hunt target, not a claim about the app: it is
hunted on every path like any entry, and becomes a finding only with code
evidence of a violation. When §1 sources show the app's actual rule, rewrite
the entry to it and replace `baseline` with that `path:line`; a baseline the app
deliberately does not follow goes to `decisions`, not to findings.

| Family | Typical statement | Derive it from |
|---|---|---|
| **OWN** ownership and tenancy | "A `<record>` is read or changed only by members of its owning `<tenant>`" | owner/tenant foreign keys; the tenancy coverage table in `reference/recon.md` §5 |
| **ROLE** role and function matrix | "Only `<role>` may `<action>`; `<role>` cannot grant a role above its own" | role enum, guards, the role matrix in `reference/recon.md` §10 |
| **PROP** property-level rules | "Callers set only `<fields>`; `<fields>` are never returned to `<actor>`" | input binding / allow-lists, serializers, hidden-field lists |
| **STATE** state machines and workflows | "`<entity>` moves only along `<transitions>`; step B requires step A by the same actor; in `<state>`, `<fields>` and `<child records>` are frozen; deleted or archived `<entity>` is visible only to `<actor>`" | status enums, transition functions, wizard steps, soft-delete and archive flags, per-state edit guards |
| **QTY** money, limits and counters | "`<amount>` is computed server-side, non-negative and charged once; `<quota>` cannot be exceeded" | price/total computation, plan limits, coupons, balances, rate and quota counters |
| **ID** identity lifecycle | "Every way of signing in applies the same checks; a credential change ends other sessions" | login paths, reset/verify flows, token issue and revocation (`reference/recon.md` §4) |
| **TRUST** trust boundaries | "Data from `<source>` never becomes code, query structure, a path, a URL or markup without `<control>`" | data sinks (`reference/recon.md` §6), inbound integrations |

Keep the ledger in scratch (`SKILL.md`, *Run contract*). It holds one row per
invariant; its per-path cells live in the path trace (§3a), not here:

| ID | Family | Invariant | Source (`path:line` or `baseline`) | Paths (trace rows) | Status |
|---|---|---|---|---|---|
| INV-01 | OWN | `<record>` belongs to one `<tenant>` | `<model file:line>` | 12 (§3a rows citing INV-01) | holds on 11/12 — see F-00x |

`Status` is one of `holds on all N paths`, `violated (F-…)`, `holds on N/M,
rest not read`, `not checked (reason)` or, for a family the app lacks,
`N/A (reason)` (`not_applicable` in `invariant_ledger`). A ledger entry whose paths were not
all read is never reported as holding.

**Cells take five values, nothing else** — in the path trace (§3a) and the
perspective steps. (The ledger `Status` column has its own
five values, above.)

| Value | Means | Required with it |
|---|---|---|
| `path:line` | The control exists here, read at the assessed revision | The line read, not the file it is expected in |
| `NONE` | Looked for it; it is absent | How it was looked for: the search, or the call chain read |
| `N/A` | Does not apply to this row | One-line reason |
| `UNKNOWN` | Cannot be settled from the repository | What would settle it (a deployed setting, a person, runtime) |
| `ASSUMED` | A check exists but does not dominate the fetch on every branch of this path, or is borrowed from a sibling, caller or callee that this path does not run through | The branch or caller that lacks it. Counted as `NONE` by the close-check (§3b) and handed to the hunt |

**Name the enforcing check.** *Enforcing check* (§3a) holds the check that actually runs
on the path — written in the handler, or **inherited**: a base class or parent
controller, a middleware or route group, a model manager or default/global
scope, a decorator or annotation, a database policy. Give the `path:line` of
the check itself, and of where this path picks it up (the registration, the
`extends`, the decorator line). Not allowed in a cell: "framework handles it",
"probably", "see middleware", "same as above". A framework default counts only
with the `path:line` of the setting or lockfile version that turns it on for
this path. Every `NONE` in a control column is a candidate: it ends as a finding
or as a `FalsePositive` reason naming the control found elsewhere on the same
path.

## 3. Hunt: every path that touches an invariant

For each ledger entry, list **every** path that reads or writes the protected
data, then check each one. Static review is complete per invariant, not per
file. A path is every entry point in the recon inventory (`reference/recon.md`
§2–§3): routes, queue consumers and scheduled jobs, import formats, channel
message types — not routes alone. Paths are easy to miss; look for all of these:

- Primary routes, and their siblings: list vs detail vs export vs search vs
  count; create vs update vs bulk; single vs batch endpoints; old API versions
  still registered; GraphQL resolvers and nested fields; RPC/server actions
- Non-HTTP writers: queue consumers, scheduled jobs, imports, webhooks, CLI and
  admin tools, cache warmers, report generators, email/notification renderers
- Indirect readers: eager-loaded relations, includes/expands chosen by the
  client, aggregate and statistics queries, file and attachment downloads by
  key, presigned-URL issuers, search indexes
- For STATE entries, per state: every writer of the fields and child records
  that state freezes (not only the status writers), and every reader that must
  hide deleted or archived records (lists, search, exports, counts, restores)

**Walk to the query.** For each path, follow the handler through every callee
(service, repository, helper, model method) down to the statement that fetches
or writes the record, and stop there or at the framework or library boundary
(an ORM call, a driver, a framework helper) — do not read library internals;
a library's behaviour counts only with the `path:line` of the config or locked
version that sets it. Cite the walk as a chain in the *Fetch* cell:
`handler path:line → service path:line → repository path:line`. A check counts for this path only if it **dominates**
that statement — runs before it on every branch, including early returns,
error paths and the alternative arms of a conditional. A check that holds on
some branches only, or that runs in a sibling route, a caller this path does
not come through, or a callee this path does not reach, is `ASSUMED`, not
`path:line`.

Then apply the comparison that reveals each family's violations:

| Family | Hunt question per path | Violation shape | Sound when |
|---|---|---|---|
| OWN | Where does the record identifier come from, and is it resolved inside the caller's tenant/owner before use? | Lookup by bare ID from path, body, header or nested object; a child fetched under a parent the caller owns but the child's own parent not checked | The query itself is constrained by the caller's owner/tenant (scope, policy, RLS), or the loaded record's owner is compared to the caller before any read or write — on this path, not a sibling |
| ROLE | Which guard runs on this path, and does it match the matrix row — for the current role, not the one held at sign-in? | Guard on the page but not the API; on the list but not the action; role read from client input; role changes not limited to roles below the actor's; role or tenant read from a session or token snapshot that survives demotion, removal or suspension | The guard is attached to the route or handler itself and compares against a server-held role read fresh (or invalidated when it changes) |
| PROP | Which fields are bound from input, and which are serialized out? | Whole-body binding that includes owner, role, price, status or verified flags; responses that include hidden fields through relations | An allow-list per actor for writes; an explicit output shape that excludes the field on every serializer path |
| STATE | Can this transition be called from any state, by any actor, or twice? Does this writer change a field or child frozen in the record's current state? Does this reader show a deleted or archived record? | Missing "from" state check; step 3 callable without step 2; approval by the requester; cancel after fulfilment; line items edited on a submitted order; a deleted record returned by search or export | Transition checks current state and actor inside the same atomic update; every frozen-field and child writer checks the parent's state; every reader applies the same visibility filter |
| QTY | Where is the amount or count computed, and is check-then-act atomic? | Client-supplied price/total/quantity/discount; negative or zero values accepted; read-check-write without a lock or conditional update (double spend, coupon reuse, quota overrun); integer/decimal overflow or rounding | Server recomputes from trusted data; constraints reject out-of-range values; the check and the update are one atomic operation or guarded by a unique constraint/idempotency key |
| ID | Does this sign-in, recovery or token path apply every check the main login does? Does a capability token (share link, invite, API key) stay within its scope and die when revoked? | Secondary login (magic link, SSO, impersonation, API token) skips role, verification or tenant checks; tokens not bound to purpose or user; sessions survive password change, suspension or removal; a link or key grants more than its scope or works after revocation | The same check function runs on every path; tokens are single-use, expiring and bound to user and purpose; scope is checked on each use and revocation is looked up, not cached |
| TRUST | Does input reach the sink as data or as structure? | Concatenated query, command, template, path, URL or markup; deserializer of untrusted bytes; redirect to a supplied URL | Parameterized APIs, allow-listed values for structural positions, canonicalized paths under a fixed root, an allow-list for outbound hosts |

**PROP: write against read.** List the model's fields, then the fields each
write path accepts (create, update, bulk, import, admin). A field accepted on
write that is never returned, or shown read-only in the UI (role, tenant or
owner ID, price, status, verified flag, quota), is a mass-assignment lead;
validation present on create but missing on update, import or the admin path is
another; so is a field hidden by one serializer of the model and returned by
another (list vs detail, own vs other's, export vs API).

"Enforced on N of M paths" is the signal: the M−N paths are candidate findings.
Read each one end to end before recording it (`SKILL.md`, *Always / Never*).
When **no** path has the control (no route checks tenancy, no upload checks
type), comparison shows nothing: a uniformly absent control the invariant
requires is a finding in its own right.

**Sink-backward pass.** The forward hunt starts from the inventory, so it
cannot see a path the inventory missed. After it, for every protected model
(each model named by an OWN, PROP, STATE or QTY entry), search every statement
that reads or writes it: ORM or query-builder calls on the model, raw queries
naming its table, repository methods, cache, search-index and file-store
writes. Follow each statement's callers up to an entry point; every statement
must map to an inventory row. An unmapped statement is a recon gap: find its
entry point (an unregistered route, a job, a CLI command, a consumer), add the
inventory row and its §3a rows, and hunt it; a statement with no caller is
recorded as unreachable in `checked_ok`. Record the search per model.

### 3a. Path trace — one table for every ledger path and record-naming input

One row per path that touches a ledger entry (entry point × entry), and one
row per entry-point input that names a record, file or tenant (recon
inventory, *Record-naming inputs*) — route parameters, and also IDs carried in
job payloads, import rows and channel messages. For those, the *Enforcing
check* is the one that runs **in the worker** when it loads the record; a check
at enqueue time is `ASSUMED` unless the payload cannot be produced any other
way. This is where cross-tenant and IDOR findings are found; an input or a
ledger path with no row is unreviewed.

| INV | Entry point | Input (name, where it arrives) | Fetch or write (chain to the statement) | Enforcing check (`path:line`, inherited from) | Before any use? | Same on write/delete? | Contrast sibling (`path:line`) |
|---|---|---|---|---|---|---|---|
| INV-01 | `GET /projects/{projectId}/files/{fileId}` | `fileId`, path | `src/files/handler:41 → src/files/service:88 → src/files/repository:23`, by `fileId` alone | `ASSUMED` — `src/projects/policy:12` (inherited from the `/projects/{projectId}` route group) checks the caller's membership of `projectId`, but the file's own project is never compared to `projectId` | No (`NONE` on the file) | `NONE`: `DELETE` reaches the same repository call, `src/files/service:120` | `GET /projects/{projectId}/files` filters by project at `src/files/repository:9` |

- *INV*: the ledger entry the row tests; an input row cites the OWN or ID entry
  for that record. A path that touches no record-naming input (a QTY amount, a
  STATE transition) still gets a row, with *Input* naming the field it concerns
- *Fetch or write*: the walk chain from the handler to the statement (§3)
- *Enforcing check*: the expression or policy call that ties the record to the
  session, dominating the fetch (§3). "The route is authenticated" is not an
  ownership check. The example row is `ASSUMED` because the dominating check
  guards the parent, not the record fetched
- *Before any use?*: before any read, write, side effect or response —
  including an error that confirms the record exists
- On create, attach, move or share, every other ID in the body gets its own row
- *Contrast sibling*: the sibling path (detail vs export, v1 vs v2, HTTP vs
  job) whose check this row is compared with; it becomes the finding's
  `Contrast:` line (§5)

### 3b. Close-check — numbers, before a unit is done

Answer each with a number; a mismatch keeps the unit open.

1. Entry points in the unit (routes, jobs and consumers, import formats,
   channel message types, from the recon inventory) = entry points with every
   ledger entry they touch marked read?
2. Record-naming inputs in the unit's entry points = input rows in §3a? List
   the missing
3. Ledger entries owned by the unit (`baseline` ones included) = entries with a
   `Status`; for each, its *Paths* count = §3a rows citing it?
4. Blank cells in the ledger and §3a = 0?
5. `NONE` and `ASSUMED` cells: each has an `F-…` or a recorded
   `FalsePositive` reason naming the dominating check found?
6. `UNKNOWN` cells: each is an environment-dependent finding, a `decisions`
   entry or a `limitations` entry?
7. Statements on the unit's protected models found by the sink-backward pass
   = statements mapped to an inventory row? Give the count of rows the pass
   added

With the `invariant_ledger` opt-in, each unit's numbers for item 2 and item 4
go into `units` (`record_inputs`, `trace_rows` = the input rows of §3a,
`blank_cells`); mark a unit
`closed: true` only when they match — the validator rejects a closed unit
that does not (`reference/findings-schema.md`).

With reviewer subagents, the reviewer returns its ledger rows, §3a rows and
these numbers; the orchestrating agent re-counts items 2, 4 and 7 itself before
accepting the unit, and sends a failing unit back with the missing rows named.
Do not stop a unit at its first finding.

### 3c. Variants of every confirmed finding

After a finding reaches `Likely` or `Valid`, write its root cause as a pattern
in plain words ("record loaded by id from the path without the tenant
constraint"), search the whole repository with at least two searches (the
literal call shape and other ways to load the same kind of record), and give
every hit a disposition: same fix location (add the route to that finding's
`request`), new finding, or safe with the reason. Record the hit count in
`checked_ok` ("variants of F-003: 14 hits, 2 new findings, 12 safe").

## 4. Chains: violations that only matter together

Some essential findings are two weak facts that combine. After the per-path
hunt, check these pairings against the ledger:

| Link A | Link B | Combined effect | Fix location (the finding) |
|---|---|---|---|
| Identifier leak: sequential IDs, IDs in a shared link, errors or exports | OWN path that trusts the bare ID | Cross-tenant read or write | The OWN path |
| Self-signup or invitation | PROP path accepting a role or tenant field | Privilege or tenant escalation | The PROP binding |
| STATE step reachable out of order | QTY rule enforced only in the skipped step | Limit or price bypass | The transition guard |
| Redirect or callback URL accepted from input | Token sent to that URL (ID) | Token theft | The URL allow-list |
| Webhook or import without sender authentication | Privileged write it triggers | Anonymous privileged write | Sender authentication |
| Removal, demotion or suspension | Session, token or cached role that is not invalidated | Former member keeps access | Invalidation on the change |

Record the chain under the root cause that a fix would remove (one finding per
fix location, *Run contract*). Name the other link and its finding ID in
`impact`; grade severity for the chain only if every link is supported.

## 5. Static reproduction steps for every finding

Each `F-*` finding must let the reader reproduce it against their own local
copy and fix it, without a payload. Write the steps into the existing fields —
no schema change:

| Field | Holds |
|---|---|
| `actor` | Who, with which role and tenant |
| `request` | `Preconditions:` numbered steps that create the state that must exist first (a record owned by another tenant, a plan, a status). `Steps:` numbered; each is method + path + parameter names, with placeholders for values (`<other tenant's invoice id>`, `<any positive integer>`); for non-HTTP paths, the job, command or message type and its fields. `Contrast:` the sibling path that enforces the invariant, with `path:line` (from §3a), or `none — uniformly absent` |
| `impact` | **Expected** first, then **actual**, using those words (`期待` … `実際` in Japanese): expected is what the invariant requires (ideally what the contrast path does: 403/404, rejection, unchanged state); actual is what the code at `location` does instead, citing the chain handler → service → query `path:line`; then the bounded impact against the crown jewels. Name the violated ledger entry, e.g. `violates INV-01` |
| `fix` | First line: the remediation as the invariant restored, in one sentence, with where the check belongs ("apply the check used at `<contrast path:line>`"). Then `Test:` at least one regression-test assertion stated as the secure outcome (`<actor> requesting <placeholder> receives not-found and no data`), red on the current code and green after the fix |
| `cwe` | The closest CWE (`CWE-<n>`), from the step's *Catalog* in `reference/perspectives.md` or `reference/coverage-trace.md` |

Example shape (placeholders, not a payload):

```
actor:   signed-in member of tenant A, no admin role
request: Preconditions: 1. tenant B has at least one invoice
         Steps: 1. GET /api/invoices — note the id format
                2. GET /api/invoices/<invoice id belonging to tenant B>/pdf
         Contrast: GET /api/invoices/<id> applies the tenant scope at
                <detail handler path:line>
impact:  expected 404, as the detail route returns (INV-01: invoices are read
         only within the owner's tenant); actual 200 with tenant B's invoice
         PDF — <pdf handler path:line> loads by id without that scope
fix:     Invoices are loaded only inside the caller's tenant: apply the
         scope used at <detail handler path:line> to the pdf handler.
         Test: a member of tenant A requesting tenant B's invoice pdf
         receives not-found and no file bytes
```

A Japanese report may write the markers as `前提条件：`, `手順：`, `対比：` and
`テスト：` (ASCII `:` also accepted). Never put working exploit strings, real
credentials or real customer data in steps; `scripts/findings.py merge` refuses literal attack strings.

## 6. Perspectives as the coverage check

The invariant hunt finds what the app's own rules forbid; it can miss classes
that no ledger entry names (a debug flag, a weak cipher, a missing header).
After the hunt, walk every perspective in `reference/perspectives.md` and each
of its hunt steps:

- Each step is either covered by a ledger entry (cite `INV-…`), checked now
  directly, `N/A` with a reason, or `Not checked` with what is missing
- Anything new that the sweep reveals about the app's rules goes back into the
  ledger as a new entry, and its paths are hunted like the rest
- The `perspectives` entry for each perspective records its result and, in
  `note`, the hunt step IDs applied with the ledger entries that covered them
  and each step left out with its reason (e.g. `AT1–AT4 via INV-01, INV-02;
  AT5 N/A: no attach or transfer actions`), so coverage can be checked step by
  step against `reference/coverage-trace.md`

## 7. Sound items are invariants that held

`checked_ok` lists invariants with `holds on all N paths`, with the paths read,
e.g. "INV-03 role changes limited to roles below the actor's: 3/3 paths
(`<file:line>` …)". A ledger entry that held only on the paths read says so.
