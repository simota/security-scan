# Recon — the attack-surface map

**Read when:** RECON, before any finding is written. Nothing in later phases is
trustworthy until this map exists, because a handler cannot be judged without
knowing who can reach it.

The map is a working artifact. Keep it in the conversation or a scratch file;
it is not part of the final report unless asked.

## 1. Stack and versions

- Language runtime, framework, ORM, database, front-end framework, with versions
  from lockfiles (`composer.lock`, `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`,
  `Gemfile.lock`, `poetry.lock`/`requirements*.txt`, `go.sum`, `pom.xml`/`build.gradle`,
  `Cargo.lock`)
- End-of-life status of the runtime and framework. An unsupported framework is a
  finding on its own: fixes for newly found flaws no longer ship

## 2. Entry points

Everything that accepts input from outside the process:

- HTTP routes — **all** route files, including API, web, admin, and versioned groups
- Server-side actions or RPC that the framework exposes implicitly
- Webhooks and callbacks from third parties
- Queue consumers, scheduled jobs and CLI commands that read external data
- WebSocket channels, GraphQL resolvers, file watchers
- Every **version and host** of the API (`/v1` and `/v2`, a mobile or partner
  API, an internal admin host), plus docs, monitoring, debug and test routes.
  A version kept alive for old clients often lacks guards added later
- Routes declared **outside the application code**: infrastructure-as-code,
  serverless function definitions, API gateway or reverse-proxy route and
  rewrite config (e.g. an OpenAPI file with gateway extensions, a serverless
  manifest, an ingress resource). Each declared route is a row; a route the
  gateway exposes that the application treats as internal is a lead
- **Event-driven consumers**: message-queue, stream, storage-event and
  scheduled triggers wired in IaC or serverless config, not only in code

## 3. Route inventory

One row per entry point: every route, and every queue consumer or scheduled
job, import format and channel message type from §2 (for those, *Method* is
`job`, `import` or `message` and *Path* is the job, format or message name).
The columns are what make the later review mechanical:

| Method | Path | Authn | Role guard | Handler | Record-naming inputs | Notes |
|---|---|---|---|---|---|---|

Build it from the route registrations themselves (search every routing call or
decorator), then reconcile it against every other list of the surface: API
description files (OpenAPI, GraphQL schema), client code (front end, mobile),
tests, feature flags, the previous API version, and gateway, proxy and IaC
route config. A route in one list and not another is a row to resolve, not to
drop: registered but absent from client and docs (forgotten, debug, legacy or
test), exposed by the gateway while the app treats it as internal, or an old
version still registered after a newer one added a guard. *Authn* and *Role
guard* name the check and where the route inherits it (route group, base
controller, decorator, or a gateway/IaC authorizer — e.g. a gateway JWT
authorizer, a serverless function's auth setting) with `path:line`. A
gateway/IaC authorizer counts as an inherited check only for the routes that
config actually binds it to, and only when the app is not also reachable
around the gateway (a public load balancer, a function URL, another ingress);
when that cannot be read from the repo, the cell is `UNKNOWN`. *Record-naming inputs* lists every parameter that
names a record, file or tenant (path, query, body, nested IDs, job payload
fields, import columns, message fields); each becomes an
object-reference trace row (`reference/invariants.md` §3a) and is the count the
close-check uses.

Then flag:

- **Unauthenticated routes** — login, token or magic-link login, password reset,
  signup, impersonation, health, webhooks
- **Routes reachable by more than one role** — the handler must branch on role
  and on tenant; this is where cross-tenant bugs live
- **Guards that differ between layers** — a page route behind an IP allowlist
  while the API that feeds it is not; a UI that hides a button while the API
  accepts the call
- **Admin capabilities** — impersonation ("login as"), bulk operations, exports

## 4. Identity

- How a session or token is issued, for each login path
- Where role and tenant are stored on the user, and how they are compared
  (strict vs loose comparison, enum vs raw value)
- Whether every login path enforces the same role check. A secondary login path
  (magic link, SSO, impersonation) that skips the role check is a common gap
- Session and token lifetime, rotation on login and privilege change, revocation
  on logout, password change and account removal

## 5. Tenancy model

- What a tenant is (company, account, organization, workspace)
- The isolation mechanism: default/global scope, policy or permission classes,
  per-handler checks, a scoped base query, row-level security, separate databases
- **Coverage table**: every model holding tenant data, and whether the mechanism
  applies to it. Models outside the mechanism depend entirely on each handler
- **Bypass list**: raw query builders, scope-removal calls, joins and eager loads
  into unscoped models, background jobs running without a user context

**Several services.** When the repo holds more than one deployable service,
build one inventory per service and record for each: how it authenticates calls
from other services (mTLS, a signed service token, a shared secret, network
position only), whether it re-derives the end user and tenant or trusts a
forwarded header or claim, and its own tenancy mechanism (§5 per service). An
internal endpoint that trusts a forwarded user or tenant ID is reachable by
anything that can reach the service; network position alone is `UNKNOWN`, not
a control.

## 6. Data sinks

Where input can change meaning: raw SQL fragments, ORDER BY and column names,
shell execution, filesystem paths, HTML rendered without escaping (server
templates, SPA raw-HTML bindings, emails), URL attributes bound from data,
outbound HTTP to user-influenced URLs, HTML-to-PDF renderers, deserializers,
XML parsers, log statements, deep merges of request objects, spreadsheet
exports, prompts sent to model APIs, model tool/function dispatch and
vector-store queries.

## 7. Files

Upload endpoints, validation of type, size and content, storage location and
ACL, whether stored files are served from the application's own origin or a CDN
domain, filenames in download headers.

## 8. Config and infrastructure in the repo

Debug flags, error display, CORS, cookie flags, CSRF configuration and
exclusions, trusted proxies and how the client IP is derived, rate-limiter keys,
security headers in server config, committed env files and keys, CI/CD workflow
secret handling, deployment artifacts.

## 9. Dependencies

Run `scripts/deps_scan.py <repo> --out <out>/deps.json` for the inventory; the
advisory audit is `deps_scan.py --audit` at the end of REVIEW
(`reference/dependencies.md`). Do not run ecosystem audit tools such as
`cargo audit`, `bundle audit` or `npm audit` against the checkout yourself:
`deps_scan.py` runs only the ones it can isolate and records the rest in
`not_run`. The audit needs network access to vulnerability databases; if that
is unavailable, record the versions and say the audit was not run.

## 10. Rules the app enforces — input to the invariant ledger

Record what the later invariant hunt needs (`reference/invariants.md`):

- **Role matrix** — one row per role (including anonymous and each tenant-side
  role), one column per sensitive action (read, create, change, delete, export,
  invite, change role, impersonate, approve, refund…). Fill each cell from the
  declared guards and policies with `path:line`; a blank cell is a question
- **Ownership chain** — for each tenant-data model, the field or relation that
  ties it to its owner or tenant, including children reached through a parent
- **State machines** — every status/stage field, its allowed transitions, who
  may make each one and where that is checked
- **Quantities** — every price, total, balance, quota, limit, counter and
  discount: where it is computed, stored and decremented
- **Identifiers** — how IDs are generated (sequential, random) and where they
  are exposed to other actors (shared links, exports, emails, errors)
