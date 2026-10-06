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

## 3. Route inventory

One row per route. The columns are what make the later review mechanical:

| Method | Path | Authn | Role guard | Handler | Notes |
|---|---|---|---|---|---|

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

## 6. Data sinks

Where input can change meaning: raw SQL fragments, ORDER BY and column names,
shell execution, filesystem paths, HTML rendered without escaping (server
templates, SPA raw-HTML bindings, emails), URL attributes bound from data,
outbound HTTP to user-influenced URLs, HTML-to-PDF renderers, deserializers,
XML parsers, log statements.

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

The audit command for each ecosystem present (`composer audit`, `npm audit` /
`yarn npm audit` / `pnpm audit`, `pip-audit`, `bundle audit`, `govulncheck`,
`cargo audit`, `osv-scanner`). They need network access to vulnerability
databases; if that is unavailable, record the versions and say the audit was not
run.
