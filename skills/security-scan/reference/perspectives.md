# Perspectives — reviewing from more than one angle

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, after the
invariant hunt (`reference/invariants.md`), as the coverage sweep; REPORT, to
fill the `perspectives` table in `findings.json`. **Reader:** the agent running
the skill. As of 2026-10-07 · owner: security-scan maintainers · review
trigger: a new edition of a standard traced in `reference/coverage-trace.md`.

The invariant ledger finds what this app's own rules forbid. The perspectives
then make sure nothing outside the ledger is skipped: apply each one within
every review unit (`SKILL.md`, *Run contract*), work through its hunt steps
below, and record every perspective in the report — including the ones that
found nothing and the ones not run.

| Perspective | The question it asks |
|---|---|
| Actor and tenant | Can each actor reach only what belongs to them, on every route? |
| Role and privilege | Can a lower role perform a higher role's action? |
| Identity and session | Is every way of becoming signed in held to the same rules, and does it end when it should? |
| Input handling | Does any client-supplied value reach a sensitive operation, or memory-unsafe code, without being constrained? |
| Data exposure | Do responses, errors, logs and exports contain more than the caller should see? |
| Business rules | Can the intended order of operations, limits or amounts be skipped or altered? |
| Files and content | Are uploaded and generated files constrained in type, size, location and how they are served? |
| Availability | Can one caller exhaust resources or lock others out? |
| Configuration and deployment | Do the settings in the repository hold in production, and does each protection sit at the layer that is actually exposed? |
| Secrets | Are credentials and keys kept out of the repository, logs and client code, and is cryptography used correctly? |
| Dependencies and platform | Are the runtime, framework and libraries supported, free of known vulnerabilities, and not malicious? (`reference/dependencies.md`) |
| Build and delivery | Can the dependency sources, CI/CD pipeline or deployed artifact be altered or leak? (`reference/dependencies.md`) |
| Integrations | Are inbound callbacks authenticated and outbound calls constrained? |
| Client side | Can stored data execute or redirect in another user's browser? |
| Privacy | Is personal data collected, kept and shown only as needed? |

Rules:

- A perspective not applicable to this application is recorded as `N/A` with a
  reason, not silently skipped
- A perspective that could not be checked statically is recorded as
  `Not checked` with what would be needed
- Every finding names the perspective that surfaced it in `category`
- A hunt step covered by an invariant ledger entry cites it (`INV-…`) in the
  perspective's `note` instead of being re-run
- The `note` lists the hunt step IDs applied and each one left out with its
  reason (e.g. `AT1–AT4 via INV-01; AT5 N/A: no attach or transfer actions`),
  so coverage can be checked step by step against `reference/coverage-trace.md`

- A step is `sound` only when its *Sound when* cell can be filled with the
  enforcing check's `path:line` on the path the actor takes — the check itself,
  or the inherited one (base class or parent controller, middleware or route
  group, model manager or default scope, decorator or annotation, database
  policy). "The framework handles it" is not evidence; a framework default
  counts only with the `path:line` of the setting or lockfile version that turns
  it on (cell vocabulary: `reference/invariants.md` §2)

## Hunt steps per perspective

Each step says **what** to hunt, **where** to look, and what evidence makes it
**sound** — with the reason that evidence suffices, so a cold reader can tell a
real control from a look-alike. Steps are stack-neutral; framework names in
parentheses are examples only. *Catalog* lists the closest CWE, ASVS 5.0
section and API Security Top 10 2023 risk; the full trace and its sources are
in `reference/coverage-trace.md`. The ASVS and API parts, and the Top 25 CWEs,
are exactly the trace rows that cite the step; other CWEs are closer children.
In a Catalog cell `—` means no entry of that catalog applies (decided);
`UNKNOWN` means no mapping has been established yet. The ledger family
(`reference/invariants.md` §2) that usually covers a perspective is in
brackets. Steps marked *(sound constructs)* have a table of sound and unsound
constructs at the end of this file.

### Actor and tenant (AT) [OWN]

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| AT1 | Object lookup by a client-supplied reference: path, query, body, header, nested or array IDs, slugs, file keys, cursors | Every handler, resolver, job and download taking a reference; one trace record per input (`reference/invariants.md` §3a) | The fetch is constrained by the caller's owner/tenant in the same query, or the loaded record's owner is compared to the session before any read, write or response — because a check on a sibling route or in the UI never runs on this request | CWE-639, CWE-862 · V5.4, V8.2, V8.4 · API1 |
| AT2 | Models outside the tenancy mechanism and calls that remove it (unscoped queries, raw SQL, scope removal, caches, search indexes, storage keys without tenant); tenant or user context held in a thread-local, global or async context set per request or job and not cleared, then reused by pooled workers, async tasks or pooled DB connections (`SET app.tenant`) | Recon tenancy coverage table and bypass list (`reference/recon.md` §5) | Each such model is reached only through a parent checked on the same path, or carries its own constraint at `path:line` — because a default scope protects only queries that go through it | CWE-862 · V8.4 · API1 |
| AT3 | Sibling asymmetry: list vs detail vs export vs search vs count vs bulk, v1 vs v2, HTTP vs job; GraphQL generic `node`/`nodes` (global ID) resolvers and nested edges that reach a type without its own authorization check | Route inventory grouped by resource; compare the enforcing checks side by side | Every sibling names the same check (or an equivalent one) at its own `path:line` — because attackers pick the weakest sibling, not the documented one | CWE-863 · V8.2 · API1, API9 |
| AT4 | Tenant or owner chosen by the client when the session also names one | Handlers reading tenant/owner/user IDs from input | The server derives them from the session, or verifies membership before use — because a client-chosen tenant ID is just another reference | CWE-639, CWE-863 · V8.2 · API1 |
| AT5 | Second object on create, attach, move, share, transfer, bulk update/delete | Body fields that name another record; the code that links them | Each referenced record gets its own ownership check — because checking the parent says nothing about the child being attached to it | CWE-639 · V8.2 · API1 |

### Role and privilege (RP) [ROLE]

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| RP1 | Function-level guard per route against the role matrix | Route and middleware groups, handler-level checks, GraphQL mutations, admin APIs; role matrix (`reference/recon.md` §10) | The guard comparing a server-held role sits on the route or handler (or a named parent it inherits from) at `path:line` — because a guard applied to the page or menu does not stop a direct call | CWE-862, CWE-285 · V8.2, V8.3, V10.3 · API5 |
| RP2 | Guard asymmetry between layers: page vs API, UI-hidden action vs endpoint, HTTP vs job or CLI | Sibling rows of the route inventory, Authn and role guard columns | The server enforces on the callable layer what the UI hides — because hiding a control is presentation, not authorization | CWE-863 · V8.3 · API5 |
| RP3 | Role assignment, invitation, impersonation, ownership transfer, API key scopes | Handlers that write role, membership or scope | The granter's level is compared to the granted one, both in one tenant — because otherwise any granter can mint a higher role | CWE-269 · V8.3 · API5 |
| RP4 | Critical functions (admin, export, internal, debug) with no authentication | Route registrations with Authn = none | Each is meant to be public and says why — because a missing authenticator has no compensating layer in the app | CWE-306 · V8.3 · API5 |
| RP5 | Guard correctness and fail-open: loose or inverted comparison, default-allow for an unknown role, parent checked while a child is acted on, check after the side effect, decision in the client; exception handlers around authorization, payment or state changes that skip the check or commit partial work | The guard functions themselves and the error handling around them | The guard denies by default, compares exact server-held values before any side effect, and its exception path denies and rolls back, at `path:line` — because a guard that is present but passes wrongly looks identical to a sound one in a route table | CWE-863, CWE-636 · V8.3, V16.5 · API5 |
| RP6 | Delegated and capability access: share links, invitations, API keys, service accounts, OAuth scopes; actors who lost access (removed or former member, demoted role, suspended account) | Token and key issue/verify code, membership removal, role change and suspension handlers | Scope is checked on each use, and removal, demotion, suspension and revocation take effect on the next request (looked up, or sessions and tokens invalidated) at `path:line` — because a role or tenant cached at sign-in outlives the change that should end it | CWE-863, CWE-613 · V8.2, V8.3, V10.3 · API1, API5 |

### Identity and session (IS) [ID]

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| IS1 | Every login path (password, magic link, SSO/OAuth/OIDC, API token, impersonation, remember-me, refresh) applies the same status, role, verification and tenant checks | `reference/recon.md` §4; one row per path | Each path calls the same check function, named at `path:line` per path — because a secondary path is where a skipped check hides | CWE-287 · V6.3, V6.5, V6.8 · API2 |
| IS2 | *(sound constructs)* Recovery and verification tokens; account-existence leaks; links in emails (reset, verify, invite, magic link) built from the request Host or a forwarded host; account lookup by email or username normalised differently at signup, login and recovery (case, Unicode NFKC, dots or plus tags) | Reset, verify, invite and signup handlers | Tokens are random, single-use, expiring and bound to user and purpose at `path:line` — because any missing property makes the token reusable or transferable | CWE-640, CWE-287 · V6.2, V6.4, V6.6 · API2 |
| IS3 | *(sound constructs)* Session lifecycle and CSRF: rotation on login and privilege change, revocation on logout, password change, suspension and removal; cookie flags; CSRF on cookie-authenticated state changes | Session issue and invalidation code; CSRF config and its exclusion list | Each event calls rotation or revocation, and CSRF protection is on with every exclusion read — because one excluded route reopens the whole class | CWE-384, CWE-613, CWE-352 · V3.3, V7.2, V7.3, V7.4, V7.5 · API2 |
| IS4 | *(sound constructs)* Self-contained tokens and federation: fixed algorithm, signature, issuer, audience, expiry; OAuth/OIDC/SAML state, PKCE, nonce, exact redirect URI, single-use assertions, identity keyed on the provider's subject, accounts never linked by an unverified email | Token verify calls, OAuth/SAML callback handlers, account-linking code, provider config in the repo | Each property is enforced in code or library config at `path:line` — because libraries often verify only what they are told to | CWE-347, CWE-287 · V6.7, V6.8, V7.6, V9.1, V9.2, V10.1, V10.2, V10.3, V10.4, V10.5, V10.6, V10.7 · API2 |
| IS5 | Guessing limits on login, MFA and recovery (with AV2) | Rate-limit config and its key | A limit keyed on account and source covers each path — because a limit on one path is bypassed through its sibling; counted per operation when one request carries many (GraphQL aliases or batches, JSON-RPC batches) | CWE-307 · V6.3, V6.6 · API2 |

### Input handling (IN) [TRUST]

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| IN1 | *(sound constructs)* Query structure from input: raw SQL/NoSQL/ORM fragments, ORDER BY and column names, filter operators, LDAP filters, XPath | Query sinks found by searching the code (`reference/recon.md` §6), traced back to callers | Every caller passes bound parameters, and structural positions are allow-listed — because one unneutralised caller makes the sink reachable | CWE-89, CWE-943, CWE-90, CWE-643 · V1.1, V1.2 · — |
| IN2 | *(sound constructs)* Shell calls, `eval`-like APIs, dynamic imports, templates built from input; CR/LF into response headers, email headers or log lines | Same sink search | Argument arrays without a shell, no input in code or template source — because escaping by hand misses a context | CWE-78, CWE-94, CWE-1336, CWE-77, CWE-93, CWE-117 · V1.2 · — |
| IN3 | *(sound constructs)* File paths and archive entries from input | File open/write and archive extraction calls | Canonicalized and checked under a fixed root after joining — because a check before canonicalization is checking a different path | CWE-22 · V5.3 · — |
| IN4 | *(sound constructs)* Deserialization and parsers on untrusted bytes: native object deserializers, XML with external entities, YAML object tags | Parser calls and their config | A data-only format or a parser config that disables types and entities, at `path:line` — because the parser default is often unsafe | CWE-502, CWE-611 · V1.5 · — |
| IN5 | Validation at the boundary: type, range, length, format, property allow-lists [PROP]; order of decode, normalise, validate, use | Every input model and binder; decoding and normalisation calls | An allow-list per input model rejects unknown and privileged fields, applied after decoding and normalisation to the same value that is used — because a deny-list misses the field added next release, and a check before decoding checks a different value | CWE-20, CWE-915 · V1.1, V2.2, V15.3 · API3 |
| IN6 | Memory-unsafe code (C/C++, unsafe blocks, FFI, native extensions): length arithmetic, size overflow, freed or null pointers. N/A with no native code | Native sources and FFI boundaries | Lengths are checked before copy and sizes cannot overflow — because static reading cannot prove the rest; record what needs a fuzzer under `limitations` | CWE-787, CWE-125, CWE-416, CWE-190, CWE-476, CWE-119 · V1.4 · — |
| IN7 | Object-key injection in dynamic languages: request data deep-merged, cloned or path-set into objects (custom merge, `lodash.merge`/`set`, `Object.assign` on nested input, query parsers producing nested keys); keys `__proto__`, `constructor`, `prototype` | Merge/set helpers and config builders fed request bodies or query strings | Input is copied into null-prototype objects or a `Map`, or those keys are rejected before merging, at `path:line` — because one polluted prototype changes every object, including authorization flags and template options | CWE-1321 · V15.3 · — |

### Data exposure (DE) [PROP]

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| DE1 | *(sound constructs)* Response shaping: serializers, eager-loaded relations, client-chosen includes/fields, GraphQL field resolvers | Every path that returns the model, including exports and nested resolvers | An explicit output shape excludes hidden fields on every path — because one generic serializer on one path leaks everything | CWE-200 · V4.3, V8.2, V14.2, V15.3 · API3 |
| DE2 | Errors, debug pages, stack traces, verbose validation messages | Error handlers and their production config | Generic errors in the shipped config at `path:line` — because debug output is decided by config, not by code | CWE-209, CWE-200 · V13.4, V16.5 · API8 |
| DE3 | Logs, analytics and exports: secrets, tokens, PII written out; security events logged without secrets; exported spreadsheet cells beginning with `=`, `+`, `-`, `@`, tab or CR not neutralised | Log calls near auth, payment and export code | Sensitive fields are masked and security events are logged — because logs travel further than the database | CWE-532, CWE-200, CWE-1236 · V14.2, V16.2, V16.3, V16.4 · — |

### Business rules (BR) [STATE, QTY]

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| BR1 | State transitions: from-state, actor and once-only checks; per state, the fields and child records it freezes and the visibility of deleted or archived records | Status enums, transition functions, every route or job that writes the status, **every writer of frozen fields and child records**, every reader of soft-deleted or archived records | The current state and the actor are checked inside the same atomic update, every frozen-field and child writer checks the parent's state, and every reader applies the visibility filter — because a status guard does not stop an edit through a child record or a sibling reader | CWE-841, CWE-863 · V2.3 · API6 |
| BR2 | Amounts and quantities: server-side computation, sign and range, rounding and overflow | Price, total, discount and counter code | Recomputed from trusted data with range constraints — because any client-supplied amount is attacker-chosen | CWE-20, CWE-190 · V2.2, V2.3 · — |
| BR3 | *(sound constructs)* Check-then-act races: balances, coupons, quotas, unique claims | Read-check-write sequences on QTY data | Atomic conditional update, lock or unique constraint at `path:line` — because two concurrent requests both pass a separate check | CWE-362, CWE-367 · V2.3, V15.4 · — |
| BR4 | Sensitive flows open to automation: signup, purchase, reservation, referral, messaging | Flow handlers and their limits | Per-account and per-flow limits exist; effectiveness is runtime, so record the control only — because static reading cannot show the deployed limit holds | CWE-799 · V2.4 · API6 |

### Files and content (FC)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| FC1 | *(sound constructs)* Upload type, size, content checks and storage name | Upload handlers and storage calls | Type verified by content, server-chosen name, size limit — because the client controls the extension and the declared type | CWE-434, CWE-22 · V5.2 · — |
| FC2 | *(sound constructs)* Serving: active types from the app origin, download headers, access check | Download routes, storage URLs, presigned-URL issuers | Served with a safe disposition from a separate origin, behind AT1 — because a stored file served inline runs as the app | CWE-434, CWE-639 · V3.2, V5.3, V5.4 · API1 |
| FC3 | *(sound constructs)* Converters and HTML-to-PDF renderers fed user content | Conversion calls | Network and file access disabled in the converter config — because renderers fetch what the content asks for | CWE-918 · V5.2 · API7 |

### Availability (AV)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| AV1 | *(sound constructs)* Unbounded work per request: page size, batch size, query complexity, regex on input, file and archive size, outbound fan-out | List endpoints, GraphQL config, regex and archive code | A server-side cap on each — because the client chooses the size otherwise | CWE-400, CWE-770, CWE-1333 · V4.3, V15.2, V17.3 · API4 |
| AV2 | *(sound constructs)* Rate limits and their key (see CD2) | Rate-limit config | The key cannot be chosen by the client — because a client-chosen key resets the limit | CWE-770, CWE-400 · V2.4 · API4, API6 |
| AV3 | Lockouts one actor can impose on another | Lockout and quota code | Lockout is keyed so a third party cannot trigger it — because otherwise the defence is the attack | CWE-645 · UNKNOWN · API4 |

### Configuration and deployment (CD)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| CD1 | *(sound constructs)* Debug flags, error display, default credentials, sample routes, GraphQL introspection and field suggestions in production | Shipped config files per environment | Off in the production config at `path:line`; deployed values are `UNKNOWN` — because the repo shows intent, not the deployed state | CWE-489, CWE-1392 · V13.2, V13.4 · API8 |
| CD2 | *(sound constructs)* Trusted proxies and client IP/host/proto derivation | Proxy and request-parsing config | The trusted-proxy list is fixed and the right header entry is taken — because the client writes the left-most entry | CWE-348 · UNKNOWN · API8 |
| CD3 | *(sound constructs)* CORS, security headers, cookie defaults, TLS settings in the repo | Middleware and server config | No credentialed wildcard origin; headers set where responses leave — because a header set on one layer is absent on another | CWE-942, CWE-1021, CWE-614 · V3.3, V3.4, V12.1 · API8 |
| CD4 | Inventory: undocumented, old-version, debug or test routes still registered; environments sharing config | Every route file and version; API description files | Each registered route is intended and guarded like its current sibling — because forgotten routes keep old guards | UNKNOWN · V4.1 · API9 |
| CD5 | Cloud permissions declared in the repo (Terraform, CloudFormation, CDK, Pulumi, Helm/K8s, serverless manifests): wildcard actions or resources on the app's role; public buckets, snapshots or function URLs without auth; database or admin ports open to `0.0.0.0/0`; instance metadata v1 allowed; storage unencrypted; K8s privileged pods, `hostPath`, default service-account tokens mounted | IaC and manifest files; the role the app runs as | Each grant names the actions and resources the code calls, and public exposure is intended and stated, at `path:line`; resources not declared in the repo are `UNKNOWN` — because SSRF or code execution in the app inherits the app's role, and one wildcard turns a bug into account takeover | CWE-732, CWE-250, CWE-1220 · — · API8 |
| CD6 | Proxy, gateway or WAF and the app disagree on the request: path rules at the edge (deny `/admin`, auth on a prefix) vs the app's routing after decoding, case folding, trailing slash, `;` parameters, `..` and duplicate slashes; header normalisation (underscores, duplicate headers); framing (both Content-Length and Transfer-Encoding accepted, HTTP/2 downgrade) | nginx/HAProxy/Envoy/ingress/gateway config in the repo next to the app's router | The control sits in the app on the route itself, or the edge rule matches the normalised path the app routes and ambiguous framing is rejected, at `path:line` — because a rule the edge applies to a different string than the app routes is not applied | CWE-444, CWE-436, CWE-180 · V4.2 · API8 |
| CD7 | Shared HTTP caches (CDN, reverse proxy, framework page or response cache): per-user or authenticated responses stored and served to others; cache rules keyed on extension or path suffix (`/account/x.css`); response content shaped by an unkeyed header or parameter (`X-Forwarded-Host`, `X-Original-URL`, locale) | CDN and proxy cache rules, cache middleware, `Cache-Control`/`Vary` on authenticated routes | Authenticated responses are `private`/`no-store` and every input that changes the body is in the cache key, at `path:line` — because a shared cache replays one user's response, or an attacker's, to everyone | CWE-524, CWE-349 · — · API8 |

### Secrets (SE)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| SE1 | *(sound constructs)* Credentials, keys and tokens committed, in client bundles or in logs. Report location and kind only | Repo search, client build output, log calls | None found by the *SE1 searches* at the end of this file, each recorded with its hit count and every hit disposed — because a committed secret is exposed to every clone | CWE-798 · V13.3 · — |
| SE2 | *(sound constructs)* Cryptography: algorithm and mode, randomness for security values, password hashing, key storage and rotation, comparison of tokens and MACs, one key per purpose | Crypto calls and config | A vetted library with current defaults at `path:line` — because hand-picked modes and seeds are where it fails | CWE-327, CWE-338, CWE-916 · V6.2, V6.7, V11.2, V11.3, V11.4, V11.5, V11.6, V11.7 · — |
| SE3 | *(sound constructs)* Transport: TLS verification never disabled; no plain channels | HTTP client config, connection strings | Verification on in every client — because one disabled client is enough to intercept | CWE-295, CWE-319 · V12.1, V12.2, V12.3 · — |

### Dependencies and platform (DP)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| DP1 | Known-vulnerable and malicious packages, reviewed per package | `deps_scan.py --audit` results (`reference/dependencies.md`) | The audit ran and each hit is reviewed for reachability — because an advisory is not a finding until the package is used | CWE-1395, CWE-506 · V15.2 · — |
| DP2 | Runtime and framework end of life | Vendor schedule, checked now, not recalled | Supported on the current date — because end-of-life means no future fixes | CWE-1104 · V15.2 · — |

### Build and delivery (BD)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| BD1 | Supply-chain checks: dependency sources, CI/CD pipeline, deployed artifact | `deps_scan.py` checks (`reference/dependencies.md`) | Every check ran or is listed in `not_run` — because an unrun check is not a pass | CWE-829 · V3.6, V15.2 · — |
| BD2 | Pipeline privileges and secret flow, read by hand: workflow token permissions (missing or `write-all` `permissions:`); secrets printed, written to artifacts or caches, or passed to steps that run fork or PR code; cloud OIDC trust policies whose subject condition is a wildcard (any repo, branch or PR); self-hosted runners reachable by outside PRs; caches and artifacts shared between untrusted and release workflows | CI workflow files, cloud trust policies in IaC, build scripts | Least-privilege `permissions:` per job, secrets only in jobs that run trusted refs, and a trust policy pinned to the repo and a protected branch or environment, at `path:line` — because the pipeline holds deploy credentials, and a log or a cache is readable by more people than the secret store | CWE-250, CWE-532, CWE-1395 · V13.3 · — |

### Integrations (IG) [TRUST]

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| IG1 | *(sound constructs)* Inbound webhooks and callbacks: sender authentication, replay protection, tenant taken from the payload | Webhook handlers | Signature verified before parsing, with a timestamp or nonce, and the tenant derived from the verified sender — because an unsigned callback is an anonymous privileged request | CWE-345, CWE-294 · V4.1 · API10 |
| IG2 | *(sound constructs)* Outbound requests to user-influenced URLs (SSRF): host allow-list, redirects, internal ranges, including cloud metadata (link-local, IPv6, IPv4-mapped and decimal/octal forms) and non-HTTP schemes | HTTP client calls traced back to input; tenant-configured outbound webhook and callback URLs, link previews, import-from-URL, avatar/image fetch, IdP metadata URLs, PDF/image/SVG processors | Allow-list checked after resolution and on each redirect — because a host check before resolution is bypassed by DNS | CWE-918 · V1.3, V13.2 · API7 |
| IG3 | Third-party responses treated as trusted in queries, markup, redirects or state changes | Code consuming external API responses | Validated like client input — because the third party can be compromised | CWE-20 · V15.3 · API10 |
| IG4 | Real-time and peer channels (WebSocket, WebRTC signalling/TURN): authentication and authorization per message or room | Channel and room handlers | Authorization per message or join, plus origin check — because the handshake check does not cover later messages | CWE-1385, CWE-862 · V4.4, V17.1, V17.2, V17.3 · — |
| IG5 | Model calls (LLM, agents, RAG): untrusted text (user input, retrieved documents, emails, web pages, tool results) placed in prompts; tools or functions the model may call with the caller's or the service's privileges; model output reaching markup, queries, commands, URLs or state changes; retrieval indexes and conversation memory shared across tenants; secrets or other tenants' data in system prompts | Prompt builders, tool/function registries and dispatch, vector-store queries, output handlers | Each tool call is authorized as the end user (AT1/RP1 on the tool's own path) and side-effecting tools need confirmation; output is treated as untrusted input at its sink (CS1, IN1, IG2); retrieval is filtered by tenant in the query — because instructions in data can choose any tool and any output, and a prompt is not a control | CWE-1427, CWE-1426 · — · API10 |

### Client side (CS)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| CS1 | *(sound constructs)* Stored and reflected markup: raw-HTML bindings, escaping off, rich-text and markdown renderers, emails | Template and component code, renderer config | Context-aware escaping on every binding, sanitizer on rich text — because one raw binding executes in every viewer's browser | CWE-79 · V1.2, V1.3, V3.2 · — |
| CS2 | *(sound constructs)* Redirects and URL attributes bound from data | Redirect calls, href/src bindings | Allow-listed targets or relative paths only — because a supplied URL can carry tokens away | CWE-601 · V3.7 · — |
| CS3 | *(sound constructs)* Browser-held secrets and cross-origin exposure: postMessage, token storage, framing | Front-end storage and messaging code | Origin checked on every message; tokens not in script-readable storage — because any injected script can read it | CWE-922, CWE-1021 · V3.5, V14.3 · — |

### Privacy (PR)

| Step | Hunt | Where to look | Sound when — because | Catalog |
|---|---|---|---|---|
| PR1 | Personal data collected beyond need, retained without expiry, shown to actors who do not need it, or missing from deletion paths | Models with personal fields; deletion and export code | Each personal field has a purpose, a retention rule and a deletion path — because data never collected cannot leak | CWE-359 · V10.7, V11.7, V14.2 · — |

## Sound constructs

A cell is `sound` only for a construct in the *Sound* column, cited at
`path:line` on the actor's path; an *Unsound* construct is a candidate even when
it looks like a control. Every named API is a labelled example from one
ecosystem (`e.g.`), not a list to grep for: find this stack's equivalent, and
confirm its configuration at `path:line` before calling it sound.

| Step | Sound (labelled examples) | Unsound look-alike (labelled examples) | Why |
|---|---|---|---|
| IN1 | Bound parameters for values (e.g. JDBC `PreparedStatement` with `?`; Python DB-API `cursor.execute(sql, params)`; ORM value arguments such as Django `filter(field=value)`, ActiveRecord `where(col: value)`); identifiers (column, sort, operator) looked up in a server-side map | String formatting or concatenation into a query (e.g. an f-string passed to `execute`; `String.format` into `createQuery`); raw-fragment helpers fed input (e.g. ActiveRecord `where("…#{x}")`, Django `extra()` / `RawSQL`, Sequelize `literal`); hand escaping; a NoSQL filter object taken whole from the request body | Escaping depends on context; only binding and allow-lists remove input from query structure |
| IN2 | Argument-vector process APIs without a shell (e.g. Python `subprocess.run([...])` without `shell=True`; Node `execFile` / `spawn` without `shell: true`; Java `ProcessBuilder(List)`); templates loaded from files with input passed as context (e.g. Jinja2 `render_template(name, **ctx)`; precompiled Handlebars) | A command string built from input (e.g. `os.system`, Node `exec`, `shell=True`), even with an escaping helper; `eval`-like calls (e.g. `eval`, `new Function`, `exec`); template source from input (e.g. Jinja2 `render_template_string(input)`, Velocity or ERB source built at run time) | A shell or template engine re-parses the string; escaping misses a context |
| IN3 | Join to a fixed root, resolve symlinks, then a component-wise containment check (e.g. Python `Path(root, name).resolve()` then `is_relative_to(root)`; Java `root.resolve(name).normalize().toRealPath()` then `Path.startsWith(root)`; Go `filepath.Rel(root, p)` not starting with `..`); archive entries checked the same way (e.g. Python `tarfile` `extractall(filter="data")`) | String prefix check (e.g. Python `str.startswith("/data")` or Java `String.startsWith`, which also match `/data-old`); check before decoding or symlink resolution; checking the name but writing the joined path; extracting archive entries by their stored names | Only the resolved path is the one the file system opens |
| IN4 | Data-only formats and safe loaders (e.g. `json.loads`; PyYAML `yaml.safe_load`; SnakeYAML `SafeConstructor`; Jackson without default typing); XML parsers with DTDs and external entities off (e.g. Python `defusedxml`; Java `DocumentBuilderFactory` with the `disallow-doctype-decl` feature) | Native object deserializers on untrusted bytes (e.g. Python `pickle.loads`, Java `ObjectInputStream.readObject`, PHP `unserialize`, .NET `BinaryFormatter`), also behind a signature checked after decoding; full or unsafe YAML loaders; Jackson polymorphic default typing on input; parser defaults | The parser default is often the unsafe mode |
| IS2 | Token from a CSPRNG (e.g. Python `secrets.token_urlsafe`, Java `SecureRandom`, Node `crypto.randomBytes`) or the framework's generator (e.g. Django `PasswordResetTokenGenerator`, Devise reset tokens), stored hashed, with expiry, user and purpose, consumed in the same transaction as the change; the same response for known and unknown accounts; absolute links built from a configured base URL (e.g. a fixed `APP_URL`; Django `ALLOWED_HOSTS` enforced) | Tokens from a general-purpose generator (e.g. Python `random`, JS `Math.random`, `java.util.Random`) or derived from time or user ID; a token not invalidated after use; lookup by token alone so an invite token works as a reset token; distinct responses or timings for unknown accounts; `request.host` or `X-Forwarded-Host` in link generation; uniqueness checked case-sensitively while lookup is case-insensitive | Any missing property makes the token guessable, reusable or transferable |
| IS3 | Session ID regenerated on login and privilege change (e.g. Django `login()` cycling the key; Express `req.session.regenerate`; Spring Security session-fixation protection); server-side revocation on logout, password change, suspension and removal (e.g. a server session store entry deleted; a per-user token version checked on each request); CSRF middleware on with each exemption read (e.g. Django `CsrfViewMiddleware` and `@csrf_exempt`; Rails `protect_from_forgery` and `skip_forgery_protection`; Spring Security CSRF and its ignored matchers) | Session ID kept across login; logout that only clears the client cookie; stateless tokens with no revocation lookup for suspension or removal; CSRF disabled globally for cookie-authenticated routes (e.g. Spring `csrf().disable()`); state changes on `GET`; reliance on `SameSite=Lax` while a state change accepts `GET` or a top-level form POST; JSON endpoints whose parser also accepts `text/plain`, form or multipart bodies with no token or custom-header check; login and logout without CSRF protection | One surviving session or one excluded route reopens the class |
| IS4 | Verification with a fixed algorithm list and required claims (e.g. PyJWT `jwt.decode(token, key, algorithms=[...], audience=..., issuer=...)`; Node `jsonwebtoken` `verify` with `algorithms`, `audience`, `issuer`; jjwt `parser().verifyWith(key).requireIssuer(...)`); OAuth/OIDC through a maintained client with state, PKCE and nonce on (e.g. Authlib, Spring Security OAuth2 Client, `openid-client`); identity keyed on issuer plus subject; exact redirect URI match | Decoding without verifying (e.g. PyJWT `options={"verify_signature": False}`, `jsonwebtoken.decode`); the algorithm taken from the token header or `none` accepted; one key used for both HMAC and public-key algorithms; audience or issuer unchecked; redirect URI matched by prefix; accounts linked by an email claim not marked verified; state not compared; the key chosen or fetched from token-controlled headers (`kid` used in a file path or query, `jku`/`x5u` URLs, an embedded `jwk`); a JWKS URL or issuer taken from the token instead of config; `exp`/`nbf` optional | Libraries verify only what they are told to |
| BR3 | One conditional update whose affected-row count is checked (e.g. SQL `UPDATE … SET balance = balance - :amt WHERE id = :id AND balance >= :amt`; Django `filter(…, balance__gte=amt).update(balance=F("balance") - amt)`; ActiveRecord `where(…).update_all(…)`); a row lock inside the transaction (e.g. `SELECT … FOR UPDATE`, Django `select_for_update()`, JPA `PESSIMISTIC_WRITE`); a unique constraint or idempotency key on the claim; an optimistic version column (e.g. JPA `@Version`, Rails `lock_version`) | Read, check in application code, then save (e.g. `obj.balance -= amt; obj.save()`); a transaction with no lock at the default isolation level; a mutex inside one process when several instances run; uniqueness checked by a prior `SELECT` | Two concurrent requests both pass a separate check |
| AV1 | A server-side cap applied after parsing (e.g. `min(requested, MAX)` on page size; Django REST Framework `max_page_size`; Spring Data `max-page-size`); GraphQL depth and complexity limits (e.g. graphql-java `MaxQueryDepthInstrumentation`; `graphql-depth-limit` for Node); body and upload size limits in repo config (e.g. Express `json({ limit })`, nginx `client_max_body_size`); a linear-time regex engine or bounded input length (e.g. Go `regexp`, RE2) | A client `limit` passed straight to the query; a cap enforced only in the front end; aliases or batched GraphQL operations not counted; backtracking regex with nested quantifiers on unbounded input | The client chooses the size otherwise |
| AV2 | Limit keyed on the authenticated identity, or on the client address derived through the trusted-proxy config of CD2 (e.g. DRF `UserRateThrottle`; Express `express-rate-limit` with an explicit `trust proxy` hop count; Bucket4j keyed on the principal); counters in a store shared by every instance (e.g. a Redis-backed limiter); the same limit on every sibling path (v1, mobile, GraphQL) | Key from a client-set header (e.g. the left-most `X-Forwarded-For` entry, a client ID header) or from a value the client rotates; in-memory counters per process behind several instances; a limit on one path and not its siblings | A client-chosen key resets the limit |
| DE1 | An explicit output shape per actor (e.g. DRF serializer with `fields = [...]`; Pydantic `response_model`; Jackson DTO classes or `@JsonView`; Rails `as_json(only: …)` or a view template); client-chosen includes checked against an allow-list; GraphQL field resolvers that authorize per field | Returning the ORM entity or model directly (e.g. Express `res.json(user)`, a Spring controller returning an `@Entity`, DRF `fields = "__all__"`); deny-lists (`exclude = [...]`) that miss the next added field; client-chosen `include` or `expand` loading any relation | One generic serializer on one path leaks every field |
| IG1 | Signature verified over the raw body before parsing, with the provider's library or an HMAC compared in constant time (e.g. Stripe `Webhook.construct_event`; GitHub `X-Hub-Signature-256` checked with Python `hmac.compare_digest` or Node `crypto.timingSafeEqual`); a timestamp tolerance or delivery-ID dedup; tenant looked up from the verified sender's account | Verifying a re-serialized body after parsing; `==` on signatures; verification only when the header is present; a secret shared across tenants with the tenant taken from the payload; no replay window | An unsigned or replayable callback is an anonymous privileged request |
| SE1 | No secret in tracked files, history, client bundles or logs, by the searches listed below; secrets read from the environment or a secret store (e.g. Python `os.environ`, Spring `@Value("${…}")` bound to a vault, a cloud secret manager client) | A secret "only in a test" or sample config; a development default that production falls back to (e.g. `os.environ.get("KEY", "<literal>")`); a masked value logged with its length or prefix; a secret compiled into a client bundle | Every clone and log reader has the secret |
| SE2 | Vetted library defaults: authenticated encryption with a fresh nonce (e.g. Python `cryptography` `AESGCM` or `Fernet`; Java `AES/GCM/NoPadding` with a random IV; libsodium secretbox); a slow password hash (e.g. Argon2 via `argon2-cffi`, Spring `BCryptPasswordEncoder`); CSPRNG for security values; constant-time comparison (e.g. `hmac.compare_digest`, Java `MessageDigest.isEqual`, Node `crypto.timingSafeEqual`); one key per purpose | Fast or unsalted hashes for passwords (MD5, SHA-1, plain SHA-256); ECB mode (e.g. Java `Cipher.getInstance("AES")`, which defaults to ECB); a fixed or reused IV or nonce; general-purpose random generators; short-circuit `==` on tokens or MACs; one key reused across purposes | Each unsound choice leaks or forges what the key protects |
| SE3 | Library verification left on in every client, including internal ones (e.g. Python `requests` default `verify=True`; Node `https` default `rejectUnauthorized: true`; the Java default trust manager); custom CAs added through a configured bundle; encrypted database connections (e.g. `sslmode=verify-full`) | Verification turned off (e.g. `verify=False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, Go `InsecureSkipVerify: true`, a Java trust manager or hostname verifier that accepts all) behind a flag that ships; plain-text or `sslmode=disable` connections to remote hosts | One disabled client is enough to intercept |
| CS1 | Auto-escaping templates (e.g. Django templates, Jinja2 with autoescape on, React JSX text, Thymeleaf `th:text`); an allow-list sanitizer on rich text (e.g. DOMPurify, Python `nh3`, OWASP Java HTML Sanitizer); markdown rendered with raw HTML off | Raw bindings fed stored data (e.g. React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrustHtml`, the Jinja2 `safe` filter or `Markup()`, Thymeleaf `th:utext`, Rails `html_safe` or `raw`); a deny-list sanitizer; HTML escaping used in a script or URL context | Escaping is per context; one raw binding executes for every viewer |
| CS2 | Relative targets that start with a single `/` not followed by `/` or `\` (after decoding) or named routes, or a host checked against an allow-list after parsing (e.g. Django `url_has_allowed_host_and_scheme`; Spring `UriComponentsBuilder` host compared to a fixed set); URL attributes limited to `http`/`https` schemes | Redirect target taken from a parameter or the referer (e.g. Flask `redirect(request.args["next"])`, Express `res.redirect(req.query.url)`); "starts with our domain" string checks; URL attributes bound without a scheme check; protocol-relative `//host` or `/\host` accepted as relative | Prefix checks pass look-alike hosts and schemes |
| CS3 | `message` listeners that compare `event.origin` to an exact origin, and `postMessage` with an exact target origin; tokens in `HttpOnly` cookies; framing restricted (e.g. CSP `frame-ancestors` via Helmet for Node, Spring Security `frameOptions()`) | `postMessage(data, "*")`; origin compared with `includes` or `indexOf`; tokens in `localStorage` or `sessionStorage`; no framing control | Any injected or framing script can otherwise read or send them |
| FC1 | Type decided from content against an allow-list (e.g. libmagic via `python-magic`, Apache Tika, Go `http.DetectContentType`); server-chosen name and directory (e.g. a UUID); size limit at the parser (e.g. Node `multer` `limits.fileSize`, Spring `spring.servlet.multipart.max-file-size`) | Trusting the extension or the declared part type (e.g. `file.mimetype`, `getContentType()`); the client file name as the stored name (even sanitized, it collides and overwrites); size checked after the whole body is stored | The client controls the name and the declared type |
| FC2 | Served from a separate origin, or as an attachment with a fixed safe type and `nosniff` (e.g. Express `res.download()`, Spring `ContentDisposition.attachment()`), behind the AT1 check; short-lived signed URLs issued only after that check (e.g. S3 `generate_presigned_url`, GCS signed URLs) | Static serving of the upload directory from the app origin (e.g. Express `express.static` on uploads, a web-root upload folder); inline serving with the stored type; public bucket ACLs; signed URLs for any key from input | A stored active file served inline runs as the app |
| FC3 | Converter with network and file access off in its configuration (e.g. wkhtmltopdf `--disable-local-file-access`; WeasyPrint with a refusing `url_fetcher`; Puppeteer request interception that aborts non-allow-listed requests); converters run without network egress | Converter defaults; a URL filter applied to the document but not to the resources it loads | Renderers fetch whatever the content references |
| IG2 | Resolve the host, check every resolved address, then connect to that checked address (e.g. a Go `net.Dialer` `Control` hook checking the IP; an OkHttp custom `Dns`) or through an egress proxy that enforces the list (e.g. Smokescreen); redirects re-checked or off | Host-name allow-list checked before resolution (e.g. `urlparse(url).hostname in allowed` then `requests.get(url)`); a regex on the URL string; a check followed by a second resolution at connect time; redirects followed automatically; a scheme not fixed to http/https (`file:`, `gopher:`, `dict:`); a deny-list of address strings instead of a check on the resolved, parsed IP; outbound webhook URLs validated only when saved, not when sent | The address connected to must be the address checked |
| CD1 | Debug, error display and sample routes off in the production config at `path:line` (e.g. Django `DEBUG = False` in production settings; Rails `consider_all_requests_local = false` in `production.rb`; Spring `server.error.include-stacktrace=never`); management endpoints limited (e.g. Spring Boot Actuator `exposure.include` naming only health); no default credentials in seeds | Off only through an environment variable whose production value is not in the repo (record `UNKNOWN`); a default that turns debug on when the variable is unset; Actuator `exposure.include=*`; seeded admin accounts with fixed passwords | The repo shows intent, not the deployed value |
| CD2 | A fixed trusted-proxy hop count or list, client address taken from the entry it makes trustworthy (e.g. Express `trust proxy` set to a number or CIDR list; Werkzeug `ProxyFix(x_for=1)` matching the real hop count; Rails `trusted_proxies`; Tomcat `RemoteIpValve` `internalProxies`) | `trust proxy: true` or "trust all proxies"; the left-most `X-Forwarded-For` entry read by hand; more hops trusted than proxies exist | The client writes the left-most entry |
| CD3 | Exact allowed origins with credentials (e.g. Node `cors({ origin: [...], credentials: true })`; Spring `allowedOrigins(...)`; `django-cors-headers` `CORS_ALLOWED_ORIGINS`); headers set by middleware on the layer that answers (e.g. Helmet, Django `SecurityMiddleware`, Spring Security headers); cookie flags in config (e.g. Django `SESSION_COOKIE_SECURE`, `express-session` `cookie.secure`) | Reflected origin (e.g. `origin: true`) or wildcard patterns with credentials (e.g. Spring `allowedOriginPatterns("*")` with `allowCredentials(true)`); unanchored origin regex; headers set only on a layer some responses skip; `null` in the allowed origins; an origin compared as a suffix or substring | A header absent on one layer is absent for that response |

**SE1 searches to record.** Run each class and record the search and its hit
count; these are search patterns, not secrets:

- File names: `.env*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`,
  `*credentials*`, `*secret*`, `*.tfvars`, `*.kdbx`
- Assignments to names matching (case-insensitive)
  `pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key`
  with a literal value
- Key-shaped literals: `-----BEGIN [A-Z ]*PRIVATE KEY-----`, `AKIA[0-9A-Z]{16}`,
  `ghp_`, `github_pat_`, `xox[abpr]-`, `sk_live_`, token-shaped `eyJ…\.eyJ…`,
  credentials in URLs `://[^/:@]+:[^@/]+@`
- The same classes over git history (`git log -p --all -S<term>` or `-G<regex>`,
  read-only), client build output and log-call arguments

Stop when every class has run over tracked files, history (when readable) and
build output, and every hit has a disposition (real secret → finding by
location and kind; test fixture or placeholder → `checked_ok` with the reason).
Never stop at the first hit; unreadable history goes to `limitations`.
