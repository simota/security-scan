# Fix verification — check the same case before and after the change

**Read when:** after a finding is supported (`reference/validation.md`) and the
requester explicitly wants to confirm a fix. The deliverable is a local
regression test plus evidence of what ran, not an attack tool.

## Preconditions (all required)

- The requester explicitly authorizes this verification work on their own code
- Use only an owned **local or throwaway** instance, never a shared, staging,
  production or third-party system
- Stay in the repository's own test framework and synthetic fixtures; do not
  use real data or credentials, send email, take payments or call external APIs
- Confirm the target, permitted actions, isolation, resource limits and stop
  conditions before writing or running tests; a report-rendering request alone
  does not authorize executing tests or changing the assessed application

## What a good verification test is

Encode the **secure expectation** as an assertion so the vulnerable behavior is
what makes it fail:

| Finding class | The test asserts (the secure outcome) |
|---|---|
| Cross-tenant / IDOR | Actor B cannot read Actor A's resource, and A's data is absent from the response |
| Missing role guard | A lower role is refused and protected state is unchanged |
| Mass assignment | A request carrying a protected field leaves that field unchanged |
| Injection | Inert metacharacters are stored/returned as data with SQL/HTML/path structure intact |
| Unbounded input | A request over the intended limit is rejected or capped |
| Auth / session | A revoked or expired synthetic credential is refused |

Assert the defended state: response, stored value, output or side effect. Keep
inputs minimal, benign and inert, with nothing that reaches outside the local
process. Pair the forbidden action with a **positive control**: the legitimate
actor can still perform the intended action on its own resource.

## Procedure

1. **Use existing helpers.** Use the repository's framework, factories and local
   HTTP client. Record the test and fixture versions; name the finding and case
2. **Preserve the boundary.** Exercise the named route/handler through the actual
   authorization, authentication and tenancy layers being assessed. Do not mock
   the very control the test is intended to check. Stub only unrelated external
   services, and record which layers were exercised and which were stubbed
3. **Observe the original failure.** On the pinned vulnerable revision, the
   secure assertion must fail because the recorded prohibited behavior occurred.
   Save expected and observed results and the failure kind. Missing dependencies,
   syntax errors, timeouts, setup errors and undiscovered tests are not valid red
   evidence. A test already green before the fix does not establish the original
   condition
4. **Retest the same case.** On the pinned fixed revision, use the same case ID,
   secure expectation and fixture/test identity. Confirm the assertion passes.
   A different test, weakened assertion or skipped path is not a before/after pair
5. **Check normal behavior and nearby paths.** Run the positive control and
   relevant regression cases on the fixed revision: for example, legitimate
   tenant access, another role and adjacent list/detail routes. Record every
   result, including failed or incomplete runs
6. **Keep it deterministic.** No external network, sleeps, real secrets or
   shared fixtures. Keep the regression in the repository's suite when requested

`skip`, `not_run`, `blocked`, `unsupported` and `error` never count as pass. A
failed positive control or regression means the fix is not verified. Original
reproduction must be `runtime_supported`: an incomplete listed current-version
run blocks runtime/retest verification even alongside legitimate red evidence.
For a `Valid` finding, a listed real-boundary security run already passing
before the fix is material counterevidence and makes verification incomplete. Do not omit it to obtain a
verified label. A scanner
no longer reporting the finding, or a merged fix PR, is not independent retest
evidence.

## A helper script, only if it earns its place

Most fixes need only a test. A small local runner may be useful for a multi-step
state machine or sequence across endpoints. If explicitly requested:

- Target only `127.0.0.1` / an owned local dev URL and refuse non-local hosts by
  default; do not allow redirects to external targets
- Report PASS/FAIL on the secure expectation and exit nonzero on failure;
  incomplete execution must stay distinguishable from a passed assertion
- Include its purpose, finding/case ID, “local, owned systems only”, and the
  benign inert input limitation in a header
- Keep it under the repository's tests or tools, not application code

Do not create a general-purpose scanner, payload generator, credential spray,
brute-force loop or a runner that varies hosts/targets.

## Recording and reporting

Opt into `schema_version: 2` and use the structured test-run and remediation
records in `reference/findings-schema.md`. Versionless/version-1 records remain
legacy even if their extension fields use these names. Link the same case before and after to the
respective revisions, environment/configuration and fixture/test identities,
expected and observed outcomes, timestamps and sanitized evidence. Link the
positive-control and regression results on the fixed revision too.

`status: Fixed` is a **recorded remediation claim**. Preserve it when supplied,
but report the separately derived retest state. Marking a status, committing a
test or setting a verdict must not synthesize a successful retest. `Accepted`
records a response decision and is not remediation verification.

If the post-fix case passes but the original revision was never shown failing
for the right reason, say so: “Post-fix case passed; original condition not
verified.” Do not label the full fix independently retested. Preserve missing,
failed and blocked evidence as limitations and name the remaining check.

The schema checks the recorded pairing and outcomes; it does not run a test,
verify that a command was really executed, or guarantee semantic equivalence of
two fixtures. A reviewer must inspect those facts before relying on the result.

## Reproducible preparation bundles

For explicitly requested seed and reproduction scripts, see
`reference/reproduction-bundles.md`. The generator binds deterministic synthetic
fixtures and generated scripts to the finding and declared revisions, then
checks two clean runs. Its SQLite owner-scope model is a preparation aid, not a
test of the application's own authorization boundary. A model red/green result
cannot satisfy the runtime-supported original case required above. Adaptation
into the project's framework needs its own authorized local target, real
boundary, pinned dependencies and before/after evidence; edited bundle code is
not accepted by the trusted template runner.
