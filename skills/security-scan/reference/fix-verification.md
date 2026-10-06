# Fix verification — lock each fix in with a local regression test

**Read when:** after a finding is `Valid` (`reference/validation.md`) and the
requester wants to confirm a fix holds. The deliverable is a **regression
test**, not an attack tool: a test that fails on the vulnerable code and passes
once the fix lands, then stays in the suite so the hole cannot reopen.

## Preconditions (all required)

- The code is the requester's own, and the test runs against a **local or
  throwaway** instance of it — never a shared, staging or production system, and
  never a system the requester does not own
- The work stays in the repository's own test suite and fixtures
- Confirm these in one line before writing anything; if any fails, stop and say so

## What a good verification test is

It encodes the **secure expectation** as an assertion, phrased so the vulnerable
behaviour is what makes it fail:

| Finding class | The test asserts (the secure outcome) |
|---|---|
| Cross-tenant / IDOR | Actor B requesting Actor A's resource gets 403/404 and no row of A's data in the body |
| Missing role guard | A lower role calling the action gets 403 and the state is unchanged |
| Mass assignment | A request carrying a protected field leaves that field unchanged in storage |
| Injection | A value containing the dangerous metacharacters is stored/returned as data, with the structure (SQL/HTML/path) intact — assert the benign, escaped outcome |
| Unbounded input | A request over the intended limit is rejected or capped |
| Auth / session | A revoked or expired credential is refused |

Write the assertion in terms of the **defended state** (status code, stored
value, escaped output), not in terms of a payload's success. The input you send
is the minimum needed to show the boundary works; keep it benign and inert
(e.g. the classic harmless marker value), never a real weaponised string, and
never anything that reaches outside the local process.

## Procedure

1. **Use the repo's own framework and helpers** — the test looks like the tests
   already there (PHPUnit/Pest, Jest/Vitest, pytest, Go test, …), uses the same
   factories, auth helpers and HTTP test client, and lives beside them
2. **Arrange two tenants/roles from factories** — never real data, never real
   credentials; seed the minimum rows the case needs
3. **Act through the public surface** — call the route/handler the finding named,
   as the lower-privilege actor, with the one boundary-crossing parameter
4. **Assert the secure outcome** — status, that none of the other tenant's data
   appears, and that protected state is unchanged. Name the finding ID in the
   test name and a one-line comment linking the assessment
5. **Show red → green** — run it on the current (vulnerable) code and confirm it
   **fails for the right reason**; a security test that passes before the fix
   proves nothing. Then apply or await the fix and confirm it passes. Record both
   outcomes
6. **Keep it deterministic and isolated** — no network, no sleeps, no shared
   fixtures; it must be safe to run in CI on every change

## A helper script, only if it earns its place

Most fixes need only a test. A small **local** runner script is worth adding
when a case is hard to express in a unit test (a multi-step state machine, a
sequence across endpoints). If so:

- It targets `127.0.0.1` / the local dev URL only, read from config or an
  argument, and refuses a non-local host by default
- It is a **verification** harness: it reports PASS/FAIL on the secure
  expectation and exits non-zero on FAIL, so CI can gate on it
- It carries a header comment: purpose, the finding ID, "local, owned systems
  only", and that it sends only benign inert input
- It lives under the repo's test or `tools/` directory, not in application code

Do not write a general-purpose scanner, a payload generator, a credential-spray
or brute-force loop, or anything that varies hosts/targets — those are not fix
verification and are out of scope here.

## Recording it

- Add to the finding's `fix` or a `verification` note: the test's `path::name`
  and the observed red → green result (`fails on <commit/before>, passes on
  <commit/after>`)
- A finding with a committed regression test may move to `status: Fixed` once
  the test is green on the fixed code; until then it stays `Open`
- In the report, list these under next steps as "regression tests added", so the
  reader knows the fixes are guarded
