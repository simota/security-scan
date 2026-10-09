<!--
Files one finding as one issue (one root cause = one fix location = one issue).
Copy each {{field}} from the field of the same name in findings.json. Delete optional lines left empty.

Before filing:
- Do not put an unfixed (status: Open) High or Medium in a public issue on a public repository.
  Use a private tracker or a GitHub Security Advisory (private vulnerability reporting)
- No working attack payloads. Give the request as method, path and parameter names with
  placeholders (<other tenant's id>)
- No secret values. Give the location and kind only
- Source excerpts carry the repository's confidentiality. Leave them out when the issue is
  visible to more people than the repository
-->

**Title:** [{{severity}}] {{title}} ({{id}})

## Summary

| Item | Value |
|---|---|
| ID | {{id}} |
| Severity | {{severity}} |
| Confidence | {{confidence}} (if Environment-dependent, name the setting under *Open questions*) |
| Verdict | {{validation.verdict}} (method: {{validation.method}}) |
| Verification | static support / runtime support / incomplete, as the dashboard shows it |
| Retest | verified / not verified / not started, as the dashboard shows it |
| Perspective | {{category}} |
| CWE | {{cwe}} |
| Location | `{{location}}` |
| Assessed revision | {{meta.commit}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

## What happens

{{impact}}

<!-- Expected vs actual, and the violated invariant (INV-…). -->
- **Expected:** 
- **Actual:** 
- **Violated invariant:** 

## Static reproduction

**Actor:** {{actor}}

**Preconditions:**
1. 

**Request shape:**
1. `<METHOD> <path>` — parameter: `<name>` = <placeholder>

**Contrast (the path that keeps the rule):** the `Contrast:` path and its control's `path:line`

<!-- List every affected route here; the same root cause stays in one issue. -->

## Evidence

{{validation.evidence}}

<!-- Optional, only if the audience allows it: a short excerpt of the cited lines, secrets masked. -->

## Fix direction

{{fix}}

- **Invariant restored:** 
- **Regression test asserts:** `Test:` the legitimate actor succeeds and <other actor> is refused

## References

<!-- One line per references[] entry. Dependency findings (D-*) always include the advisory and fix commit. -->
- [{{references[].title}}]({{references[].url}}) ({{references[].type}})

## Open questions

<!-- Conditions static reading cannot show (deployed config, data present, proxy) and decisions for a human. -->
- 

## Done when

- [ ] The fix is merged
- [ ] A regression test fails before the fix and passes after it
- [ ] The legitimate path (positive control) still passes
- [ ] `status` in findings.json is `Fixed` (record an independent retest separately)
