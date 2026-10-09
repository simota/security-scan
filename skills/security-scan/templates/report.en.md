<!--
Reports detected vulnerabilities to the owner, a security contact or a manager (email, private ticket,
Security Advisory). One report can carry several findings. Copy the counts and each finding from
findings.json (or the dashboard's copy button) so the report never disagrees with the dashboard.

Before sending:
- Every recipient can already read the repository; otherwise remove source excerpts
- No working attack payloads and no secret values
- Unverified, Likely and Unlikely findings are not written as established facts
-->

**Subject:** [Security report] {{meta.project}} — {{n_high}} High / {{n_medium}} Medium ({{meta.date}})

## 1. Summary

<!-- Conclusion first, e.g. "One confirmed flaw lets a customer read another tenant's orders; until it is fixed, restrict that API." -->


| Severity | Count | Valid with sufficient verification |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

Excluded (FalsePositive / NotApplicable): {{n_excluded}}. Unverified: {{n_unverified}}.

## 2. Scope and method

| Item | Value |
|---|---|
| System | {{meta.project}} |
| Scope | {{meta.scope}} |
| Revision | {{meta.commit}} |
| Method | {{meta.method}} |
| Date / assessor | {{meta.date}} / {{meta.assessor}} |

No requests were sent to any deployed environment.

## 3. Findings to act on first

<!-- In severity order; repeat the block per finding and link the issue filed from templates/issue.en.md. -->

### {{id}}: {{title}}

- **Severity / confidence / verdict:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **Location:** `{{location}}`
- **Actor:** {{actor}}
- **Request shape:** {{request}}
- **Impact:** {{impact}}
- **Fix direction:** {{fix}}
- **Tracked in:** <issue / advisory URL>

## 4. Dependencies and supply chain

<!-- D-* findings: package, affected and fixed versions, advisory URL. Also the audits that did not run (the "Dependency audit not run:" lines in limitations, or not_run in deps.json). -->
- 

## 5. Checked and sound

<!-- checked_ok: what was examined and held. A report with no negatives cannot be told apart from one that did not look. -->
- 

## 6. What could not be checked

<!-- limitations: deployed config, data present, infrastructure outside the repository. -->
- 

## 7. Decisions needed

<!-- decisions: undocumented rules, whether to accept a risk. -->
- 

## 8. Recommended order of work

<!-- next_steps. -->
1. 

## Attachments

- `assessment.pdf` — the assessment document
- `dashboard.html` — every finding, works offline

<!-- If disclosure is planned: the disclosure date, the fixed release, and whether a CVE is needed. -->
