# Coverage trace — standards to perspectives and hunt steps

**Read when:** CHECKLIST, to confirm nothing a standard names is skipped;
REPORT, to choose a finding's `cwe`. **Reader:** the agent running the skill,
or a reviewer asking "does this skill cover class X?". As of 2026-10-07 · owner:
security-scan maintainers · review trigger: a new edition of any standard below
(a CWE Top 25 newer than 2024 is not traced here yet), or a change to step IDs
in `reference/perspectives.md`.

Every class below maps to a perspective in `reference/perspectives.md` and to
one or more hunt steps there (step IDs such as `AT1`); each hunt step also
carries its own *Catalog* cell, so the trace runs both ways. The invariant
family in `reference/invariants.md` §2 is named when the class is app-specific.
The trace is hand-built and is not an official mapping: ASVS 5.0 removed direct
mappings to other standards and no longer maintains CWE mappings
(`5.0/en/0x05-For-Users-Of-4.0.md`, *Removal of Direct Mappings to Other
Standards*), so no ASVS↔CWE link is claimed. A mapped class is a place the skill
looks, not a guarantee it is absent.

Two columns say where to spend effort:

- **Semantic** — `yes`: the class needs this app's own rules to see (the
  invariant ledger finds it; pattern tools usually miss it); `partly`: a
  pattern shows the sink, the app's rules decide whether it is a flaw; `no`:
  mostly visible to pattern tools — still checked, not prioritised
- **Static limit** — what reading the repository cannot settle, named as the
  out-of-repo dependency; record it as `UNKNOWN` in the cell and under
  `limitations`. `none: decidable from source` means the class is settled by
  reading the repository (the *General limits* at the end still apply)
- **`—` vs `UNKNOWN`** — in any column, `—` is a decided "nothing applies"
  (`— (decisions)` in *Steps*: checked as a `decisions` entry, no hunt step);
  `UNKNOWN` means no mapping has been established yet and is a gap to close
- **Steps ↔ Catalog** — each step's *Catalog* cell in `reference/perspectives.md`
  lists exactly the ASVS sections, API risks and Top 25 CWEs whose rows below
  cite that step (the skill repository's tests check that the two sides match)

Sources (fetched 2026-10-07):
ASVS 5.0 — `https://github.com/OWASP/ASVS/tree/master/5.0/en` (all 80 section
numbers and titles re-fetched 2026-10-07 from the chapter files `0x10`–`0x26`
at master `9b5da31`; they match the table below exactly);
API Security Top 10 2023 — `https://api-security.owasp.org/editions/2023/en/0x11-t10`;
CWE Top 25 2024 — `https://cwe.mitre.org/top25/archive/2024/2024_top25_list.html`.

## OWASP ASVS 5.0 (section level)

Documentation sections (`Vn.1 … Documentation`) are checked as `decisions`
(is the rule written down?), not as findings.

| Section | Title | Perspective | Steps | Semantic | Static limit |
|---|---|---|---|---|---|
| V1.1 | Encoding and Sanitization Architecture | Input handling | IN1, IN5 | partly | none: decidable from source |
| V1.2 | Injection Prevention | Input handling; Client side | IN1, IN2, CS1 | partly | none: decidable from source |
| V1.3 | Sanitization | Input handling; Integrations | CS1, IG2 | partly | none: decidable from source |
| V1.4 | Memory, String, and Unmanaged Code | Input handling | IN6 | no | Needs a fuzzer or sanitizer run |
| V1.5 | Safe Deserialization | Input handling | IN4 | partly | none: decidable from source |
| V2.1 | Validation and Business Logic Documentation | Business rules | ledger §1 | yes | Intent may live outside the repo |
| V2.2 | Input Validation | Input handling; Business rules | IN5, BR2 | partly | none: decidable from source |
| V2.3 | Business Logic Security | Business rules | BR1–BR3 | yes | Intended rule may live outside the repo (`decisions`) |
| V2.4 | Anti-automation | Business rules; Availability | BR4, AV2 | yes | Limit effectiveness is runtime |
| V3.1 | Web Frontend Security Documentation | Client side | — (decisions) | no | none: decidable from source |
| V3.2 | Unintended Content Interpretation | Client side; Files and content | CS1, FC2 | partly | none: decidable from source |
| V3.3 | Cookie Setup | Identity and session; Configuration and deployment | IS3, CD3 | no | Proxy-set cookies `UNKNOWN` |
| V3.4 | Browser Security Mechanism Headers | Configuration and deployment | CD3 | no | Headers set outside the repo `UNKNOWN` |
| V3.5 | Browser Origin Separation | Client side | CS3 | partly | none: decidable from source |
| V3.6 | External Resource Integrity | Build and delivery | BD1 | no | Assets served by a CDN outside the repo `UNKNOWN` |
| V3.7 | Other Browser Security Considerations | Client side | CS2 | partly | none: decidable from source |
| V4.1 | Generic Web Service Security | Configuration and deployment; Integrations | CD4, IG1 | partly | none: decidable from source |
| V4.2 | HTTP Message Structure Validation | Configuration and deployment | CD6 | partly | Edge config outside the repo `UNKNOWN` |
| V4.3 | GraphQL | Availability; Data exposure | AV1, DE1 | partly | none: decidable from source |
| V4.4 | WebSocket | Integrations | IG4 | yes | none: decidable from source |
| V5.1 | File Handling Documentation | Files and content | — (decisions) | no | none: decidable from source |
| V5.2 | File Upload and Content | Files and content | FC1, FC3 | partly | none: decidable from source |
| V5.3 | File Storage | Files and content; Input handling | IN3, FC2 | partly | Storage ACLs environment-dependent |
| V5.4 | File Download | Files and content | FC2, AT1 | yes | none: decidable from source |
| V6.1 | Authentication Documentation | Identity and session | — (decisions) | no | none: decidable from source |
| V6.2 | Password Security | Identity and session; Secrets | IS2, SE2 | no | none: decidable from source |
| V6.3 | General Authentication Security | Identity and session | IS1, IS5 | yes | none: decidable from source |
| V6.4 | Authentication Factor Lifecycle and Recovery | Identity and session | IS2 | yes | none: decidable from source |
| V6.5 | General Multi-factor authentication requirements | Identity and session | IS1 | partly | none: decidable from source |
| V6.6 | Out-of-Band authentication mechanisms | Identity and session | IS2, IS5 | partly | none: decidable from source |
| V6.7 | Cryptographic authentication mechanism | Identity and session; Secrets | IS4, SE2 | no | none: decidable from source |
| V6.8 | Authentication with an Identity Provider | Identity and session | IS1, IS4 | yes | IdP config outside the repo `UNKNOWN` |
| V7.1 | Session Management Documentation | Identity and session | — (decisions) | no | none: decidable from source |
| V7.2 | Fundamental Session Management Security | Identity and session | IS3 | partly | none: decidable from source |
| V7.3 | Session Timeout | Identity and session | IS3 | no | Store config outside the repo `UNKNOWN` |
| V7.4 | Session Termination | Identity and session | IS3 | yes | none: decidable from source |
| V7.5 | Defenses Against Session Abuse | Identity and session | IS3 | partly | none: decidable from source |
| V7.6 | Federated Re-authentication | Identity and session | IS4 | partly | none: decidable from source |
| V8.1 | Authorization Documentation | Role and privilege | ledger §2 (ROLE) | yes | Intended role matrix may live outside the repo (`decisions`) |
| V8.2 | General Authorization Design | Actor and tenant; Role and privilege; Data exposure | AT1, AT3–AT5, RP1, RP6, DE1 | yes | none: decidable from source |
| V8.3 | Operation Level Authorization | Role and privilege | RP1–RP6 | yes | none: decidable from source |
| V8.4 | Other Authorization Considerations | Actor and tenant | AT1, AT2 | yes | none: decidable from source |
| V9.1 | Token source and integrity | Identity and session | IS4 | partly | none: decidable from source |
| V9.2 | Token content | Identity and session | IS4 | partly | none: decidable from source |
| V10.1 | Generic OAuth and OIDC Security | Identity and session | IS4 | partly | Provider-side client registration `UNKNOWN` |
| V10.2 | OAuth Client | Identity and session | IS4 | partly | Provider-side registered redirect URIs `UNKNOWN` |
| V10.3 | OAuth Resource Server | Identity and session; Role and privilege | IS4, RP1, RP6 | yes | none: decidable from source |
| V10.4 | OAuth Authorization Server | Identity and session | IS4 | partly | N/A unless the app is one |
| V10.5 | OIDC Client | Identity and session | IS4 | partly | IdP config outside the repo `UNKNOWN` |
| V10.6 | OpenID Provider | Identity and session | IS4 | partly | N/A unless the app is one |
| V10.7 | Consent Management | Identity and session; Privacy | IS4, PR1 | partly | none: decidable from source |
| V11.1 | Cryptographic Inventory and Documentation | Secrets | — (decisions) | no | none: decidable from source |
| V11.2 | Secure Cryptography Implementation | Secrets | SE2 | no | none: decidable from source |
| V11.3 | Encryption Algorithms | Secrets | SE2 | no | none: decidable from source |
| V11.4 | Hashing and Hash-based Functions | Secrets | SE2 | no | none: decidable from source |
| V11.5 | Random Values | Secrets | SE2 | no | none: decidable from source |
| V11.6 | Public Key Cryptography | Secrets | SE2 | no | none: decidable from source |
| V11.7 | In-Use Data Cryptography | Secrets; Privacy | SE2, PR1 | no | Memory encryption is deployment `UNKNOWN` |
| V12.1 | General TLS Security Guidance | Secrets; Configuration and deployment | SE3, CD3 | no | Deployed TLS environment-dependent |
| V12.2 | HTTPS Communication with External Facing Services | Secrets | SE3 | no | Deployed TLS environment-dependent |
| V12.3 | General Service to Service Communication Security | Secrets | SE3 | no | Network-level mutual TLS outside the repo `UNKNOWN` |
| V13.1 | Configuration Documentation | Configuration and deployment | — (decisions) | no | none: decidable from source |
| V13.2 | Backend Communication Configuration | Configuration and deployment; Integrations | CD1, IG2 | partly | none: decidable from source |
| V13.3 | Secret Management | Secrets; Build and delivery | SE1, BD2 | no | Vault and key custody `UNKNOWN` |
| V13.4 | Unintended Information Leakage | Configuration and deployment; Data exposure | CD1, DE2 | no | Deployed flags `UNKNOWN` |
| V14.1 | Data Protection Documentation | Privacy | — (decisions) | partly | none: decidable from source |
| V14.2 | General Data Protection | Data exposure; Privacy | DE1, DE3, PR1 | yes | Data actually stored not visible |
| V14.3 | Client-side Data Protection | Client side | CS3 | partly | none: decidable from source |
| V15.1 | Secure Coding and Architecture Documentation | Dependencies and platform | — (decisions) | no | none: decidable from source |
| V15.2 | Security Architecture and Dependencies | Dependencies and platform; Build and delivery; Availability | DP1, DP2, BD1, AV1 | no | Advisory databases at run time (`deps_scan.py --audit`); vendor EOL schedule |
| V15.3 | Defensive Coding | Input handling; Data exposure; Integrations | IN5, IN7, DE1, IG3 | partly | none: decidable from source |
| V15.4 | Safe Concurrency | Business rules | BR3 | yes | Interleavings need runtime to confirm |
| V16.1 | Security Logging Documentation | Data exposure | — (decisions) | no | none: decidable from source |
| V16.2 | General Logging | Data exposure | DE3 | no | Log shipping `UNKNOWN` |
| V16.3 | Security Events | Data exposure | DE3 | partly | none: decidable from source |
| V16.4 | Log Protection | Data exposure | DE3 | no | Log storage outside the repo `UNKNOWN` |
| V16.5 | Error Handling | Data exposure; Role and privilege | DE2, RP5 | no | none: decidable from source |
| V17.1 | TURN Server | Integrations | IG4 | no | N/A without WebRTC; TURN config usually outside |
| V17.2 | Media | Integrations | IG4 | no | N/A without WebRTC |
| V17.3 | Signaling | Integrations; Availability | IG4, AV1 | partly | N/A without WebRTC |

## OWASP API Security Top 10 2023

| Risk | Perspective | Hunt steps | Family | Semantic | Static limit |
|---|---|---|---|---|---|
| API1:2023 Broken Object Level Authorization | Actor and tenant; Role and privilege; Files and content | AT1–AT5, RP6, FC2 | OWN | yes | none: decidable from source |
| API2:2023 Broken Authentication | Identity and session | IS1–IS5 | ID | partly | IdP config `UNKNOWN` |
| API3:2023 Broken Object Property Level Authorization | Data exposure; Input handling | DE1, IN5 | PROP | yes | none: decidable from source |
| API4:2023 Unrestricted Resource Consumption | Availability | AV1–AV3 | QTY | partly | Gateway limits outside the repo `UNKNOWN` |
| API5:2023 Broken Function Level Authorization | Role and privilege | RP1–RP6 | ROLE | yes | none: decidable from source |
| API6:2023 Unrestricted Access to Sensitive Business Flows | Business rules; Availability | BR1, BR4, AV2 | QTY, STATE | yes | Limit effectiveness is runtime |
| API7:2023 Server Side Request Forgery | Integrations | IG2, FC3 | TRUST | partly | Egress network rules `UNKNOWN` |
| API8:2023 Security Misconfiguration | Configuration and deployment | CD1–CD3, CD5–CD7, DE2 | — | no | Deployed config `UNKNOWN` |
| API9:2023 Improper Inventory Management | Configuration and deployment | CD4, AT3 | — | partly | Gateway-exposed routes `UNKNOWN` |
| API10:2023 Unsafe Consumption of APIs | Integrations | IG1, IG3, IG5 | TRUST | yes | Third-party behaviour outside the repo |

## CWE Top 25 (2024)

Use the CWE ID below as a finding's `cwe` when it is the closest match; a more
specific child CWE (as in the steps' *Catalog* cells) is fine when the evidence
supports it.

| Rank | CWE | Perspective | Hunt steps | Family | Semantic | Static limit |
|---|---|---|---|---|---|---|
| 1 | CWE-79 Cross-site Scripting | Client side | CS1 | TRUST | partly | none: decidable from source |
| 2 | CWE-787 Out-of-bounds Write | Input handling | IN6 | TRUST | no | Needs fuzzer/sanitizer |
| 3 | CWE-89 SQL Injection | Input handling | IN1 | TRUST | no | none: decidable from source |
| 4 | CWE-352 Cross-Site Request Forgery | Identity and session | IS3 | ID | partly | none: decidable from source |
| 5 | CWE-22 Path Traversal | Input handling; Files and content | IN3, FC1 | TRUST | partly | none: decidable from source |
| 6 | CWE-125 Out-of-bounds Read | Input handling | IN6 | TRUST | no | Needs fuzzer/sanitizer |
| 7 | CWE-78 OS Command Injection | Input handling | IN2 | TRUST | no | none: decidable from source |
| 8 | CWE-416 Use After Free | Input handling | IN6 | TRUST | no | Needs fuzzer/sanitizer |
| 9 | CWE-862 Missing Authorization | Actor and tenant; Role and privilege; Integrations | AT1, AT2, RP1, IG4 | OWN, ROLE | yes | none: decidable from source |
| 10 | CWE-434 Unrestricted Upload of File with Dangerous Type | Files and content | FC1, FC2 | — | partly | Storage serving config `UNKNOWN` |
| 11 | CWE-94 Code Injection | Input handling | IN2 | TRUST | no | none: decidable from source |
| 12 | CWE-20 Improper Input Validation | Input handling; Business rules; Integrations | IN5, BR2, IG3 | PROP, QTY | partly | none: decidable from source |
| 13 | CWE-77 Command Injection | Input handling | IN2 | TRUST | no | none: decidable from source |
| 14 | CWE-287 Improper Authentication | Identity and session | IS1, IS2, IS4 | ID | yes | none: decidable from source |
| 15 | CWE-269 Improper Privilege Management | Role and privilege | RP3 | ROLE | yes | none: decidable from source |
| 16 | CWE-502 Deserialization of Untrusted Data | Input handling | IN4 | TRUST | no | none: decidable from source |
| 17 | CWE-200 Exposure of Sensitive Information | Data exposure | DE1–DE3 | PROP | yes | Data actually present not visible |
| 18 | CWE-863 Incorrect Authorization | Actor and tenant; Role and privilege; Business rules | AT3, AT4, RP2, RP5, RP6, BR1 | OWN, ROLE, STATE | yes | none: decidable from source |
| 19 | CWE-918 Server-Side Request Forgery | Integrations; Files and content | IG2, FC3 | TRUST | partly | Egress network rules `UNKNOWN` |
| 20 | CWE-119 Improper Restriction of Memory Buffer Operations | Input handling | IN6 | TRUST | no | Needs fuzzer/sanitizer |
| 21 | CWE-476 NULL Pointer Dereference | Input handling | IN6 | — | no | Needs fuzzer/sanitizer |
| 22 | CWE-798 Use of Hard-coded Credentials | Secrets | SE1 | — | no | none: decidable from source |
| 23 | CWE-190 Integer Overflow or Wraparound | Business rules; Input handling | BR2, IN6 | QTY | partly | none: decidable from source |
| 24 | CWE-400 Uncontrolled Resource Consumption | Availability | AV1, AV2 | QTY | partly | Deployed limits `UNKNOWN` |
| 25 | CWE-306 Missing Authentication for Critical Function | Role and privilege | RP4 | ROLE | partly | none: decidable from source |

## General limits

These hold for every row, including `none: decidable from source`; each one
that touches a finding or a `Sound` claim goes into `limitations`:

- **Deployed values** — environment variables, secrets, feature flags and
  settings set outside the repository; the repo shows intent, not state
- **Infrastructure outside the repo** — gateways, WAFs, load balancers, IAM and
  storage ACLs, network segmentation and egress rules, unless declared in IaC
  that is in the repo (`reference/recon.md` §2)
- **Data actually present** — what is stored, who already holds access, and
  records created by migrations or by hand
- **Runtime behaviour** — concurrency interleavings, timing, resource limits
  under load, and library behaviour that depends on runtime configuration
- **Code not in the repo or not readable** — generated, vendored or minified
  code, private packages, separate services, and routes registered dynamically
  (reflection, plugin loading, configuration-driven routing) that a search did
  not resolve
- **Third parties** — identity providers, payment and webhook senders,
  external APIs and their registered settings
- **History and process** — secrets removed from history the run could not
  read, and review or deployment practice outside the code

## Limits of this trace

- Memory-safety CWEs (ranks 2, 6, 8, 20, 21, 23 in native code) are only
  partly visible to static reading; IN6 records what was read and what needs a
  fuzzer or sanitizer run, under `limitations`
- Coverage is recorded per perspective and per ledger entry; the trace says
  where the skill looks, not what a run proves absent
- Business-logic classes (STATE, QTY) have no Top 25 entry that captures the
  app's own rule: pick the closest weakness (often CWE-863, CWE-841 or CWE-20)
  and name the violated `INV-…` in `impact`
- The `Semantic` and `Static limit` values are the maintainers' judgement, not
  part of any standard

## Edition upgrade

When a standard above publishes a new edition (or the ASVS section list
changes), regenerate in this order:

1. Fetch the new section or entry list from its source; record the URL, date
   and commit or edition under *Sources*
2. Diff it against the table: added, removed, renumbered and retitled rows
3. Map each new or changed row to a perspective and hunt steps, or write
   `UNKNOWN (no step)`; never add a perspective — the 15 names are fixed
   (`scripts/contract_check.py` parses them). A class no step covers is a
   step to add to `reference/perspectives.md`, with its *Sound when* reason
4. Regenerate every step's *Catalog* cell in `reference/perspectives.md` as the
   union of the rows that now cite it (closer child CWEs may stay)
5. Update the *As of* lines and review triggers of both files, and the Top 25
   note in the header
6. Run the step↔trace consistency test (`tests/test_coverage_trace.py` in the
   skill repository); it fails on any Catalog cell that does not match
