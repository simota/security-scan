# Perspectives — reviewing from more than one angle

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, to assign
them; REPORT, to fill the `perspectives` table in `findings.json`.

One reading of the code finds what that reading looks for. Review the same
application through several perspectives, each asking a different question.
Pick the ones that apply from the recon map, apply each of them within every
review unit (`SKILL.md`, *Run contract*), and record every perspective in the
report — including the ones that found nothing and the ones not run.

| Perspective | The question it asks |
|---|---|
| Actor and tenant | Can each actor reach only what belongs to them, on every route? |
| Role and privilege | Can a lower role perform a higher role's action? |
| Identity and session | Is every way of becoming signed in held to the same rules, and does it end when it should? |
| Input handling | Does any client-supplied value reach a sensitive operation without being constrained? |
| Data exposure | Do responses, errors, logs and exports contain more than the caller should see? |
| Business rules | Can the intended order of operations, limits or amounts be skipped or altered? |
| Files and content | Are uploaded and generated files constrained in type, size, location and how they are served? |
| Availability | Can one caller exhaust resources or lock others out? |
| Configuration and deployment | Do the settings in the repository hold in production, and does each protection sit at the layer that is actually exposed? |
| Secrets | Are credentials kept out of the repository, logs and client code? |
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
