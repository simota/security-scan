# Report — output formats

**Read when:** CHECKLIST, to deliver a checklist; REPORT, to deliver findings.
Write in the requester's language.

## Checklist deliverable

- First line: how many perspectives apply, and that suspicions are unverified
- One section per perspective from `reference/perspectives.md`, most important
  first; list the ones judged N/A with a reason
- Each item: the question, the concrete routes/files it applies to, and an
  optional `initial note (unverified)`
- Close with the recommended starting point and one decision for the requester

## Findings report

1. **First line** — status and counts: how many confirmed findings at each
   severity, and that the review was static
2. **Evidence line** — what was read, how it was split, which findings the
   reporting agent re-verified personally
3. **Findings, by severity** — each as:

   ```
   [High|Medium|Low][Confirmed|Environment-dependent|Suspected] one-line title
     location: path:line
     actor and request shape: role, method, path, parameter names
     what happens: the code fact that causes it
     fix direction: one line
     references: source link for code; advisory / fix commit / article for libraries
   ```

   Many findings of the same class may be grouped into a table.
4. **Checked and sound** — a short list of what was examined and held
5. **Decisions for a human** — specification questions (is this data meant to
   be visible to that role?) and deployment settings to confirm
6. **Next step** — fix order, and whether a local reproduction is worthwhile
7. **Files** — paths to `dashboard.html` and `assessment.pdf` rendered from
   `findings.json` (`reference/findings-schema.md`); link them, do not paste them

The chat report is the view; `findings.json` is the record. Every finding in
the chat must exist in `findings.json` with the same severity and confidence.

Describe weaknesses and parameters; do not include working payloads. Never
print secret values — give location and kind only.
