# Local evidence integrity — bytes, hashes and commit correspondence

**Read when:** checking that evidence artifacts actually exist and match their
recorded digests, or requiring those checks before structured verification,
review handoffs or reproducibility-bundle use.

## What is checked

`scripts/evidence_integrity.py verify` reads a schema-version-2 evidence registry
and an explicit local evidence root. For each supported artifact it compares the
actual file's SHA-256 with the declared `sha256`. For `source` evidence it also
requires an explicitly supplied owned local Git repository, an explicit
`source_path`, and a full clean commit pin. The complete artifact bytes must match
the blob at that path in that commit. A source excerpt or edited/sanitized copy
is not the same blob; do not relabel it to make the check pass.

The check writes a separate deterministic receipt. It does not modify
`findings.json`, change a verdict, run a test, change `Fixed`, finish a workflow
or authorize application execution. Structural claims, source correspondence,
recorded observations and actual application behavior remain different questions.

The command only reads local inputs. It never downloads evidence, fetches Git
objects, initializes submodules, checks out a revision, runs hooks or executes
commands recorded in evidence. Repository inspection uses a bounded sanitized
copy for read-only Git-object operations, without inheriting the supplied
repository's configuration or executing its application code. The original
repository and its files are not rewritten. Use a trusted Python and Git
installation and a stable, owned local repository.

## Input contract

Use `evidence.location` for an artifact path relative to the evidence root and
`source_path` for its separate repository-relative source path:

```json
{
  "id": "source-before",
  "kind": "source",
  "commit": "<full 40- or 64-character hexadecimal commit ID>",
  "location": "source/orders.py",
  "source_path": "src/orders.py",
  "summary": "Sanitized explanation of what this source is used to review.",
  "sha256": "<SHA-256 of the complete artifact bytes>"
}
```

The placeholders above must be replaced by real digests; they are not valid
sample records. The finding's display `location` can still be `src/orders.py:18`.
Do not put line selectors in artifact locations or infer `source_path` by
splitting a display location. Every source record to be checked needs the
explicit source path. Runtime/environment artifacts do not require `source_path`;
their hash comparison establishes byte correspondence only.

Both paths must be safe relative local paths. Absolute paths, traversal, URLs,
line anchors, backslashes, symlinks, hardlinked files and non-regular artifacts
are refused. Root-directory ancestors must also be free of symlinks; use physical
paths on systems where `/tmp` or another parent is a symlink. Keep the evidence root
and all source material unchanged while the check runs. Before producing a
receipt, the verifier rereads every initially byte-matched artifact and compares
its hash and original file/path-chain identity and stat snapshots, then checks
the root again. Detected changes make affected observations incomplete and remove
matched/observed values. These are bounded sequential stability checks, not an
atomic multi-file snapshot or protection against a hostile kernel. Keep inputs
stable; path checks and bounded reads are not a filesystem sandbox. Missing,
unsupported, unreadable or mismatching inputs stay unsuccessful; none can
silently become verified. Size/time bounds can also make a check incomplete.

Dirty source-worktree pins are unsupported: a `diff_sha256` declaration cannot establish
which source bytes were actually reviewed. Supply a supported clean commit and
artifacts or leave the limitation visible. The implementation does not apply a
diff, resolve a remote revision or fall back to current working-tree files.
A commit ID is checked as a local Git object; repository names, authors and
reviewer labels are not authenticated identities. The supplied repository's
working-tree status is not inspected: committed objects are the source of truth,
not uncommitted files. The unsupported dirty pin refers to declared evidence
with `diff_sha256`, not a command that cleans or rewrites the user's checkout.

Supported Git layouts are a normal checkout with a `.git` directory or a bare
object repository. Linked worktrees/`.git` files, alternate object stores, grafts
and promisor packs are unsupported; `evidence_capture.py` refuses them too, and
refuses a subdirectory of a checkout, so it never pins evidence the verifier
cannot match. Hardlinked object files are refused, so a `git clone` of a local
path needs `--no-hardlinks`. Missing objects are not fetched. The verifier
uses `/usr/bin/git`, not a repository-supplied executable or a target `PATH`.
It requires POSIX `dir_fd`/no-follow filesystem operations; an unsupported platform
is reported rather than silently weakening checks.

Current fixed limits are 512 evidence records; 16 MiB per artifact/Git object;
64 MiB of cumulative artifact reads (`limits.total_artifact_bytes`); 128 MiB
and 8,192 files for the copied Git object store; 4,096 UTF-8 bytes and 64
components per relative path; 30 seconds overall; and 5 seconds per Git command.
The 64 MiB budget counts all attempted artifact bytes, including unsuccessful
reads and final rereads. A successful whole-file check normally reads each
artifact twice, so at most 32 MiB of distinct artifact bytes fit when there are
no other attempted reads. A small artifact cannot bypass the cumulative limit
by failing repeatedly. Exhaustion reports `total_read_limit`; it does not skip
the final check or grant verification. The separate 128 MiB Git snapshot budget
also counts attempted reads. Exceeding any bound stays incomplete or invalid,
not verified. This intentionally does not support arbitrary repository sizes.

## Verify and consume

From the repository root:

```sh
python3 skills/security-scan/scripts/evidence_integrity.py verify findings.json \
  --root /path/to/local-evidence \
  --repository /path/to/owned-local-repository \
  --out /path/to/new-receipt.json
```

The output must be a new file in an existing parent directory. Exit `0` means
all selected artifacts matched; exit `3` writes an `incomplete` observation
receipt; exit `2` means invalid input or a refused/failed receipt write. No
selected evidence is `incomplete`, not vacuous success. The standalone command
checks the entire evidence registry. Review its per-artifact results as well as
its overall result.

A version-1 receipt has `status` (`matched` or `incomplete`), `selection`, `items`,
`input_sha256`, `engine_sha256`, `limits` and `limitations`. Each item separates
`bytes` from `source`, with a machine-readable `reason`. Source correspondence
must be `matched` for source evidence. Runtime/environment items can match bytes
while their source revision remains `declared`. Observed hash and size are
included only after the declared artifact hash matches; mismatches do not expose
new file fingerprints. The receipt omits local paths, source content and raw Git
stderr.

A receipt binds the current
assessment, evidence and test-run declarations, the required-integrity policy,
and the verification engine's SHA-256. It is not a signed attestation. Editing
those declarations changes the context; changing the engine changes its binding.
Deterministic output for unchanged inputs is useful for comparison, not proof of
who generated the receipt or when an event happened.

An imported, copied or hand-authored receipt never grants verification. Each
consumer needs the actual local sources and performs fresh checks:

```sh
python3 skills/security-scan/scripts/render.py findings.json \
  --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repository \
  --out /path/to/new-report --lang ja --no-pdf
python3 skills/security-scan/scripts/verification_workflow.py status findings.json \
  --evidence-root /path/to/local-evidence \
  --evidence-repository /path/to/owned-local-repository
```

The workflow's `init`, `next`, `status`, `submit`, `resume` and `invalidate`
commands accept these same evidence flags. Its `evidence` alias provides the
standalone receipt operation with `--root`, `--repository` and `--out`.
`reproduction.py generate`, `verify` and `run`
also accept the flags; read `reference/reproduction-bundles.md` before running a
synthetic model. The `--repo` report option only embeds source excerpts and is
not an alias for `--evidence-repository` or proof of source correspondence.

### Require integrity for structured support

Opt in at the top level of a version-2 findings file:

```json
"evidence_integrity": {"required": true}
```

Under this policy, missing or unsuccessful fresh checks for the relevant
artifacts prevent sufficient structured verification and verified retest.
Existing claim, pin, independent-review, environment, real-boundary and
before/after/control requirements still apply. A successful byte check cannot
satisfy those requirements by itself. A failure does not rewrite the recorded
verdict or manufacture a contrary vulnerability claim; report the missing or
failed integrity check alongside the existing findings.

Without this opt-in, existing structured-record behavior remains compatible,
but report provenance distinguishes declarations from fresh local checks.
Versionless/version-1 files and historical extension fields receive no new
verification credit. Old fixtures with invented commits, line-number artifact
locations or placeholder hashes remain fictional; they are not migrated into
verified evidence automatically.

## Portable, synthetic-only demonstration

Run from this tool repository's root with trusted Git and Python installations.
The example creates a new local Git repository containing a plain text fixture,
not an application. It copies that blob as source evidence and writes a clearly
synthetic runtime observation. No network, target application or scanner is used.
The demonstration findings remain `Unverified` even when the bytes match.

```sh
work=$(mktemp -d "${TMPDIR:-/tmp}/security-scan-evidence.XXXXXX")
work=$(cd "$work" && pwd -P)
mkdir "$work/evidence"
# Empty templates and disabled hooks/signing keep the new demo repository inert.
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -c core.hooksPath=/dev/null init --quiet --template= "$work/repository"
printf 'Synthetic source fixture; no application behavior is asserted.\n' \
  > "$work/repository/fixture.txt"
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -C "$work/repository" -c core.hooksPath=/dev/null add fixture.txt
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -C "$work/repository" -c core.hooksPath=/dev/null \
  -c user.name='Synthetic demo' -c user.email='demo@example.invalid' \
  -c commit.gpgSign=false commit --quiet -m 'Add synthetic text fixture'
cp "$work/repository/fixture.txt" "$work/evidence/source.txt"
printf '{"synthetic":true,"observation":"Example bytes only; no test ran."}\n' \
  > "$work/evidence/observation.json"

python3 - "$work" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

work = Path(sys.argv[1])
commit = subprocess.check_output(
    ["git", "-C", str(work / "repository"), "rev-parse", "HEAD"], text=True
).strip()
records = []
for evidence_id, kind, location in [
    ("source-demo", "source", "source.txt"),
    ("runtime-demo", "runtime", "observation.json"),
]:
    record = {
        "id": evidence_id, "kind": kind, "commit": commit,
        "location": location, "summary": "Synthetic byte-verification example only.",
        "sha256": hashlib.sha256((work / "evidence" / location).read_bytes()).hexdigest(),
    }
    if kind == "source":
        record["source_path"] = "fixture.txt"
    records.append(record)
reason = "This demo does not assess application behavior."
data = {
    "schema_version": 2,
    "meta": {"project": "Synthetic byte check", "date": "2026-10-06", "commit": commit},
    "assessment": {"repository": "synthetic/evidence-demo", "commit": commit, "worktree": "clean"},
    "evidence_integrity": {"required": True},
    "evidence": records,
    "test_runs": [],
    "findings": [{
        "id": "F-001", "title": "Synthetic unverified candidate", "severity": "Info",
        "confidence": "Suspected", "location": "fixture.txt:1", "status": "Open",
        "validation": {"verdict": "Unverified", "method": "review", "evidence": reason},
        "verification": {
            "reviewer": "synthetic-demo",
            "claims": {name: {"status": "unknown", "reason": reason, "evidence_ids": []}
                       for name in ("reachability", "preconditions", "defenses", "impact")},
            "falsification": [], "reviews": [], "run_ids": [],
            "environment": {"status": "not_required", "reason": reason, "evidence_ids": []},
        },
    }],
    "limitations": [reason, "A matching runtime hash does not establish that a test ran."],
}
(work / "findings.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

python3 skills/security-scan/scripts/evidence_integrity.py verify "$work/findings.json" \
  --root "$work/evidence" --repository "$work/repository" \
  --out "$work/receipt.json"
python3 skills/security-scan/scripts/render.py "$work/findings.json" \
  --evidence-root "$work/evidence" --evidence-repository "$work/repository" \
  --out "$work/report" --lang ja --no-pdf
```

To check the failure path, append a harmless line to the copied source artifact,
then repeat `verify` with a new receipt output path. The recorded hash no longer
matches, and the changed copy also cannot establish correspondence with the
commit blob. Restore the exact original bytes before expecting success; do not
edit the recorded hash merely to hide a mismatch. Do not modify a real
assessment's files to demonstrate this behavior.

## What a matching hash does not prove

- That a source condition is reachable, exploitable or even a vulnerability.
- That a log describes an event that happened, that the named command ran, or
  that a runtime observation came from the named commit.
- That the original environment, fixture, credentials, deployed configuration
  or before/after conditions were as recorded.
- That reviewers are real, independent, authorized or correct.
- That repository identity, authorship or a receipt is authentic.
- That all relevant paths were reviewed or that the application is safe.

Keep independent source review, falsification and authorized real-boundary
retesting. Synthetic bundle observations stay `mocked` even when their actual
artifact bytes are checked. Receipts do not expand permission to run code,
contact a service, fetch a repository or publish source/evidence. Inspect
summaries, paths, source and runtime artifacts for sensitive information before
sharing; hash verification is not redaction.
