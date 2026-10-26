# Resumable assessment execution

`scan_run.py` coordinates the existing static-assessment tools on POSIX hosts
with Python 3.9 or later and no extra packages. It makes work possible within
existing permissions: it does not change host approval rules or execute an
application, arbitrary command, shell string or provider call. Source review
is still done by the reviewing agent.

## Start and continue

Run the commands from the installed skill directory. First use the host's
file-write/edit tool to create a JSON fragment containing only `meta` with the
project name, date and assessor (host and model). Include scope and method as
appropriate, using the existing findings schema. Do not put finding prose in
shell arguments.

```sh
python3 scripts/scan_run.py init <repo> --meta <metadata-fragment> --parent <writable-parent> --lang ja
```

`--parent` must already exist, be writable under the host's permissions and
lie outside the assessed repository. If omitted, it uses the system temp
directory. A symlinked temp path is resolved to its physical location. The
command prints JSON with the new `run` and `out` paths. Child-tool diagnostics
go to stderr; the runner's stdout is JSON.

Initialization records a preflight of repository readability, real temporary
file creation in output/scratch, trusted Git availability, and optional audit
and PDF executable candidates. `preflight <run>` refreshes those diagnostics
without launching the tools, querying a provider or retrying a failed operation.
An executable's presence does not establish that the host permits launching it;
missing optional tools do not prevent starting the static review.

The new private directory contains:

```text
<run>/
  state.json       operational checkpoint history
  .lock            OS-managed lock; file existence alone does not mean busy
  scratch/         fragments and isolated attempt directories
  out/             the existing run-contract output set, not control records
```

`init` merges the metadata through `findings.py`; it does not invent findings,
perspective coverage or evidence. If this first merge fails, the returned run
path can still be used with a corrected meta fragment and `merge`.

Use the returned path as `<run>`, and proceed with the ordinary RECON,
CHECKLIST, REVIEW, VERIFY and REPORT phases between commands:

```sh
python3 scripts/scan_run.py preflight <run>
python3 scripts/scan_run.py inventory <run>
python3 scripts/scan_run.py merge <run> <run>/scratch/frag-002.json
python3 scripts/scan_run.py renumber <run>
python3 scripts/scan_run.py capture <run> <repo-relative-source-path>
python3 scripts/scan_run.py render <run>
python3 scripts/scan_run.py check <run>
python3 scripts/scan_run.py status <run>
```

After source review and capture, finish the report with one command:

```sh
python3 scripts/scan_run.py finish <run>
```

`finish` performs an offline inventory only if no inventory has yet been
attempted or recorded, then renders and checks the report. An incomplete or
failed stage does not prevent independent stages from running. It preserves
existing dependency results and manual package reviews, never enables online
audits, and never automatically retries a previously failed inventory. A failed
inventory refresh remains visible even if an older inventory is available.
Missing inventory adds a report limitation before rendering. After an explicit,
permitted inventory succeeds, a later `finish` removes that obsolete limitation.
An interruption of the current command stops subsequent stages; an old
interruption does not stop a newly requested report generation.

`--no-pdf`, `--timeout` and `--allow NAME` are also accepted by `finish`. Its
stdout is one JSON summary with every attempted or retained stage's outcome;
details remain in the ordinary checkpoint history. Exit `0` requires all
selected operations and the contract check to succeed, `3` reports optional
omissions, `2` reports any failed/deadline stage, and `130` reports a current
interruption. A successful contract check alone cannot hide an earlier failed
stage. Standalone operation exit codes are unchanged. Finishing the mechanical
report work does not perform or certify source review, independent verification
or the separate optional-profile gates.

Merge still enforces the five-new-findings bound, source capture still requires
the assessed revision and safe source files, and renumbering still refuses
already-pinned references. `capture` supports `--commit`; `check` supports
`--allow NAME` for explicitly requested extra outputs. The runner does not
enable optional verification profiles or relax any evidence gate.

Inventory is offline by default and records advisory coverage as not requested.
After authorization for package-list disclosure, `inventory <run> --audit`
runs the existing public-advisory audits. This explicit invocation is never
inferred from a saved checkpoint. As with `deps_scan.py --into`, another
inventory replaces dependency auto-triage and preserves manual reviews as
history; do the final inventory before per-package review.

## Deadlines, failure and recovery

Each child command has a 60-second default deadline; set `--timeout SECONDS`
on an operation to change it, up to 3600 seconds. A render operation uses
separate bounded child commands for HTML, PDF and the limitation fallback.
Copying and publishing local output files are not covered by this child-process
deadline. Large runs need enough disk space for an output copy per attempt,
and a second copy for a render attempt that tries a PDF.

| Result | Exit | Published output |
|---|---|---|
| Successful operation | `0` | Updated after successful staging |
| Offline/incomplete advisory coverage or PDF omitted/unavailable/timed out | `3` | Useful results plus explicit limitations; not an all-clear |
| Another process still holds this run's OS lock | `3` | Unchanged; inspect that process instead of retrying blindly |
| Record or contract rejected | Tool's `1` or `2` | Last published checkpoint retained |
| Unreadable run record, or child stopped by a signal | `2` | Last published checkpoint retained |
| Child command exceeds its deadline | `124` | Last published checkpoint retained, except the explicit PDF/HTML fallback |
| Keyboard interruption | `130` | Last published checkpoint retained; interruption recorded |

`status` does not execute tools or retry anything. It acquires the same lock,
repairs an interrupted publication if needed, marks abandoned operations as
interrupted, and shows history with the current output digest.
When another operation owns the lock, it instead returns a read-only journal
snapshot with `busy: true`, exit `3`, and no current output digest. It never
marks that live work interrupted or reads a possibly changing output tree.
Running stage records include their owner's PID for diagnosis; a recorded PID
alone is not authority to terminate a process or clear a lock. Checkpoint
digests refer to whole output snapshots. A historical successful check whose
digest no longer matches is not a check of the current report. Always invoke
`check` again after changing the report.

Every operation uses a fresh copy of `out` under scratch. A failure or forced
termination can leave partial files or a child writer lock only in that attempt,
so a later permitted operation starts from the published checkpoint. Successful
publication replaces the output directory with a rollback copy available until
the replacement completes. A later command repairs a publication interrupted
between renames. The publication is recorded before the rollback copy is
deleted; if that deletion fails or is interrupted, the operation keeps its
recorded result and a later command removes the leftover copy. The OS run lock releases when the last process holding it
exits; never remove `.lock` based on its filename or age. A still-running child
inherits the lock even if its parent is terminated.

If a child times out, the runner interrupts its process group, allows 15
seconds for cleanup, and force-stops any remaining members of that group. A
child that exits on the interrupt ends the wait at once; the allowance lets
`render.py` stop a PDF engine, which it gives 10 seconds to exit before forcing
it. Group
cleanup also runs after normal or error exits: a launcher finishing does not
mean that its descendants have finished or released the inherited run lock.
It records a timeout even if the child's interrupt handler returns zero. This
cleanup covers the process group the runner created; tools that start separate
sessions remain responsible for their own process cleanup. Failed attempts
remain private in scratch for inspection; they are never scanned for findings or promoted
automatically. They can be removed with the rest of the run when no operation
is active and its outputs are no longer needed.

PDF generation is optional work within rendering: HTML is prepared first. A
missing/failed/timed-out PDF engine adds a missing-PDF limitation through the
ordinary merge tool, then regenerates the HTML with that limitation. An
intentional `render <run> --no-pdf` records that reason. The PDF is printed on
a private copy of the staged output and that copy is used only when printing
succeeds, so a stopped engine's staging or late writes stay in the failed
attempt and never reach `out`. A later successful PDF
attempt removes the outdated missing-PDF limitation. Invalid input or an HTML
rendering error is still a failed operation, not a PDF fallback.

Use runner operations consistently for `out`. The OS lock coordinates runner
processes, not arbitrary editors or the underlying standalone scripts; a
digest comparison detects an external change before replacing outputs, but is
not a sandbox against concurrent malicious filesystem changes. Run directories
must remain private and stable. Links, hardlinks and special files inside
output trees are rejected before copying; checkpoints are not imported as
authorization or proof of security.

A host-rejected action is not retried by this runner. Follow the skill's
refusal guidance, record the missing work when permitted, and continue only
independent authorized steps. Nothing in the checkpoint file grants consent.

## Verification

From the security-scan source repository's root:

```sh
python3 -m unittest discover -s tests -p test_scan_run.py -v
make check
```

The regressions run metadata → offline inventory → source capture → merge →
HTML → contract check in a synthetic committed repository. They also exercise
real process deadlines, descendant cleanup after success/error/timeout, lock
contention, partial-writer isolation, interrupted
publication, stale check digests, and PDF fallback with controlled engine
outcomes. They validate execution behavior, not vulnerability detection quality
or an assurance that a host will approve every tool call.
