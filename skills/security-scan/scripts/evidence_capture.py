#!/usr/bin/env python3
"""Capture assessed-revision source files as schema-version-2 evidence records.

    python3 evidence_capture.py REPO --findings findings.json PATH [PATH ...] [--commit REV]

Each PATH (repository-relative) is read from the commit's Git blob, compared
with the checked-out file, and written to <findings dir>/evidence/source/PATH.
The findings file gains `schema_version: 2`, the `assessment` pin and one
`SRC-NNN` evidence record per new path; the path -> evidence ID map is printed
as JSON so claims can cite the IDs. Re-running with the same paths rechecks the
existing artifacts and changes nothing; a missing or changed artifact is an error.

Only `rev-parse`, `ls-tree` and `cat-file` are run, with hooks, fsmonitor, replace
objects and lazy fetches disabled; no application code or filter runs. A path
whose checked-out bytes differ from the commit is refused: assess a clean tree.
Symlinks, hardlinks and non-regular children are refused, and so is a file
holding a secret-looking value (a credential file, a private-key block, a known
token format, a literal assigned to a secret-named key, or URL credentials),
since evidence/ is shareable output; reads, Git output and elapsed time are
bounded. Repeated captures recheck their existing artifacts (without the secret check).

Exit codes: 0 done, 2 bad input or a path differs from / is missing at the commit.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_integrity import EvidenceError, _Root, _parts, _deadline, _json_object
from render import SchemaError, derive_expert, secret_in_source, validate_data

GIT_BINARY = "/usr/bin/git"  # Never resolve a program through target PATH/config.
GIT_ENV = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_COUNT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
           "GIT_LITERAL_PATHSPECS": "1", "LC_ALL": "C"}
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PATHS = 512
MAX_SECONDS = 30
GIT_TIMEOUT = 5
FULL_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class CaptureError(ValueError):
    pass


def git(repo, *args, limit=4096, until=None):
    """Read bounded trusted-Git output; never accumulate raw stderr."""
    until = min(until or time.monotonic() + MAX_SECONDS, time.monotonic() + GIT_TIMEOUT)
    command = [GIT_BINARY, "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
               # Command-line -c beats repository config such as protocol.ext.allow=always.
               "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
               "-C", str(repo), *args]
    process = None
    try:
        process = subprocess.Popen(command, env=GIT_ENV, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        blocks, size = [], 0
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = until - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise CaptureError(f"git {args[0]} exceeded time limit")
                block = os.read(process.stdout.fileno(), min(65536, limit + 1 - size))
                if not block:
                    break
                size += len(block)
                if size > limit:
                    raise CaptureError(f"git {args[0]} exceeded output limit")
                blocks.append(block)
        if process.wait(timeout=max(0.001, until - time.monotonic())):
            raise CaptureError(f"git {args[0]} failed; required local object or path is unavailable")
        return b"".join(blocks)
    except (OSError, subprocess.TimeoutExpired):
        raise CaptureError(f"git {args[0]} failed or exceeded time limit") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


def relative(path):
    return "/".join(_parts(str(path)))


def _write_source(root, location, blob, budget):
    """Create beneath no-follow directories; never truncate an existing file."""
    extra, fd = [], None
    parts = _parts(location)
    try:
        root.check()
        parent = root.fd
        for part in parts[:-1]:
            _deadline(root.until)
            try:
                os.mkdir(part, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            parent = root._open_dir(parent, part, extra)
        try:
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
        except FileExistsError:
            if root.read(location, MAX_FILE_BYTES, budget=budget) != blob:
                raise CaptureError(f"{location}: exists with different content")
            return
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(blob)
        root._check(extra)
        root.check()
    finally:
        if fd is not None:
            os.close(fd)
        for _, _, child, _ in reversed(extra):
            os.close(child)


def _write_report(root, name, raw, original, identity):
    """Replace atomically only if the original safe report is unchanged."""
    if len(raw) > MAX_FILE_BYTES:
        raise CaptureError("findings file exceeds size limit")
    current, current_identity = root.read(name, MAX_FILE_BYTES, with_identity=True)
    if current != original or current_identity != identity:
        raise CaptureError("findings file changed during capture")
    mode = stat.S_IMODE(root.entry_stat(name).st_mode)
    temporary = ".capture-" + secrets.token_hex(12)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=root.fd)
    try:
        os.fchmod(fd, mode)  # Keep the report's own permissions across the replace.
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        root.check()
        os.replace(temporary, name, src_dir_fd=root.fd, dst_dir_fd=root.fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=root.fd)
        except FileNotFoundError:
            pass


def validate_findings(data):
    try:
        # Validation supplies display defaults; do not persist those changes.
        validated = validate_data(copy.deepcopy(data))
        derive_expert(validated, SchemaError)
    except SchemaError as exc:
        raise CaptureError(f"findings do not match the schema: {exc}") from None
    except RecursionError:
        raise CaptureError("findings nesting is too deep") from None


def capture(repo, findings_path, paths, commit="HEAD"):
    until = time.monotonic() + MAX_SECONDS
    source_root = out_root = None
    try:
        # Resolve caller-selected roots once for aliases such as macOS /tmp.
        # Every source/artifact/report child remains subject to no-follow checks.
        repository = Path(repo).resolve()
        findings_path = Path(findings_path)
        if not os.path.lexists(findings_path):
            raise CaptureError(f"{findings_path.name} not found; run findings.py merge with the meta fragment first")
        source_root = _Root(repository, until)
        out_root = _Root(findings_path.parent.resolve(), until)
        return _capture(repository, out_root, source_root, findings_path.name, paths, commit, until)
    except EvidenceError as exc:
        raise CaptureError(f"unsafe or unsupported capture input: {exc.reason}") from None
    finally:
        if source_root is not None:
            source_root.close()
        if out_root is not None:
            out_root.close()


def _capture(repo, out_root, source_root, findings_name, paths, commit, until):
    original, identity = out_root.read(findings_name, MAX_FILE_BYTES, with_identity=True)
    try:
        data = json.loads(original, object_pairs_hook=_json_object)
    except RecursionError:
        raise CaptureError("findings nesting is too deep") from None
    if not isinstance(data, dict):
        raise CaptureError("findings file must hold a JSON object")
    # Paths are recorded relative to REPO and verified against REPO/.git: a
    # subdirectory or a linked worktree (.git file) would pin evidence that
    # evidence_integrity.py can never match.
    try:
        git_dir = source_root.entry_stat(".git")
    except EvidenceError:
        git_dir = None
    if git_dir is None or not stat.S_ISDIR(git_dir.st_mode):
        raise CaptureError("REPO must be the top level of a checkout with a .git directory")
    validate_findings(data)
    if not isinstance(paths, (list, tuple)) or not 0 < len(paths) <= MAX_PATHS:
        raise CaptureError(f"capture requires 1 to {MAX_PATHS} paths")
    oid = git(repo, "rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}",
              limit=128, until=until).decode().strip()
    if not FULL_OID.match(oid):
        raise CaptureError(f"unexpected commit id {oid!r}")

    version = data.get("schema_version")
    if version is not None and (type(version) is not int or version not in (1, 2)):
        raise CaptureError(f"unsupported schema_version {version!r}")
    pin = data.get("assessment")
    if pin is not None and (not isinstance(pin, dict) or not isinstance(pin.get("commit"), str)
                            or pin["commit"].lower() != oid):
        raise CaptureError("findings already pin a different assessment; capture from that commit")
    if pin is not None and (pin.get("worktree") != "clean" or "diff_sha256" in pin):
        raise CaptureError("capture requires an existing clean assessment pin")
    meta = data.setdefault("meta", {})
    if not isinstance(meta, dict):
        raise CaptureError("meta must be an object")
    if meta.get("commit") and meta["commit"].lower() != oid:
        raise CaptureError(f"meta.commit {meta['commit']} differs from {oid}")

    evidence = data.setdefault("evidence", [])
    if not isinstance(evidence, list) or len(evidence) > MAX_PATHS:
        raise CaptureError(f"evidence must be a list of at most {MAX_PATHS} records")
    known, used = {}, set()
    for record in evidence:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"].strip():
            raise CaptureError("evidence records must have nonblank IDs")
        if record["id"] in used:
            raise CaptureError("duplicate evidence ID")
        used.add(record["id"])
        if record.get("kind") == "source":
            key = (record.get("commit"), record.get("source_path"))
            if not all(isinstance(value, str) for value in key):
                raise CaptureError("source evidence requires commit and source_path")
            key = (key[0].lower(), key[1])
            if key in known:
                raise CaptureError("duplicate source evidence path at the same commit")
            known[key] = record
    serial = 1 + max([int(m.group(1)) for i in used if isinstance(i, str)
                      for m in [re.match(r"^SRC-(\d+)$", i)] if m] or [0])

    mapping, new, budget = {}, [], [MAX_TOTAL_BYTES]
    for raw in paths:
        rel = relative(raw)
        if rel in mapping:
            continue
        checked_out = source_root.read(rel, MAX_FILE_BYTES, budget=budget)
        tree = git(repo, "ls-tree", "-z", oid, "--", rel, limit=8192, until=until)
        metadata, separator, name = tree.partition(b"\t")
        fields = metadata.split()
        if (not separator or name != rel.encode("utf-8") + b"\0" or len(fields) != 3 or
                fields[:2] not in ([b"100644", b"blob"], [b"100755", b"blob"]) or
                not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", fields[2])):
            raise CaptureError(f"{rel}: commit path is not a regular source file")
        object_name = fields[2].decode("ascii")
        size_raw = git(repo, "cat-file", "-s", object_name, limit=32, until=until).strip()
        if not size_raw.isdigit() or int(size_raw) > MAX_FILE_BYTES:
            raise CaptureError(f"{rel}: Git object exceeds size limit")
        size = int(size_raw)
        blob = git(repo, "cat-file", "blob", object_name, limit=size, until=until)
        if len(blob) != size:
            raise CaptureError(f"{rel}: Git object size changed")
        if checked_out != blob:
            raise CaptureError(f"{rel}: checked-out file differs from {oid[:12]}; assess a clean tree")
        location = f"evidence/source/{rel}"
        if (oid, rel) in known:
            record = known[(oid, rel)]
            if (record.get("location") != location or record.get("diff_sha256") or
                    record.get("sha256") != hashlib.sha256(blob).hexdigest()):
                raise CaptureError(f"{rel}: existing evidence record differs from captured source")
            if out_root.read(location, MAX_FILE_BYTES, budget=budget) != blob:
                raise CaptureError(f"{location}: captured evidence differs from source")
            mapping[rel] = record["id"]
            continue
        # evidence/ is shareable output: a copied secret would break "never print the value".
        # Checked for new paths only, so rechecking an earlier capture keeps working.
        if secret_in_source(rel, blob.decode("utf-8", "replace")):
            raise CaptureError(f"{rel}: contains a secret-looking value; cite it by location "
                               "instead (location and kind only, never the value)")
        if out_root.exists(location) and out_root.read(location, MAX_FILE_BYTES, budget=budget) != blob:
            raise CaptureError(f"{location}: exists with different content")
        new.append((rel, location, blob))
        mapping[rel] = f"SRC-{serial:03d}"
        serial += 1

    if len(evidence) + len(new) > MAX_PATHS:
        raise CaptureError(f"capture exceeds {MAX_PATHS} evidence records")

    source_root.check()
    out_root.check()
    for rel, location, blob in new:
        record_id = mapping[rel]
        evidence.append({"id": record_id, "kind": "source", "commit": oid,
                         "location": location, "source_path": rel,
                         "summary": f"Source at the assessed revision: {rel}",
                         "sha256": hashlib.sha256(blob).hexdigest()})

    data["schema_version"] = 2
    if pin is None:
        data["assessment"] = {"repository": repo.name, "commit": oid, "worktree": "clean"}
    if not meta.get("commit"):
        meta["commit"] = oid
    # Validate the complete upgraded report before creating any new artifacts.
    validate_findings(data)
    serialized = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(serialized) > MAX_FILE_BYTES:
        raise CaptureError("findings file exceeds size limit")
    for rel, location, blob in new:
        _write_source(out_root, location, blob, budget)
    if serialized != original:  # A rerun that adds nothing leaves the file untouched.
        _write_report(out_root, findings_name, serialized, original, identity)
    return mapping


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo")
    p.add_argument("paths", nargs="+", help="repository-relative source paths")
    p.add_argument("--findings", required=True, help="findings.json to update (evidence is written beside it)")
    p.add_argument("--commit", default="HEAD", help="assessed revision (default: HEAD)")
    a = p.parse_args(argv)
    try:
        mapping = capture(a.repo, a.findings, a.paths, a.commit)
    except (CaptureError, OSError, ValueError, UnicodeError) as exc:
        print(f"evidence_capture.py: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(mapping, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
