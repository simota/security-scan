#!/usr/bin/env python3
"""Capture assessed-revision source files as schema-version-2 evidence records.

    python3 evidence_capture.py REPO --findings findings.json PATH [PATH ...] [--commit REV]

Each PATH (repository-relative) is read from the commit's Git blob, compared
with the checked-out file, and written to <findings dir>/evidence/source/PATH.
The findings file gains `schema_version: 2`, the `assessment` pin and one
`SRC-NNN` evidence record per new path; the path -> evidence ID map is printed
as JSON so claims can cite the IDs. Re-running with the same paths is a no-op.

Only `rev-parse` and `cat-file blob` are run, with hooks, fsmonitor, replace
objects and lazy fetches disabled; no application code or filter runs. A path
whose checked-out bytes differ from the commit is refused: assess a clean tree.

Exit codes: 0 done, 2 bad input or a path differs from / is missing at the commit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

GIT_BINARY = "/usr/bin/git"  # Never resolve a program through target PATH/config.
GIT_ENV = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_COUNT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
MAX_FILE_BYTES = 16 * 1024 * 1024
FULL_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class CaptureError(ValueError):
    pass


def git(repo, *args):
    command = [GIT_BINARY, "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "-C", str(repo), *args]
    try:
        done = subprocess.run(command, env=GIT_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError(f"git {args[0]} failed: {exc}") from None
    if done.returncode:
        raise CaptureError(f"git {args[0]} failed: {done.stderr.decode('utf-8', 'replace').strip()}")
    return done.stdout


def relative(path):
    text = str(path).replace("\\", "/")
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or any(part in ("", ".", "..") for part in text.split("/")):
        raise CaptureError(f"{path}: give a repository-relative path without '.' or '..'")
    return pure.as_posix()


def capture(repo, findings_path, paths, commit="HEAD"):
    repo = Path(repo).resolve()
    findings_path = Path(findings_path)
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CaptureError("findings file must hold a JSON object")
    oid = git(repo, "rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}").decode().strip()
    if not FULL_OID.match(oid):
        raise CaptureError(f"unexpected commit id {oid!r}")

    version = data.get("schema_version")
    if version not in (None, 1, 2):
        raise CaptureError(f"unsupported schema_version {version!r}")
    pin = data.get("assessment")
    if pin is not None and (not isinstance(pin, dict) or pin.get("commit") != oid):
        raise CaptureError("findings already pin a different assessment; capture from that commit")
    meta = data.setdefault("meta", {})
    if meta.get("commit") and meta["commit"] != oid:
        raise CaptureError(f"meta.commit {meta['commit']} differs from {oid}")

    evidence = data.setdefault("evidence", [])
    known = {(e.get("commit"), e.get("source_path")): e["id"] for e in evidence
             if isinstance(e, dict) and e.get("kind") == "source" and "id" in e}
    used = {e.get("id") for e in evidence if isinstance(e, dict)}
    serial = 1 + max([int(m.group(1)) for i in used if isinstance(i, str)
                      for m in [re.match(r"^SRC-(\d+)$", i)] if m] or [0])

    out_root = findings_path.resolve().parent
    mapping, new = {}, []
    for raw in paths:
        rel = relative(raw)
        blob = git(repo, "cat-file", "blob", f"{oid}:{rel}")
        if len(blob) > MAX_FILE_BYTES:
            raise CaptureError(f"{rel}: larger than {MAX_FILE_BYTES} bytes")
        try:
            checked_out = (repo / rel).read_bytes()
        except OSError:
            checked_out = None
        if checked_out != blob:
            raise CaptureError(f"{rel}: checked-out file differs from {oid[:12]}; assess a clean tree")
        if (oid, rel) in known:
            mapping[rel] = known[(oid, rel)]
            continue
        target = out_root / "evidence" / "source" / rel
        if target.exists() and target.read_bytes() != blob:
            raise CaptureError(f"{target}: exists with different content")
        new.append((rel, target, blob))

    for rel, target, blob in new:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        record_id = f"SRC-{serial:03d}"
        serial += 1
        evidence.append({"id": record_id, "kind": "source", "commit": oid,
                         "location": f"evidence/source/{rel}", "source_path": rel,
                         "summary": f"Source at the assessed revision: {rel}",
                         "sha256": hashlib.sha256(blob).hexdigest()})
        mapping[rel] = record_id

    data["schema_version"] = 2
    data["assessment"] = {"repository": repo.name, "commit": oid, "worktree": "clean"}
    meta["commit"] = oid
    findings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
    except (CaptureError, OSError, json.JSONDecodeError) as exc:
        print(f"evidence_capture.py: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(mapping, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
