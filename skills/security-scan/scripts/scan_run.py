#!/usr/bin/env python3
"""Run fixed local assessment operations with deadlines and recoverable outputs.

POSIX, Python standard library only. This coordinates tools, not source review
or host authorization. No target application, recorded command or shell is run.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from contract_check import read_regular
from evidence_capture import GIT_BINARY
from findings import read_json as read_record
from scan_report_kit.pdf import CHROME_CANDIDATES
from scan_report_kit.output import write_output

STEPS = ("merge", "inventory", "capture", "renumber", "render", "check")
PDF_LIMIT = "assessment.pdf not produced"


def stamp():
    return datetime.now(timezone.utc).isoformat()


def document(path):
    raw = read_regular(path, 1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("run metadata exceeds 1 MiB")
    try:
        return json.loads(raw)
    except RecursionError:
        raise ValueError("run metadata is nested too deeply") from None


def directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError(f"not a physical directory: {path}")
    return path


def tree_digest(root):
    """Check every entry before copying; no links, devices or FIFOs in a run."""
    directory(root)
    digest = hashlib.sha256()
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(8, "big") + relative)
            if stat.S_ISDIR(info.st_mode):
                digest.update(b"directory")
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                digest.update(b"file" + info.st_size.to_bytes(8, "big"))
                digest.update(hashlib.sha256(read_regular(path)).digest())
            else:
                raise ValueError(f"run contains a link or non-regular entry: {path}")
        dirs.sort()
    return digest.hexdigest()


@contextmanager
def run_lock(root):
    path = root / ".lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
    fd = os.open(str(path), flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unsafe run lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BlockingIOError("this run has a live operation; inspect it before retrying") from None
        yield fd
    finally:
        os.close(fd)


def save(root, state):
    path = root / "state.json"
    if path.is_symlink():
        raise ValueError("unsafe run state")
    write_output(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def load(root):
    state = document(root / "state.json")
    if (not isinstance(state, dict) or state.get("version") != 1
            or not isinstance(state.get("repo"), str)
            or not Path(state["repo"]).is_absolute()
            or state.get("lang") not in ("ja", "en")
            or not isinstance(state.get("history"), list)
            or any(not isinstance(event, dict) for event in state["history"])):
        raise ValueError("invalid run state")
    repo = Path(state["repo"]).resolve(strict=True)
    if not repo.is_dir() or root == repo or repo in root.parents:
        raise ValueError("run must be outside the assessed repository")
    directory(root / "scratch")
    return state


def recover(root, state):
    # The lock is held here. A directory rename interrupted between these two
    # paths can be restored without trusting a stored PID or deleting a lock.
    previous, out = root / ".previous-out", root / "out"
    if previous.exists() or previous.is_symlink():
        tree_digest(previous)
        if not out.exists() and not out.is_symlink():
            previous.rename(out)
        else:
            tree_digest(out)
            shutil.rmtree(previous)
    directory(out)
    for event in state["history"]:
        if event.get("status") == "running":
            event.update(status="interrupted", finished=stamp())
    save(root, state)


def preflight(root, state):
    """Availability is diagnostic, not permission to execute or contact a host."""
    writable = {}
    for name in ("out", "scratch"):
        try:
            with tempfile.TemporaryFile(dir=root / name):
                pass
            writable[name] = True
        except OSError:
            writable[name] = False
    chrome = [os.environ.get("CHROME", ""), *CHROME_CANDIDATES]
    return {"checked": stamp(), "repo_readable": os.access(state["repo"], os.R_OK | os.X_OK),
            "writable": writable,
            "git_available": os.path.isfile(GIT_BINARY) and os.access(GIT_BINARY, os.X_OK),
            "pdf_candidate_available": any(shutil.which(name) for name in chrome if name)
                                       or shutil.which("weasyprint") is not None,
            "audit_tools_available": {name: shutil.which(name) is not None
                                      for name in ("osv-scanner", "npm", "composer", "pip-audit")}}


def execute(script, args, timeout, lock_fd):
    """Never use a shell; a child retains the lock if its parent is interrupted."""
    command = [sys.executable, "-I", "-B", str(SCRIPTS / script), *map(str, args)]
    process = subprocess.Popen(command, cwd=str(SCRIPTS), stdin=subprocess.DEVNULL,
                               stdout=sys.stderr, stderr=sys.stderr, start_new_session=True,
                               pass_fds=(lock_fd,))
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        if isinstance(error, KeyboardInterrupt):
            raise
        return 124


def publish(root, stage, original):
    out, previous = root / "out", root / ".previous-out"
    if tree_digest(out) != original:
        raise ValueError("published outputs changed during this operation; nothing replaced")
    tree_digest(stage)
    if previous.exists() or previous.is_symlink():
        raise ValueError("unfinished publication requires recovery first")
    out.rename(previous)
    try:
        stage.rename(out)
    except BaseException:
        previous.rename(out)
        raise
    shutil.rmtree(previous)


def report_limits(stage, attempt, addition, run):
    findings = stage / "findings.json"
    # Findings can be much larger than control metadata; use the existing reader.
    data = read_record(findings)
    old = [value for value in data.get("limitations", [])
           if isinstance(value, str) and value.lower().startswith(PDF_LIMIT)]
    patch = {"remove": {"limitations": old}, "limitations": [addition] if addition else []}
    fragment = attempt / "pdf-limit.json"
    write_output(fragment, json.dumps(patch))
    return run("findings.py", ["merge", findings, fragment])


def operation(args, root, state, fd):
    recover(root, state)
    out = root / "out"
    original = tree_digest(out)
    attempt = Path(tempfile.mkdtemp(prefix="attempt-", dir=root / "scratch"))
    stage = attempt / "out"
    shutil.copytree(out, stage)
    event = {"step": args.step, "started": stamp(), "status": "running",
             "attempt": attempt.name, "commands": []}
    state["history"].append(event)
    save(root, state)

    def run(script, argv):
        code = execute(script, argv, args.timeout, fd)
        event["commands"].append({"tool": script, "exit_code": code})
        save(root, state)
        return code

    findings = stage / "findings.json"
    code, incomplete = 0, False
    try:
        if args.step == "merge":
            code = run("findings.py", ["merge", findings, *[Path(p).resolve() for p in args.fragments]])
        elif args.step == "inventory":
            argv = [state["repo"], "--out", stage / "deps.json", "--into", findings]
            if args.audit:
                argv.append("--audit")
            code = run("deps_scan.py", argv)
            if code == 0:
                incomplete = bool(read_record(stage / "deps.json").get("not_run"))
        elif args.step == "capture":
            code = run("evidence_capture.py", [state["repo"], *args.paths, "--findings", findings,
                                                "--commit", args.commit])
        elif args.step == "renumber":
            code = run("findings.py", ["renumber", findings])
        elif args.step == "render":
            argv = [findings, "--out", stage, "--repo", state["repo"], "--lang", state["lang"]]
            # HTML is prepared independently of the optional PDF engine.
            code = report_limits(stage, attempt, None, run)
            if code == 0:
                code = run("render.py", [*argv, "--no-pdf"])
            if code == 0:
                pdf = None if args.no_pdf else run("render.py", argv)
                if pdf in (None, 3, 124):
                    incomplete = True
                    reason = ("PDF intentionally skipped (--no-pdf)" if pdf is None else
                              "PDF engine failed (runner deadline)" if pdf == 124 else
                              "PDF engine unavailable or failed (render.py exit 3)")
                    code = report_limits(stage, attempt, PDF_LIMIT + ": " + reason, run)
                    if code == 0:
                        code = run("render.py", [*argv, "--no-pdf"])
                elif pdf != 0:
                    code = pdf
        elif args.step == "check":
            argv = [stage]
            if not (stage / "assessment.pdf").exists():
                argv.append("--no-pdf")
            for name in args.allow:
                argv += ["--allow", name]
            code = run("contract_check.py", argv)
        if code == 0:
            publish(root, stage, original)
            event.update(status="incomplete" if incomplete else "complete",
                         output_sha256=tree_digest(out))
        else:
            event["status"] = "timed_out" if code == 124 else "failed"
    except KeyboardInterrupt:
        event["status"] = "interrupted"
        code = 130
    except (OSError, ValueError) as error:
        print(f"scan_run.py: {error}", file=sys.stderr)
        event["status"] = "failed"
        code = 2
    finally:
        event.update(finished=stamp(), exit_code=code if code else (3 if incomplete else 0))
        save(root, state)
    print(json.dumps({"run": str(root), "out": str(out), **event}, ensure_ascii=False))
    return event["exit_code"]


def positive_seconds(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0 or seconds > 3600:
        raise argparse.ArgumentTypeError("timeout must be positive, finite and at most 3600 seconds")
    return seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="step", required=True)
    init = sub.add_parser("init", help="create a private run outside the assessed repository")
    init.add_argument("repo", type=Path)
    init.add_argument("--meta", required=True, type=Path, help="a meta-only JSON fragment")
    init.add_argument("--parent", type=Path, default=Path(tempfile.gettempdir()))
    init.add_argument("--lang", choices=("ja", "en"), default="ja")
    init.add_argument("--timeout", type=positive_seconds, default=60)
    for name in ("status", "preflight"):
        inspect = sub.add_parser(name, help="inspect the run without executing or retrying tools")
        inspect.add_argument("run", type=Path)
    for name in STEPS:
        child = sub.add_parser(name)
        child.add_argument("run", type=Path)
        child.add_argument("--timeout", type=positive_seconds, default=60)
        if name == "merge":
            child.add_argument("fragments", nargs="+")
        elif name == "inventory":
            child.add_argument("--audit", action="store_true", help="explicitly opt into public advisory queries")
        elif name == "capture":
            child.add_argument("paths", nargs="+")
            child.add_argument("--commit", default="HEAD")
        elif name == "render":
            child.add_argument("--no-pdf", action="store_true")
        elif name == "check":
            child.add_argument("--allow", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.step == "init":
            repo = args.repo.resolve(strict=True)
            parent = args.parent.resolve(strict=True)
            if not repo.is_dir() or not parent.is_dir() or parent == repo or repo in parent.parents:
                raise ValueError("choose an existing writable parent outside the assessed repository")
            meta = document(args.meta)
            if not isinstance(meta, dict) or set(meta) != {"meta"}:
                raise ValueError("--meta must contain only the meta object")
            root = Path(tempfile.mkdtemp(prefix="security-scan-run-", dir=parent)).resolve()
            (root / "out").mkdir(mode=0o700)
            (root / "scratch").mkdir(mode=0o700)
            state = {"version": 1, "repo": str(repo), "lang": args.lang, "history": []}
            state["preflight"] = preflight(root, state)
            save(root, state)
            args.step, args.fragments = "merge", [str(args.meta.resolve())]
        else:
            root = args.run.resolve(strict=True)
            directory(root)
            state = load(root)
        with run_lock(root) as fd:
            # Re-read under the lock; concurrent invocations cannot lose history.
            state = load(root)
            if args.step == "preflight":
                recover(root, state)
                state["preflight"] = preflight(root, state)
                save(root, state)
                print(json.dumps(state["preflight"], ensure_ascii=False, indent=2))
                checks = state["preflight"]
                return 0 if checks["repo_readable"] and all(checks["writable"].values()) else 2
            if args.step == "status":
                recover(root, state)
                current = tree_digest(root / "out")
                print(json.dumps({"run": str(root), "out": str(root / "out"),
                                  "output_sha256": current, **state}, ensure_ascii=False, indent=2))
                return 0
            return operation(args, root, state, fd)
    except BlockingIOError as error:
        print(f"scan_run.py: {error}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as error:
        print(f"scan_run.py: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
