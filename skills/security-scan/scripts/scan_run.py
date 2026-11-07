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
from report_schema import SchemaError
from scan_report_kit.pdf import CHROME_CANDIDATES
from scan_report_kit.output import write_output

STEPS = ("merge", "inventory", "capture", "renumber", "triage", "render", "check")
PDF_LIMIT = "assessment.pdf not produced"
FINISH_LIMIT = "Runner finish: dependency inventory unavailable"
# Interrupted tools get this long to stop their own sessions before the group is
# killed; render.py allows a PDF engine 10 seconds to exit before forcing it.
CLEANUP_GRACE = 15
# Held while outputs are swapped in and recorded, so a stop cannot land between.
TERMINATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
# Review phases in order, with assumed relative effort used only until the run's
# own pace is observed. Estimates are planning aids, never a commitment.
PHASES = ("RECON", "CHECKLIST", "REVIEW", "VERIFY", "REPORT")
WEIGHTS = {"RECON": 20, "CHECKLIST": 10, "REVIEW": 40, "VERIFY": 20, "REPORT": 10}


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


def record(path):
    """Read a tool's JSON record; an unreadable or non-object record is a ValueError."""
    try:
        data = read_record(path)
    except SchemaError as error:
        raise ValueError(str(error)) from None
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must be a JSON object")
    return data


def limitations(data):
    """The limitation list, or none: the tools themselves reject a malformed value."""
    value = data.get("limitations")
    return value if isinstance(value, list) else []


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
        elif any(event.get("status") == "running" for event in state["history"]):
            # Swapped in, but the runner was killed before recording it: keep
            # the recorded checkpoint and leave the unrecorded copy in scratch.
            tree_digest(out)
            aside = Path(tempfile.mkdtemp(prefix="unrecorded-", dir=root / "scratch"))
            out.rename(aside / "out")
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
        code = process.wait(timeout=timeout)
        if code < 0:
            # A signal (for example an out-of-memory kill) is a failed command.
            print(f"scan_run.py: {script} stopped by signal {-code}", file=sys.stderr)
            return 2
        return code
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=CLEANUP_GRACE)
        except subprocess.TimeoutExpired:
            pass
        if isinstance(error, KeyboardInterrupt):
            raise
        return 124
    finally:
        # A launcher can exit while descendants still hold the run lock. Clean
        # its whole group on every outcome, including a successful early exit.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise OSError("child did not exit after forced stop; inspect the live operation") from None


def publish(root, stage, original):
    """Swap the staged outputs in and return their digest; the rollback copy is
    left for the caller to discard once the publication is recorded."""
    out, previous = root / "out", root / ".previous-out"
    if tree_digest(out) != original:
        raise ValueError("published outputs changed during this operation; nothing replaced")
    digest = tree_digest(stage)
    if previous.exists() or previous.is_symlink():
        raise ValueError("unfinished publication requires recovery first")
    out.rename(previous)
    try:
        stage.rename(out)
    except BaseException:
        previous.rename(out)
        raise
    return digest


def report_limits(stage, attempt, addition, run):
    findings = stage / "findings.json"
    # Findings can be much larger than control metadata; use the existing reader.
    data = record(findings)
    old = [value for value in limitations(data)
           if isinstance(value, str) and value.lower().startswith(PDF_LIMIT)]
    patch = {"remove": {"limitations": old}, "limitations": [addition] if addition else []}
    fragment = attempt / "pdf-limit.json"
    write_output(fragment, json.dumps(patch))
    return run("findings.py", ["merge", findings, fragment])


def operation(args, root, state, fd, emit=True):
    recover(root, state)
    out = root / "out"
    event = {"step": args.step, "started": stamp(), "status": "running", "owner_pid": os.getpid(),
             "commands": []}
    state["history"].append(event)
    save(root, state)

    def run(script, argv):
        code = execute(script, argv, args.timeout, fd)
        event["commands"].append({"tool": script, "exit_code": code})
        save(root, state)
        return code

    code, incomplete, published, held, stopped = 0, False, None, None, False
    try:
        original = tree_digest(out)
        attempt = Path(tempfile.mkdtemp(prefix="attempt-", dir=root / "scratch"))
        event["attempt"] = attempt.name
        stage = attempt / "out"
        shutil.copytree(out, stage)
        findings = stage / "findings.json"
        if args.step == "merge":
            code = run("findings.py", ["merge", findings, *[Path(p).resolve() for p in args.fragments]])
        elif args.step == "inventory":
            argv = [state["repo"], "--out", stage / "deps.json", "--into", findings]
            if args.audit:
                argv.append("--audit")
            code = run("deps_scan.py", argv)
            if code == 0:
                incomplete = bool(record(stage / "deps.json").get("not_run"))
        elif args.step == "capture":
            # Options first, then "--": a source path may begin with "-".
            code = run("evidence_capture.py", ["--findings", findings, "--commit", args.commit,
                                                "--", state["repo"], *args.paths])
        elif args.step == "renumber":
            code = run("findings.py", ["renumber", findings])
        elif args.step == "triage":
            code = run("triage.py", ["apply", findings, Path(args.decisions).resolve()])
        elif args.step == "render":
            def render(where, *extra):
                return run("render.py", [where / "findings.json", "--out", where, "--repo", state["repo"],
                                         "--lang", state["lang"], *extra])

            # HTML is prepared independently of the optional PDF engine.
            code = report_limits(stage, attempt, None, run)
            if code == 0:
                code = render(stage, "--no-pdf")
            if code == 0:
                pdf = None
                if not args.no_pdf:
                    # A stopped engine can leave its staging behind or keep
                    # writing: print on a private copy, used only on success.
                    trial = attempt / "pdf-out"
                    shutil.copytree(stage, trial)
                    pdf = render(trial)
                    if pdf == 0:
                        stage = trial
                if pdf in (None, 3, 124):
                    incomplete = True
                    reason = ("PDF intentionally skipped (--no-pdf)" if pdf is None else
                              "PDF engine failed (runner deadline)" if pdf == 124 else
                              "PDF engine unavailable or failed (render.py exit 3)")
                    code = report_limits(stage, attempt, PDF_LIMIT + ": " + reason, run)
                    if code == 0:
                        code = render(stage, "--no-pdf")
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
            # Pending stops are delivered once the outcome below is saved.
            held = signal.pthread_sigmask(signal.SIG_BLOCK, TERMINATION)
            digest = publish(root, stage, original)
            # Only now is the rollback copy disposable; a failed swap keeps it.
            published = stage
            event.update(status="incomplete" if incomplete else "complete", output_sha256=digest)
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
        try:
            if event["status"] == "running":
                # An unexpected error must not leave a successful-looking record.
                event["status"], code = "failed", code or 2
            event.update(finished=stamp(), exit_code=code if code else (3 if incomplete else 0))
            save(root, state)
        finally:
            if held is not None:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, held)
                except KeyboardInterrupt:
                    stopped = True
    if stopped:
        # The publication stands as recorded; the runner itself still stops.
        event["interrupted_after_record"] = True
        save(root, state)
    if published is not None:
        # Recorded already; a leftover copy is removed by the next recovery.
        shutil.rmtree(root / ".previous-out", ignore_errors=True)
        if published != attempt / "out":
            shutil.rmtree(attempt / "out", ignore_errors=True)
    if emit:
        print(json.dumps({"run": str(root), "out": str(out), **event}, ensure_ascii=False))
    return 130 if stopped else event["exit_code"]


def seconds_between(start, end):
    return max(0.0, (end - datetime.fromisoformat(start)).total_seconds())


def mark_phase(state, name, done, total, now):
    """Record the agent-reported phase; the same phase again updates its counts."""
    marks = state.setdefault("progress", [])
    current = marks[-1] if marks else None
    if current is not None and "finished" not in current and current["phase"] == name:
        mark = current
    else:
        if current is not None and "finished" not in current:
            current["finished"] = now
        if name == "DONE":
            return
        mark = {"phase": name, "started": now}
        marks.append(mark)
    if total is not None:
        mark["total"] = total
    if done is not None:
        mark["done"] = done
    if mark.get("done", 0) > mark.get("total", mark.get("done", 0)):
        raise ValueError("--done cannot exceed --total")
    mark["updated"] = now


def progress(state, now=None):
    """Estimate from recorded phase marks only; nothing is executed or inferred
    from the review content. Unknown stays unknown rather than guessed."""
    now = now or datetime.now(timezone.utc)
    marks = state.get("progress") or []
    running = [{"step": e["step"], "elapsed_seconds": round(seconds_between(e["started"], now))}
               for e in state["history"] if e.get("status") == "running" and "started" in e]
    result = {"phase": None, "phase_index": None, "phases": len(PHASES), "percent": 0,
              "elapsed_seconds": None, "remaining_seconds": None, "eta": None,
              "basis": "no phase recorded", "running": running}
    if not marks:
        return result
    elapsed = seconds_between(marks[0]["started"], now)
    result["elapsed_seconds"] = round(elapsed)
    last = marks[-1]
    if "finished" in last:
        return {**result, "phase": "DONE", "percent": 100, "remaining_seconds": 0,
                "elapsed_seconds": round(seconds_between(marks[0]["started"],
                                                         datetime.fromisoformat(last["finished"]))),
                "eta": last["finished"], "basis": "all phases recorded complete"}
    index = PHASES.index(last["phase"])
    weight = WEIGHTS[last["phase"]]
    # A phase skipped or passed counts as done: the agent moved beyond it.
    before = sum(WEIGHTS[name] for name in PHASES[:index])
    after = sum(WEIGHTS[name] for name in PHASES[index + 1:])
    in_phase = seconds_between(last["started"], now)
    spent_before = elapsed - in_phase
    done, total = last.get("done"), last.get("total")
    fraction = done / total if total and done is not None else None
    result.update(phase=last["phase"], phase_index=index + 1,
                  percent=round(before + weight * (fraction or 0)))
    if total is not None:
        result["units"] = {"done": done or 0, "total": total}
    if before and spent_before > 0:
        pace = spent_before / before
        basis = "pace of completed phases"
    elif fraction:
        pace = in_phase / (weight * fraction)
        basis = "pace of units in the current phase"
    else:
        result["basis"] = "unknown until a phase completes or units are reported"
        return result
    if fraction:
        current_left = in_phase / fraction - in_phase
        basis += "; current phase from its units"
    else:
        current_left = max(0.0, pace * weight - in_phase)
    remaining = current_left + pace * after
    result.update(remaining_seconds=round(remaining), basis=basis,
                  eta=datetime.fromtimestamp(now.timestamp() + remaining, timezone.utc).isoformat())
    return result


def progress_line(report, lang):
    """One line for chat or a terminal; the JSON form carries the same values."""
    def span(seconds):
        if seconds is None:
            return "?"
        minutes = round(seconds / 60)
        return f"{minutes // 60}h{minutes % 60:02d}m" if minutes >= 60 else f"{minutes}m"

    ja = lang == "ja"
    if report["phase"] is None:
        return "進捗未記録" if ja else "no progress recorded"
    eta = (datetime.fromisoformat(report["eta"]).astimezone().strftime("%H:%M")
           if report["eta"] else None)
    phase = ("完了" if ja else "done") if report["phase"] == "DONE" else (
        f"{report['phase']} {report['phase_index']}/{report['phases']}")
    parts = [phase]
    if "units" in report:
        parts.append(f"{report['units']['done']}/{report['units']['total']}")
    parts.append(f"{report['percent']}%")
    parts.append(("経過 " if ja else "elapsed ") + span(report["elapsed_seconds"]))
    if report["phase"] != "DONE":
        parts.append((f"残り約 {span(report['remaining_seconds'])} (完了見込み {eta})" if ja else
                      f"~{span(report['remaining_seconds'])} left (ETA {eta})") if eta else
                     ("残り時間は推定不可" if ja else "time left unknown"))
    for item in report["running"]:
        parts.append(f"{item['step']} " + ("実行中 " if ja else "running ") + span(item["elapsed_seconds"]))
    return " · ".join(parts)


def finish(args, root, state, fd):
    """Deliver independent reporting work without retrying a failed operation."""
    recover(root, state)
    started, steps = stamp(), []

    def run_step(name, **options):
        child = argparse.Namespace(step=name, timeout=args.timeout, **options)
        try:
            code = operation(child, root, state, fd, emit=False)
        except (OSError, ValueError) as error:
            print(f"scan_run.py: {name}: {error}", file=sys.stderr)
            code = 2
            state["history"].append({"step": name, "status": "failed", "exit_code": code,
                                     "finished": stamp()})
            save(root, state)
        event = state["history"][-1]
        steps.append({"step": name, "status": event["status"], "exit_code": code})
        return code

    try:
        data = record(root / "out/findings.json")
    except ValueError as error:
        # Every stage reports its own failure; the summary stays complete.
        print(f"scan_run.py: finish: {error}", file=sys.stderr)
        data = {}
    inventory = data.get("dependency_scan")
    previous = next((event for event in reversed(state["history"])
                     if event.get("step") == "inventory"), None)
    interrupted = False
    if previous is not None and previous.get("status") not in ("complete", "incomplete"):
        inventory_code = previous.get("exit_code")
        if type(inventory_code) is not int or inventory_code in (0, 3):
            inventory_code = 2
        steps.append({"step": "inventory", "status": "not_retried", "exit_code": inventory_code})
    elif (isinstance(inventory, dict) and inventory.get("tool") == "deps_scan.py"
            and (root / "out/deps.json").is_file()):
        inventory_code = 3 if inventory.get("not_run") else 0
        steps.append({"step": "inventory", "status": "already_recorded", "exit_code": inventory_code})
    elif previous is not None:
        # A later finish must not silently retry an earlier failed/refused step.
        inventory_code = 2
        steps.append({"step": "inventory", "status": "not_retried", "exit_code": inventory_code})
    else:
        inventory_code = run_step("inventory", audit=False)
        interrupted = inventory_code == 130

    if not interrupted:
        old = [text for text in limitations(data)
               if isinstance(text, str) and text.startswith(FINISH_LIMIT)]
        note = ([f"{FINISH_LIMIT} (exit {inventory_code}); this static report is partial."]
                if inventory_code not in (0, 3) else [])
        if old or note:
            fragment = root / "scratch" / ("finish-limits-" + os.urandom(8).hex() + ".json")
            write_output(fragment, json.dumps({"remove": {"limitations": old}, "limitations": note}))
            interrupted = run_step("merge", fragments=[str(fragment)]) == 130
    if not interrupted:
        interrupted = run_step("render", no_pdf=args.no_pdf) == 130
    if not interrupted:
        interrupted = run_step("check", allow=args.allow) == 130

    codes = [step["exit_code"] for step in steps]
    if interrupted:
        code, status = 130, "interrupted"
    elif any(value not in (0, 3) for value in codes):
        code, status = 2, "failed"
    elif 3 in codes:
        code, status = 3, "incomplete"
    else:
        code, status = 0, "complete"
    event = {"step": "finish", "started": started, "finished": stamp(), "steps": steps,
             "status": status, "exit_code": code,
             "output_sha256": tree_digest(root / "out")}
    state["history"].append(event)
    save(root, state)
    print(json.dumps({"run": str(root), "out": str(root / "out"), **event}, ensure_ascii=False))
    return code


@contextmanager
def termination_as_interrupt():
    """A host stopping the runner gets the same child cleanup as Ctrl-C.

    Without this, SIGTERM or SIGHUP ends the runner at once and its child keeps
    running past its deadline while holding the run lock. A signal the caller
    chose to ignore (for example under nohup) stays ignored.
    """
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    previous = {}
    try:
        for sig in (signal.SIGTERM, signal.SIGHUP):
            if signal.getsignal(sig) is not signal.SIG_IGN:
                previous[sig] = signal.signal(sig, interrupt)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def positive_seconds(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0 or seconds > 3600:
        raise argparse.ArgumentTypeError("timeout must be positive, finite and at most 3600 seconds")
    return seconds


def count(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or more")
    return number


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
    mark = sub.add_parser("phase", help="record the review phase the agent is starting or its unit counts")
    mark.add_argument("run", type=Path)
    mark.add_argument("name", type=str.upper, choices=(*PHASES, "DONE"))
    mark.add_argument("--done", type=count)
    mark.add_argument("--total", type=count)
    view = sub.add_parser("progress", help="show phase, completion and estimated finish without locking")
    view.add_argument("run", type=Path)
    view.add_argument("--text", action="store_true", help="one line instead of JSON")
    final = sub.add_parser("finish", help="finish independent report operations despite incomplete steps")
    final.add_argument("run", type=Path)
    final.add_argument("--timeout", type=positive_seconds, default=60)
    final.add_argument("--no-pdf", action="store_true")
    final.add_argument("--allow", action="append", default=[])
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
        elif name == "triage":
            child.add_argument("decisions", help="a decisions file for triage.py apply")
        elif name == "render":
            child.add_argument("--no-pdf", action="store_true")
        elif name == "check":
            child.add_argument("--allow", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        with termination_as_interrupt():
            return dispatch(args)
    except KeyboardInterrupt:
        print("scan_run.py: interrupted", file=sys.stderr)
        return 130


def dispatch(args):
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
        if args.step == "progress":
            # Reads the atomically replaced journal only, so it works while
            # another operation holds the lock.
            report = progress(state)
            print(progress_line(report, state["lang"]) if args.text
                  else json.dumps({"run": str(root), **report}, ensure_ascii=False, indent=2))
            return 0
        with run_lock(root) as fd:
            # Re-read under the lock; concurrent invocations cannot lose history.
            state = load(root)
            if args.step == "finish":
                return finish(args, root, state, fd)
            if args.step == "phase":
                mark_phase(state, args.name, args.done, args.total, stamp())
                save(root, state)
                print(json.dumps({"run": str(root), **progress(state)}, ensure_ascii=False))
                return 0
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
                print(json.dumps({"run": str(root), "out": str(root / "out"), "busy": False,
                                  "output_sha256": current, **state}, ensure_ascii=False, indent=2))
                return 0
            return operation(args, root, state, fd)
    except BlockingIOError as error:
        if args.step == "status":
            # Read the atomic journal only: outputs may be between publication
            # renames, and a live operation must not be marked interrupted.
            try:
                snapshot = load(root)
            except (OSError, ValueError):
                snapshot = {"state_unavailable": True}
            print(json.dumps({**snapshot, "run": str(root), "out": str(root / "out"),
                              "busy": True, "output_sha256": None}, ensure_ascii=False, indent=2))
        print(f"scan_run.py: {error}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as error:
        print(f"scan_run.py: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
