"""Print an HTML page to PDF with headless Chrome, else WeasyPrint. Standard library only."""

import math
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from .output import unsafe_target

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
]

PDF_TIMEOUT_BASE, PDF_TIMEOUT_PER_FINDING, PDF_TIMEOUT_MAX = 120.0, 0.05, 900.0
TIMEOUT_ENV = "SCAN_REPORT_PDF_TIMEOUT"


def pdf_timeout(findings=0, env=TIMEOUT_ENV):
    """Seconds one engine may take: the env variable when set, else scaled by report size."""
    value = os.environ.get(env, "").strip()
    if value:
        try:
            seconds = float(value)
            if math.isfinite(seconds) and seconds > 0:
                return seconds
        except ValueError:
            pass
    return min(PDF_TIMEOUT_MAX, PDF_TIMEOUT_BASE + PDF_TIMEOUT_PER_FINDING * max(0, findings))


def _running_as_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _tail(text, redact, limit=300):
    """Redact before truncating, so truncation cannot hide a secret's prefix."""
    cleaned = redact(str(text or ""))
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    return " | ".join(lines[-2:])[-limit:]


def _complete_pdf(path):
    """Reject empty, non-PDF and visibly truncated output; not a full PDF parser."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_size < 12:
        return False
    with path.open("rb") as handle:
        if handle.read(5) != b"%PDF-":
            return False
        handle.seek(max(0, info.st_size - 1024))
        return handle.read().rstrip().endswith(b"%%EOF")


def _stop(proc):
    """Reap an engine and its POSIX process group, returning its prior status."""
    status = proc.poll()
    grouped = os.name == "posix"

    def stop_group(sig):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            # macOS reports EPERM, not ESRCH, while the group's remaining
            # members are exiting. A leader still running is signalled
            # directly, so a refusal can never leave the wait below unbounded.
            if proc.poll() is None:
                proc.send_signal(sig)

    if grouped:
        stop_group(signal.SIGTERM)
    elif status is None:
        proc.terminate()
    try:
        if status is None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if grouped:
                    stop_group(signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait()
    finally:
        # A launcher can exit before its children; do not leave renderers
        # running after a successful print, timeout, or interruption.
        if grouped:
            stop_group(signal.SIGKILL)
    if status is None and grouped and proc.returncode not in (-signal.SIGTERM, -signal.SIGKILL):
        # The engine may have exited on its own between poll() and killpg().
        # Preserve a failure instead of treating it as our intentional stop.
        return proc.returncode
    return status


def _publish(source, destination, mode):
    # The engine never sees the final destination. Refuse a newly planted
    # symlink/FIFO, then atomically replace a regular file (never follow links).
    bad = unsafe_target(destination.parent, [destination.name])
    if bad:
        raise OSError(f"refusing to write {bad}: symlink or non-regular file")
    os.chmod(source, mode)
    os.replace(source, destination)


def to_pdf(html_path, pdf_path, failures=None, timeout=None, redact=None):
    """Print HTML with Chrome, else WeasyPrint; return the engine used or None.

    failures receives (engine, reason, redacted stderr tail) for each failed
    attempt. Each engine writes privately; only successful, complete output is
    published. A timeout never succeeds. Stale output is removed before trying
    engines. Invalid paths and output I/O errors raise OSError or ValueError.
    """
    failures = [] if failures is None else failures
    timeout = pdf_timeout() if timeout is None else float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("PDF timeout must be a positive, finite number")
    redact = redact or (lambda text: text)
    html, pdf = Path(html_path).resolve(), Path(pdf_path).absolute()
    if html == pdf.resolve() or (pdf.exists() and html.exists() and html.samefile(pdf)):
        raise ValueError("HTML input and PDF output must be different files")
    if not html.is_file():
        raise FileNotFoundError(f"HTML input is not a regular file: {html}")
    bad = unsafe_target(pdf.parent, [pdf.name])
    if bad:
        raise OSError(f"refusing to write {bad}: symlink or non-regular file")
    mode = (stat.S_IMODE(pdf.stat().st_mode) & 0o777) if pdf.exists() else 0o600
    # A previous run's PDF must never survive next to newer HTML.
    pdf.unlink(missing_ok=True)
    chrome = os.environ.get("CHROME")
    candidates = [chrome] if chrome else CHROME_CANDIDATES
    # Keep engine output away from public paths and on the same filesystem as
    # the destination so publication is atomic.
    with tempfile.TemporaryDirectory(prefix=".scan-report-pdf-", dir=str(pdf.parent)) as staging:
        staged = Path(staging) / "report.pdf"
        tried = set()
        for candidate in candidates:
            exe = (candidate if os.path.isabs(candidate) and os.path.exists(candidate)
                   else shutil.which(candidate))
            if not exe:
                continue
            identity = os.path.realpath(exe)
            if identity in tried:
                continue
            tried.add(identity)
            staged.unlink(missing_ok=True)
            sandbox = ["--no-sandbox"] if _running_as_root() else []
            timed_out = False
            with tempfile.TemporaryDirectory(dir=staging) as profile, tempfile.TemporaryFile(
                    "w+", encoding="utf-8", errors="replace", dir=staging) as err:
                try:
                    proc = subprocess.Popen(
                        [exe, "--headless=new", "--disable-gpu", *sandbox, "--no-pdf-header-footer",
                         f"--user-data-dir={profile}", f"--print-to-pdf={staged}", html.as_uri()],
                        stdout=subprocess.DEVNULL, stderr=err, start_new_session=os.name == "posix")
                except OSError as error:
                    failures.append(("chrome", "could not be started", _tail(error.strerror or error, redact)))
                    continue
                try:
                    last, deadline = -1, time.monotonic() + timeout
                    while True:
                        status = proc.poll()
                        if status is not None:
                            break
                        if time.monotonic() >= deadline:
                            timed_out = True
                            break
                        size = staged.stat().st_size if staged.exists() else -1
                        # Some Chrome versions stay alive after printing. Do
                        # not stop them at a pause in an incomplete PDF write.
                        if size > 0 and size == last and _complete_pdf(staged):
                            break
                        last = size
                        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
                    status = proc.poll()
                finally:
                    stopped_status = _stop(proc)
                if status is None:
                    status = stopped_status
                if not timed_out and status in (None, 0) and _complete_pdf(staged):
                    _publish(staged, pdf, mode)
                    return "chrome"
                err.seek(0)
                detail = _tail(err.read(), redact)
            if timed_out:
                reason = f"timed out after {timeout:g} s"
            elif staged.exists() and staged.stat().st_size:
                reason = f"exited with status {status}; its PDF was discarded"
            else:
                reason = f"exited with status {status} without writing a PDF"
            if not timed_out and status == 0 and staged.exists():
                reason += " (empty, invalid or incomplete PDF)"
            failures.append(("chrome", reason + (" (as root, with --no-sandbox)" if sandbox else ""), detail))
            staged.unlink(missing_ok=True)
        wp = shutil.which("weasyprint")
        if wp:
            with tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace", dir=staging) as err:
                try:
                    proc = subprocess.Popen([wp, str(html), str(staged)], stdout=subprocess.DEVNULL,
                                            stderr=err, start_new_session=os.name == "posix")
                except OSError as error:
                    failures.append(("weasyprint", "could not be started", _tail(error.strerror or error, redact)))
                    return None
                try:
                    try:
                        status = proc.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        failures.append(("weasyprint", f"timed out after {timeout:g} s", ""))
                        return None
                finally:
                    _stop(proc)
                if status == 0 and _complete_pdf(staged):
                    _publish(staged, pdf, mode)
                    return "weasyprint"
                err.seek(0)
                detail = _tail(err.read(), redact)
            reason = f"exited with status {status} without writing a complete PDF"
            failures.append(("weasyprint", reason, detail))
    return None
