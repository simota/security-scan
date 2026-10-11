"""Print an HTML page to PDF with headless Chrome, else WeasyPrint. Standard library only."""

import math
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

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
    """The last meaningful stderr line(s), on one line, for the diagnostic."""
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    tail = " | ".join(lines[-2:])
    return redact(tail[-limit:]) if tail else ""


def to_pdf(html_path, pdf_path, failures=None, timeout=None, redact=None):
    """Print html_path to pdf_path with headless Chrome, else WeasyPrint. Returns the engine used or None.

    failures, when a list, receives one (engine, reason, stderr tail) triple for
    each engine that was found but failed or timed out, so the caller can tell
    "no engine" from "engine failed". redact, when given, is applied to every
    stderr tail before it is recorded (engine output can echo page content).
    """
    failures = [] if failures is None else failures
    timeout = pdf_timeout() if timeout is None else timeout
    redact = redact or (lambda text: text)
    # A previous run's PDF must never survive next to newer HTML.
    Path(pdf_path).unlink(missing_ok=True)
    chrome = os.environ.get("CHROME")
    cands = [chrome] if chrome else CHROME_CANDIDATES
    for c in cands:
        exe = c if os.path.isabs(c) and os.path.exists(c) else shutil.which(c)
        if not exe:
            continue
        pdf = Path(pdf_path)
        pdf.unlink(missing_ok=True)
        # Chrome refuses to start as root without --no-sandbox (containers, CI).
        sandbox = ["--no-sandbox"] if _running_as_root() else []
        timed_out = False
        with tempfile.TemporaryDirectory() as profile, tempfile.TemporaryFile("w+", encoding="utf-8",
                                                                              errors="replace") as err:
            try:
                proc = subprocess.Popen(
                    [exe, "--headless=new", "--disable-gpu", *sandbox, "--no-pdf-header-footer",
                     f"--user-data-dir={profile}", f"--print-to-pdf={pdf}", Path(html_path).resolve().as_uri()],
                    stdout=subprocess.DEVNULL, stderr=err)
            except OSError as e:
                failures.append(("chrome", "could not be started", str(e.strerror or e)))
                continue
            # Chrome on some platforms keeps running after the PDF is written:
            # wait for the file to appear and stop growing, then stop the process.
            last, deadline = -1, time.monotonic() + timeout
            while True:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                size = pdf.stat().st_size if pdf.exists() else -1
                if proc.poll() is not None and size <= 0 and (size < 0 or size == last):
                    break  # Exited without writing (or left an empty file): try the next engine.
                if size > 0 and size == last:
                    break
                last = size
                time.sleep(0.5)
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if pdf.exists() and pdf.stat().st_size > 0:
                return "chrome"
            err.seek(0)
            detail = _tail(err.read(), redact)
        reason = (f"timed out after {timeout:g} s" if timed_out
                  else f"exited with status {proc.returncode} without writing a PDF")
        failures.append(("chrome", reason + (" (as root, with --no-sandbox)" if sandbox else ""), detail))
        pdf.unlink(missing_ok=True)
    wp = shutil.which("weasyprint")
    if wp:
        try:
            r = subprocess.run([wp, str(html_path), str(pdf_path)], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            failures.append(("weasyprint", f"timed out after {timeout:g} s", ""))
            Path(pdf_path).unlink(missing_ok=True)
            return None
        except OSError as e:
            failures.append(("weasyprint", "could not be started", str(e.strerror or e)))
            return None
        if r.returncode == 0 and Path(pdf_path).exists():
            return "weasyprint"
        detail = _tail(r.stderr, redact)
        failures.append(("weasyprint", f"exited with status {r.returncode} without writing a PDF", detail))
    return None
