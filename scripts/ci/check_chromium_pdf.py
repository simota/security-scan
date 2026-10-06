#!/usr/bin/env python3
"""Bounded, synthetic-only diagnostic for the renderer's actual Chromium flags."""
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time


def run_preflight(chrome, output, timeout=20, headless_flags=("--headless=new", "--disable-gpu")):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    html = output / "probe.html"
    pdf = output / "probe.pdf"
    pdf.unlink(missing_ok=True)
    html.write_text('<!doctype html><meta charset="utf-8"><title>Synthetic PDF probe</title>'
                    '<p>SYNTHETIC_PDF_PROBE 日本語</p>', encoding="utf-8")
    try:
        version = subprocess.run([chrome, "--version"], capture_output=True, text=True, timeout=3)
        (output / "version.txt").write_text(version.stdout + version.stderr, encoding="utf-8")
    except (OSError, subprocess.TimeoutExpired) as error:
        (output / "version.txt").write_text(str(error), encoding="utf-8")
    succeeded = False
    with tempfile.TemporaryDirectory(prefix="security-scan-chrome-probe-") as profile:
        # The baseline and system-browser comparison use the production flags.
        command = [chrome, *headless_flags, "--no-pdf-header-footer",
                   f"--user-data-dir={profile}", f"--print-to-pdf={pdf.resolve()}",
                   html.resolve().as_uri()]
        (output / "command.txt").write_text("\n".join(command) + "\n", encoding="utf-8")
        with (output / "stdout.txt").open("w") as stdout, (output / "stderr.txt").open("w") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            last, deadline = -1, time.monotonic() + timeout
            try:
                while time.monotonic() < deadline:
                    size = pdf.stat().st_size if pdf.exists() else -1
                    if size > 0 and size == last:
                        succeeded = pdf.read_bytes().startswith(b"%PDF-")
                        break
                    if process.poll() is not None and size <= 0:
                        break
                    last = size
                    time.sleep(0.25)
            finally:
                if process.poll() is None:
                    # Terminate only the process group created for this probe.
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)
        (output / "result.txt").write_text(
            f"pdf_created={succeeded}\nexit_code={process.returncode}\ntimeout_seconds={timeout}\n",
            encoding="utf-8")
    print(f"Chromium CLI PDF preflight [{output.name}]: {'passed' if succeeded else 'FAILED'}", flush=True)
    if not succeeded:
        for name in ("version.txt", "command.txt", "result.txt", "stdout.txt", "stderr.txt"):
            contents = (output / name).read_text(encoding="utf-8", errors="replace")
            print(f"--- {name} ---\n{contents[:32000]}", file=sys.stderr, flush=True)
        print(f"Full synthetic diagnostic artifacts: {output}", file=sys.stderr, flush=True)
    return 0 if succeeded else 1


def main():
    chrome = os.environ.get("CHROME")
    artifacts = os.environ.get("SECURITY_SCAN_REPORT_ARTIFACTS")
    if not chrome or not artifacts:
        print("Set CHROME and SECURITY_SCAN_REPORT_ARTIFACTS for the CI PDF probe.", file=sys.stderr)
        return 1
    result = run_preflight(chrome, Path(artifacts) / "chromium-preflight")
    if result:
        # A diagnostic-only comparison, never a replacement for the production
        # command or permission to consider the required PDF tests successful.
        system_chrome = shutil.which("google-chrome") or shutil.which("google-chrome-stable")
        comparison = Path(artifacts) / "system-chrome-diagnostic"
        if system_chrome:
            run_preflight(system_chrome, comparison)
        else:
            comparison.mkdir(parents=True, exist_ok=True)
            message = "System Google Chrome comparison unavailable: executable not installed."
            (comparison / "result.txt").write_text("available=False\n" + message + "\n", encoding="utf-8")
            print(message, flush=True)
        # A separate two-flag diagnostic for the originally selected binary.
        run_preflight(chrome, Path(artifacts) / "chromium-plain-headless-diagnostic",
                      headless_flags=("--headless",))
    return result


if __name__ == "__main__":
    sys.exit(main())
