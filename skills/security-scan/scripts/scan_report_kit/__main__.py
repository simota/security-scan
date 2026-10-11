"""Render a common-format report into a dashboard, a printable report and its PDF.

    python3 -m scan_report_kit report.json --out DIR [--lang ja|en] [--no-pdf]

Writes DIR/dashboard.html, DIR/report.html and DIR/report.pdf (headless Chrome,
else WeasyPrint; set CHROME to pick a binary, SCAN_REPORT_PDF_TIMEOUT for seconds).
Exit status: 0 written, 2 invalid input or unwritable output, 3 no PDF produced.
"""

import argparse
import json
import sys
from pathlib import Path

from . import output, pdf, report

OUTPUTS = ("dashboard.html", "report.html", "report.pdf")


def main(argv=None):
    p = argparse.ArgumentParser(prog="scan_report_kit", description=__doc__.splitlines()[0])
    p.add_argument("report")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(report.LABELS), default="en")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    a = p.parse_args(argv)
    try:
        data = report.validate(json.loads(Path(a.report).read_text(encoding="utf-8")))
        dashboard, document = report.render_dashboard(data, a.lang), report.render_document(data, a.lang)
    except (report.FormatError, ValueError, OSError) as e:
        print(f"scan_report_kit: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        bad = output.unsafe_target(out, OUTPUTS)
        if bad:
            print(f"scan_report_kit: refusing to write {bad}: it exists as a symlink or non-regular file",
                  file=sys.stderr)
            return 2
        output.write_output(out / "dashboard.html", dashboard)
        output.write_output(out / "report.html", document)
        if a.no_pdf:
            (out / "report.pdf").unlink(missing_ok=True)
    except OSError as e:
        print(f"scan_report_kit: cannot write outputs to {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    print(f"wrote {out / 'dashboard.html'}")
    print(f"wrote {out / 'report.html'}")
    if a.no_pdf:
        return 0
    failures = []
    engine = pdf.to_pdf(out / "report.html", out / "report.pdf", failures,
                        timeout=pdf.pdf_timeout(len(data["findings"])))
    if not engine:
        detail = "; ".join(f"{name} {why}" + (f" [{tail}]" if tail else "") for name, why, tail in failures)
        print("scan_report_kit: " + (f"PDF engine failed: {detail}" if failures else
                                     "no PDF engine found (Chrome/Chromium or weasyprint)")
              + ". report.html is ready to print.", file=sys.stderr)
        return 3
    print(f"wrote {out / 'report.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
