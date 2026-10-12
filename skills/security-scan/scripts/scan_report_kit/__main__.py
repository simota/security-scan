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


def _unique_object(pairs):
    """Reject ambiguous objects before JSON decoding can discard report data."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise report.FormatError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value):
    raise report.FormatError(f"invalid JSON constant: {value}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="scan_report_kit", description=__doc__.splitlines()[0])
    p.add_argument("report")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(report.LABELS), default="en")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    a = p.parse_args(argv)
    try:
        data = report.validate(json.loads(Path(a.report).read_text(encoding="utf-8"),
                                          object_pairs_hook=_unique_object,
                                          parse_constant=_reject_constant))
        dashboard, document = report.render_dashboard(data, a.lang), report.render_document(data, a.lang)
    except (report.FormatError, ValueError, OSError, RecursionError) as e:
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
        source = Path(a.report).resolve()
        for name in OUTPUTS:
            target = out / name
            if target.resolve() == source or (target.exists() and source.samefile(target)):
                print(f"scan_report_kit: refusing to overwrite input report {a.report}", file=sys.stderr)
                return 2
        # Prepare both linked pages before changing any output, and invalidate
        # the previous PDF only as part of the same recoverable update.
        output.write_outputs(out, {"dashboard.html": dashboard, "report.html": document},
                             remove=("report.pdf",))
    except (OSError, UnicodeError) as e:
        print(f"scan_report_kit: cannot write outputs to {out}: {getattr(e, 'strerror', None) or e}", file=sys.stderr)
        return 2
    print(f"wrote {out / 'dashboard.html'}")
    print(f"wrote {out / 'report.html'}")
    if a.no_pdf:
        return 0
    failures = []
    try:
        engine = pdf.to_pdf(out / "report.html", out / "report.pdf", failures,
                            timeout=pdf.pdf_timeout(len(data["findings"])))
    except OSError as e:
        print(f"scan_report_kit: cannot write PDF to {out}: {e.strerror or e}. "
              "report.html is ready to print.", file=sys.stderr)
        return 2
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
