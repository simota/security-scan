"""Bounded end-to-end regressions for source-secret redaction."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import render


class RedactionLimitTests(unittest.TestCase):
    def test_unterminated_escape_runs_do_not_block_report_generation(self):
        with tempfile.TemporaryDirectory(prefix="security-scan-redaction-limit-") as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            source = "\n".join("# password = " + quote + "\\" * 10000 + "UNTERMINATED"
                               for quote in ('"', "'")) + "\n"
            (repo / "app.py").write_text(source, encoding="utf-8")
            findings = root / "findings.json"
            findings.write_text(json.dumps({
                "meta": {"project": "Inert redaction fixture", "date": "2026-10-07"},
                "findings": [{"id": "F-001", "title": "Inert comment", "severity": "Info",
                              "confidence": "Suspected", "location": "app.py:1-2"}],
            }), encoding="utf-8")
            # A parent timeout turns pathological backtracking into a test
            # failure and always terminates the child; no timing microbenchmark.
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPTS / "render.py"), str(findings),
                 "--repo", str(repo), "--out", str(root / "report"), "--no-pdf"],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("dashboard.html", "assessment.html"):
                report = (root / "report" / name).read_text(encoding="utf-8")
                self.assertIn("Inert comment", report)
                self.assertNotIn("UNTERMINATED", report)

    def test_escaped_quote_values_are_still_fully_redacted(self):
        for quote in ('"', "'"):
            for separator in (" ", "\r"):
                with self.subTest(quote=quote, separator=separator):
                    value = "password = " + quote + "prefix\\" + quote + "SYNTHETIC_SECRET" + separator + "with spaces" + quote
                    self.assertEqual(render.redact(value), "password = " + quote + "********" + quote)


if __name__ == "__main__":
    unittest.main()
