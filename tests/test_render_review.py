"""render.py regressions: excerpt numbering, ordering, CWE values and PDF fallbacks."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location("render_review_" + name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


def finding(fid="F-001", **extra):
    return {"id": fid, "title": "Synthetic fixture", "severity": "High", "confidence": "Confirmed",
            "location": "app.py:4", **extra}


class RenderReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.render = load_script("render")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-render-review-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def load(self, *findings):
        path = self.root / "findings.json"
        path.write_text(json.dumps({"meta": {"project": "Synthetic", "date": "2026-10-09"},
                                    "findings": list(findings)}), encoding="utf-8")
        return self.render.load(path)

    def test_excerpt_lines_match_git_numbering(self):
        (self.root / "app.py").write_bytes(b"line1\nline2\x0cstill2\r\nline3\nTARGET4\nline5\n")
        data = self.load(finding())
        self.render.attach_sources(data, self.root, context=0)
        self.assertEqual(data["findings"][0]["snippet"]["lines"], ["TARGET4"])

    def test_location_past_end_of_file_has_no_excerpt(self):
        (self.root / "app.py").write_text("one\ntwo\n", encoding="utf-8")
        data = self.load(finding(location="app.py:50"))
        self.render.attach_sources(data, self.root)
        self.assertNotIn("snippet", data["findings"][0])

    def test_cwe_requires_ascii_digits_and_allows_empty(self):
        for bad in ("CWE-79\n", "CWE-７９"):
            with self.subTest(cwe=bad), self.assertRaises(self.render.SchemaError):
                self.load(finding(cwe=bad))
        self.assertNotIn("cwe", self.load(finding(cwe=""))["findings"][0])

    def test_code_findings_precede_dependency_findings_in_the_queue(self):
        data = self.load(finding("D-001"), finding("F-001"))
        queue = [item["finding"]["id"] for item in self.render.report_model(data)["queue"]]
        self.assertEqual(queue, ["F-001", "D-001"])

    def test_dashboard_search_ignores_key_names(self):
        html = self.render.render_dashboard(self.load(finding()), self.render.LABELS["en"], "en")
        self.assertIn("function searchText(f)", html)
        self.assertNotIn("JSON.stringify(f).toLowerCase()", html)

    def fake_engine(self, name, body):
        tool = self.root / "bin" / name
        tool.parent.mkdir(exist_ok=True)
        tool.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        tool.chmod(0o755)
        return tool

    @unittest.skipIf(os.name == "nt", "POSIX shell fixture")
    def test_chrome_leaving_an_empty_pdf_fails_fast(self):
        chrome = self.fake_engine("chrome", 'for a; do case "$a" in --print-to-pdf=*) : > "${a#*=}";; esac; done; exit 1')
        html = self.root / "a.html"
        html.write_text("<p>x</p>", encoding="utf-8")
        started = time.monotonic()
        with patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(chrome.parent)}):
            self.assertIsNone(self.render.to_pdf(html, self.root / "a.pdf"))
        self.assertLess(time.monotonic() - started, 10)

    @unittest.skipIf(os.name == "nt", "POSIX shell fixture")
    def test_weasyprint_timeout_is_not_a_crash_and_stale_pdf_is_removed(self):
        self.fake_engine("weasyprint", "exit 0")
        html, pdf = self.root / "a.html", self.root / "a.pdf"
        html.write_text("<p>x</p>", encoding="utf-8")
        pdf.write_bytes(b"%PDF stale")
        timeout = self.render.subprocess.TimeoutExpired("weasyprint", 120)
        with patch.dict(os.environ, {"CHROME": str(self.root / "missing"), "PATH": str(self.root / "bin")}), \
             patch.object(self.render.subprocess, "run", side_effect=timeout):
            self.assertIsNone(self.render.to_pdf(html, pdf))
        self.assertFalse(pdf.exists())

    def test_unwritable_output_is_reported_without_traceback(self):
        source = self.root / "findings.json"
        source.write_text(json.dumps({"meta": {"project": "Synthetic", "date": "2026-10-09"},
                                      "findings": [finding()]}), encoding="utf-8")
        blocker = self.root / "out"
        blocker.write_text("not a directory", encoding="utf-8")
        with patch.object(sys, "stderr"), patch.object(sys, "stdout"):
            code = self.render.main([str(source), "--out", str(blocker), "--no-pdf"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
