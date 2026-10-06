"""Offline CI contracts and real CLI-generated PDF regressions.

PDF tests are optional for stdlib-only local runs and mandatory in the strict CI
runner. They only render synthetic fixtures; they never invoke an advisory scan.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
BROWSER_TESTS = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"


class RequiredCIRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "required_ci_runner", REPO / "scripts/ci/run_required_tests.py")
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_skipped_required_test_fails_the_runner(self):
        class Skipped(unittest.TestCase):
            def runTest(self):
                self.skipTest("browser dependency is missing")

        stream = io.StringIO()
        self.assertEqual(self.runner.run_suite(unittest.TestSuite([Skipped()]), stream), 1)
        self.assertIn("refusing a successful result", stream.getvalue())

    def test_expected_failure_fails_the_runner(self):
        class ExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail("a required regression cannot be waived")

        stream = io.StringIO()
        self.assertEqual(self.runner.run_suite(unittest.TestSuite([ExpectedFailure()]), stream), 1)
        self.assertIn("expected failures", stream.getvalue())

    def test_empty_suite_fails_the_runner(self):
        self.assertEqual(self.runner.run_suite(unittest.TestSuite(), io.StringIO()), 1)

    def test_passing_suite_succeeds(self):
        self.assertEqual(self.runner.run_suite(
            unittest.TestSuite([unittest.FunctionTestCase(lambda: None)]), io.StringIO()), 0)

    def test_failing_suite_fails_the_runner(self):
        class Failed(unittest.TestCase):
            def runTest(self):
                self.fail("synthetic regression")

        self.assertEqual(self.runner.run_suite(unittest.TestSuite([Failed()]), io.StringIO()), 1)

    def test_required_browser_and_pdf_tests_are_present(self):
        suite = unittest.TestLoader().discover(str(REPO / "tests"))
        self.assertFalse(self.runner.REQUIRED_TESTS - set(self.runner.test_ids(suite)))


@unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium PDF tests")
class ReportArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chrome = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not cls.chrome or not shutil.which(cls.chrome):
            raise AssertionError("Required Chromium is missing; set CHROME to the installed executable")
        for command in ("pdftotext", "pdfinfo", "fc-list"):
            if not shutil.which(command):
                raise AssertionError(f"Required PDF test dependency is missing: {command}")
        fonts = subprocess.run(["fc-list", ":lang=ja", "family"],
                               capture_output=True, text=True, check=True, timeout=15)
        if not fonts.stdout.strip():
            raise AssertionError("Japanese fonts are missing; install fonts-noto-cjk")

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="security-scan-pdf-tests-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        destination = os.environ.get("SECURITY_SCAN_REPORT_ARTIFACTS")
        self.artifacts = Path(destination) if destination else self.root / "artifacts"

    @staticmethod
    def normalized(text):
        # Drop only generated page furniture before checking paragraphs that may
        # cross a page boundary; retain the original extraction in the artifact.
        footer = re.compile(r"\s*(?:SECURITY ASSESSMENT(?:\s+\d+\s*/\s*\d+)?|\d+\s*/\s*\d+)\s*")
        content = " ".join(line for line in text.splitlines() if not footer.fullmatch(line))
        # PDF line wrapping can insert spaces between Japanese glyphs or split words.
        return "".join(content.split())

    def render_pdf(self, input_path, lang, name):
        output = self.artifacts / name
        output.mkdir(parents=True, exist_ok=True)
        pdf = output / "assessment.pdf"
        # A previous run's PDF must never turn a failed render into a passing test.
        pdf.unlink(missing_ok=True)
        completed = subprocess.run(
            [sys.executable, str(REPO / "skills/security-scan/scripts/render.py"),
             str(input_path), "--out", str(output), "--lang", lang],
            env={**os.environ, "CHROME": self.chrome}, capture_output=True, text=True,
            timeout=150, cwd=REPO)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("(chrome)", completed.stdout,
                      "CI requires real Chromium output, not a fallback PDF engine")
        self.assertTrue(pdf.is_file(), "The CLI did not create assessment.pdf")
        self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
        text_path = output / "assessment.txt"
        subprocess.run(["pdftotext", "-enc", "UTF-8", str(pdf), str(text_path)],
                       capture_output=True, text=True, check=True, timeout=30)
        text = text_path.read_text(encoding="utf-8")
        self.assertTrue(text.strip(), "The PDF has no extractable text")
        info = subprocess.run(["pdfinfo", str(pdf)], capture_output=True,
                              text=True, check=True, timeout=30).stdout
        (output / "pdfinfo.txt").write_text(info, encoding="utf-8")
        pages = re.search(r"^Pages:\s+(\d+)$", info, re.MULTILINE)
        self.assertIsNotNone(pages, info)
        title = "セキュリティ診断書" if lang == "ja" else "Security Assessment Report"
        self.assertIn(self.normalized(title), self.normalized(text))
        return text, int(pages.group(1))

    def check_sample(self, lang):
        name = "findings.sample.ja.json" if lang == "ja" else "findings.sample.json"
        sample = REPO / "examples" / name
        data = json.loads(sample.read_text(encoding="utf-8"))
        text, pages = self.render_pdf(sample, lang, lang + "-sample")
        self.assertGreaterEqual(pages, 1)
        extracted = self.normalized(text)
        self.assertIn(self.normalized(data["meta"]["project"]), extracted)
        for finding in data["findings"]:
            with self.subTest(finding=finding["id"]):
                self.assertIn(self.normalized(finding["title"]), extracted)
                evidence = finding.get("validation", {}).get("evidence", "")
                if evidence:
                    self.assertIn(self.normalized(evidence), extracted)
                previous = finding.get("previous_validation", {}).get("evidence", "")
                if previous:
                    self.assertIn(self.normalized(previous), extracted)

    def test_english_sample_pdf(self):
        self.check_sample("en")

    def test_japanese_sample_pdf(self):
        self.check_sample("ja")

    def check_long_pdf(self, lang):
        sentence = ("これは架空の検証根拠です。改ページの前後を含め、すべての文章が診断書に残る必要があります。"
                    if lang == "ja" else
                    "This is synthetic validation evidence. Every paragraph must survive page breaks in the generated assessment.")
        evidence = [f"EVIDENCE_{index:03d}: {sentence}" for index in range(120)]
        fixes = [f"FIX_{index:03d}: {sentence}" for index in range(60)]
        payload = {
            "meta": {"project": "PDF 長文テスト" if lang == "ja" else "Long PDF fixture",
                     "date": "2026-10-06"},
            "findings": [{
                "id": "LONG-001", "title": "長い検証根拠" if lang == "ja" else "Long validation evidence",
                "severity": "High", "confidence": "Confirmed", "location": "synthetic.py:1",
                "impact": sentence, "fix": "\n\n".join(fixes),
                "validation": {"verdict": "Valid", "method": "review",
                               "evidence": "\n\n".join(evidence)},
            }],
        }
        source = self.root / "long-findings.json"
        source.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        text, pages = self.render_pdf(source, lang, lang + "-long")
        self.assertGreaterEqual(pages, 3, "Long evidence must really span PDF pages")
        extracted = self.normalized(text)
        # Check every complete paragraph, not just first/last sentinels or PDF size.
        for paragraph in fixes + evidence:
            self.assertIn(self.normalized(paragraph), extracted)

    def test_english_long_pdf_retains_every_evidence_paragraph(self):
        self.check_long_pdf("en")

    def test_japanese_long_pdf_retains_every_evidence_paragraph(self):
        self.check_long_pdf("ja")


if __name__ == "__main__":
    unittest.main()
