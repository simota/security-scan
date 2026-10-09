"""Regressions for URL redaction, evidence capture and the integrity CLI."""
import json
import os
import subprocess
import sys
import unittest

import test_run_contract as fixture
from test_run_contract import SCRIPTS, git
from test_security_scan import import_module

sys.path.insert(0, str(SCRIPTS))
from url_redaction import redact_urls  # noqa: E402


class RedactionReviewTests(unittest.TestCase):
    def test_json_escaped_url_credentials_are_removed(self):
        text = '{"url":"https:\\/\\/oauth2:SYNTHETIC_TOKEN@gitlab.invalid\\/x.git?t=SYNTHETIC_Q"}'
        self.assertEqual(redact_urls(text), '{"url":"https:\\/\\/gitlab.invalid\\/x.git"}')

    def test_parameters_in_the_host_part_are_redacted(self):
        for text in ("jdbc:sqlserver://db.invalid;user=sa;pwd=SYNTHETIC_PW",
                     "https://host.invalid;auth=SYNTHETIC_PW/path"):
            with self.subTest(text=text):
                self.assertNotIn("SYNTHETIC_PW", redact_urls(text))
        self.assertEqual(redact_urls("https://host.invalid:8443/a?b"), "https://host.invalid:8443/a")


class CaptureReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = import_module(SCRIPTS / "evidence_capture.py", "capture_review_tests")
        cls.contract = import_module(SCRIPTS / "contract_check.py", "capture_review_contract")
        cls.deps = import_module(SCRIPTS / "deps_scan.py", "capture_review_deps")

    setUp = fixture.RunContractTests.setUp
    base = fixture.RunContractTests.base
    build = fixture.RunContractTests.build

    def test_subdirectory_of_a_repository_is_refused(self):
        self.findings.write_text(json.dumps(self.base()), encoding="utf-8")
        original = self.findings.read_bytes()
        with self.assertRaisesRegex(self.capture.CaptureError, "top level"):
            self.capture.capture(self.repo / "src", self.findings, ["orders.py"])
        self.assertEqual(self.findings.read_bytes(), original)

    def test_duplicate_keys_are_refused(self):
        # A valid report whose last key repeats an earlier one.
        self.findings.write_text(json.dumps(self.base())[:-1] + ', "checked_ok": ["shadowed"]}', encoding="utf-8")
        with self.assertRaisesRegex(self.capture.CaptureError, "duplicate_json_key"):
            self.capture.capture(self.repo, self.findings, ["src/orders.py"])

    def test_capture_keeps_report_permissions(self):
        self.findings.write_text(json.dumps(self.base()), encoding="utf-8")
        os.chmod(self.findings, 0o644)
        self.capture.capture(self.repo, self.findings, ["src/orders.py"])
        self.assertEqual(self.findings.stat().st_mode & 0o777, 0o644)

    def test_dot_relative_roots_verify_under_isolated_python(self):
        self.build()
        receipt = self.tmp / "receipt.json"
        done = subprocess.run([sys.executable, "-I", str(SCRIPTS / "evidence_integrity.py"), "verify",
                               "out/findings.json", "--root", "./out", "--repository", "./app",
                               "--out", str(receipt)], cwd=str(self.tmp), capture_output=True, text=True,
                              timeout=60)
        self.assertNotIn("Traceback", done.stderr)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(json.loads(receipt.read_text())["status"], "matched")

    def test_parent_relative_roots_stay_refused(self):
        self.build()
        done = subprocess.run([sys.executable, str(SCRIPTS / "evidence_integrity.py"), "verify",
                               "out/findings.json", "--root", "app/../out",
                               "--out", str(self.tmp / "r.json")], cwd=str(self.tmp),
                              capture_output=True, text=True, timeout=60)
        self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
