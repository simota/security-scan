"""Second-round verification regressions: identity spelling, retest order, digests, messages."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import render  # noqa: E402
import verification  # noqa: E402
import verification_workflow as workflow  # noqa: E402
from test_record_tools_review import WorkflowReviewTests  # noqa: E402


class RecordError(ValueError):
    pass


class IdentityAndRetestTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
        self.finding = self.data["findings"][0]
        self.record = self.finding["verification"]

    def derive(self):
        return verification.derive_verification(self.data, RecordError)[self.finding["id"]]

    def test_invisible_and_compatibility_spellings_are_one_reviewer(self):
        self.assertEqual(self.derive()["gaps"], [])
        author = self.record["reviewer"]
        for spelling in (author + "​", "­" + author, "ｓ" + author[1:] if author[0] == "s" else author.upper(),
                         author + "\ufe0f", "\u115f" + author, "  " + author + "\u3164 "):
            with self.subTest(spelling=spelling):
                data = copy.deepcopy(self.data)
                data["findings"][0]["verification"]["reviews"][0]["reviewer"] = spelling
                state = verification.derive_verification(data, RecordError)[self.finding["id"]]
                self.assertIn("review_missing", state["gaps"])
                self.assertNotEqual(state["retest"], "verified")

    def test_distinct_spaced_names_stay_distinct(self):
        self.assertNotEqual(verification.identity("Ann Lee"), verification.identity("AnnLee"))
        self.assertEqual(verification.identity(" Ann\u3000 Lee "), verification.identity("ann lee"))

    def test_after_fix_runs_older_than_the_failure_do_not_verify(self):
        for run in self.data["test_runs"]:
            if run["id"] != "before":
                run["recorded_at"] = "2020-01-01T00:00:00Z"
        state = self.derive()
        self.assertIn("retest_order_invalid", state["gaps"])
        self.assertEqual(state["retest"], "incomplete")
        self.assertIn("retest_order_invalid", render._GAP_LABELS)


class WorkflowSecondReviewTests(WorkflowReviewTests):
    def test_invisible_actor_spelling_is_not_independent(self):
        workflow.initialize(self.data, self.identifier, "coordinator")
        workflow.submit(self.data, self.identifier, self.output())
        falsification = self.output()
        falsification["actor"] = "author​"
        falsification["reviews"][0]["reviewer"] = "author​"
        with self.assertRaises(workflow.WorkflowError):
            workflow.submit(self.data, self.identifier, falsification)

    def test_empty_cwe_digest_matches_the_report(self):
        self.finding["cwe"] = ""
        workflow.initialize(self.data, self.identifier, "coordinator")
        for _ in range(3):
            workflow.submit(self.data, self.identifier, self.output())
        cli = workflow.derive_workflow(self.data, self.finding)["status"]
        report = render.validate_data(copy.deepcopy(self.data))["findings"][0]["_workflow"]["status"]
        self.assertEqual(cli, report)

    def test_duplicate_key_message_escapes_control_characters(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            path.write_text('{"\\u001b[2J": 1, "\\u001b[2J": 2}', encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(workflow.main(["status", str(path)]), 2)
            self.assertNotIn("\x1b", err.getvalue())


if __name__ == "__main__":
    unittest.main()
