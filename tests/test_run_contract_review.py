"""Run-contract regressions: required outputs, ID order, verification shape, freshness."""
import copy
import json
import os
import shutil
import unittest

import test_run_contract as fixture
from test_run_contract import SCRIPTS
from test_security_scan import import_module


class RunContractReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.RunContractTests.setUpClass.__func__(cls)
        cls.merge = import_module(SCRIPTS / "findings.py", "contract_review_findings")

    setUp = fixture.RunContractTests.setUp
    base = fixture.RunContractTests.base
    build = fixture.RunContractTests.build
    render = fixture.RunContractTests.render
    problems = fixture.RunContractTests.problems

    def test_deps_json_and_evidence_are_required_outputs(self):
        data = self.build()
        self.render()
        self.assertEqual(self.problems(data), [])
        (self.out / "deps.json").unlink()
        shutil.rmtree(self.out / "evidence")
        found = self.problems(data)
        self.assertTrue(any("deps.json missing" in p for p in found))
        self.assertTrue(any("evidence missing" in p for p in found))

    def test_pdf_hint_names_the_no_pdf_fallback(self):
        data = self.build()
        self.render()
        found = self.contract.check(data, self.out, pdf=True)
        self.assertTrue(any("assessment.pdf missing" in p and "--no-pdf" in p for p in found))

    def test_code_findings_are_numbered_in_severity_order(self):
        data = self.build()
        self.render()
        low = copy.deepcopy(data["findings"][0])
        data["findings"][0]["severity"] = "Low"
        data["findings"].append(dict(low, id="F-002", severity="High"))
        self.assertIn("F-*: number code findings in severity order (High first), then path and line", self.problems(data))

    def test_verification_needs_four_claims_and_a_falsification_check(self):
        data = self.build()
        self.render()
        for mutate in (lambda v: v.__setitem__("falsification", []),
                       lambda v: v["claims"].pop("impact"),
                       lambda v: v.__setitem__("claims", [])):
            broken = copy.deepcopy(data)
            mutate(broken["findings"][0]["verification"])
            self.assertTrue(any("structured verification" in p for p in self.problems(broken)))

    def test_reports_must_be_rendered_from_the_current_record(self):
        data = self.build()
        self.render()
        # Timestamps do not matter: a touched or copied file with the same bytes is fresh.
        stamp = (self.out / "dashboard.html").stat().st_mtime
        os.utime(self.out / "findings.json", (stamp + 10, stamp + 10))
        self.assertEqual(self.problems(data), [])
        # Any change after rendering is stale, even within the same second.
        (self.out / "findings.json").write_text((self.out / "findings.json").read_text() + " ")
        found = self.problems(data)
        self.assertTrue(any("dashboard.html was not rendered from the current findings.json" in p for p in found))
        self.assertTrue(any("assessment.html was not rendered from the current findings.json" in p for p in found))

    def test_excluded_findings_keep_their_place_in_the_numbering(self):
        data = self.build()
        self.render()
        high = copy.deepcopy(data["findings"][0])
        data["findings"][0]["severity"] = "Low"
        data["findings"].append(dict(high, id="F-002", severity="High",
                                     validation={"verdict": "FalsePositive", "evidence": "ruled out", "method": "review"}))
        self.assertNotIn("F-*: number code findings in severity order (High first), then path and line", self.problems(data))

    def test_rerunning_capture_without_new_paths_leaves_the_record_untouched(self):
        self.build()
        before = (self.findings.read_bytes(), self.findings.stat().st_mtime_ns)
        self.capture.capture(self.repo, self.findings, ["src/orders.py"])
        self.assertEqual((self.findings.read_bytes(), self.findings.stat().st_mtime_ns), before)

    def test_perspective_names_come_only_from_the_perspective_table(self):
        names = self.contract.perspective_names()
        self.assertEqual(len(names), 15)
        self.assertEqual(names[0], "Actor and tenant")

    def test_verification_and_evidence_wait_for_capture(self):
        first = self.tmp / "frag-1.json"
        first.write_text(json.dumps(self.base()))
        self.assertEqual(self.merge.main(["merge", str(self.findings), str(first)]), 0)
        for fragment in ({"findings": [{"id": "F-001", "verification": {"reviewer": "x"}}]},
                         {"evidence": [{"id": "SRC-009", "summary": "guessed"}]}):
            path = self.tmp / "frag-2.json"
            path.write_text(json.dumps(fragment))
            self.assertEqual(self.merge.main(["merge", str(self.findings), str(path)]), 2)

    def test_capture_before_the_first_merge_says_what_to_do(self):
        with self.assertRaisesRegex(self.capture.CaptureError, "run findings.py merge"):
            self.capture.capture(self.repo, self.out / "findings.json", ["src/orders.py"])


if __name__ == "__main__":
    unittest.main()
