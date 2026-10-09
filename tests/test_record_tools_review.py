"""Regressions for findings.py, contract_check.py and verification_workflow.py."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_security_scan import import_module

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import verification  # noqa: E402
import verification_workflow as workflow  # noqa: E402

META = {"project": "demo", "date": "2026-10-09", "assessor": "Test host (model)"}
FINDING = {"id": "F-001", "title": "Profile link accepts javascript: URLs", "severity": "High",
           "confidence": "Confirmed", "category": "Actor and tenant", "location": "src/my orders.py:2",
           "actor": "any signed-in user", "request": "GET /orders/{id}",
           "impact": "reads another tenant's order", "fix": "scope the query by tenant", "status": "Open"}


class FindingsMergeReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = import_module(SCRIPTS / "findings.py", "review_findings_merge")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-record-review-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.out = self.tmp / "findings.json"

    def fragment(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def merge(self, *fragments):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.tool.main(["merge", str(self.out), *fragments])

    def test_prose_naming_a_scheme_is_not_a_payload(self):
        self.assertEqual(self.merge(self.fragment("a.json", {"meta": META, "findings": [FINDING]})), 0)
        bad = dict(FINDING, request="link=javascript:alert(1)")
        self.assertEqual(self.merge(self.fragment("b.json", {"findings": [bad]})), 1)

    def test_perspective_result_can_be_corrected(self):
        first = {"name": "Actor and tenant", "result": "Not checked - need routes"}
        self.assertEqual(self.merge(self.fragment("a.json", {"meta": META, "perspectives": [first]})), 0)
        second = {"name": "Actor and tenant", "result": "1 High"}
        self.assertEqual(self.merge(self.fragment("b.json", {"perspectives": [second]})), 0)
        self.assertEqual(json.loads(self.out.read_text())["perspectives"], [second])

    def test_merge_respects_the_workflow_lock_and_keeps_permissions(self):
        self.assertEqual(self.merge(self.fragment("a.json", {"meta": META, "findings": [FINDING]})), 0)
        os.chmod(self.out, 0o644)
        lock = self.out.with_name(self.out.name + ".workflow.lock")
        lock.write_text("busy")
        before = self.out.read_bytes()
        self.assertEqual(self.merge(self.fragment("b.json", {"limitations": ["x"]})), 2)
        self.assertEqual(self.out.read_bytes(), before)
        lock.unlink()
        self.assertEqual(self.merge(self.fragment("b.json", {"limitations": ["x"]})), 0)
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o644)
        self.assertFalse(lock.exists())

    def test_concurrent_change_is_not_overwritten(self):
        self.assertEqual(self.merge(self.fragment("a.json", {"meta": META, "findings": [FINDING]})), 0)
        real = self.tool.render.validate_data

        def edit_meanwhile(data):
            self.out.write_text(self.out.read_text() + " ")
            return real(data)

        with patch.object(self.tool.render, "validate_data", side_effect=edit_meanwhile):
            self.assertEqual(self.merge(self.fragment("b.json", {"limitations": ["x"]})), 2)
        self.assertNotIn('"x"', self.out.read_text())


class ContractReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = import_module(SCRIPTS / "contract_check.py", "review_contract_check")

    def test_ids_and_locations_need_ascii_digits_and_allow_spaces(self):
        for value in ("F-٠٠١", "F-００１", "F-001\n"):
            self.assertIsNone(self.contract.CODE_ID.fullmatch(value), value)
        self.assertIsNotNone(self.contract.LOCATION.fullmatch("src/my orders.py:2"))
        for value in ("src/orders.py:2\n", "src/orders.py:٢", "src/orders.py", " src/orders.py:2"):
            self.assertIsNone(self.contract.LOCATION.fullmatch(value), value)

    def test_non_list_sections_are_violations_not_crashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            for data in ({"findings": {}}, {"findings": None, "perspectives": None}):
                problems = self.contract.check(data, Path(tmp))
                self.assertIn("findings: required list", problems)

    def test_hidden_files_are_not_unexpected_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".DS_Store").write_text("")
            problems = self.contract.check({"findings": []}, Path(tmp))
            self.assertFalse([p for p in problems if "unexpected" in p])

    def test_deep_nesting_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "findings.json").write_text("[" * 100000)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self.contract.main([tmp]), 2)


class WorkflowReviewTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "examples/findings.verification.sample.json").read_text())
        self.finding = self.data["findings"][0]
        self.reference = copy.deepcopy(self.finding["verification"])
        self.finding.pop("verification")
        self.finding.pop("remediation")
        self.finding.update(status="Open", confidence="Suspected")
        self.finding["validation"] = {"verdict": "Unverified", "evidence": "", "method": ""}
        self.identifier = self.finding["id"]

    def output(self, status="complete"):
        state = workflow.derive_workflow(self.data, self.finding)
        stage = state["next_stage"]
        output = dict(stage=stage, actor={"conditions": "author", "falsification": "independent",
                                          "decision": "judge"}[stage],
                      status=status, summary="Synthetic observations only.", evidence_ids=["source-before"],
                      input_digest=state["input_digest"])
        if stage == "conditions":
            output.update(claims=copy.deepcopy(self.reference["claims"]),
                          environment=copy.deepcopy(self.reference["environment"]))
        elif stage == "falsification":
            reviews = copy.deepcopy(self.reference["reviews"])
            reviews[0]["reviewer"] = "independent"
            output.update(checks=copy.deepcopy(self.reference["falsification"]), reviews=reviews)
        else:
            output.update(validation={"verdict": "Valid", "method": "Synthetic review",
                                      "evidence": "Pinned synthetic evidence."}, run_ids=[])
        return output

    def test_timestamps_follow_one_profile_on_every_python(self):
        for good in ("2026-10-09T12:00:00Z", "2026-10-09T12:00:00.5Z", "2026-10-09T12:00:00.123456+09:00",
                     "2026-10-09 12:00+00:00"):
            verification.parse_timestamp(good)
        for bad in ("2026-10-09T12:00:00", "2026-10-09T12:00:00+0000", "20261009T120000Z",
                    "2026-10-09T12:00:00Z\n", "2026-10-09T12:00:00.1234567Z"):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                verification.parse_timestamp(bad)

    def test_lone_surrogates_are_rejected_not_a_crash(self):
        workflow.initialize(self.data, self.identifier, "coordinator")
        output = self.output(status="held")
        output.update(summary="blocked \ud800 x", reasons=["synthetic"])
        with self.assertRaisesRegex(workflow.WorkflowError, "surrogate"):
            workflow.submit(self.data, self.identifier, output)

    def test_stray_integrity_cache_does_not_change_the_digest(self):
        before = workflow.input_digest(self.data, self.finding)
        self.finding["_evidence_integrity"] = {"status": "matched"}
        self.assertEqual(workflow.input_digest(self.data, self.finding), before)

    def test_resume_explains_a_hold_after_all_stages(self):
        workflow.initialize(self.data, self.identifier, "coordinator")
        for _ in range(3):
            workflow.submit(self.data, self.identifier, self.output())
        with patch.object(workflow, "_decision_result", return_value=("held", ["environment_unknown"])):
            with self.assertRaisesRegex(workflow.WorkflowError, "invalidate and then resume"):
                workflow.resume(self.data, self.identifier, "coordinator", "retry")

    def test_cli_keeps_report_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            path.write_text(json.dumps(self.data))
            os.chmod(path, 0o644)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(workflow.main(["init", str(path), "--finding", self.identifier,
                                                "--actor", "coordinator"]), 0)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_cli_deep_nesting_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            path.write_text("[" * 100000)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(workflow.main(["status", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
