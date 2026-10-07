"""Sanctioned incremental profile authoring, journal ownership and local capture."""
import contextlib
import copy
import io
import json
from pathlib import Path
import unittest

import test_expert as expert_fixture
import test_findings_merge as merge_fixture
from test_run_contract import git
from test_security_scan import import_module

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts"


class FindingsExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = import_module(SCRIPTS / "findings.py", "extension_findings")
        cls.capture = import_module(SCRIPTS / "evidence_capture.py", "extension_capture")
        # Use the same module instance as verification's fresh-result boundary.
        import evidence_integrity
        cls.integrity = evidence_integrity
        cls.workflow = expert_fixture.workflow

    setUp = merge_fixture.FindingsMergeTests.setUp
    fragment = merge_fixture.FindingsMergeTests.fragment

    def merge(self, data):
        path = self.fragment("fragment.json", data)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.tool.main(["merge", str(self.out), path])

    def data(self):
        return json.loads(self.out.read_text())

    def pinned(self, initial=None):
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        for name in ("route.py", "policy.py", "scope.py"):
            (self.repo / name).write_text("# Inert owned source fixture: " + name + "\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "synthetic source")
        directory = self.tmp / "report"
        directory.mkdir()
        self.out = directory / "findings.json"
        self.assertEqual(self.merge(initial or {"meta": merge_fixture.META,
                                              "findings": [merge_fixture.FINDING]}), 0)
        mapping = self.capture.capture(self.repo, self.out, ["route.py", "policy.py", "scope.py"])
        return dict(zip(("route-source", "policy-source", "scope-source"), mapping.values()))

    def run_record(self):
        return {"id": "run-1", "case_id": "synthetic-case", "commit": self.data()["assessment"]["commit"],
                "role": "security", "result": "not_run", "failure_kind": "none", "exit_code": None,
                "expected": "Source-only review", "observed": "No application execution requested",
                "command": "NOT EXECUTED", "recorded_at": "2026-10-07T00:00:00Z", "evidence_ids": [],
                "context": {"environment": "local", "boundary": "unknown", "configuration": "fixture",
                            "fixture": "owned-synthetic", "test_version": "v1"}}

    def test_test_runs_upsert_and_profile_field_replacement(self):
        self.pinned()
        record = self.run_record()
        self.assertEqual(self.merge({"test_runs": [record], "evidence_integrity": {"required": False}}), 0)
        self.assertEqual(self.merge({"test_runs": [{"id": "run-1", "observed": "Still not executed"}]}), 0)
        self.assertEqual(self.data()["test_runs"], [dict(record, observed="Still not executed")])
        expert = copy.deepcopy(expert_fixture.complete_data()["expert"])
        initial = {key: expert[key] for key in ("version", "mode", "host", "consent")}
        self.assertEqual(self.merge({"expert": initial}), 0)
        self.assertEqual(expert_fixture.expert.derive_expert(self.data())["status"], "held")
        self.assertEqual(self.merge({"expert": {"preflight": expert["preflight"]}}), 0)
        self.assertEqual(self.merge({"expert": {"preflight": []}}), 0)
        self.assertEqual(self.data()["expert"], dict(initial, preflight=[]))
        self.assertEqual(self.merge({"expert": {"consent": {"ceiling": 5}}}), 2,
                         "nested records replace wholesale, so a partial consent is invalid")

    def test_extensions_require_capture_and_invalid_shapes_are_atomic(self):
        self.assertEqual(self.merge({"meta": merge_fixture.META, "findings": []}), 0)
        before = self.out.read_bytes()
        for fragment in ({"expert": {"version": 1}}, {"test_runs": []},
                         {"three_pass": {}}, {"evidence_integrity": {"required": True}}):
            self.assertEqual(self.merge(fragment), 2)
            self.assertEqual(self.out.read_bytes(), before)
        for fragment in ({"meta": []}, {"findings": [{"id": "F-001"}, {"id": "F-001"}]},
                         {"evidence": [{"id": []}]}, {"expert": {"status": "complete"}},
                         {"test_runs": {}}, {"three_pass": None}):
            self.assertEqual(self.merge(fragment), 1)
            self.assertEqual(self.out.read_bytes(), before)

    def test_reserved_pin_and_workflow_fields_cannot_be_forged(self):
        self.pinned()
        before = self.out.read_bytes()
        for fragment in ({"schema_version": 2}, {"assessment": {"commit": "0" * 40}},
                         {"meta": {"commit": "0" * 40}},
                         {"findings": [{"id": "F-001", "verification_workflow": {"history": []}}]},
                         {"findings": [{"id": "F-001", "_workflow": {"status": "complete"}}]},
                         {"evidence_integrity": {"required": True, "_receipt": {"status": "matched"}}}):
            self.assertEqual(self.merge(fragment), 1)
            self.assertEqual(self.out.read_bytes(), before)

    def test_bad_run_references_and_profile_shapes_are_schema_errors(self):
        mapping = self.pinned()
        record = self.run_record()
        record.update(result="pass", exit_code=0, evidence_ids=[mapping["route-source"]])
        before = self.out.read_bytes()
        cases = ({"test_runs": [record]}, {"evidence_integrity": {"required": "yes"}},
                 {"three_pass": {"version": 1, "coverage": [], "discovery": {}}},
                 {"test_runs": [dict(record, evidence_ids=["missing"])]})
        for fragment in cases:
            self.assertEqual(self.merge(fragment), 2)
            self.assertEqual(self.out.read_bytes(), before)

    def test_unknown_expert_evidence_cannot_overwrite_the_report(self):
        self.out.write_text(json.dumps(expert_fixture.complete_data()))
        before = self.out.read_bytes()
        panels = copy.deepcopy(self.data()["expert"]["panels"])
        panels[0]["skeptics"][0]["evidence_ids"] = ["missing-evidence"]
        self.assertEqual(self.merge({"expert": {"panels": panels}}), 2)
        self.assertEqual(self.out.read_bytes(), before)

    def remap(self, value, mapping):
        if isinstance(value, dict):
            return {key: [mapping.get(item, item) for item in item_value] if key == "evidence_ids"
                    else self.remap(item_value, mapping) for key, item_value in value.items()}
        if isinstance(value, list):
            return [self.remap(item, mapping) for item in value]
        return value

    def complete_sanctioned_flow(self):
        fixture = expert_fixture.complete_data()
        finding = copy.deepcopy(fixture["findings"][0])
        finding.pop("verification_workflow")
        finding.pop("verification")
        finding["validation"] = {"verdict": "Unverified", "evidence": "", "method": ""}
        meta = dict(fixture["meta"])
        meta.pop("commit")
        initial = {"meta": meta, "findings": [finding], "perspectives": fixture["perspectives"]}
        mapping = self.pinned(initial)
        expert = self.remap(fixture["expert"], mapping)
        core = {key: expert[key] for key in ("version", "mode", "host", "consent")}
        self.assertEqual(self.merge({"expert": core, "three_pass": self.remap(fixture["three_pass"], mapping),
                                     "evidence_integrity": {"required": True},
                                     "test_runs": [self.run_record()]}), 0)
        options = ["--evidence-root", str(self.out.parent), "--evidence-repository", str(self.repo)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.workflow.main(["init", str(self.out), "--finding", "F-001",
                                                "--actor", "coordinator", *options]), 0)
            for stage in self.workflow.STAGES:
                output = expert_fixture.benchmark.submission(self.data(), stage)
                path = self.fragment("submission.json", self.remap(output, mapping))
                self.assertEqual(self.workflow.main(["submit", str(self.out), "--finding", "F-001",
                                                    "--submission", path, *options]), 0)
        # Each later phase is authored separately through the sanctioned writer.
        for key, value in expert.items():
            if key not in core:
                self.assertEqual(self.merge({"expert": {key: value}}), 0, key)
        return options

    def test_fragment_capture_workflow_and_expert_end_to_end(self):
        options = self.complete_sanctioned_flow()
        data = self.data()
        integrity = self.integrity.verify_evidence(data, self.out.parent, self.repo)
        self.assertEqual(integrity.receipt["status"], "matched")
        self.assertEqual(expert_fixture.expert.derive_expert(data, integrity=integrity)["status"], "complete")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.workflow.main(["audit", str(self.out), "--require-complete", *options]), 0)
        # Exercise the final report/file gate with synthetic, explicitly inert run records.
        import deps_scan
        deps_scan.merge_into(self.out, {"findings": [], "not_run": []}, audit=True)
        data = self.data()
        files = [data["expert"]["consent"]["record"]]
        files += [row["record"] for row in data["expert"]["preflight"]]
        files += [row[key] for row in data["expert"]["spawns"] for key in ("prompt", "return")]
        for relative in files:
            path = self.out.parent / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Synthetic gate fixture only. No worker or application was executed.\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(expert_fixture.render.main([str(self.out), "--out", str(self.out.parent),
                                                         "--lang", "en", "--no-pdf", *options]), 0)
        result = expert_fixture.expert_audit.audit(data, self.out.parent, pdf=False,
                                                   evidence_root=self.out.parent, evidence_repository=self.repo)
        self.assertEqual(result["gaps"], [])
        self.assertEqual(result["status"], "complete")

    def test_profile_and_run_updates_preserve_journal_and_make_it_stale(self):
        self.complete_sanctioned_flow()
        pristine = self.out.read_bytes()
        data = self.data()
        journal = copy.deepcopy(data["findings"][0]["verification_workflow"])
        discovery = dict(data["three_pass"]["discovery"], summary="Changed discovery observation")
        for fragment in ({"three_pass": {"discovery": discovery}},
                         {"test_runs": [{"id": "run-1", "observed": "Changed recorded observation"}]}):
            self.out.write_bytes(pristine)
            self.assertEqual(self.merge(fragment), 0)
            updated = self.data()
            self.assertEqual(updated["findings"][0]["verification_workflow"], journal)
            self.assertEqual(self.workflow.derive_workflow(updated, updated["findings"][0])["status"], "stale")


if __name__ == "__main__":
    unittest.main()
