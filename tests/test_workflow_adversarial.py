"""Independent workflow integrity regressions using inert local records only."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"


def load_script(name):
    spec = importlib.util.spec_from_file_location("adversarial_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(SCRIPTS)] + sys.path):
        spec.loader.exec_module(module)
    return module


class WorkflowAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path_patch = patch.object(sys, "path", [str(SCRIPTS)] + sys.path)
        path_patch.start()
        cls.addClassCleanup(path_patch.stop)
        cls.workflow = load_script("verification_workflow")
        cls.renderer = load_script("render")

    def setUp(self):
        self.data = json.loads((ROOT / "examples/findings.workflow.sample.json").read_text(encoding="utf-8"))
        self.finding = self.data["findings"][0]
        self.finding["confidence"] = "Confirmed"
        self.workflow.initialize(self.data, "F-001", "owner")

    def output(self, stage):
        handoff = self.workflow.next_handoff(self.data, "F-001")
        record = {"stage": stage, "actor": "reviewer-B" if stage == "falsification" else "reviewer-A",
                  "status": "complete", "summary": "Synthetic manual source observation",
                  "evidence_ids": ["source-before"], "input_digest": handoff["input_digest"]}
        if stage == "conditions":
            record.update(claims={key: {"status": "supported", "reason": "Synthetic source observation",
                                       "evidence_ids": ["source-before"]} for key in self.workflow.CLAIMS},
                          environment={"status": "not_required", "reason": "Local source-only assertion", "evidence_ids": []})
        elif stage == "falsification":
            record.update(checks=[{"check": "Inspect owner scope", "result": "clear", "reason": "Synthetic source observation",
                                   "evidence_ids": ["source-before"]}],
                          reviews=[{"reviewer": "reviewer-B", "conclusion": "agree", "reason": "Synthetic independent observation",
                                    "evidence_ids": ["source-before"]}])
        elif stage == "decision":
            record.update(validation={"verdict": "Valid", "method": "Synthetic source review", "evidence": "Synthetic decision basis"},
                          run_ids=[])
        return record

    def advance(self, stage):
        return self.workflow.submit(self.data, "F-001", self.output(stage))

    def complete(self):
        for stage in self.workflow.STAGES:
            state = self.advance(stage)
        self.assertEqual(state["status"], "complete")

    def not_complete(self):
        try:
            state = self.workflow.derive_workflow(self.data, self.finding)
        except ValueError:
            return
        self.assertNotEqual(state["status"], "complete")

    def test_initial_handoff_pins_unreferenced_evidence_it_exposes(self):
        output = self.output("conditions")
        self.data["evidence"][0].update(sha256="a" * 64, summary="Changed after review")
        before = copy.deepcopy(self.data)
        with self.assertRaises(ValueError):
            self.workflow.submit(self.data, "F-001", output)
        self.assertEqual(self.data, before)

    def test_later_handoff_pins_new_counterevidence_it_exposes(self):
        self.data["evidence"].append(dict(self.data["evidence"][0], id="counterevidence"))
        # A new initial round includes the prepared registry.
        self.workflow.invalidate(self.data, "F-001", "owner", "Include counterevidence")
        self.workflow.resume(self.data, "F-001", "owner", "Start fresh")
        self.advance("conditions")
        output = self.output("falsification")
        output["evidence_ids"].append("counterevidence")
        output["checks"][0]["evidence_ids"].append("counterevidence")
        self.data["evidence"][1]["sha256"] = "b" * 64
        with self.assertRaises(ValueError):
            self.workflow.submit(self.data, "F-001", output)

    def test_changed_historical_claim_body_cannot_retain_completion(self):
        self.complete()
        event = self.finding["verification_workflow"]["history"][1]
        event["submission"]["claims"]["impact"] = {"status": "unknown", "reason": "Never reviewed", "evidence_ids": []}
        self.not_complete()

    def test_changed_historical_falsification_cannot_retain_completion(self):
        self.complete()
        event = self.finding["verification_workflow"]["history"][2]
        event["submission"]["checks"][0]["result"] = "unresolved"
        self.not_complete()

    def test_changed_historical_decision_cannot_retain_completion(self):
        self.complete()
        event = self.finding["verification_workflow"]["history"][3]
        event["submission"]["validation"] = {"verdict": "FalsePositive", "method": "Changed", "evidence": "Contradicts active decision"}
        self.not_complete()

    def test_report_loading_does_not_invalidate_completed_workflow(self):
        self.complete()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "finding.json"
            source.write_text(json.dumps(self.data), encoding="utf-8")
            loaded = self.renderer.load(source)
        self.assertEqual(self.renderer.workflow_states(loaded)["F-001"]["status"], "complete")
        self.assertEqual(self.renderer.report_model(loaded)["fix_now"], 1)

    def test_stale_original_stage_cannot_be_replayed_after_restart(self):
        output = self.output("conditions")
        self.workflow.submit(self.data, "F-001", output)
        self.finding["location"] = "src/orders.py:19"
        self.workflow.resume(self.data, "F-001", "owner", "Review changed location")
        with self.assertRaises(ValueError):
            self.workflow.submit(self.data, "F-001", output)

    def test_prior_round_falsification_cannot_replay_after_explicit_invalidation(self):
        self.advance("conditions")
        previous = self.output("falsification")
        self.workflow.submit(self.data, "F-001", previous)
        self.advance("decision")
        self.workflow.invalidate(self.data, "F-001", "owner", "Require another independent review")
        self.workflow.resume(self.data, "F-001", "owner", "Begin the new round")
        self.advance("conditions")
        with self.assertRaises(ValueError):
            self.workflow.submit(self.data, "F-001", previous)

    def test_invalid_base_severity_cannot_disable_independent_review_requirement(self):
        self.finding.pop("verification_workflow")
        self.finding["severity"] = "HIGH"
        with self.assertRaises(ValueError):
            self.workflow.initialize(self.data, "F-001", "owner")

    def test_malformed_base_references_are_schema_errors(self):
        self.finding.pop("verification_workflow")
        self.finding["references"] = [7]
        with self.assertRaises(ValueError):
            self.workflow.initialize(self.data, "F-001", "owner")

    def prior_record(self):
        self.data = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
        self.finding = self.data["findings"][0]
        self.finding.pop("remediation")
        self.finding.update(status="Open", confidence="Confirmed")
        self.finding["validation"]["verdict"] = "Unverified"

    def assert_existing_counterevidence_blocks_new_valid(self):
        self.workflow.initialize(self.data, "F-001", "owner")
        for stage in self.workflow.STAGES:
            try:
                state = self.advance(stage)
            except ValueError:
                self.assertNotEqual(self.workflow.derive_workflow(self.data, self.finding)["status"], "complete")
                return
            if state["status"] != "ready":
                break
        self.assertNotEqual(state["status"], "complete")
        self.assertNotEqual(self.finding["validation"]["verdict"], "Valid")

    def test_conditions_cannot_silently_drop_existing_runtime_contradiction(self):
        self.prior_record()
        self.data["test_runs"][0].update(result="pass", failure_kind="none", exit_code=0)
        self.assert_existing_counterevidence_blocks_new_valid()

    def test_conditions_cannot_silently_drop_existing_unresolved_dissent(self):
        self.prior_record()
        self.finding["verification"]["run_ids"] = []
        self.finding["verification"]["reviews"][0].update(reviewer="dissenting-reviewer", conclusion="disagree",
                                                              reason="The impact observation contradicts source evidence")
        self.assert_existing_counterevidence_blocks_new_valid()

    def test_falsification_cannot_silently_drop_existing_unresolved_countercheck(self):
        self.prior_record()
        self.finding["verification"]["run_ids"] = []
        self.finding["verification"]["falsification"][0].update(result="unresolved", reason="The guard was not inspected")
        self.assert_existing_counterevidence_blocks_new_valid()

    def test_sidecar_writer_lock_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "finding.json"
            original = json.dumps(self.data).encode("utf-8")
            source.write_bytes(original)
            lock = Path(str(source) + ".workflow.lock")
            lock.write_text("another writer", encoding="utf-8")
            with patch("sys.stderr"):
                result = self.workflow.main(["invalidate", str(source), "--finding", "F-001", "--actor", "owner", "--reason", "test"])
            self.assertEqual(result, 2)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(lock.read_text(encoding="utf-8"), "another writer")

    def test_atomic_save_rejects_external_edit_during_temporary_write(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "finding.json"
            original = json.dumps(self.data).encode("utf-8")
            source.write_bytes(original)
            external = b'{"external_editor":"preserve me"}'
            real_fsync = self.workflow.os.fsync
            def concurrent_edit(fd):
                source.write_bytes(external)
                return real_fsync(fd)
            with patch.object(self.workflow.os, "fsync", side_effect=concurrent_edit):
                with self.assertRaises(ValueError):
                    self.workflow._save(source, self.data, original)
            self.assertEqual(source.read_bytes(), external)
            self.assertEqual(list(Path(directory).iterdir()), [source])


if __name__ == "__main__":
    unittest.main()
