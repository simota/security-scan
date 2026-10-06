"""Independent three-pass regressions using inert records and local Git blobs.

These tests exercise assurance gates, not vulnerability detection accuracy.
No assessed application, recorded command, or external service is executed.
"""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import evidence_integrity
import render
import three_pass
import verification
import verification_workflow as workflow

spec = importlib.util.spec_from_file_location(
    "three_pass_adversarial_benchmark", ROOT / "scripts/ci/benchmark_three_pass.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class _ThreePassFixture:
    def setUp(self):
        self.data = benchmark.sample()
        self.finding = self.data["findings"][0]

    def submit(self, stage, identifier="F-001", mutate=None, integrity=None):
        output = benchmark.submission(self.data, stage, identifier)
        if mutate:
            mutate(output)
        return workflow.submit(self.data, identifier, output, integrity=integrity)

    def complete(self, identifier="F-001", mutate=None, integrity=None):
        state = workflow.initialize(self.data, identifier, "coordinator", integrity=integrity)
        for stage in workflow.STAGES:
            if state["status"] != "ready":
                break
            state = self.submit(stage, identifier,
                                (lambda output: mutate(stage, output)) if mutate else None,
                                integrity)
        return state

    def add_second_candidate(self):
        second = copy.deepcopy(self.finding)
        second.update(id="F-002", title="Synthetic second candidate")
        self.data["findings"].append(second)
        self.data["three_pass"]["discovery"]["checks"][0]["finding_ids"].append("F-002")
        return second

    @staticmethod
    def unresolved_scope(output):
        output["coverage_checks"][1].update(result="unresolved", reason="Scope evidence remains unknown.")


class ThreePassAdversarialTests(_ThreePassFixture, unittest.TestCase):
    def test_union_cannot_outvote_an_unresolved_scope_cell(self):
        self.add_second_candidate()
        self.assertEqual(self.complete()["status"], "complete")
        workflow.initialize(self.data, "F-002", "coordinator")
        self.submit("conditions", "F-002")
        state = self.submit("falsification", "F-002", self.unresolved_scope)
        self.assertEqual(state["status"], "held")
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "held")
        self.assertIn("order-list", audit["coverage_challenge"]["missing_coverage_ids"])
        self.assertEqual(audit["coverage_challenge"]["completed"], 2)

    def test_union_cannot_outvote_a_scope_contradiction(self):
        self.add_second_candidate()
        self.complete()
        workflow.initialize(self.data, "F-002", "coordinator")
        self.submit("conditions", "F-002")
        state = self.submit("falsification", "F-002", lambda output:
                            output["coverage_checks"][1].update(result="contradiction"))
        self.assertEqual(state["status"], "conflict")
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "held")
        self.assertIn("three_pass_scope_contradiction", audit["reasons"])
        self.assertIn("order-list", audit["coverage_challenge"]["missing_coverage_ids"])

    def test_stale_finding_cannot_supply_union_coverage(self):
        self.add_second_candidate()
        self.complete()
        def only_candidate_scope(stage, output):
            if stage == "falsification":
                output["coverage_checks"] = output["coverage_checks"][:1]
        self.assertEqual(self.complete("F-002", only_candidate_scope)["status"], "complete")
        self.finding["title"] += " changed after review"
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["findings"]["F-001"]["status"], "stale")
        self.assertEqual(audit["findings"]["F-002"]["status"], "complete")
        self.assertEqual(set(audit["coverage_challenge"]["missing_coverage_ids"]),
                         {"order-list", "admin-route"})

    def test_historical_round_cannot_supply_current_coverage(self):
        self.complete()
        workflow.invalidate(self.data, "F-001", "coordinator", "Require a new challenge")
        workflow.resume(self.data, "F-001", "coordinator", "Start a new round")
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["coverage_challenge"]["completed"], 0)
        self.submit("conditions")
        self.submit("falsification", mutate=lambda output:
                    output.update(coverage_checks=output["coverage_checks"][:1]))
        self.assertEqual(self.submit("decision")["status"], "complete")
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "held")
        self.assertEqual(set(audit["coverage_challenge"]["missing_coverage_ids"]),
                         {"order-list", "admin-route"})

    def test_resume_preserves_unresolved_scope_counterevidence(self):
        workflow.initialize(self.data, "F-001", "coordinator")
        self.submit("conditions")
        self.submit("falsification", mutate=self.unresolved_scope)
        workflow.resume(self.data, "F-001", "coordinator", "Reconsider the blocked stage")
        original = copy.deepcopy(self.data)
        with self.assertRaisesRegex(workflow.WorkflowError, "cannot drop active scope counterevidence"):
            self.submit("falsification")
        self.assertEqual(self.data, original)

    def test_restart_preserves_unresolved_scope_counterevidence(self):
        workflow.initialize(self.data, "F-001", "coordinator")
        self.submit("conditions")
        self.submit("falsification", mutate=self.unresolved_scope)
        prior = copy.deepcopy(self.finding["verification"]["coverage_checks"])
        workflow.invalidate(self.data, "F-001", "coordinator", "Start another round")
        workflow.resume(self.data, "F-001", "coordinator", "Preserve the observations")
        self.submit("conditions")
        self.assertEqual(self.finding["verification"]["coverage_checks"], prior)
        with self.assertRaisesRegex(workflow.WorkflowError, "cannot drop active scope counterevidence"):
            self.submit("falsification")

    def test_all_three_declared_actors_must_be_distinct(self):
        discovery_actor = self.data["three_pass"]["discovery"]["actor"]
        workflow.initialize(self.data, "F-001", "coordinator")
        before = copy.deepcopy(self.data)
        with self.assertRaisesRegex(workflow.WorkflowError, "different declared actors"):
            self.submit("conditions", mutate=lambda output:
                        output.update(actor=" " + discovery_actor.upper() + " "))
        self.assertEqual(self.data, before)
        self.submit("conditions")
        for actor in (discovery_actor.upper(), " SYNTHETIC-CONDITIONS "):
            with self.subTest(actor=actor):
                before = copy.deepcopy(self.data)
                with self.assertRaisesRegex(workflow.WorkflowError, "different declared actors"):
                    self.submit("falsification", mutate=lambda output: output.update(actor=actor))
                self.assertEqual(self.data, before)

    def test_schema_one_extensions_do_not_enable_or_validate_profile(self):
        for version in (None, 1):
            with self.subTest(version=version):
                data = benchmark.sample()
                if version is None:
                    data.pop("schema_version")
                else:
                    data["schema_version"] = version
                data["three_pass"] = {"version": "historical", "coverage": "not a current plan"}
                data["findings"][0]["verification_workflow"] = "historical extension"
                loaded = render.validate_data(data)
                self.assertFalse(three_pass.derive_three_pass(loaded)["opted_in"])
                self.assertEqual(three_pass.derive_three_pass(loaded)["status"], "not_requested")
                self.assertNotIn("three_pass", render.report_model(loaded))

    def test_restart_snapshots_preserve_original_profile_lineage(self):
        initial = copy.deepcopy(self.data["three_pass"])
        workflow.initialize(self.data, "F-001", "coordinator")
        self.assertEqual(self.finding["verification_workflow"]["history"][0]["three_pass_snapshot"], initial)
        self.data["three_pass"]["discovery"]["summary"] += " Changed scope observation."
        self.assertEqual(workflow.derive_workflow(self.data, self.finding)["status"], "stale")
        workflow.resume(self.data, "F-001", "coordinator", "Repin changed discovery")
        history = self.finding["verification_workflow"]["history"]
        self.assertEqual(history[0]["three_pass_snapshot"], initial)
        self.assertEqual(history[-1]["three_pass_snapshot"], self.data["three_pass"])
        self.assertIsNot(history[-1]["three_pass_snapshot"], self.data["three_pass"])
        self.assertNotEqual(history[0]["round_id"], history[-1]["round_id"])
        self.assertEqual(history[-1]["previous_event_digest"], history[0]["event_digest"])

    def test_snapshot_tampering_breaks_event_digest(self):
        workflow.initialize(self.data, "F-001", "coordinator")
        self.finding["verification_workflow"]["history"][0]["three_pass_snapshot"]["discovery"]["summary"] = "Changed history"
        with self.assertRaisesRegex(ValueError, "event body differs"):
            workflow.derive_workflow(self.data, self.finding)


@unittest.skipUnless(os.name == "posix" and Path(evidence_integrity.GIT_BINARY).is_file(),
                     "POSIX and trusted Git required")
class ThreePassIntegrityAdversarialTests(_ThreePassFixture, unittest.TestCase):
    """Fresh byte checks must cover scope evidence outside the finding claims."""

    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.environment = {
            "PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "Synthetic fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Synthetic fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z",
        }
        self.git("init", "-q")
        discovery_record = dict(copy.deepcopy(self.data["evidence"][0]), id="discovery-source")
        self.data["evidence"].append(discovery_record)
        for record in self.data["evidence"]:
            path = record["id"] + ".txt"
            payload = ("Inert synthetic source record: " + record["id"] + "\n").encode("utf-8")
            (self.repository / path).write_bytes(payload)
            (self.artifacts / path).write_bytes(payload)
            record.update(location=path, source_path=path, sha256=hashlib.sha256(payload).hexdigest())
        self.git("add", ".")
        self.git("commit", "-qm", "Inert synthetic source records")
        commit = self.git("rev-parse", "HEAD").strip()
        self.data["assessment"]["commit"] = self.data["meta"]["commit"] = commit
        for record in self.data["evidence"]:
            record["commit"] = commit
        for check in self.data["three_pass"]["discovery"]["checks"]:
            check["evidence_ids"] = ["discovery-source"]
        self.data["evidence_integrity"] = {"required": True}

    def git(self, *args):
        return subprocess.run([evidence_integrity.GIT_BINARY, "-C", str(self.repository), *args],
                              env=self.environment, check=True, capture_output=True, text=True,
                              timeout=10).stdout

    def check(self, evidence_ids=None):
        return evidence_integrity.verify_evidence(self.data, self.artifacts,
                                                  repository=self.repository, evidence_ids=evidence_ids)

    def test_required_discovery_only_evidence_failure_holds_audit(self):
        checked = self.check()
        self.assertEqual(self.complete(integrity=checked)["status"], "complete")
        (self.artifacts / "discovery-source.txt").unlink()
        changed = self.check()
        self.assertEqual(verification.derive_verification(self.data, integrity=changed)["F-001"]["level"],
                         "static_supported")
        audit = three_pass.derive_three_pass(self.data, integrity=changed)
        self.assertEqual(audit["status"], "held")
        self.assertIn("evidence_integrity_failed", audit["discovery"]["reasons"])
        self.assertIn("evidence_integrity_failed", audit["findings"]["F-001"]["reasons"])

    def test_required_scope_only_evidence_failure_holds_audit(self):
        self.assertEqual(self.complete(integrity=self.check())["status"], "complete")
        (self.artifacts / "scope-source.txt").write_bytes(b"Changed synthetic scope evidence\n")
        changed = self.check()
        self.assertEqual(verification.derive_verification(self.data, integrity=changed)["F-001"]["level"],
                         "static_supported")
        audit = three_pass.derive_three_pass(self.data, integrity=changed)
        self.assertEqual(audit["discovery"]["status"], "complete")
        self.assertEqual(audit["status"], "held")
        self.assertIn("evidence_integrity_failed", audit["findings"]["F-001"]["reasons"])

    def test_claim_checks_alone_do_not_grant_scope_integrity_credit(self):
        checked = self.check(["route-source", "policy-source", "discovery-source"])
        state = self.complete(integrity=checked)
        self.assertEqual(state["status"], "held")
        self.assertEqual(state["next_stage"], "falsification")
        self.assertIn("evidence_integrity_failed", state["reasons"])
        self.assertEqual(three_pass.derive_three_pass(self.data, integrity=checked)["status"], "held")

    def test_required_discovery_rejects_missing_or_recorded_receipt(self):
        receipt = self.check().receipt
        for checked in (None, receipt):
            with self.subTest(recorded_receipt=checked is not None):
                original = copy.deepcopy(self.data)
                with self.assertRaisesRegex(workflow.WorkflowError, "evidence_integrity_unchecked"):
                    workflow.initialize(self.data, "F-001", "coordinator", integrity=checked)
                self.assertEqual(self.data, original)


if __name__ == "__main__":
    unittest.main()
