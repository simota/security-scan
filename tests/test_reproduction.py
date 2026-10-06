"""Real offline execution of auditor-owned synthetic fixtures, never an application."""
import contextlib
import copy
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import reproduction as repro
import reproduction_runtime as runtime
import verification_workflow as workflow
from render import validate_data


class ReproductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.findings = self.root / "findings.json"
        self.findings.write_bytes((ROOT / "examples/findings.workflow.sample.json").read_bytes())
        self.plan = json.loads((ROOT / "examples/reproduction.plan.sample.json").read_text())
        self.bundle = self.root / "bundle"
        self.out = self.root / "results"

    def generate(self):
        return repro.generate(self.findings, "F-001", self.plan, self.bundle)

    def script(self, name):
        return subprocess.run([sys.executable, "-I", "-S", str(self.bundle / name), "--findings", str(self.findings)], capture_output=True, text=True, timeout=10)

    def test_generate_is_deterministic_not_run_and_does_not_modify_findings(self):
        original = self.findings.read_bytes()
        generated = self.generate()
        second = self.root / "second"
        repro.generate(self.findings, "F-001", self.plan, second)
        self.assertEqual(generated["status"], "not_run")
        self.assertFalse((self.bundle / ".fixture").exists())
        for path in self.bundle.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        self.assertEqual(original, self.findings.read_bytes())
        self.assertEqual(repro.verify(self.bundle, self.findings)["finding_id"], "F-001")

    def test_actual_repeat_twice_is_deterministic_and_records_controls(self):
        self.generate()
        result = repro.run(self.bundle, self.findings, self.out)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["repeatable"])
        self.assertTrue(result["tool_versions_match"])
        self.assertEqual(len(result["cycles"]), 2)
        first, second = result["cycles"]
        self.assertEqual(first["semantic_sha256"], second["semantic_sha256"])
        self.assertEqual([s["action"] for s in first["steps"]], ["cleanup", "seed", "reproduce", "cleanup"])
        self.assertEqual([c["result"] for c in first["reproduction"]["cases"]], ["fail", "pass", "pass", "pass", "pass", "pass"])
        self.assertFalse((self.bundle / ".fixture").exists())
        self.assertFalse((self.bundle / ".fixture.lock").exists())
        records = json.loads((self.out / "records.json").read_text())
        self.assertEqual(len(records["test_runs"]), 12)
        self.assertTrue(all(x["context"]["boundary"] == "mocked" for x in records["test_runs"]))
        for evidence in records["evidence"]:
            self.assertEqual(evidence["sha256"], runtime.digest((self.out / evidence["location"]).read_bytes()))
        # These are structurally valid records, but a mocked fixture is never real target proof.
        data = json.loads(self.findings.read_text())
        data["evidence"].extend(records["evidence"])
        data["test_runs"] = records["test_runs"]
        validate_data(data)

    def test_export_synthetic_replay_evidence_for_ci(self):
        self.generate()
        result = repro.run(self.bundle, self.findings, self.out)
        self.assertTrue(result["repeatable"])
        artifact_root = os.environ.get("SECURITY_SCAN_REPORT_ARTIFACTS")
        if artifact_root:
            destination = Path(artifact_root) / "reproduction-evidence"
            destination.mkdir(parents=True, exist_ok=False)
            shutil.copytree(self.bundle, destination / "bundle")
            shutil.copytree(self.out, destination / "results")
            shutil.copyfile(self.findings, destination / "findings.synthetic.json")

    def test_standalone_seed_and_cleanup_are_idempotent_and_reproduction_is_red(self):
        self.generate()
        first = self.script("seed.py")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.script("seed.py")
        self.assertTrue(json.loads(second.stdout)["idempotent"])
        reproduced = self.script("reproduce.py")
        self.assertEqual(reproduced.returncode, 1)
        self.assertEqual(json.loads(reproduced.stdout)["status"], "completed")
        self.assertEqual(self.script("cleanup.py").returncode, 0)
        self.assertTrue(json.loads(self.script("cleanup.py").stdout)["idempotent"])
        self.assertEqual(self.script("reproduce.py").returncode, 2)

    def test_standalone_rejects_stale_findings(self):
        self.generate()
        self.findings.write_bytes(self.findings.read_bytes() + b"\n")
        self.assertEqual(self.script("seed.py").returncode, 2)
        self.assertFalse((self.bundle / ".fixture").exists())

    def test_new_seed_changes_fixture_identity(self):
        self.generate()
        manifest = repro.verify(self.bundle, self.findings)
        self.plan["seed"] += 1
        other, _ = repro.build_manifest(self.findings, "F-001", self.plan)
        self.assertNotEqual(manifest["fixture_sha256"], other["fixture_sha256"])
        self.assertNotEqual(manifest["bundle_id"], other["bundle_id"])

    def test_workflow_alias_generates_without_mutation(self):
        plan_path = self.root / "plan.json"
        plan_path.write_text(json.dumps(self.plan))
        original = self.findings.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            result = workflow.main(["bundle", str(self.findings), "--finding", "F-001", "--plan", str(plan_path), "--out", str(self.bundle)])
        self.assertEqual(result, 0)
        self.assertEqual(original, self.findings.read_bytes())
        self.assertFalse(self.findings.with_name("findings.json.workflow.lock").exists())

    def test_manual_target_is_unsupported_and_never_runs(self):
        self.plan["template"] = "manual-target-v1"
        self.generate()
        with patch.object(subprocess, "run", side_effect=AssertionError("must not execute")):
            result = repro.run(self.bundle, self.findings, self.out)
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse(result["repeatable"])
        self.assertFalse((self.bundle / ".fixture").exists())
        self.assertEqual(self.script("run.py").returncode, 3)
        adapter = json.loads((self.bundle / "adapter.todo.json").read_text())
        self.assertIsNone(adapter["target_binding"]["entrypoint"])
        self.assertFalse(adapter["target_binding"]["real_boundary_exercised"])

    def test_existing_outputs_not_overwritten(self):
        self.generate()
        with self.assertRaises(FileExistsError):
            self.generate()
        self.out.mkdir()
        with self.assertRaises(FileExistsError):
            repro.run(self.bundle, self.findings, self.out)

    def test_unknown_or_unsafe_plan_fields_rejected(self):
        for patch_plan in ({"command": "echo nope"}, {"template": "postgres-live"}, {"seed": True},
                           {"seed": -1}, {"case_id": "../escape"}, {"fixture": {"owners": 999999, "resources_per_owner": 2}},
                           {"evidence_ids": ["source-before", "source-before"]}, {"before": {"policy": "owner_scoped"}}):
            with self.subTest(patch_plan=patch_plan):
                plan = {**self.plan, **patch_plan}
                with self.assertRaises(repro.BundleError):
                    repro.generate(self.findings, "F-001", plan, self.bundle)
                self.assertFalse(self.bundle.exists())

    def test_tamper_manifest_and_reseal_does_not_bypass_trusted_generator(self):
        self.generate()
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        manifest["boundary"] = "real"
        (self.bundle / "manifest.json").write_bytes(runtime.canonical(manifest))
        (self.bundle / "manifest.sha256.json").write_text(json.dumps({"sha256": runtime.digest(runtime.canonical(manifest))}))
        with self.assertRaisesRegex(repro.BundleError, "trusted template|Bundle identity"):
            repro.verify(self.bundle, self.findings)

    def test_timeout_is_captured_with_no_successful_runs(self):
        self.generate()
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("auditor runtime", 1)):
            result = repro.run(self.bundle, self.findings, self.out, 1)
        self.assertEqual(result["status"], "timeout")
        self.assertFalse(result["repeatable"])
        self.assertEqual(json.loads((self.out / "records.json").read_text())["test_runs"], [])

    def test_runtime_error_does_not_echo_stderr_secrets(self):
        self.generate()
        process = subprocess.CompletedProcess([], 2, b"oops", b"password=do-not-copy")
        with patch.object(subprocess, "run", return_value=process):
            result = repro.run(self.bundle, self.findings, self.out)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("do-not-copy", (self.out / "results.json").read_text())

    def test_legacy_findings_cannot_generate_pinned_bundle(self):
        data = json.loads(self.findings.read_text())
        data.pop("schema_version")
        self.findings.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.generate()

    def test_wrong_evidence_revision_and_secret_category_fail_before_output(self):
        data = json.loads(self.findings.read_text())
        data["evidence"][0]["commit"] = "a" * 40
        self.findings.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.generate()
        data["evidence"][0]["commit"] = data["assessment"]["commit"]
        data["findings"][0]["category"] = "Secrets"
        self.findings.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.generate()

    def test_changed_findings_text_is_not_embedded(self):
        data = json.loads(self.findings.read_text())
        data["findings"][0]["title"] = "password=never-copy-this"
        data["evidence"][0]["summary"] = "person@example.com token=private"
        self.findings.write_text(json.dumps(data))
        self.generate()
        for path in self.bundle.iterdir():
            self.assertNotIn("never-copy-this", path.read_text())
            self.assertNotIn("person@example.com", path.read_text())

    def test_failure_still_cleans_owned_fixture(self):
        self.generate()
        manifest = repro.verify(self.bundle, self.findings)
        with patch.object(runtime, "reproduce", side_effect=runtime.BundleError("private details")):
            result = runtime.repeat(self.bundle, manifest)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["repeatable"])
        self.assertFalse((self.bundle / ".fixture").exists())
        self.assertNotIn("private details", json.dumps(result))

    def test_lock_blocks_all_standalone_actions_without_deleting_existing_lock(self):
        self.generate()
        lock = self.bundle / ".fixture.lock"
        lock.write_text("another run")
        for script in runtime.SCRIPTS:
            with self.subTest(script=script):
                self.assertEqual(self.script(script).returncode, 2)
                self.assertEqual(lock.read_text(), "another run")
                self.assertFalse((self.bundle / ".fixture").exists())


if __name__ == "__main__":
    unittest.main()
