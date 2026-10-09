"""Independent bundle integrity tests. Only inert, owned temporary fixtures run."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"


def load_script(name):
    spec = importlib.util.spec_from_file_location("reproduction_adversarial_" + name,
                                                  SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReproductionAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path_patch = patch.object(sys, "path", [str(SCRIPTS)] + sys.path)
        path_patch.start()
        cls.addClassCleanup(path_patch.stop)
        cls.repro = load_script("reproduction")
        cls.runtime = cls.repro.runtime
        cls.verification = load_script("verification")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.findings = self.root / "findings.json"
        self.data = json.loads((ROOT / "examples/findings.workflow.sample.json").read_text())
        self.findings.write_text(json.dumps(self.data), encoding="utf-8")
        self.original = self.findings.read_bytes()
        self.plan = json.loads((ROOT / "examples/reproduction.plan.sample.json").read_text())
        self.bundle = self.root / "bundle"
        self.out = self.root / "results"

    def generate(self):
        result = self.repro.generate(self.findings, "F-001", self.plan, self.bundle)
        self.assertEqual(result["status"], "not_run")
        return self.runtime.load_json(self.bundle / "manifest.json")

    def reseal(self, manifest):
        (self.bundle / "manifest.json").write_bytes(self.runtime.canonical(manifest))
        (self.bundle / "manifest.sha256.json").write_bytes(
            self.runtime.canonical({"sha256": self.runtime.digest(self.runtime.canonical(manifest))}))

    def test_undeclared_commands_sql_and_paths_rejected_before_creation(self):
        for key, value in (("command", "touch marker"), ("sql", "DROP TABLE resources"),
                           ("target", "https://invalid.example"), ("scratch", "../other")):
            with self.subTest(key=key):
                plan = dict(self.plan, **{key: value})
                with self.assertRaises(self.repro.BundleError):
                    self.repro.generate(self.findings, "F-001", plan, self.bundle)
                self.assertFalse(self.bundle.exists())

    def test_boundary_sensitive_plan_values_are_strict(self):
        plans = [dict(self.plan, template="sqlite-owner-scope-v999"),
                 dict(self.plan, seed=True), dict(self.plan, seed=-1),
                 dict(self.plan, case_id="../../outside"),
                 dict(self.plan, case_id="case\ncommand"),
                 dict(self.plan, fixture={"owners": 1000000, "resources_per_owner": 2}),
                 dict(self.plan, evidence_ids=["source-before", "source-before"]),
                 dict(self.plan, before={"policy": "unscoped", "sql": "SELECT 1"})]
        for plan in plans:
            with self.subTest(plan=plan):
                with self.assertRaises((self.repro.BundleError, ValueError)):
                    self.repro.generate(self.findings, "F-001", plan, self.bundle)
                self.assertFalse(self.bundle.exists())

    def test_finding_prose_never_becomes_generated_code_or_output(self):
        marker = "INERT_PRIVATE_FINDING_MARKER_782"
        self.data["findings"][0]["title"] = marker + "; import os; os.system('false')"
        self.findings.write_text(json.dumps(self.data))
        self.generate()
        result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertTrue(result["repeatable"])
        for path in list(self.bundle.rglob("*")) + list(self.out.rglob("*")):
            if path.is_file():
                self.assertNotIn(marker.encode(), path.read_bytes(), str(path))

    def test_current_findings_bytes_are_bound_even_for_whitespace_change(self):
        self.generate()
        self.findings.write_bytes(self.original + b"\n")
        with patch.object(self.repro.subprocess, "run") as execute:
            with self.assertRaises(self.repro.BundleError):
                self.repro.run(self.bundle, self.findings, self.out)
        execute.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_modified_script_with_updated_self_hash_cannot_execute(self):
        manifest = self.generate()
        marker = self.root / "unexpected-execution"
        path = self.bundle / "run.py"
        path.write_text("from pathlib import Path\nPath(%r).touch()\n" % str(marker))
        manifest["files"]["run.py"] = self.runtime.digest(path.read_bytes())
        self.reseal(manifest)
        with patch.object(self.repro.subprocess, "run") as execute:
            with self.assertRaises(self.repro.BundleError):
                self.repro.run(self.bundle, self.findings, self.out)
        execute.assert_not_called()
        self.assertFalse(marker.exists())

    def test_resealed_manifest_cannot_falsify_boundary(self):
        manifest = self.generate()
        manifest["boundary"] = "real"
        self.reseal(manifest)
        with self.assertRaises(self.repro.BundleError):
            self.repro.verify(self.bundle, self.findings)

    def test_standalone_manifest_loading_preserves_fixture_bounds(self):
        manifest = self.generate()
        manifest["plan"]["fixture"]["owners"] = 11
        self.reseal(manifest)
        with self.assertRaises(self.repro.BundleError):
            self.runtime.manifest_at(self.bundle, self.findings)

    def test_standalone_manifest_rejects_resealed_namespace_change(self):
        manifest = self.generate()
        manifest["namespace"] = "../unowned-fixture"
        self.reseal(manifest)
        with self.assertRaises(self.repro.BundleError):
            self.runtime.manifest_at(self.bundle, self.findings)

    def test_script_replaced_after_initial_verification_is_never_executed(self):
        self.generate()
        marker = self.root / "replaced-script-executed"
        execute = self.repro.subprocess.run
        def replace_then_execute(*args, **kwargs):
            (self.bundle / "run.py").write_text(
                "from pathlib import Path\nPath(%r).touch()\n" % str(marker))
            return execute(*args, **kwargs)
        with patch.object(self.repro.subprocess, "run", side_effect=replace_then_execute):
            result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertFalse(marker.exists())
        self.assertFalse(result["repeatable"])
        self.assertNotEqual(result["status"], "completed")

    def test_duplicate_json_keys_fail_closed(self):
        self.generate()
        path = self.bundle / "manifest.json"
        raw = path.read_bytes()
        path.write_bytes(b'{"bundle_version": 1,' + raw[1:])
        with self.assertRaises(self.repro.BundleError):
            self.repro.verify(self.bundle, self.findings)

    def test_symlinked_output_ancestor_is_rejected(self):
        actual = self.root / "actual"
        actual.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(self.repro.BundleError):
            self.repro.generate(self.findings, "F-001", self.plan, alias / "bundle")
        self.assertEqual(list(actual.iterdir()), [])

    def test_hardlinked_findings_are_rejected(self):
        os.link(self.findings, self.root / "second-name.json")
        with self.assertRaises(self.repro.BundleError):
            self.repro.generate(self.findings, "F-001", self.plan, self.bundle)
        self.assertEqual(self.findings.read_bytes(), self.original)

    def test_foreign_scratch_contents_survive_cleanup_and_run(self):
        manifest = self.generate()
        self.runtime.seed(self.bundle, manifest)
        foreign = self.bundle / ".fixture" / "do-not-delete.txt"
        foreign.write_text("preserve")
        with self.assertRaises(self.repro.BundleError):
            self.runtime.cleanup(self.bundle, manifest)
        result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertNotEqual(result["status"], "completed")
        self.assertFalse(result["repeatable"])
        self.assertEqual(foreign.read_text(), "preserve")
        self.assertTrue((foreign.parent / "fixture.sqlite3").exists())

    def test_symlinked_fixture_database_never_touched(self):
        manifest = self.generate()
        self.runtime.seed(self.bundle, manifest)
        database = self.bundle / ".fixture" / "fixture.sqlite3"
        database.unlink()
        outside = self.root / "outside.sqlite3"
        outside.write_bytes(b"preserve external bytes")
        database.symlink_to(outside)
        for action in (self.runtime.seed, self.runtime.reproduce, self.runtime.cleanup):
            with self.subTest(action=action.__name__):
                with self.assertRaises(self.repro.BundleError):
                    action(self.bundle, manifest)
                self.assertEqual(outside.read_bytes(), b"preserve external bytes")
                self.assertTrue(database.is_symlink())

    def test_hardlinked_fixture_database_survives_cleanup_refusal(self):
        manifest = self.generate()
        self.runtime.seed(self.bundle, manifest)
        database = self.bundle / ".fixture" / "fixture.sqlite3"
        outside = self.root / "second-database-name"
        os.link(database, outside)
        original = outside.read_bytes()
        with self.assertRaises(self.repro.BundleError):
            self.runtime.cleanup(self.bundle, manifest)
        self.assertTrue(database.exists())
        self.assertEqual(outside.read_bytes(), original)

    def test_wrong_fixture_owner_is_not_deleted(self):
        manifest = self.generate()
        self.runtime.seed(self.bundle, manifest)
        owner = self.bundle / ".fixture" / "owner.json"
        owner.write_text('{"owner": "another actor"}')
        with self.assertRaises(self.repro.BundleError):
            self.runtime.cleanup(self.bundle, manifest)
        self.assertEqual(owner.read_text(), '{"owner": "another actor"}')

    def test_foreign_lock_preserved_and_prevents_fixture_execution(self):
        self.generate()
        lock = self.bundle / ".fixture.lock"
        lock.write_text("another active run")
        result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertNotEqual(result["status"], "completed")
        self.assertFalse(result["repeatable"])
        self.assertFalse((self.bundle / ".fixture").exists())
        self.assertEqual(lock.read_text(), "another active run")

    def test_preexisting_result_directory_is_never_overwritten(self):
        self.generate()
        self.out.mkdir()
        foreign = self.out / "results.json"
        foreign.write_bytes(b"user result")
        with self.assertRaises((self.repro.BundleError, OSError)):
            self.repro.run(self.bundle, self.findings, self.out)
        self.assertEqual(foreign.read_bytes(), b"user result")
        self.assertFalse((self.bundle / ".fixture").exists())

    def test_import_shadow_file_blocks_trusted_runner_before_execution(self):
        self.generate()
        marker = self.root / "shadow-import-executed"
        (self.bundle / "sqlite3.py").write_text("from pathlib import Path\nPath(%r).touch()\n" % str(marker))
        with self.assertRaises(self.repro.BundleError):
            self.repro.run(self.bundle, self.findings, self.out)
        self.assertFalse(marker.exists())

    def test_inherited_pythonpath_cannot_execute_sitecustomize(self):
        self.generate()
        poison = self.root / "poison"
        poison.mkdir()
        marker = self.root / "sitecustomize-executed"
        (poison / "sitecustomize.py").write_text("from pathlib import Path\nPath(%r).touch()\n" % str(marker))
        with patch.dict(os.environ, {"PYTHONPATH": str(poison)}):
            result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(marker.exists())

    def test_manual_adapter_is_unsupported_and_never_invokes_subprocess(self):
        self.plan["template"] = "manual-target-v1"
        self.generate()
        with patch.object(self.repro.subprocess, "run") as execute:
            result = self.repro.run(self.bundle, self.findings, self.out)
        execute.assert_not_called()
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse(result["repeatable"])
        self.assertFalse((self.bundle / ".fixture").exists())
        self.assertEqual(self.runtime.load_json(self.out / "records.json")["test_runs"], [])

    def test_timeout_cannot_become_red_evidence_or_completed(self):
        self.generate()
        error = subprocess.TimeoutExpired(["trusted-runtime"], 1, output=b"private partial output")
        with patch.object(self.repro.subprocess, "run", side_effect=error):
            result = self.repro.run(self.bundle, self.findings, self.out, timeout=1)
        self.assertEqual(result["status"], "timeout")
        self.assertFalse(result["repeatable"])
        records = self.runtime.load_json(self.out / "records.json")
        self.assertEqual(records["test_runs"], [])
        self.assertNotIn("private partial output", json.dumps(result))

    def test_incomplete_replay_exports_no_records(self):
        manifest = self.generate()
        cycle = {"cycle": 1, "status": "completed", "reproduction": {"cases": [
            {"phase": "before", "role": "security", "case_id": "c", "expected": "x", "actual": "x",
             "result": "fail", "failure_kind": "assertion"}]}}
        for result in ({"status": "incomplete", "repeatable": False, "cycles": [cycle, dict(cycle, cycle=2, status="error")]},
                       {"status": "timeout", "repeatable": False, "cycles": [cycle]}):
            with self.subTest(status=result["status"]):
                out = self.root / ("records-" + result["status"])
                out.mkdir()
                records = self.repro.export_records(manifest, result, out)
                self.assertEqual((records["evidence"], records["test_runs"]), ([], []))

    def test_child_deadline_follows_the_run_timeout(self):
        self.generate()
        captured = {}

        def fake_run(argv, **kwargs):
            captured["program"] = argv[argv.index("-c") + 1]
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        with patch.object(self.repro.subprocess, "run", side_effect=fake_run):
            self.repro.run(self.bundle, self.findings, self.out, timeout=30)
        self.assertIn('entry("run", evidence_checked=True, timeout=29)', captured["program"])

    def test_child_reports_timeout_when_a_cycle_times_out(self):
        manifest = self.generate()
        with patch.object(self.runtime.time, "monotonic", side_effect=[0, 0, 0, 0, 0, 100, 100, 100, 100]):
            result = self.runtime.repeat(self.bundle, manifest, timeout=10)
        self.assertEqual(result["status"], "timeout")
        self.assertFalse(result["repeatable"])

    def test_runner_output_and_errors_do_not_leak_into_public_results(self):
        self.generate()
        private = "INERT_PRIVATE_STDOUT_MARKER_691"
        process = subprocess.CompletedProcess(["trusted-runtime"], 2,
                                               stdout=private.encode(), stderr=private.encode())
        with patch.object(self.repro.subprocess, "run", return_value=process):
            result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertEqual(result["status"], "error")
        self.assertFalse(result["repeatable"])
        self.assertNotIn(private, json.dumps(result))
        self.assertNotIn(private, (self.out / "results.json").read_text())

    def test_findings_changed_during_execution_marks_results_stale(self):
        self.generate()
        execute = self.repro.subprocess.run
        def execute_then_change(*args, **kwargs):
            result = execute(*args, **kwargs)
            self.findings.write_bytes(self.original + b"\n")
            return result
        with patch.object(self.repro.subprocess, "run", side_effect=execute_then_change):
            result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertEqual(result["status"], "stale")
        self.assertFalse(result["repeatable"])
        records = self.runtime.load_json(self.out / "records.json")
        self.assertEqual(records["status"], "stale")
        # Stale replays export no evidence or test runs that could be imported as current.
        self.assertEqual((records["evidence"], records["test_runs"]), ([], []))
        self.assertEqual(list((self.out / "evidence").iterdir()), [])

    def test_successful_mocked_records_cannot_certify_actual_finding_or_fix(self):
        self.generate()
        result = self.repro.run(self.bundle, self.findings, self.out)
        self.assertTrue(result["repeatable"])
        records = self.runtime.load_json(self.out / "records.json")
        self.assertTrue(records["test_runs"])
        self.assertTrue(all(run["context"]["boundary"] == "mocked" for run in records["test_runs"]))
        assessment = json.loads((ROOT / "examples/findings.verification.sample.json").read_text())
        assessment["test_runs"] = records["test_runs"]
        assessment["evidence"] += records["evidence"]
        finding = assessment["findings"][0]
        def choose(phase, role):
            return next(run["id"] for run in records["test_runs"]
                        if ("-1-" + phase + "-") in run["id"] and run["role"] == role)
        finding["verification"]["run_ids"] = [choose("before", "security")]
        finding["remediation"].update(before_run_id=choose("before", "security"),
                                       after_run_id=choose("after", "security"),
                                       positive_control_run_ids=[choose("after", "positive_control")],
                                       regression_run_ids=[choose("after", "regression")])
        state = self.verification.derive_verification(assessment)["F-001"]
        self.assertNotEqual(state["level"], "runtime_supported")
        self.assertNotEqual(state["retest"], "verified")
        self.assertEqual(self.findings.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
