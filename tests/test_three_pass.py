"""Offline three-pass gate regressions; no model or application execution."""
from collections import Counter
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import three_pass
import verification_workflow as workflow

SPEC = importlib.util.spec_from_file_location("three_pass_benchmark", ROOT / "scripts/ci/benchmark_three_pass.py")
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class ThreePassTests(unittest.TestCase):
    def setUp(self):
        self.data = benchmark.sample()
        self.finding = self.data["findings"][0]

    def state(self):
        return workflow.derive_workflow(self.data, self.finding)

    def advance(self, stage, edit=None):
        output = benchmark.submission(self.data, stage)
        if edit:
            edit(output)
        return workflow.submit(self.data, "F-001", output)

    def falsification_ready(self):
        workflow.initialize(self.data, "F-001", "coordinator")
        self.advance("conditions")

    def cli(self, data, *args):
        with tempfile.TemporaryDirectory(prefix="three-pass-audit-") as directory:
            path = Path(directory) / "findings.json"
            raw = json.dumps(data, indent=2)
            path.write_text(raw, encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = workflow.main(["audit", str(path), *args])
            self.assertEqual(path.read_text(encoding="utf-8"), raw, "audit must be read-only")
            self.assertFalse(path.with_name(path.name + ".workflow.lock").exists())
        return code, out.getvalue(), err.getvalue()

    def test_pending_sample_is_small_valid_and_not_a_serialized_journal(self):
        workflow._validate_base(self.data)
        self.assertLess(benchmark.SAMPLE.stat().st_size, 8000)
        self.assertNotIn("verification_workflow", self.finding)
        self.assertNotIn("verification", self.finding)
        self.assertEqual(self.finding["validation"]["verdict"], "Unverified")
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "held")
        self.assertEqual(audit["discovery"]["status"], "complete")
        self.assertEqual(audit["coverage_challenge"]["missing_coverage_ids"], ["admin-route", "order-detail", "order-list"])

    def test_all_passes_complete_only_after_sequential_decision(self):
        workflow.initialize(self.data, "F-001", "coordinator")
        for stage in workflow.STAGES:
            self.assertEqual(self.state()["next_stage"], stage)
            self.assertEqual(three_pass.derive_three_pass(self.data)["status"], "held")
            self.advance(stage)
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "complete")
        self.assertEqual([(row["id"], row["status"]) for row in audit["passes"]],
                         [("discovery", "complete"), ("conditions", "complete"), ("challenge", "complete")])
        self.assertEqual(audit["coverage_challenge"]["completed"], 3)
        self.assertEqual(self.finding["validation"]["verdict"], "Valid")
        self.assertEqual(self.finding["confidence"], "Suspected")
        self.assertEqual([row["stage"] for row in self.state()["stages"]], list(workflow.STAGES))

    def test_incomplete_discovery_derives_held_and_prevents_initialization(self):
        mutations = (
            lambda data: data["three_pass"]["discovery"]["checks"].pop(),
            lambda data: data["three_pass"]["discovery"]["checks"][1].update(status="not_checked", evidence_ids=[]),
            lambda data: data["three_pass"]["discovery"]["checks"][0].update(finding_ids=[]),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = benchmark.sample()
                mutate(data)
                before = copy.deepcopy(data)
                self.assertEqual(three_pass.derive_three_pass(data)["status"], "held")
                with self.assertRaisesRegex(workflow.WorkflowError, "finish discovery"):
                    workflow.initialize(data, "F-001", "coordinator")
                self.assertEqual(data, before)

    def test_three_actors_are_distinct_after_case_and_whitespace_normalization(self):
        for stage, duplicate in (("conditions", " SYNTHETIC-DISCOVERY "),
                                 ("falsification", " SYNTHETIC-DISCOVERY "),
                                 ("falsification", " SYNTHETIC-CONDITIONS ")):
            with self.subTest(stage=stage, actor=duplicate):
                self.setUp()
                workflow.initialize(self.data, "F-001", "coordinator")
                if stage == "falsification":
                    self.advance("conditions")
                output = benchmark.submission(self.data, stage)
                output["actor"] = duplicate
                if stage == "falsification":
                    output["reviews"][0]["reviewer"] = duplicate
                before = copy.deepcopy(self.data)
                with self.assertRaisesRegex(workflow.WorkflowError, "different declared actors"):
                    workflow.submit(self.data, "F-001", output)
                self.assertEqual(self.data, before)

    def test_actual_challenge_actor_must_review_every_claim_reference_at_all_severities(self):
        for severity in ("High", "Medium", "Low", "Info"):
            with self.subTest(severity=severity):
                self.setUp()
                self.finding["severity"] = severity
                self.falsification_ready()
                output = benchmark.submission(self.data, "falsification")
                output["reviews"].append(dict(copy.deepcopy(output["reviews"][0]), reviewer="other-complete-reviewer"))
                output["reviews"][0]["evidence_ids"] = ["route-source"]
                state = workflow.submit(self.data, "F-001", output)
                self.assertEqual(state["status"], "held")
                self.assertIn("three_pass_review_coverage_incomplete", state["reasons"])
                self.assertEqual(self.finding["validation"]["verdict"], "Unverified")
                self.assertEqual(self.finding["verification"]["reviews"], output["reviews"])

    def test_missing_actor_review_is_rejected_atomically(self):
        self.falsification_ready()
        output = benchmark.submission(self.data, "falsification")
        output["reviews"][0]["reviewer"] = "someone-else"
        before = copy.deepcopy(self.data)
        with self.assertRaisesRegex(workflow.WorkflowError, "own review"):
            workflow.submit(self.data, "F-001", output)
        self.assertEqual(self.data, before)

    def test_every_negative_claim_is_required_and_unlabelled_checks_do_not_count(self):
        for omitted in (*workflow.CLAIMS, "unlabelled"):
            with self.subTest(omitted=omitted):
                self.setUp()
                self.falsification_ready()
                output = benchmark.submission(self.data, "falsification")
                if omitted == "unlabelled":
                    for check in output["checks"]:
                        check.pop("claim")
                else:
                    output["checks"] = [row for row in output["checks"] if row["claim"] != omitted]
                state = workflow.submit(self.data, "F-001", output)
                self.assertEqual(state["status"], "held")
                self.assertIn("three_pass_negative_checks_incomplete", state["reasons"])
                self.assertEqual(self.finding["validation"]["verdict"], "Unverified")

    def test_benign_and_inapplicable_cells_cannot_be_skipped_in_aggregate(self):
        for omitted in ("order-list", "admin-route"):
            with self.subTest(omitted=omitted):
                self.setUp()
                def transform(stage, output):
                    if stage == "falsification":
                        output["coverage_checks"] = [row for row in output["coverage_checks"] if row["coverage_id"] != omitted]
                self.assertEqual(benchmark.complete(self.data, transform=transform)["status"], "complete")
                audit = three_pass.derive_three_pass(self.data)
                self.assertEqual(audit["status"], "held")
                self.assertEqual(audit["coverage_challenge"]["missing_coverage_ids"], [omitted])

    def test_associated_candidate_scope_is_required_before_decision(self):
        self.falsification_ready()
        output = benchmark.submission(self.data, "falsification")
        output["coverage_checks"] = [row for row in output["coverage_checks"] if row["coverage_id"] != "order-detail"]
        state = workflow.submit(self.data, "F-001", output)
        self.assertEqual(state["status"], "held")
        self.assertIn("three_pass_scope_challenge_incomplete", state["reasons"])
        self.assertEqual(self.finding["validation"]["verdict"], "Unverified")

    def test_scope_union_across_current_finding_workflows_and_stale_rounds(self):
        second = copy.deepcopy(self.finding)
        second.update(id="F-002", title="Second synthetic candidate")
        self.data["findings"].append(second)
        self.data["three_pass"]["discovery"]["checks"][1]["finding_ids"] = ["F-002"]
        def scope_only(ids):
            def transform(stage, output):
                if stage == "falsification":
                    output["coverage_checks"] = [row for row in output["coverage_checks"] if row["coverage_id"] in ids]
            return transform
        benchmark.complete(self.data, transform=scope_only({"order-detail", "admin-route"}))
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "held")
        self.assertEqual(audit["coverage_challenge"]["missing_coverage_ids"], ["order-list"])
        benchmark.complete(self.data, "F-002", scope_only({"order-list"}))
        self.assertEqual(three_pass.derive_three_pass(self.data)["status"], "complete")
        workflow.invalidate(self.data, "F-002", "coordinator", "Require a fresh round")
        workflow.resume(self.data, "F-002", "coordinator", "Restart review")
        state = three_pass.derive_three_pass(self.data)
        self.assertEqual(state["status"], "held")
        self.assertEqual(state["coverage_challenge"]["missing_coverage_ids"], ["order-list"])
        self.assertEqual(self.state()["status"], "complete", "Independent finding progress should not stale the first journal")

    def test_clear_scope_review_cannot_outvote_another_workflows_contradiction(self):
        second = copy.deepcopy(self.finding)
        second["id"] = "F-002"
        self.data["findings"].append(second)
        self.data["three_pass"]["discovery"]["checks"][0]["finding_ids"].append("F-002")
        benchmark.complete(self.data)
        def contradiction(stage, output):
            if stage == "falsification":
                output["coverage_checks"][1]["result"] = "contradiction"
        benchmark.complete(self.data, "F-002", contradiction)
        state = three_pass.derive_three_pass(self.data)
        self.assertEqual(state["status"], "held")
        self.assertIn("three_pass_scope_contradiction", state["reasons"])
        self.assertIn("order-list", state["coverage_challenge"]["missing_coverage_ids"])

    def test_removing_candidate_and_its_discovery_reference_stales_surviving_review(self):
        second = copy.deepcopy(self.finding)
        second["id"] = "F-002"
        self.data["findings"].append(second)
        self.data["three_pass"]["discovery"]["checks"][0]["finding_ids"].append("F-002")
        benchmark.complete(self.data)
        benchmark.complete(self.data, "F-002")
        self.assertEqual(three_pass.derive_three_pass(self.data)["status"], "complete")
        self.data["findings"].pop()
        self.data["three_pass"]["discovery"]["checks"][0]["finding_ids"].pop()
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "held")
        self.assertEqual(audit["findings"]["F-001"]["status"], "stale")

    def test_scope_counterevidence_cannot_be_removed_by_resuming(self):
        self.falsification_ready()
        output = benchmark.submission(self.data, "falsification")
        output["coverage_checks"][1]["result"] = "contradiction"
        workflow.submit(self.data, "F-001", output)
        workflow.resume(self.data, "F-001", "coordinator", "Review the conflicting observation")
        replacement = benchmark.submission(self.data, "falsification")
        before = copy.deepcopy(self.data)
        with self.assertRaisesRegex(workflow.WorkflowError, "cannot drop active scope counterevidence"):
            workflow.submit(self.data, "F-001", replacement)
        self.assertEqual(self.data, before)

    def test_exclusions_preserve_candidate_tracking_and_require_counterevidence(self):
        for scenario, verdict in (("false_positive", "FalsePositive"), ("not_applicable", "NotApplicable")):
            with self.subTest(verdict=verdict):
                data, state = benchmark.execute_case({"scenario": scenario})
                self.assertEqual(state["status"], "complete")
                self.assertEqual(data["findings"][0]["validation"]["verdict"], verdict)
                self.assertEqual(data["three_pass"]["discovery"]["checks"][0]["finding_ids"], ["F-001"])
                self.assertEqual(data["findings"][0]["verification"]["claims"]["preconditions"]["status"], "contradicted")
                self.assertTrue(data["findings"][0]["verification"]["exclusion"]["evidence_ids"])
        self.falsification_ready()
        self.advance("falsification")
        output = benchmark.submission(self.data, "decision")
        output["validation"]["verdict"] = "FalsePositive"
        with self.assertRaisesRegex(workflow.WorkflowError, "exclusion"):
            workflow.submit(self.data, "F-001", output)

    def test_runtime_nonresults_and_unknown_environment_do_not_promote(self):
        for outcome in ("not_run", "blocked", "unsupported", "error", "skip"):
            with self.subTest(outcome=outcome):
                data = benchmark.sample()
                benchmark._prepare(data, "unsupported_runtime")
                data["test_runs"][0]["result"] = outcome
                state = benchmark.complete(data, transform=lambda stage, output: benchmark._transform("unsupported_runtime", stage, output))
                self.assertEqual(state["status"], "held")
                self.assertIn("runtime_incomplete", state["reasons"])
                self.assertEqual(data["findings"][0]["validation"]["verdict"], "Unverified")
                self.assertEqual(data["findings"][0]["confidence"], "Suspected")
        data, audit = benchmark.execute_case({"scenario": "unknown_environment"})
        self.assertEqual(audit["findings"]["F-001"]["status"], "unknown")
        self.assertEqual(data["findings"][0]["validation"]["verdict"], "Unverified")

    def test_unresolved_dissent_is_preserved_despite_majority(self):
        data, audit = benchmark.execute_case({"scenario": "dissent"})
        self.assertEqual(audit["status"], "held")
        state = audit["findings"]["F-001"]
        self.assertEqual(state["status"], "conflict")
        self.assertIn("review_disagreement", state["reasons"])
        reviews = data["findings"][0]["verification"]["reviews"]
        self.assertEqual(Counter(row["conclusion"] for row in reviews), {"agree": 5, "disagree": 1})
        self.assertEqual(data["findings"][0]["validation"]["verdict"], "Unverified")

    def test_evidence_and_discovery_changes_stale_completed_review(self):
        for scenario in ("stale_evidence", "stale_discovery"):
            with self.subTest(scenario=scenario):
                data, audit = benchmark.execute_case({"scenario": scenario})
                self.assertEqual(audit["status"], "held")
                self.assertEqual(audit["findings"]["F-001"]["status"], "stale")
                self.assertEqual(audit["coverage_challenge"]["completed"], 0)
                with self.assertRaisesRegex(workflow.WorkflowError, "resume"):
                    workflow.submit(data, "F-001", benchmark.submission(data, "conditions"))

    def test_old_round_handoff_cannot_be_replayed_after_restart(self):
        self.falsification_ready()
        old = benchmark.submission(self.data, "falsification")
        old_round = self.state()["history"][0]["round_id"]
        workflow.invalidate(self.data, "F-001", "coordinator", "Request another review")
        workflow.resume(self.data, "F-001", "coordinator", "Start a fresh review")
        self.advance("conditions")
        before = copy.deepcopy(self.data)
        with self.assertRaisesRegex(workflow.WorkflowError, "stale handoff"):
            workflow.submit(self.data, "F-001", old)
        self.assertEqual(self.data, before)
        rounds = [row["round_id"] for row in self.state()["history"] if "round_id" in row]
        self.assertEqual(len(rounds), 2)
        self.assertNotEqual(rounds[-1], old_round)

    def test_duplicate_unknown_and_wrong_pin_discovery_references_rejected(self):
        mutations = {
            "duplicate plan": lambda d: d["three_pass"]["coverage"].append(copy.deepcopy(d["three_pass"]["coverage"][0])),
            "duplicate check": lambda d: d["three_pass"]["discovery"]["checks"].append(copy.deepcopy(d["three_pass"]["discovery"]["checks"][0])),
            "unknown coverage": lambda d: d["three_pass"]["discovery"]["checks"][0].update(coverage_id="unknown"),
            "unknown finding": lambda d: d["three_pass"]["discovery"]["checks"][0].update(finding_ids=["unknown"]),
            "duplicate finding": lambda d: d["three_pass"]["discovery"]["checks"][0].update(finding_ids=["F-001", "F-001"]),
            "unknown evidence": lambda d: d["three_pass"]["discovery"]["checks"][0].update(evidence_ids=["unknown"]),
            "duplicate evidence": lambda d: d["three_pass"]["discovery"]["checks"][0].update(evidence_ids=["route-source", "route-source"]),
            "wrong pin": lambda d: d["evidence"][0].update(commit="9" * 40),
            "N/A with candidate": lambda d: d["three_pass"]["discovery"]["checks"][0].update(status="not_applicable"),
            "unknown field": lambda d: d["three_pass"].update(complete=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                data = benchmark.sample()
                mutate(data)
                with self.assertRaises(ValueError):
                    three_pass.validate_profile(data)

    def test_unknown_duplicate_and_wrong_pin_challenge_references_are_atomic_errors(self):
        self.data["evidence"].append(dict(self.data["evidence"][2], id="stale-source", commit="9" * 40))
        self.falsification_ready()
        mutations = {
            "unknown coverage": lambda o: o["coverage_checks"][0].update(coverage_id="unknown"),
            "duplicate coverage": lambda o: o["coverage_checks"].append(copy.deepcopy(o["coverage_checks"][0])),
            "unknown evidence": lambda o: o["coverage_checks"][0].update(evidence_ids=["unknown"]),
            "duplicate evidence": lambda o: o["coverage_checks"][0].update(evidence_ids=["scope-source", "scope-source"]),
            "wrong pin": lambda o: o["coverage_checks"][0].update(evidence_ids=["stale-source"]),
            "empty source": lambda o: o["coverage_checks"][0].update(evidence_ids=[]),
            "unknown result": lambda o: o["coverage_checks"][0].update(result="pass"),
            "unknown field": lambda o: o["coverage_checks"][0].update(approved=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                output = benchmark.submission(self.data, "falsification")
                mutate(output)
                before = copy.deepcopy(self.data)
                with self.assertRaises(workflow.WorkflowError):
                    workflow.submit(self.data, "F-001", output)
                self.assertEqual(self.data, before)

    def test_handoff_prompts_all_claims_and_all_scope_cells(self):
        self.falsification_ready()
        handoff = workflow.next_handoff(self.data, "F-001")
        self.assertEqual(handoff["pass"], 3)
        template = handoff["submission_template"]
        self.assertEqual({row["claim"] for row in template["checks"]}, set(workflow.CLAIMS))
        self.assertEqual({row["coverage_id"] for row in template["coverage_checks"]}, {"order-detail", "order-list", "admin-route"})
        self.assertTrue(all(row["result"] == "unresolved" for row in template["coverage_checks"]))

    def test_required_integrity_is_not_satisfied_by_synthetic_hash_declarations(self):
        self.data["evidence_integrity"] = {"required": True}
        audit = three_pass.derive_three_pass(self.data)
        self.assertEqual(audit["status"], "held")
        self.assertIn("evidence_integrity_unchecked", audit["reasons"])
        with self.assertRaisesRegex(workflow.WorkflowError, "finish discovery"):
            workflow.initialize(self.data, "F-001", "coordinator")

    def test_empty_findings_never_satisfy_all_three_passes(self):
        data, audit = benchmark.execute_case({"scenario": "zero_findings"})
        self.assertEqual(audit["status"], "held")
        self.assertIn("three_pass_no_candidates", audit["reasons"])
        self.assertEqual([row["status"] for row in audit["passes"]], ["complete", "held", "held"])
        self.assertEqual(self.cli(data, "--require-complete")[0], 3)

    def test_legacy_without_profile_is_unchanged_and_not_opted_in(self):
        for version in (1, 2):
            with self.subTest(version=version):
                data = benchmark.sample()
                data["schema_version"] = version
                data.pop("three_pass")
                if version == 1:
                    data["three_pass"] = "historical uninterpreted extension"
                state = three_pass.derive_three_pass(data)
                self.assertEqual(state, {"opted_in": False, "status": "not_requested", "reasons": [], "passes": [], "findings": {}})
                self.assertEqual(self.cli(data)[0], 0)
                self.assertEqual(self.cli(data, "--require-complete")[0], 3)

    def test_audit_cli_exit_codes_and_read_only_behavior(self):
        code, output, error = self.cli(self.data, "--require-complete")
        self.assertEqual((code, error), (3, ""))
        self.assertEqual(json.loads(output)["status"], "held")
        self.assertEqual(self.cli(self.data)[0], 0)
        benchmark.complete(self.data)
        code, output, error = self.cli(self.data, "--require-complete")
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)["status"], "complete")
        self.data["three_pass"]["discovery"]["checks"][0]["finding_ids"] = ["unknown"]
        code, output, error = self.cli(self.data, "--require-complete")
        self.assertEqual((code, output), (2, ""))
        self.assertIn("unknown finding ID", error)


class ThreePassBenchmarkTests(unittest.TestCase):
    def test_exact_synthetic_matrix_outcomes_without_external_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("Must not execute applications")), \
             patch("subprocess.Popen", side_effect=AssertionError("Must not execute models")), \
             patch("os.system", side_effect=AssertionError("Must not execute recorded commands")):
            report = benchmark.run_benchmark()
        self.assertEqual(report["case_count"], 26)
        self.assertEqual(report["matched"], 26)
        self.assertEqual(report["mismatched"], 0)
        self.assertEqual(report["expected_audit_counts"], {"complete": 4, "held": 17, "rejected": 5})
        self.assertEqual(report["actual_audit_counts"], report["expected_audit_counts"])
        self.assertEqual({key: value["cases"] for key, value in report["categories"].items()},
                         {"TP": 1, "FP": 2, "TN": 1, "FN": 7, "guardrail": 11, "malformed": 4})
        for row in report["results"]:
            with self.subTest(case=row["id"]):
                self.assertEqual(row["actual"], row["expected"], row)
        self.assertIn("not detector evaluation", report["limitations"])

    def test_benchmark_json_and_human_output_and_mismatch_exit(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(benchmark.main(["--json"]), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["case_count"], len(report["results"]))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(benchmark.main([]), 0)
        self.assertIn("expected complete/kept; actual complete/kept", stdout.getvalue())
        self.assertIn("Cases: 26; matched: 26; mismatched: 0", stdout.getvalue())
        fixture = json.loads(benchmark.FIXTURE.read_text(encoding="utf-8"))
        fixture["cases"][0]["expected"] = {"audit": "held", "disposition": "held"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(benchmark.main(["--fixture", str(path)]), 1)

    def test_unknown_or_duplicate_fixture_cases_fail_instead_of_counting_success(self):
        fixture = json.loads(benchmark.FIXTURE.read_text(encoding="utf-8"))
        for variant in ("unknown", "duplicate"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                data = copy.deepcopy(fixture)
                if variant == "unknown":
                    data["cases"][0]["scenario"] = "typo"
                else:
                    data["cases"].append(copy.deepcopy(data["cases"][0]))
                path = Path(directory) / "cases.json"
                path.write_text(json.dumps(data), encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(benchmark.main(["--fixture", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
