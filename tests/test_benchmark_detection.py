"""Offline detection benchmark boundaries, scoring, sealing, and aggregation."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "benchmark_detection.py"
GROUND_TRUTH = ROOT / "examples" / "detection-ground-truth.sample.json"
RUNS = [ROOT / "examples" / f"detection-run-{number}.sample.json" for number in (1, 2, 3)]
spec = importlib.util.spec_from_file_location("benchmark_detection", SCRIPT)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def fixture(path):
    raw = path.read_bytes()
    return json.loads(raw), raw


def measured(path):
    ground_truth, gt_raw = fixture(GROUND_TRUTH)
    run, run_raw = fixture(path)
    return benchmark.measurement(
        ground_truth, benchmark.digest(gt_raw), run, benchmark.digest(run_raw), GROUND_TRUTH.parent)


class DetectionBenchmarkTests(unittest.TestCase):
    def assertRefused(self, code, function, *args):
        with self.assertRaises(benchmark.Refusal) as raised:
            function(*args)
        self.assertEqual(raised.exception.code, code, str(raised.exception))

    def altered_measurement(self, change):
        ground_truth, gt_raw = fixture(GROUND_TRUTH)
        run, _ = fixture(RUNS[0])
        change(ground_truth, run)
        gt_raw = benchmark.canonical(ground_truth)
        run["manifest"]["ground_truth_sha256"] = benchmark.digest(gt_raw)
        run_raw = benchmark.canonical(run)
        return benchmark.measurement(
            ground_truth, benchmark.digest(gt_raw), run, benchmark.digest(run_raw), GROUND_TRUTH.parent)

    def test_fixture_reports_confusion_metrics_partitions_bounds_and_cost(self):
        result = measured(RUNS[0])
        self.assertEqual(result["status"], "measured")
        self.assertEqual(result["score"]["confusion_matrix"], {
            "true_positive": 3, "false_positive": 2, "false_negative": 1, "true_negative": 1,
        })
        self.assertEqual(result["score"]["metrics"], {
            "precision": 0.6, "recall": 0.75, "f1": 0.6667, "false_positive_rate": 0.6667,
        })
        self.assertEqual(result["score"]["detected"], 3)
        self.assertEqual(result["score"]["total"], 4)
        self.assertEqual(result["score"]["denominator"], 4)
        self.assertEqual(result["score"]["detection_rate"], 0.75)
        self.assertEqual(result["score"]["detection_rate_wilson95"], [0.3006, 0.9544])
        self.assertEqual(result["score"]["gate_scores_over_detected"]["class"]["weight"], 2)
        self.assertEqual(result["score"]["weighted_gate_points"], 13)
        self.assertEqual(result["score"]["weighted_gate_points_available"], 15)
        self.assertEqual(result["score"]["precision_bounds_until_candidates_verified"], [0.4286, 0.6])
        self.assertEqual([item["id"] for item in result["score"]["true_positive_findings"]],
                         ["F-001", "F-002", "F-003"])
        self.assertEqual([item["id"] for item in result["score"]["false_positive_findings"]],
                         ["F-004", "F-007"])
        self.assertEqual([item["id"] for item in result["score"]["false_negative_cases"]], ["GT-004"])
        self.assertEqual([item["id"] for item in result["score"]["true_negative_cases"]], ["BT-002"])
        self.assertEqual([item["id"] for item in result["score"]["discovery_candidates"]], ["F-006"])
        self.assertEqual([item["id"] for item in result["score"]["invalid_findings_excluded"]], ["F-005"])
        self.assertEqual(result["resources"]["estimated_cost_usd"], 0.0)
        self.assertEqual(result["target"]["source_license"], "CC0-1.0")
        self.assertEqual(result["scanner"]["subject_role"], "primary-source-reviewer")
        self.assertEqual(result["target"]["source_artifact_path"], "detection-fixture-source.txt")
        self.assertEqual(result["input_identity"]["scanner_configuration_sha256"],
                         result["bound_inputs"]["scanner_configuration"]["sha256"])
        self.assertEqual(result["adjudications"]["vulnerable"][0]["evidence"]["source_location"],
                         "detection-fixture-source.txt:1")
        self.assertEqual(result["condition"], {"id": "full-static-review-v1", "source_access": "full-source"})
        self.assertFalse(result["comparability"]["artex_outcome_comparable"])
        self.assertEqual(result["comparability"]["measured_modality"], "static-source-review")
        benchmark.verify_seal(result, "fixture")

    def test_wilson_boundaries_have_explicit_zero_and_full_denominators(self):
        self.assertEqual(benchmark.wilson(0, 0), [0.0, 0.0])
        self.assertEqual(benchmark.wilson(0, 4), [0.0, 0.4899])
        self.assertEqual(benchmark.wilson(4, 4), [0.5101, 1.0])

    def test_public_git_pins_are_accepted_without_changing_the_modality(self):
        def change(ground_truth, run):
            revision = "git:" + "a" * 40
            ground_truth["source"].update(kind="public", uri="https://example.invalid/corpus", revision=revision)
            run["manifest"]["source_revision"] = revision

        result = self.altered_measurement(change)
        self.assertEqual(result["input_identity"]["source_revision"], "git:" + "a" * 40)
        self.assertFalse(result["comparability"]["artex_outcome_comparable"])
        self.assertEqual(result["target"]["source_kind"], "public")

    def test_ground_truth_requires_benign_cases_locations_gates_and_provenance(self):
        def missing_benign(ground_truth, run):
            ground_truth["cases"] = [case for case in ground_truth["cases"] if case["disposition"] == "vulnerable"]
            run["benign_adjudications"] = []

        self.assertRefused("invalid_schema", self.altered_measurement, missing_benign)
        for field in ("location", "gate_expectations"):
            def invalid(ground_truth, run, field=field):
                ground_truth["cases"][0].pop(field)

            with self.subTest(field=field):
                self.assertRefused("invalid_schema", self.altered_measurement, invalid)

        def changed_artifact(ground_truth, run):
            ground_truth["source"]["artifact_sha256"] = "sha256:" + "0" * 64

        self.assertRefused("source_artifact_mismatch", self.altered_measurement, changed_artifact)

        def absent_artifact(ground_truth, run):
            ground_truth["source"]["artifact_path"] = "absent-source.txt"

        self.assertRefused("missing_source_artifact", self.altered_measurement, absent_artifact)

        def absent_location(ground_truth, run):
            ground_truth["cases"][0]["location"] = "detection-fixture-source.txt:999"

        self.assertRefused("invalid_source_location", self.altered_measurement, absent_location)

        with tempfile.TemporaryDirectory() as directory:
            ground_truth, _ = fixture(GROUND_TRUTH)
            run, _ = fixture(RUNS[0])
            ground_truth["source"]["artifact_path"] = "linked-source.txt"
            for case in ground_truth["cases"]:
                case["location"] = case["location"].replace(
                    "detection-fixture-source.txt", "linked-source.txt")
            gt_raw = benchmark.canonical(ground_truth)
            run["manifest"]["ground_truth_sha256"] = benchmark.digest(gt_raw)
            linked = Path(directory) / "linked-source.txt"
            linked.symlink_to(GROUND_TRUTH.parent / "detection-fixture-source.txt")
            self.assertRefused(
                "unsafe_source_artifact", benchmark.measurement, ground_truth, benchmark.digest(gt_raw), run,
                benchmark.digest(benchmark.canonical(run)), Path(directory))

    def test_identity_status_pin_and_modality_fail_before_scoring(self):
        ground_truth, gt_raw = fixture(GROUND_TRUTH)
        run, run_raw = fixture(RUNS[0])
        cases = (
            ("input_identity_mismatch", lambda gt, item: item["manifest"].update(ground_truth_sha256="sha256:" + "0" * 64)),
            ("incomplete_run", lambda gt, item: item["manifest"].update(status="failed")),
            ("non_comparable_modality", lambda gt, item: item["manifest"].update(modality="black-box-execution")),
            ("unpinned_source", lambda gt, item: gt["source"].update(revision="main")),
        )
        for code, change in cases:
            with self.subTest(code=code):
                changed_ground_truth = copy.deepcopy(ground_truth)
                changed_run = copy.deepcopy(run)
                change(changed_ground_truth, changed_run)
                self.assertRefused(
                    code,
                    benchmark.measurement,
                    changed_ground_truth,
                    benchmark.digest(gt_raw),
                    changed_run,
                    benchmark.digest(run_raw),
                    GROUND_TRUTH.parent,
                )

    def test_adjudications_cannot_inflate_detections(self):
        ground_truth, gt_raw = fixture(GROUND_TRUTH)
        base, _ = fixture(RUNS[0])

        missing = copy.deepcopy(base)
        missing["adjudications"].pop()
        self.assertRefused("missing_adjudication", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           missing, benchmark.digest(benchmark.canonical(missing)), GROUND_TRUTH.parent)

        invalid_match = copy.deepcopy(base)
        invalid_match["adjudications"][0]["matched_finding_id"] = "F-005"
        self.assertRefused("invalid_match", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           invalid_match, benchmark.digest(benchmark.canonical(invalid_match)), GROUND_TRUTH.parent)

        reused = copy.deepcopy(base)
        reused["adjudications"][1]["matched_finding_id"] = "F-001"
        self.assertRefused("reused_finding", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           reused, benchmark.digest(benchmark.canonical(reused)), GROUND_TRUTH.parent)

        unsupported = copy.deepcopy(base)
        unsupported["adjudications"][0]["gates"]["class"] = False
        self.assertRefused("unsupported_detection", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           unsupported, benchmark.digest(benchmark.canonical(unsupported)), GROUND_TRUTH.parent)

        unrelated = copy.deepcopy(base)
        unrelated["adjudications"][0]["evidence"]["finding_excerpt"] = "unrelated words"
        self.assertRefused("unrelated_evidence", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           unrelated, benchmark.digest(benchmark.canonical(unrelated)), GROUND_TRUTH.parent)

        missing_benign = copy.deepcopy(base)
        missing_benign["benign_adjudications"].pop()
        self.assertRefused("missing_adjudication", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           missing_benign, benchmark.digest(benchmark.canonical(missing_benign)), GROUND_TRUTH.parent)

        no_evidence = copy.deepcopy(base)
        no_evidence["benign_adjudications"][0]["evidence"] = {}
        self.assertRefused("invalid_schema", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           no_evidence, benchmark.digest(benchmark.canonical(no_evidence)), GROUND_TRUTH.parent)

        reused_across_outcomes = copy.deepcopy(base)
        reused_across_outcomes["benign_adjudications"][0]["matched_finding_ids"][0] = "F-001"
        self.assertRefused("reused_finding", benchmark.measurement, ground_truth, benchmark.digest(gt_raw),
                           reused_across_outcomes, benchmark.digest(benchmark.canonical(reused_across_outcomes)),
                           GROUND_TRUTH.parent)

    def test_three_independent_runs_report_confusion_metrics_mean_and_spread(self):
        result = benchmark.summary([measured(path) for path in RUNS], 3)
        self.assertEqual(result["run_count"], 3)
        self.assertEqual(result["aggregate"]["confusion_matrix_totals"], {
            "true_positive": 8, "false_positive": 3, "false_negative": 4, "true_negative": 4,
        })
        self.assertEqual(result["aggregate"]["micro_metrics"], {
            "precision": 0.7273, "recall": 0.6667, "f1": 0.6957, "false_positive_rate": 0.4286,
        })
        self.assertEqual(result["aggregate"]["detection_rate"], {
            "mean": 0.6667, "min": 0.5, "max": 0.75, "sample_stdev": 0.1443,
        })
        self.assertEqual(result["aggregate"]["per_run_metrics"]["precision"]["mean"], 0.7833)
        self.assertEqual(result["aggregate"]["precision_lower_bound"]["mean"], 0.6151)
        self.assertIn("recall is separate", result["aggregate"]["gate_note"])
        self.assertEqual(result["resources"]["wall_seconds_total"], 134)
        self.assertEqual(result["resources"]["estimated_cost_usd_total"], 0.0)
        self.assertFalse(result["comparability"]["artex_outcome_comparable"])
        benchmark.verify_seal(result, "summary")

    def test_summary_refuses_duplicate_tampered_and_incomparable_runs(self):
        results = [measured(path) for path in RUNS]
        self.assertRefused("duplicate_run", benchmark.summary, [results[0], results[0], results[2]], 3)
        self.assertRefused("insufficient_replication", benchmark.summary, results[:2], 3)

        relabeled = copy.deepcopy(results[0])
        relabeled.pop("seal")
        relabeled["run_id"] = "fixture-run-relabeled"
        relabeled["input_identity"]["run_envelope_sha256"] = "sha256:" + "f" * 64
        relabeled = benchmark.sealed(relabeled)
        self.assertRefused("duplicate_observation", benchmark.summary,
                           [results[0], relabeled, results[2]], 3)

        tampered = copy.deepcopy(results)
        tampered[1]["score"]["detected"] = 4
        self.assertRefused("result_identity_mismatch", benchmark.summary, tampered, 3)

        different_scanner = copy.deepcopy(results)
        payload = dict(different_scanner[2])
        payload.pop("seal")
        payload["scanner"]["configuration"] = "changed-after-run"
        different_scanner[2] = benchmark.sealed(payload)
        self.assertRefused("invalid_result", benchmark.summary, different_scanner, 3)

        different_condition = copy.deepcopy(results)
        payload = copy.deepcopy(different_condition[2])
        payload.pop("seal")
        payload["condition"]["id"] = "different-condition"
        different_condition[2] = benchmark.sealed(payload)
        self.assertRefused("invalid_result", benchmark.summary, different_condition, 3)

        malformed = copy.deepcopy(results)
        malformed[1] = benchmark.sealed({"schema_version": 1})
        self.assertRefused("invalid_schema", benchmark.summary, malformed, 3)

        boolean_metric = copy.deepcopy(results)
        payload = copy.deepcopy(boolean_metric[1])
        payload.pop("seal")
        payload["score"]["metrics"]["precision"] = True
        boolean_metric[1] = benchmark.sealed(payload)
        self.assertRefused("invalid_result", benchmark.summary, boolean_metric, 3)

    def test_cli_creates_results_refuses_overwrite_and_summarizes(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = [Path(directory) / f"run-{number}.json" for number in (1, 2, 3)]
            for source, output in zip(RUNS, outputs):
                command = [sys.executable, str(SCRIPT), "validate", "--ground-truth", str(GROUND_TRUTH),
                           "--findings", str(source), "--out", str(output)]
                process = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertIn("ARTEX-comparable=no", process.stdout)
                self.assertIn("TP=", process.stdout)
                self.assertIn("subject=fixture-no-model role=primary-source-reviewer", process.stdout)
                self.assertIn("condition=full-static-review-v1 cost_usd=0.000000", process.stdout)
                benchmark.verify_seal(json.loads(output.read_text()), str(output))
            repeated = subprocess.run(
                [sys.executable, str(SCRIPT), "validate", "--ground-truth", str(GROUND_TRUTH),
                 "--findings", str(RUNS[0]), "--out", str(outputs[0])],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(repeated.returncode, 2)
            self.assertEqual(json.loads(repeated.stderr)["code"], "output_exists")

            summary = Path(directory) / "summary.json"
            process = subprocess.run(
                [sys.executable, str(SCRIPT), "summarize", "--runs", *map(str, outputs),
                 "--min-runs", "3", "--out", str(summary)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn("summary 3 runs: pooled TP=8 FP=3 FN=4 TN=4", process.stdout)
            self.assertIn("source=sha256:2e74b3be", process.stdout)
            summary_data = json.loads(summary.read_text())
            self.assertEqual(summary_data["run_count"], 3)
            self.assertEqual(summary_data["aggregate"]["micro_metrics"]["f1"], 0.6957)

    def test_make_target_retains_all_sealed_outputs_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "retained-evidence"
            command = ["make", "detection-benchmark", f"DETECTION_OUT={output}"]
            process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn(f"sealed evidence retained at {output}", process.stdout)
            self.assertEqual({path.name for path in output.iterdir()},
                             {"run-1.json", "run-2.json", "run-3.json", "summary.json"})
            for path in output.iterdir():
                benchmark.verify_seal(json.loads(path.read_text()), str(path))

            repeated = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("choose a new DETECTION_OUT", repeated.stderr)

    def test_resource_cost_and_subject_condition_are_validated(self):
        cases = (
            ("estimated_cost_usd", -0.01, "invalid_schema"),
            ("estimated_cost_usd", float("inf"), "invalid_schema"),
        )
        for field, value, code in cases:
            def change(ground_truth, run, field=field, value=value):
                run["manifest"]["resources"][field] = value

            with self.subTest(value=value):
                self.assertRefused(code, self.altered_measurement, change)

        def changed_access(ground_truth, run):
            run["manifest"]["condition"]["source_access"] = "partial-source"

        self.assertRefused("non_comparable_modality", self.altered_measurement, changed_access)

        def changed_configuration_bytes(ground_truth, run):
            run["manifest"]["scanner_configuration"]["content"] += "changed"

        self.assertRefused("input_bytes_mismatch", self.altered_measurement, changed_configuration_bytes)

    def test_json_reader_rejects_duplicate_keys_and_nonfinite_values(self):
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")
            self.assertRefused("duplicate_json_key", benchmark.read_json, duplicate)
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"value": NaN}', encoding="utf-8")
            self.assertRefused("invalid_json_number", benchmark.read_json, nonfinite)


if __name__ == "__main__":
    unittest.main()
