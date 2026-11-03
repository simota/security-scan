"""Keep diagnostics opt-in and prevent comparisons from silently changing revisions."""
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import benchmark_performance  # noqa: E402
import compare_performance  # noqa: E402


class PerformanceHarnessTests(unittest.TestCase):
    def test_original_measurement_shape_remains_the_default(self):
        result = benchmark_performance.measure(lambda: [1, 2], lambda value: value, 2)
        self.assertEqual(set(result), {"median_seconds", "samples_seconds", "output_sha256"})
        self.assertEqual(len(result["samples_seconds"]), 2)

    def test_forwarded_options_cannot_override_revision_or_sample_selection(self):
        scripts = str(ROOT / "skills/security-scan/scripts")
        for override in ("--scripts-dir=/different/revision", "--scripts=/different/revision",
                         "--repeats=99", "--rep=99", "--memory", "--mem"):
            with self.subTest(override=override):
                argv = ["compare_performance.py", "--before", scripts, "--after", scripts, "--", override]
                with patch.object(sys, "argv", argv), redirect_stderr(io.StringIO()), \
                        patch.object(compare_performance.subprocess, "Popen") as process:
                    with self.assertRaises(SystemExit) as error:
                        compare_performance.main()
                self.assertEqual(error.exception.code, 2)
                process.assert_not_called()

    def test_isolated_workers_complete_the_same_workload_with_equal_outputs(self):
        scripts = str(ROOT / "skills/security-scan/scripts")
        process = subprocess.run([
            sys.executable, str(ROOT / "scripts/ci/compare_performance.py"),
            "--before", scripts, "--after", scripts, "--samples", "2",
            "--", "--size", "small", "--workloads", "contract",
        ], capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        for revision in ("before", "after"):
            self.assertEqual(len(result[revision]["workloads"]["contract"]["samples_seconds"]), 2)
        self.assertTrue(result["comparisons"]["contract"]["output_identical"])
        self.assertEqual(result["samples_per_revision"], 2)


if __name__ == "__main__":
    unittest.main()
