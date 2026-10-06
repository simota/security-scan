"""Offline workflow regressions: parse inert YAML without executing any steps."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


class WorkflowScanRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts/deps_scan.py"
        spec = importlib.util.spec_from_file_location("workflow_regression_deps", path)
        cls.deps = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(path.parent)] + sys.path):
            spec.loader.exec_module(cls.deps)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-workflow-regressions-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.path = self.root / ".github/workflows/test.yml"
        self.path.parent.mkdir(parents=True)

    def workflow(self, steps):
        text = ("name: test\non: pull_request\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n" + steps)
        self.path.write_text(text, encoding="utf-8")
        c = self.deps.Collector(self.root)
        self.deps.check_workflow(c, self.path)
        return c

    def injection_findings(self, c):
        return [f for f in c.findings if "untrusted event text" in f["title"]]

    def assert_incomplete(self, c):
        self.assertTrue(any(n["tool"] == "workflow run scan"
                            and ".github/workflows/test.yml" in n["reason"]
                            for n in c.not_run))

    def test_flow_mapping_step_is_incomplete_after_either_steps_or_a_previous_step(self):
        flow = '      - {run: \'echo "${{ github.event.pull_request.title }}"\'}\n'
        for prefix in ("", "      - run: echo safe\n"):
            with self.subTest(previous_step=bool(prefix)):
                c = self.workflow(prefix + flow)
                self.assert_incomplete(c)
                self.assertFalse(self.injection_findings(c))

    def test_indentationless_flow_mapping_step_is_incomplete(self):
        c = self.workflow('    - {run: \'echo "${{ github.event.pull_request.title }}"\'}\n')
        self.assert_incomplete(c)

    def test_aliased_anchored_and_merged_steps_are_incomplete(self):
        for step in ("      - *shared_step\n",
                     "      - &shared_step\n        run: echo safe\n",
                     "      - <<: *shared_step\n        run: echo safe\n"):
            with self.subTest(step=step):
                self.assert_incomplete(self.workflow("      - run: echo safe\n" + step))

    def test_multiline_flow_step_does_not_hide_the_next_run(self):
        c = self.workflow('''      - {
          env: {EXAMPLE: '${{ github.event.pull_request.title }}'},
          run: 'echo safe'
        }
      - run: echo "${{ github.head_ref }}"
''')
        self.assert_incomplete(c)
        findings = self.injection_findings(c)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"], ".github/workflows/test.yml:11")

    def test_flow_and_alias_examples_inside_non_run_blocks_are_ignored(self):
        c = self.workflow('''      - name: safe
        env:
          BRANCH: ${{ github.head_ref }}
          EXAMPLE: |
            - {run: 'echo "${{ github.event.pull_request.title }}"'}
            - *shared_step
        run: printf '%s\\n' "$BRANCH"
      - uses: actions/example@0000000000000000000000000000000000000000
        with:
          branch: ${{ github.head_ref }}
          example: |
            - {run: 'echo "${{ github.head_ref }}"'}
            - *shared_step
        # - {run: 'echo "${{ github.head_ref }}"'}
''')
        self.assertFalse(c.findings)
        self.assertFalse(c.not_run)

    def test_head_ref_is_detected_in_supported_run_scalars(self):
        for step, line in (
                ('      - run: echo "${{ github.head_ref }}"\n', 7),
                ('      - run: |\n          echo "${{github.head_ref}}"\n', 8),
                ('      - run: >-\n          echo "${{ github.head_ref }}"\n', 8),
                ('      - "run": echo "${{ github.head_ref }}"\n', 7)):
            with self.subTest(step=step):
                c = self.workflow(step)
                findings = self.injection_findings(c)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["location"], f".github/workflows/test.yml:{line}")
                self.assertFalse(c.not_run)


if __name__ == "__main__":
    unittest.main()
