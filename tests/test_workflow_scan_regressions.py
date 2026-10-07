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

    def test_event_reads_through_index_access_and_function_arguments_are_detected(self):
        expressions = (
            "github.event['issue']['title']",
            "github['event']['pull_request'].body",
            "github['head_ref']",
            "github.event.commits[0]['message']",
            "format('{0}', github.event.issue.title)",
            "format('}} {0}', github.event.issue.title)",
            "format('it''s {0}', github.event.issue.title)",
            "join(github.event.issue.labels.*.name, ', ')",
            "join(github.event.*.title, ' ')",
            "toJSON(github.event.*)",
            "toJSON(github.event)",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                c = self.workflow('      - run: |\n          echo "${{ ' + expression + ' }}"\n')
                findings = self.injection_findings(c)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["location"], ".github/workflows/test.yml:8")
                self.assertFalse(c.not_run)

    def test_multiline_expression_is_detected_at_its_opening_line(self):
        c = self.workflow('''      - run: |
          echo "${{
            format('{0}',
              github.event['issue']['title'])
          }}"
''')
        findings = self.injection_findings(c)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"], ".github/workflows/test.yml:8")
        self.assertFalse(c.not_run)

    def test_event_strings_and_safe_env_handoffs_are_not_source_reads(self):
        c = self.workflow('''      - name: safe
        env:
          TITLE: ${{ format('{0}', github.event['issue']['title']) }}
          BODY: ${{
            github.event.issue.body
            }}
        run: |
          printf '%s\\n' "$TITLE" "$BODY"
          echo "${{ format('{0}', 'github.event.issue.title') }}"
          echo "${{ 'github[''event''][''issue''][''title'']' }}"
          echo "${{ github.event.issue.number }}"
          echo "${{ github.sha }}"
''')
        self.assertFalse(self.injection_findings(c))
        self.assertFalse(c.not_run)

    def test_dynamic_event_selector_is_incomplete_instead_of_clean(self):
        c = self.workflow('      - run: echo "${{ github.event[inputs.kind][inputs.field] }}"\n')
        self.assert_incomplete(c)
        self.assertFalse(self.injection_findings(c))

    def test_unresolved_event_subtrees_are_incomplete_instead_of_clean(self):
        for expression in ("toJSON(github.event.pull_request.head)",
                           "toJSON(github.event.issue.labels)",
                           "toJSON(github.event.inputs)"):
            with self.subTest(expression=expression):
                c = self.workflow('      - run: echo "${{ ' + expression + ' }}"\n')
                self.assert_incomplete(c)

    def test_double_quoted_yaml_escapes_are_incomplete_instead_of_clean(self):
        for step in (
                r'''      - run: "echo '${{ \u0067ithub.event.issue.title }}'"''',
                r'''      - run: "echo '${{\ngithub.event.issue.title\n}}'"''',
                r'''      - run: "echo '\u0024{{ github.event.issue.title }}'"''',
                '''      - run: "echo '${{\n          \\u0067ithub.event.issue.title }}'"''',
                '''      - run:\n          "echo '${{ \\u0067ithub.event.issue.title }}'"''',
                '''      - run: # scalar below\n\n          # comment\n          "echo '${{ \\u0067ithub.event.issue.title }}'"'''):
            with self.subTest(step=step):
                self.assert_incomplete(self.workflow(step + "\n"))

    def test_plain_and_block_shell_escapes_do_not_require_yaml_decoding(self):
        for step in (r'''      - run: printf '%s\\n' "$TITLE"''',
                     '''      - run: |\n          printf '%s\\n' "$TITLE"'''):
            with self.subTest(step=step):
                c = self.workflow(step + "\n")
                self.assertFalse(self.injection_findings(c))
                self.assertFalse(c.not_run)

    def test_escaped_workflow_mapping_keys_are_incomplete_instead_of_clean(self):
        text = ("name: test\non: pull_request\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                '      - run: echo "${{ github.head_ref }}"\n')
        for original, escaped in (("run:", r'"r\u0075n":'),
                                  ("steps:", r'"st\u0065ps":'),
                                  ("jobs:", r'"j\u006fbs":')):
            with self.subTest(key=original):
                self.path.write_text(text.replace(original, escaped), encoding="utf-8")
                c = self.deps.Collector(self.root)
                self.deps.check_workflow(c, self.path)
                self.assert_incomplete(c)

    def test_expressions_cannot_continue_into_a_separate_run_step(self):
        c = self.workflow('''      - run: echo "${{ github.event.issue.number
      - run: echo "github.event.issue.title }}"
''')
        self.assert_incomplete(c)
        self.assertFalse(self.injection_findings(c))

    def test_multiple_expressions_keep_one_finding_per_script_line(self):
        c = self.workflow('''      - run: |
          echo "${{ github.event.issue.title }} ${{ github['head_ref'] }}"
          echo "${{ format('{0}', github.event.issue.body) }}"
''')
        findings = self.injection_findings(c)
        self.assertEqual([f["location"] for f in findings],
                         [".github/workflows/test.yml:8", ".github/workflows/test.yml:9"])
        self.assertFalse(c.not_run)


if __name__ == "__main__":
    unittest.main()
