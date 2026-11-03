"""Offline scan regressions for redundant traversal and input classification."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import deps_scan  # noqa: E402


class ScanEfficiencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-scan-efficiency-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def compose(self, text):
        path = self.write("compose.yaml", text)
        collector = deps_scan.Collector(self.root)
        deps_scan.check_compose(collector, path)
        return [(finding["location"], finding["title"]) for finding in collector.findings]

    def test_compose_services_and_extensions_keep_order_and_distinct_locations(self):
        self.assertEqual(self.compose(
            "x-shared:\n  image: nginx\n"
            "services:\n  x-shared:\n    image: redis\n"
            "  built:\n    image: builder\n    build: .\n"
            "  pinned:\n    image: app:1.0\n"
            "x-built:\n  image: ignored\n  build: .\n"
            "volumes:\n  data: {}\n"), [
                ("compose.yaml:5", "compose image redis is not pinned"),
                ("compose.yaml:2", "compose image nginx is not pinned"),
            ])

    def test_compose_legacy_empty_and_repeated_service_sections_keep_behavior(self):
        cases = [
            ("api:\n  image: nginx\nworker:\n  image: redis\n",
             [("compose.yaml:2", "compose image nginx is not pinned"),
              ("compose.yaml:4", "compose image redis is not pinned")]),
            ("services: {}\nx-template:\n  image: nginx\n",
             [("compose.yaml:3", "compose image nginx is not pinned")]),
            ("services:\n  first:\n    image: nginx\n"
             "services:\n  later:\n    image: redis\n"
             "x-template:\n  image: alpine\n",
             [("compose.yaml:3", "compose image nginx is not pinned"),
              ("compose.yaml:8", "compose image alpine is not pinned")]),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(self.compose(text), expected)

    def test_compose_key_comparisons_scale_with_entries(self):
        # Count comparisons instead of setting a machine-dependent time limit.
        # Membership scans between top-level templates and nested services used
        # to compare every pair even though their source ranges are disjoint.
        class Key(str):
            comparisons = 0

            def __eq__(self, other):
                Key.comparisons += 1
                return super().__eq__(other)

        original = deps_scan.yaml_children

        def counted(*args, **kwargs):
            entries = original(*args, **kwargs)
            for entry in entries:
                if entry[0] is not None:
                    entry[0] = Key(entry[0])
            return entries

        size = 192
        text = "".join(f"x-template-{i}:\n  image: app:1.0\n" for i in range(size))
        text += "services:\n" + "".join(
            f"  service-{i}:\n    image: app:1.0\n" for i in range(size))
        with patch.object(deps_scan, "yaml_children", side_effect=counted):
            self.assertEqual(self.compose(text), [])
        self.assertLess(Key.comparisons, 20 * size)

    def test_workflows_without_local_calls_still_report_risks(self):
        path = self.write(".github/workflows/check.yml",
            "on: pull_request_target\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@main\n        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: echo '${{ github.event.issue.title }}'\n")
        with patch.object(deps_scan, "yaml_children", wraps=deps_scan.yaml_children) as children:
            calls = deps_scan.local_calls([path], self.root, {path: "pull_request_target"})
        self.assertFalse(calls)
        self.assertFalse(calls.incomplete)
        children.assert_not_called()
        result = deps_scan.scan(self.root, False)
        titles = [finding["title"] for finding in result["findings"]]
        self.assertIn("pull_request_target workflow checks out the pull request's code", titles)
        self.assertTrue(any("untrusted event text" in title for title in titles))

    def test_local_calls_preserve_transitive_inputs_and_privilege(self):
        entry = self.write(".github/workflows/entry.yml",
            "on: issue_comment\njobs:\n  delegate:\n"
            "    uses: ./.github/workflows/reuse.yml\n    with:\n"
            "      ref: ${{ github.event.pull_request.head.sha }}\n")
        reused = self.write(".github/workflows/reuse.yml",
            "on: workflow_call\njobs:\n  check:\n    steps:\n"
            "      - uses: ./action\n        with:\n          ref: ${{ inputs.ref }}\n")
        action = self.write("action/action.yml",
            "runs:\n  using: composite\n  steps:\n    - run: echo inert\n      shell: bash\n")
        files = [entry, reused, action]
        privileged = deps_scan.privileged_workflows(files, self.root)
        calls = deps_scan.local_calls(files, self.root, privileged)
        self.assertEqual(calls[reused], [
            (entry, {"ref": "${{ github.event.pull_request.head.sha }}"}, True)])
        self.assertEqual(calls[action], [
            (reused, {"ref": "${{ inputs.ref }} ${{ github.event.pull_request.head.sha }}"}, True)])
        self.assertFalse(calls.incomplete)

    def test_privileged_trigger_priority_and_escaped_fallback_are_preserved(self):
        cases = [
            ("on: push\n", None),
            ("on: [issue_comment, workflow_run, pull_request_target]\n", "pull_request_target"),
            ("on: [issue_comment, workflow_run]\n", "workflow_run"),
            ('on: "\\u0069ssue_comment"\n', "pull_request_target"),
        ]
        files = [self.write(f".github/workflows/case-{i}.yml", text)
                 for i, (text, _) in enumerate(cases)]
        with patch.object(deps_scan, "workflow_triggers", wraps=deps_scan.workflow_triggers) as triggers:
            result = deps_scan.privileged_workflows(files, self.root)
        self.assertEqual(result, {path: expected for path, (_, expected) in zip(files, cases) if expected})
        self.assertEqual(triggers.call_count, len(files))

    def test_local_call_discovery_reads_each_workflows_triggers_once(self):
        caller = self.write(".github/workflows/entry.yml",
            "on: push\njobs:\n  check:\n    steps:\n      - uses: ./action\n")
        target = self.write("action/action.yml", "runs:\n  using: composite\n  steps: []\n")
        with patch.object(deps_scan, "workflow_triggers", wraps=deps_scan.workflow_triggers) as triggers:
            result = deps_scan.local_calls([caller, target], self.root, {})
        self.assertEqual(result, {target: [(caller, {}, False)]})
        triggers.assert_called_once()

    def test_requirements_names_and_suffix_iterators_keep_their_meaning(self):
        expected = {
            "requirements.txt": True, "requirements-dev.in": True,
            "dev-requirements.txt": True, "test_requirements.in": True,
            "requirements/base.txt": True, "requirements/README.txt": False,
            "requirements/LICENSE.in": False, "requirements/readme-extra.txt": False,
            "requirements/READMErequirements.txt": True,
            "requirements/requirements.txt": True, "requirements/base.py": False,
            "requirements.txt.py": False, "requirements.TXT": False,
            "requirements/sub/base.txt": False, "readme.txt": False,
        }
        for name, selected in expected.items():
            with self.subTest(name=name):
                result = deps_scan.is_requirements(name)
                self.assertIs(type(result), bool)
                self.assertEqual(result, selected)
                self.assertEqual(deps_scan.is_requirements(Path(name)), selected)
                self.assertEqual(deps_scan.is_requirements(name, iter(("txt", "in"))), selected)
        self.assertTrue(deps_scan.is_requirements("requirements/base.py", ("py",)))
        self.assertFalse(deps_scan.is_requirements("requirements/README.py", ("py",)))


if __name__ == "__main__":
    unittest.main()
