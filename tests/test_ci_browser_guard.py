"""Execute the workflow's exact version guard without launching a browser."""
import ast
from pathlib import Path
import re
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BrowserVersionGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.approved = re.search(r"CHROME_VERSIONS: '([^']+)'", workflow).group(1)
        source = textwrap.dedent(workflow.split("python - <<'PYTHON'\n", 1)[1]
                                 .split("\n          PYTHON", 1)[0])
        tree = ast.parse(source)
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "expected"
                                  for target in node.targets))
        check = next(node for node in tree.body if isinstance(node, ast.If)
                     and isinstance(node.test, ast.Compare)
                     and isinstance(node.test.left, ast.Name) and node.test.left.id == "version")
        cls.guard = compile(ast.Module(body=[assignment, check], type_ignores=[]),
                            "ci.yml browser guard", "exec")

    def check_version(self, version):
        class Environment:
            environ = {"CHROME_VERSIONS": self.approved}
        exec(self.guard, {"os": Environment, "version": version})

    def test_only_the_two_explicit_runner_versions_are_accepted(self):
        self.assertEqual(set(self.approved.split(",")), {"154.0.8037.57", "154.0.8037.97"})
        for version in self.approved.split(","):
            with self.subTest(version=version):
                self.check_version("Google Chrome " + version)

    def test_unknown_versions_and_other_distributions_are_rejected(self):
        for version in ("Google Chrome 154.0.8037.98", "Google Chrome 155.0.0.0",
                        "Chromium 154.0.8037.97", "Google Chrome 154.0.8037.97 beta", ""):
            with self.subTest(version=version), self.assertRaises(SystemExit):
                self.check_version(version)


if __name__ == "__main__":
    unittest.main()
