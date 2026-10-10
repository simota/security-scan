"""Minimal crash inputs found by fuzzing every CLI: each must exit with a documented code."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"


class FuzzRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-fuzz-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.out = self.tmp / "out"
        self.out.mkdir()

    def run_cli(self, script, *args):
        done = subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], cwd=str(self.tmp),
                              capture_output=True, timeout=120, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertNotIn(b"Traceback", done.stderr, done.stderr[-2000:])
        return done.returncode

    def test_contract_check_with_scalar_findings(self):
        for value in ("1.5", "1", "true"):
            (self.out / "findings.json").write_text('{"findings": %s}' % value)
            self.assertEqual(self.run_cli("contract_check.py", self.out), 1)

    def test_expert_audit_with_deep_nesting(self):
        (self.out / "findings.json").write_text('{"x":' + "[" * 9998 + "]" * 9998 + "}")
        self.assertEqual(self.run_cli("expert_audit.py", self.out, "--no-pdf"), 2)

    def test_findings_merge_with_deep_fragment_or_base(self):
        fragment = self.tmp / "frag.json"
        fragment.write_text('{"limitations":[' + "[" * 498 + "]" * 498 + "]}")
        self.assertEqual(self.run_cli("findings.py", "merge", self.tmp / "findings.json", fragment), 2)
        base = self.tmp / "base.json"
        base.write_text('{"findings":[{"request":' + '{"a":' * 496 + "1" + "}" * 496 + "}]}")
        fragment.write_text('{"limitations": ["x"]}')
        self.assertEqual(self.run_cli("findings.py", "merge", base, fragment), 2)

    def test_reproduction_generate_with_deep_inputs(self):
        findings = json.loads((ROOT / "examples/findings.workflow.sample.json").read_text())
        plan = ROOT / "examples/reproduction.plan.sample.json"
        deep = self.tmp / "findings.json"
        deep.write_text(json.dumps(findings)[:-1] + ', "limitations": [' + "[" * 497 + "]" * 497 + "]}")
        self.assertEqual(self.run_cli("reproduction.py", "generate", deep, "--finding", "F-001",
                                      "--plan", plan, "--out", self.tmp / "b1"), 2)
        deep_plan = self.tmp / "plan.json"
        deep_plan.write_text('{"x":' + "[" * 9998 + "]" * 9998 + "}")
        (self.tmp / "ok.json").write_text(json.dumps(findings))
        self.assertEqual(self.run_cli("reproduction.py", "generate", self.tmp / "ok.json", "--finding", "F-001",
                                      "--plan", deep_plan, "--out", self.tmp / "b2"), 2)

    @unittest.skipIf(sys.platform == "darwin", "macOS refuses non-UTF-8 file names")
    def test_deps_scan_with_undecodable_file_name(self):
        repo = self.tmp / "repo"
        bad = os.path.join(os.fsencode(str(repo)), b"bad\xffname")
        os.makedirs(bad)
        with open(os.path.join(bad, b"package.json"), "w") as stream:
            stream.write('{"dependencies": {"a": "*"}}')
        self.assertEqual(self.run_cli("deps_scan.py", repo, "--out", self.tmp / "deps.json"), 0)
        data = json.loads((self.tmp / "deps.json").read_text(encoding="utf-8"))
        self.assertIn("bad\\udcffname/package.json:1", [f["location"] for f in data["findings"]])


if __name__ == "__main__":
    unittest.main()
