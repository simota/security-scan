"""Round-6 regressions: block-scalar env values, quoted local `uses`, NuGet pattern ownership."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

from test_security_scan import import_module

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
SHA = "0" * 40
PRT = "on: pull_request_target\njobs:\n  j:\n    runs-on: x\n    steps:\n"


class DepsScanRound6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(SCRIPTS))
        cls.deps = import_module(SCRIPTS / "deps_scan.py", "round6_deps")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-round6-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, value):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def found(self):
        return [(f["severity"], f["location"], f["title"]) for f in self.deps.scan(self.tmp, False)["findings"]]

    def high(self):
        return [t for s, _, t in self.found() if s == "High"]

    def test_block_scalar_env_values_are_read(self):
        checkout = "      - uses: actions/checkout@" + SHA + "\n        with:\n          ref: ${{ env.PR_SHA }}\n"
        for style in (">-", "|", "|+ # sha"):
            with self.subTest(style=style):
                self.write(".github/workflows/w.yml", "on: pull_request_target\nenv:\n  PR_SHA: " + style + "\n"
                           "    ${{ github.event.pull_request.head.sha }}\njobs:\n  j:\n    runs-on: x\n"
                           "    steps:\n" + checkout)
                self.assertTrue(self.high())
        self.write(".github/workflows/w.yml", "on: pull_request_target\nenv:\n  PR_SHA: >-\n    main\n"
                   "jobs:\n  j:\n    runs-on: x\n    steps:\n" + checkout)
        self.assertFalse(self.high())

    def test_nested_block_scalars_stay_linear(self):
        body = "".join(" " * (2 + k) + "K%d: |\n" % k for k in range(4000))
        self.write(".github/workflows/w.yml", PRT + "      - run: echo\n        env:\n" + body)
        started = time.monotonic()
        self.found()
        self.assertLess(time.monotonic() - started, 2.0)

    def test_quoted_uses_key_follows_local_actions(self):
        self.write(".github/workflows/w.yml", PRT + '      - "uses": ./actions/build\n')
        self.write("actions/build/action.yml", "runs:\n  using: composite\n  steps:\n"
                   "    - uses: actions/checkout@" + SHA + "\n      with:\n"
                   "        ref: ${{ github.event.pull_request.head.sha }}\n")
        self.assertTrue(self.high())

    def test_nuget_pattern_mapped_to_two_sources_is_not_mitigated(self):
        sources = ('<packageSources>\n<add key="a" value="https://a.example/v3" />\n'
                   '<add key="b" value="https://api.nuget.org/v3/index.json" />\n</packageSources>\n')
        title = "nuget.config mixes several package sources without packageSourceMapping"
        for mapping, flagged in (
                ('<packageSource key="b"><package pattern="*" /><package pattern="Fabrikam.*" /></packageSource>'
                 '<packageSource key="a"><package pattern="Fabrikam.*" /></packageSource>', True),
                ('<packageSource key="b"><package pattern="*" /><package pattern="Other.*" /></packageSource>'
                 '<packageSource key="a"><package pattern="Fabrikam.*" /></packageSource>', False)):
            with self.subTest(mapping=mapping):
                self.write("nuget.config", "<configuration>\n" + sources + "<packageSourceMapping>\n" + mapping
                           + "\n</packageSourceMapping>\n</configuration>\n")
                self.assertEqual(title in [t for _, _, t in self.found()], flagged)


if __name__ == "__main__":
    unittest.main()
