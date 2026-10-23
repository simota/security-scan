"""Attacker-shaped inputs that used to take seconds to minutes; each must stay fast."""
import json
from pathlib import Path
import random
import sys
import tempfile
import time
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import deps_scan  # noqa: E402
import render  # noqa: E402

LIMIT = 3.0  # seconds; the old code took 5 s to 6 min on these inputs


class RedactionTests(unittest.TestCase):
    def reference(self, line):
        line = render.redact_urls(line)
        line = render.QUOTED_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "********" + m.group(2), line)
        return render.SECRET_RE.sub(lambda m: m.group(1) + "********", line)

    def test_linear_redaction_matches_the_reference_patterns(self):
        rng = random.Random(20261010)
        parts = ["token", "Password", "api-key", "secret", "x", "_", ".", "-", "=", ":", "=>", ":=", " ", "'",
                 '"', "\\", "abcd", "$x", "os.environ", "null", ",", ";", ")", "f(", "12345"]
        for _ in range(20000):
            line = "".join(rng.choice(parts) for _ in range(rng.randint(1, 14)))
            self.assertEqual(render.redact(line), self.reference(line), line)

    def test_repeated_keywords_are_linear(self):
        started = time.monotonic()
        render.redact("token" * 20000)
        render.redact("password=" * 5000)
        self.assertLess(time.monotonic() - started, LIMIT)

    def test_payload_and_secret_gates_are_linear(self):
        # Workflow submissions and capture blobs have no line or string limit of their own.
        import payloads
        started = time.monotonic()
        payloads.PAYLOAD.search("<svg " * 40000)
        render.secret_in_source("a.js", "'password', " * 100000 + "define('DB_PASSWORD', `" * 50000)
        self.assertLess(time.monotonic() - started, LIMIT)


class DepsScanPathologicalTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-perf-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def timed_scan(self):
        started = time.monotonic()
        result = deps_scan.scan(self.root, False)
        self.assertLess(time.monotonic() - started, LIMIT)
        return result

    def test_pathological_files(self):
        (self.root / "pyproject.toml").write_text("\n" * 30000)
        (self.root / "Dockerfile").write_text("RUN " + "curl x " * 6000 + "\n")
        (self.root / "pnpm-lock.yaml").write_text("resolution: {" * 20000 + "\n")
        (self.root / "yarn.lock").write_text("\n" * 40000 + "x\n")
        workflows = self.root / ".github/workflows"
        workflows.mkdir(parents=True)
        (workflows / "a.yml").write_text("jobs:\n  j:\n    steps:\n      - " + " " * 30000 + "x: 1\n"
                                         "      - run: echo ${{ " + "github[" * 3000 + " }}\n")
        self.timed_scan()

    def test_pathological_dependency_source_lines(self):
        # Unclosed extras and strings: each candidate start must not rescan to the end of the line.
        (self.root / "pyproject.toml").write_text("[project]\ndependencies = [" + '"a[' * 200000 + "\n")
        (self.root / "requirements.txt").write_text("a" * 300000 + "[" * 300000 + "\n./" + "[" * 300000 + "\n")
        (self.root / "Cargo.toml").write_text("[dependencies]\nx = { " + 'git = "a' * 200000 + "\n")
        (self.root / "Cargo.lock").write_text('source = "' * 300000 + "\n")
        (self.root / "yarn.lock").write_text('  resolution: "' + "@" * 300000 + "\n")
        # Continuation joins: one statement spanning every line must not be rebuilt per line.
        (self.root / "Gemfile").write_text('gem "x",\n' * 100000)
        (self.root / "Dockerfile").write_text("RUN curl x \\\n" * 100000 + "  | sh\n")
        self.timed_scan()

    def test_long_whitespace_runs_in_new_manifest_parsers(self):
        # Two quantifiers able to share one whitespace run backtrack quadratically or worse.
        (self.root / "Cargo.toml").write_text("[" + " " * 100000 + "x\n[" + " " * 100000 + "]\n[" + " ." * 50000 + "]\n")
        (self.root / "requirements.txt").write_text("a" + " " * 100000 + "!\n-e a" + " " * 100000 + "!\n")
        (self.root / "pyproject.toml").write_text('[project]\ndependencies = ["a' + " " * 100000 + '!"]\n'
                                                  "[" + " " * 100000 + "x\n")
        # Dotted keys and an unclosed Poetry constraint array that never closes.
        (self.root / "Pipfile").write_text("[packages]\na" + " " * 100000 + "." + " " * 100000 + "b!\n"
                                           "x = [" + "{" * 200000 + "\n" + '{ git = "a' * 100000 + "\n")
        self.timed_scan()

    def test_many_dependencies_and_hosts(self):
        deps = {"pkg-%d" % i: "^1.0.%d" % i for i in range(20000)}
        (self.root / "package.json").write_text(json.dumps({"dependencies": deps}, indent=1))
        packages = {"node_modules/p%d" % i: {"resolved": "https://h%d.invalid/p.tgz" % i, "integrity": "x"}
                    for i in range(5000)}
        (self.root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}, indent=1))
        result = self.timed_scan()
        self.assertEqual(sum("non-default host" in f["title"] for f in result["findings"]), 5000)

    def test_triage_parses_each_lockfile_once(self):
        (self.root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
        (self.root / "app.js").write_text("require('p1')\n" * 2000)
        c = deps_scan.Collector(self.root)
        for i in range(300):
            deps_scan.vuln(c, "high", "p%d" % i, "1.0", ["GHSA-%d" % i], "s", self.root / "package-lock.json", "t")
        calls = []
        real = deps_scan.lock_context
        with unittest.mock.patch.object(deps_scan, "lock_context", side_effect=lambda lock: calls.append(lock) or real(lock)):
            deps_scan.triage(c, self.root)
        self.assertEqual(len(calls), 1)
        self.assertEqual(c.findings[1]["validation"]["referenced"], "yes")
        self.assertEqual(c.findings[2]["validation"]["referenced"], "no")


if __name__ == "__main__":
    unittest.main()
