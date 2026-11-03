"""Dependency triage reads source only when its reachability model needs it."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import deps_scan  # noqa: E402


class TriageSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-scan-triage-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.collector = deps_scan.Collector(self.root)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content) if isinstance(content, dict) else content,
                        encoding="utf-8")
        return path

    def finding(self, package, lock):
        deps_scan.vuln(self.collector, "high", package, "1.0.0", ["BENCH-1"],
                       "synthetic advisory", self.root / lock, "fixture")
        return self.collector.findings[-1]

    def npm(self):
        self.write("package.json", {"dependencies": {"used": "1.0.0"},
                                    "devDependencies": {"unused": "1.0.0"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "node_modules/used": {}, "node_modules/quoted": {},
            "node_modules/unused": {"dev": True}}})

    def composer(self):
        self.write("composer.json", {"require": {"vendor/used": "1.0.0"}})
        self.write("composer.lock", {"packages": [
            {"name": "vendor/used", "autoload": {"psr-4": {"Vendor\\Used\\": "src/"}}},
            {"name": "vendor/unused", "autoload": {"psr-0": {"Vendor\\Unused\\": "src/"}}},
            {"name": "vendor/no-model"},
        ]})

    def test_ecosystems_without_source_models_do_not_read_source(self):
        self.composer()
        self.write("app.py", "import fixture_package\n")
        findings = [self.finding("fixture-package", lock) for lock in
                    ("requirements.txt", "poetry.lock", "Cargo.lock", "go.mod")]
        findings.append(self.finding("vendor/no-model", "composer.lock"))
        with patch.object(deps_scan, "source_index", wraps=deps_scan.source_index) as source:
            deps_scan.triage(self.collector, self.root)
        source.assert_not_called()
        self.assertEqual([f["validation"]["referenced"] for f in findings], ["unknown"] * 5)
        self.assertEqual([f["validation"]["verdict"] for f in findings], ["Unverified"] * 5)
        self.assertEqual(findings[-1]["validation"]["exposure"], "runtime")

    def test_npm_imports_quotes_and_dev_only_verdicts_are_preserved(self):
        self.npm()
        self.write("app.js", "import used from 'used/subpath';\nconst name = 'quoted';\n")
        findings = [self.finding(name, "package-lock.json") for name in ("used", "quoted", "unused")]
        with patch.object(deps_scan, "source_index", wraps=deps_scan.source_index) as source, \
             patch.object(deps_scan, "npm_index", wraps=deps_scan.npm_index) as index:
            deps_scan.triage(self.collector, self.root)
        source.assert_called_once_with(self.root)
        index.assert_called_once()
        self.assertEqual([f["validation"]["referenced"] for f in findings], ["yes", "unknown", "no"])
        self.assertEqual([f["validation"]["verdict"] for f in findings], ["Likely", "Unverified", "Unlikely"])
        self.assertEqual([f["validation"]["exposure"] for f in findings], ["runtime", "runtime", "dev-only"])

    def test_composer_namespaces_keep_their_reachability_results(self):
        self.composer()
        self.write("app.php", "<?php new Vendor\\Used\\Handler();\n")
        findings = [self.finding(name, "composer.lock") for name in
                    ("vendor/used", "vendor/unused", "vendor/no-model")]
        with patch.object(deps_scan, "source_index", wraps=deps_scan.source_index) as source:
            deps_scan.triage(self.collector, self.root)
        source.assert_called_once_with(self.root)
        self.assertEqual([f["validation"]["referenced"] for f in findings], ["yes", "no", "unknown"])
        self.assertEqual([f["validation"]["verdict"] for f in findings], ["Likely", "Unverified", "Unverified"])

    def test_mixed_ecosystems_share_one_source_read_without_reordering(self):
        self.npm()
        self.composer()
        self.write("app.js", "require('used');\n")
        self.write("app.php", "<?php new Vendor\\Used\\Handler();\n")
        findings = [self.finding(name, lock) for name, lock in (
            ("python-package", "poetry.lock"), ("vendor/used", "composer.lock"),
            ("used", "package-lock.json"), ("rust-package", "Cargo.lock"))]
        with patch.object(deps_scan, "source_index", wraps=deps_scan.source_index) as source:
            deps_scan.triage(self.collector, self.root)
        source.assert_called_once_with(self.root)
        self.assertEqual(self.collector.findings, findings)
        self.assertEqual([f["validation"]["referenced"] for f in findings], ["unknown", "yes", "yes", "unknown"])

    def test_empty_source_index_is_not_loaded_again(self):
        self.npm()
        self.composer()
        findings = [self.finding(name, lock) for name, lock in (
            ("used", "package-lock.json"), ("vendor/used", "composer.lock"),
            ("unused", "package-lock.json"), ("vendor/unused", "composer.lock"))]
        with patch.object(deps_scan, "source_index", wraps=deps_scan.source_index) as source, \
             patch.object(deps_scan, "npm_index", wraps=deps_scan.npm_index) as index:
            deps_scan.triage(self.collector, self.root)
        source.assert_called_once_with(self.root)
        index.assert_called_once_with([])
        self.assertEqual([f["validation"]["referenced"] for f in findings], ["no"] * 4)

    def test_later_triage_reads_updated_source(self):
        self.npm()
        self.write("app.js", "require('used');\n")
        finding = self.finding("used", "package-lock.json")
        with patch.object(deps_scan, "source_index", wraps=deps_scan.source_index) as source:
            deps_scan.triage(self.collector, self.root)
            self.assertEqual(finding["validation"]["referenced"], "yes")
            self.write("app.js", "const noImports = true;\n")
            deps_scan.triage(self.collector, self.root)
            self.assertEqual(finding["validation"]["referenced"], "no")
        self.assertEqual(source.call_count, 2)


if __name__ == "__main__":
    unittest.main()
