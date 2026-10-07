"""Optional trusted-npm parser tests; advisory I/O is mocked and network blocked."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from test_audit_boundaries import load_script


class NpmAuditScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deps = load_script("deps_scan")
        executable = shutil.which("npm")
        if not executable:
            raise RuntimeError("trusted npm is not installed")
        cls.npm = Path(executable).resolve()
        cls.audit_report = cls.npm.parent.parent / "node_modules/@npmcli/arborist/lib/audit-report.js"
        if not cls.audit_report.is_file():
            raise RuntimeError("npm installation does not expose the offline audit test hook")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-npm-scope-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / "project"
        self.root.mkdir()
        self.payload = self.base / "payload.json"
        hook = self.base / "offline-audit.cjs"
        hook.write_text("""
const blocked = () => { throw new Error('Network disabled by offline regression test'); };
for (const name of ['http', 'https']) {
  const module = require(name);
  module.request = module.get = blocked;
}
require('net').Socket.prototype.connect = blocked;
require('tls').connect = blocked;
globalThis.fetch = blocked;
const fs = require('fs');
const AuditReport = require(""" + json.dumps(str(self.audit_report)) + """);
AuditReport.load = async (tree, opts) => {
  const report = new AuditReport(tree, opts);
  fs.writeFileSync(process.env.SECURITY_SCAN_TEST_PAYLOAD, JSON.stringify(report.prepareBulkData()));
  return report;
};
""", encoding="utf-8")
        config = self.base / "empty.npmrc"
        config.write_text("", encoding="utf-8")
        global_config = self.base / "empty-global.npmrc"
        global_config.write_text("", encoding="utf-8")
        self.env = {
            "PATH": os.environ.get("PATH", ""), "HOME": str(self.base),
            "NODE_OPTIONS": "--require=" + str(hook),
            "NPM_CONFIG_USERCONFIG": str(config), "NPM_CONFIG_GLOBALCONFIG": str(global_config),
            "NPM_CONFIG_CACHE": str(self.base / "cache"), "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "SECURITY_SCAN_TEST_PAYLOAD": str(self.payload),
        }

    def fixture(self, version):
        manifest = {"name": "root-fixture", "version": "1.0.0",
                    "dependencies": {"root-dep": "1.0.0"}, "devDependencies": {"dev-dep": "1.0.0"}}
        (self.root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        def dependency(name, **flags):
            return dict(version="1.0.0", resolved="https://registry.npmjs.org/" + name
                        + "/-/" + name + "-1.0.0.tgz", integrity="sha512-c2FmZQ==", **flags)
        lock = {"name": "root-fixture", "version": "1.0.0", "lockfileVersion": version}
        if version < 3:
            lock["dependencies"] = {"root-dep": dependency("root-dep"),
                                    "dev-dep": dependency("dev-dep", dev=True),
                                    "orphan-dep": dependency("orphan-dep")}
        if version > 1:
            lock["packages"] = {"": manifest, "node_modules/root-dep": dependency("root-dep"),
                                "node_modules/dev-dep": dependency("dev-dep", dev=True),
                                "node_modules/orphan-dep": dependency("orphan-dep", extraneous=True)}
        path = self.root / "package-lock.json"
        path.write_text(json.dumps(lock), encoding="utf-8")
        return path

    def audit(self, lock, config="", env=None):
        (self.root / ".npmrc").write_text(config, encoding="utf-8")
        self.payload.unlink(missing_ok=True)
        collector = self.deps.Collector(self.root)
        with patch.dict(os.environ, dict(self.env, **(env or {})), clear=True):
            self.deps.audit_npm(collector, self.root, lock)
        return collector

    def test_single_project_payload_keeps_root_and_dev_for_lock_versions(self):
        for version in (1, 2, 3):
            for config in ("", "workspaces=false\nomit[]=dev\npackage-lock=false\n", "workspaces=true\n"):
                with self.subTest(version=version, config=config):
                    collector = self.audit(self.fixture(version), config,
                                           {"NODE_ENV": "production", "NPM_CONFIG_WORKSPACES": "false"})
                    self.assertEqual(collector.not_run, [])
                    self.assertEqual(json.loads(self.payload.read_text()),
                                     {"root-dep": ["1.0.0"], "dev-dep": ["1.0.0"],
                                      "orphan-dep": ["1.0.0"]})

    def test_inherited_workspace_filters_fail_before_advisory_io(self):
        for config, env in (("workspace=SYNTHETIC_SELECTED_WORKSPACE\n", {}),
                            ("", {"NPM_CONFIG_WORKSPACE": "SYNTHETIC_SELECTED_WORKSPACE"}),
                            ("", {"npm_config_workspace": "SYNTHETIC_SELECTED_WORKSPACE"})):
            with self.subTest(config=config, env=env):
                collector = self.audit(self.fixture(3), config, env)
                self.assertTrue(collector.not_run)
                self.assertFalse(self.payload.exists())
                self.assertNotIn("SYNTHETIC_SELECTED_WORKSPACE", json.dumps(collector.not_run))

    def test_prefix_keeps_a_nested_single_project_at_its_own_lock(self):
        (self.base / "package.json").write_text(json.dumps({"name": "outer-fixture",
            "workspaces": ["project"], "dependencies": {"outer-dep": "1.0.0"}}), encoding="utf-8")
        (self.base / ".npmrc").write_text("workspace=root-fixture\n", encoding="utf-8")
        collector = self.audit(self.fixture(3))
        self.assertEqual(collector.not_run, [])
        self.assertEqual(set(json.loads(self.payload.read_text())), {"root-dep", "dev-dep", "orphan-dep"})


if __name__ == "__main__":
    unittest.main()
