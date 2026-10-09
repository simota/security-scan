"""Independent audit-boundary regressions; external auditors are mocked."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location("boundary_" + name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


class AuditBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deps, cls.renderer = load_script("deps_scan"), load_script("render")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-boundary-tests-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def collector(self):
        return self.deps.Collector(self.root)

    def test_cargo_fallback_never_executes_target_or_cargo(self):
        lock = self.write("Cargo.lock", "version = 3\n")
        manifest = self.write("Cargo.toml", '[package]\nname="fixture"\nversion="0.1.0"\n')
        self.write(".cargo/config.toml", '[alias]\naudit="SYNTHETIC_INERT_ALIAS"\n')
        c = self.collector()
        with patch.object(self.deps, "audit_osv", return_value=set()), patch.object(self.deps, "run") as run:
            self.deps.audits(c, self.root, [lock, manifest])
        run.assert_not_called()
        self.assertTrue(any(n["tool"] == "cargo audit" and "Cargo.lock" in n["reason"] for n in c.not_run))

    def test_osv_covered_cargo_needs_no_fallback(self):
        lock = self.write("Cargo.lock", "version = 3\n")
        c = self.collector()
        with patch.object(self.deps, "audit_osv", return_value={lock}), patch.object(self.deps, "run") as run:
            self.deps.audits(c, self.root, [lock])
        run.assert_not_called()
        self.assertFalse(c.not_run)

    def test_npm_includes_all_dependency_kinds_despite_production_config(self):
        lock = self.write("package-lock.json", {"lockfileVersion": 3, "packages": {}})
        self.write("package.json", {})
        self.write(".npmrc", "omit[]=dev\nomit[]=optional\nomit[]=peer\n")
        c = self.collector()
        with patch.dict(os.environ, {"NODE_ENV": "production", "NPM_CONFIG_OMIT": "dev"}), \
             patch.object(self.deps.shutil, "which", return_value="/trusted/npm"), \
             patch.object(self.deps, "run", return_value=(0, '{"vulnerabilities": {}}', "")) as run:
            self.deps.audit_npm(c, self.root, lock)
        argv = run.call_args.args[0]
        for kind in ("prod", "dev", "optional", "peer"):
            self.assertIn("--include=" + kind, argv)
        self.assertIn("--ignore-scripts", argv)
        self.assertIn("--workspaces=null", argv)
        self.assertIn("--package-lock=true", argv)
        # The audit runs on a copy: neither the repository's .npmrc nor inherited
        # npm_config_* variables can redirect the advisory registry.
        self.assertNotIn("--prefix=" + str(self.root), argv)
        self.assertIn("--registry=https://registry.npmjs.org/", argv)
        self.assertTrue(any(a.startswith("--userconfig=") for a in argv))
        self.assertTrue(any(a.startswith("--globalconfig=") for a in argv))
        env = run.call_args.kwargs["env"]
        self.assertFalse([k for k in env if k.lower().startswith("npm_config_")
                          and k.lower() not in ("npm_config_cache", "npm_config_update_notifier")])
        self.assertFalse(c.not_run)

    def test_npm_shared_workspaces_are_explicitly_incomplete_without_invoking_npm(self):
        for version in (1, 2, 3):
            for config in ("", "workspace=safe-workspace\n", "workspaces=false\n"):
                with self.subTest(version=version, config=config):
                    payload = {"lockfileVersion": version, "packages": {
                        "": {"workspaces": ["apps/*"], "dependencies": {"root-dep": "1.0.0"}},
                        "apps/safe": {"name": "safe-workspace", "dependencies": {"safe-dep": "1.0.0"}},
                        "node_modules/safe-workspace": {"link": True, "resolved": "apps/safe"},
                        "node_modules/root-dep": {"version": "1.0.0"},
                        "node_modules/safe-dep": {"version": "1.0.0"}}}
                    if version == 1:
                        payload.pop("packages")
                        payload["dependencies"] = {
                            "root-dep": {"version": "1.0.0"},
                            "safe-workspace": {"version": "file:apps/safe", "dependencies": {
                                "safe-dep": {"version": "1.0.0"}}}}
                    lock = self.write("package-lock.json", payload)
                    self.write("package.json", {"workspaces": ["apps/*"]})
                    self.write(".npmrc", config)
                    c = self.collector()
                    with patch.dict(os.environ, {"NPM_CONFIG_WORKSPACE": "safe-workspace",
                                                 "npm_config_workspaces": "false"}), \
                         patch.object(self.deps, "audit_osv", return_value=set()), \
                         patch.object(self.deps, "run") as run:
                        self.deps.audits(c, self.root, [lock])
                    run.assert_not_called()
                    self.assertTrue(any(n["tool"] == "npm audit" and "whole-lock coverage" in n["reason"]
                                        for n in c.not_run))

    def test_npm_lock_workspace_metadata_is_checked_without_project_manifest(self):
        for packages in ({"": {"workspaces": ["apps/*"]}},
                         {"apps/safe": {"name": "safe-workspace", "version": "1.0.0"}},
                         {"node_modules/safe-workspace": {"link": True, "resolved": "apps/safe"}}):
            with self.subTest(packages=packages):
                lock = self.write("npm-shrinkwrap.json", {"lockfileVersion": 3, "packages": packages})
                c = self.collector()
                with patch.object(self.deps, "run") as run:
                    self.deps.audit_npm(c, self.root, lock)
                run.assert_not_called()
                self.assertTrue(any("whole-lock coverage" in n["reason"] for n in c.not_run))

    def test_npm_legacy_linked_inputs_are_explicitly_incomplete(self):
        lock = self.write("package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "fixture": {"version": "1.0.0", "dependencies": {
                "linked-fixture": {"version": "file:apps/fixture"}}}}})
        c = self.collector()
        with patch.object(self.deps, "run") as run:
            self.deps.audit_npm(c, self.root, lock)
        run.assert_not_called()
        self.assertTrue(any("whole-lock coverage" in n["reason"] for n in c.not_run))

    def test_osv_covered_npm_workspace_needs_no_fallback(self):
        lock = self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"workspaces": ["apps/*"]}}})
        self.write("package.json", {"workspaces": ["apps/*"]})
        c = self.collector()
        with patch.object(self.deps, "audit_osv", return_value={lock}), patch.object(self.deps, "run") as run:
            self.deps.audits(c, self.root, [lock])
        run.assert_not_called()
        self.assertFalse(c.not_run)

    def test_npm_invalid_scope_metadata_fails_closed(self):
        for content in ("[]", '{"packages": []}', '{"packages": {"node_modules/example": null}}',
                        '{"dependencies": [1]}', '{"dependencies": {"example": null}}'):
            with self.subTest(content=content):
                lock = self.write("package-lock.json", content)
                c = self.collector()
                with patch.object(self.deps, "run") as run:
                    self.deps.audit_npm(c, self.root, lock)
                run.assert_not_called()
                self.assertTrue(c.not_run)

    def test_composer_project_and_environment_exclusions_are_not_inherited(self):
        lock = self.write("composer.lock", {"packages": [], "packages-dev": []})
        manifest = self.write("composer.json", {"config": {
            "audit": {"ignore": ["GHSA-SYNTHETIC"], "abandoned": "ignore"},
            "policy": {"advisories": {"audit": "ignore"}, "abandoned": {"audit": "ignore"}}}})
        original = lock.read_bytes(), manifest.read_bytes()
        seen = []

        def audit(argv, cwd, **kwargs):
            cwd = Path(cwd)
            self.assertNotEqual(cwd, self.root)
            self.assertEqual((cwd / "composer.lock").read_bytes(), original[0])
            settings = json.loads((cwd / "composer.json").read_text())
            self.assertNotIn("policy", settings["config"])
            self.assertEqual(settings["config"]["audit"]["ignore"], [])
            self.assertEqual(settings["config"]["audit"]["ignore-abandoned"], [])
            env = kwargs["env"]
            self.assertNotIn("COMPOSER", env)
            self.assertNotIn("COMPOSER_AUDIT_ABANDONED", env)
            self.assertEqual(env["COMPOSER_NO_DEV"], "0")
            self.assertEqual(Path(env["COMPOSER_HOME"]), cwd / "home")
            self.assertEqual(list((cwd / "home").iterdir()), [])
            self.assertIn("--abandoned=report", argv)
            self.assertIn("--no-plugins", argv)
            self.assertIn("--no-scripts", argv)
            seen.append(cwd)
            return 0, '{"advisories": [], "abandoned": []}', ""

        c = self.collector()
        with patch.dict(os.environ, {"COMPOSER": "other.json", "COMPOSER_NO_DEV": "1",
                                    "COMPOSER_AUDIT_ABANDONED": "ignore", "COMPOSER_HOME": "/unused"}), \
             patch.object(self.deps.shutil, "which", return_value="/trusted/composer"), \
             patch.object(self.deps, "run", side_effect=audit):
            self.deps.audit_composer(c, self.root, lock)
        self.assertFalse(c.not_run)
        self.assertEqual((lock.read_bytes(), manifest.read_bytes()), original)
        self.assertTrue(seen)
        self.assertTrue(all(not p.exists() for p in seen))

    def test_composer_custom_repository_coverage_is_explicitly_incomplete(self):
        lock = self.write("composer.lock", {"packages": []})
        self.write("composer.json", {"repositories": [{"type": "composer", "url": "https://registry.invalid"}]})
        c = self.collector()
        with patch.object(self.deps.shutil, "which", return_value="/trusted/composer"), \
             patch.object(self.deps, "run", return_value=(0, '{"advisories": [], "abandoned": []}', "")):
            self.deps.audit_composer(c, self.root, lock)
        self.assertTrue(any("custom-repository" in n["reason"] for n in c.not_run))

    def test_composer_invalid_input_never_invokes_auditor(self):
        lock = self.write("composer.lock", "not JSON")
        c = self.collector()
        with patch.object(self.deps.shutil, "which", return_value="/trusted/composer"), \
             patch.object(self.deps, "run") as run:
            self.deps.audit_composer(c, self.root, lock)
        run.assert_not_called()
        self.assertTrue(c.not_run)

    def report(self, verdict, evidence):
        finding = {"id": "F-001", "title": "Synthetic", "severity": "High", "confidence": "Confirmed",
                   "location": "src.py:1", "validation": {"verdict": verdict, "evidence": evidence}}
        return self.write("findings.json", {"meta": {"project": "fixture", "date": "2026-10-06"},
                                            "findings": [finding]})

    def test_conclusive_verdicts_reject_non_string_or_empty_evidence(self):
        for verdict in ("Valid", "FalsePositive", "NotApplicable"):
            for evidence in (None, False, 0, [], {}, ["reason"], "", " \n\t"):
                with self.subTest(verdict=verdict, evidence=evidence), self.assertRaises(self.renderer.SchemaError):
                    self.renderer.load(self.report(verdict, evidence))

    def test_conclusive_verdicts_keep_real_evidence(self):
        for verdict in ("Valid", "FalsePositive", "NotApplicable"):
            data = self.renderer.load(self.report(verdict, "Reviewed source and compensating control."))
            self.assertTrue(data["findings"][0]["validation"]["evidence"])
            self.assertEqual(data["findings"][0]["verdict"], verdict)

    def test_unverified_may_have_empty_string_evidence(self):
        self.renderer.load(self.report("Unverified", ""))

    @unittest.skipUnless(sys.version_info >= (3, 11), "TOML ownership requires stdlib tomllib")
    def test_cargo_declared_member_shares_root_lock_and_audit_coverage(self):
        parent = self.write("Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n')
        lock = self.write("Cargo.lock", "version = 3\n")
        member = self.write("crates/app/Cargo.toml", '[package]\nname="app"\nversion="0.1.0"\n')
        c = self.collector()
        self.deps.check_lockfile(c, member)
        self.assertFalse(c.findings)
        with patch.object(self.deps, "audit_osv", return_value={lock}), patch.object(self.deps, "run") as run:
            self.deps.audits(c, self.root, [parent, lock, member])
        run.assert_not_called()
        self.assertFalse(c.not_run)

    @unittest.skipUnless(sys.version_info >= (3, 11), "TOML ownership requires stdlib tomllib")
    def test_cargo_excluded_or_nested_workspace_does_not_inherit_root_lock(self):
        self.write("Cargo.toml", '[workspace]\nmembers=["crates/*"]\nexclude=["crates/excluded"]\n')
        self.write("Cargo.lock", "version=3\n")
        for name, content in (("excluded", '[package]\nname="excluded"\nversion="0.1.0"\n'),
                              ("nested", '[workspace]\nmembers=[]\n')):
            c = self.collector()
            manifest = self.write(f"crates/{name}/Cargo.toml", content)
            self.deps.check_lockfile(c, manifest)
            self.assertTrue(any("has no lockfile" in f["title"] for f in c.findings))

    def test_unavailable_toml_parser_is_incomplete_not_missing_lock(self):
        self.write("Cargo.toml", '[workspace]\nmembers=["member"]\n')
        self.write("Cargo.lock", "version=3\n")
        member = self.write("member/Cargo.toml", '[package]\nname="member"\n')
        c = self.collector()
        with patch.dict(sys.modules, {"tomllib": None}):
            self.deps.check_lockfile(c, member)
        self.assertFalse(c.findings)
        self.assertTrue(c.not_run)

    def test_npm_explicit_workspace_shares_lock_but_unrelated_project_does_not(self):
        self.write("package.json", {"workspaces": ["apps/*"]})
        lock = self.write("package-lock.json", {"lockfileVersion": 3})
        member = self.write("apps/site/package.json", {})
        unrelated = self.write("unrelated/package.json", {})
        c = self.collector()
        self.assertEqual(self.deps.matching_lockfiles(c, member), [lock])
        self.assertEqual(self.deps.matching_lockfiles(c, unrelated), [])
        self.assertFalse(c.not_run)

    def test_workspace_globs_do_not_cross_slashes_unless_explicit(self):
        self.assertFalse(self.deps.workspace_pattern("apps/a/nested", "apps/*"))
        self.assertTrue(self.deps.workspace_pattern("apps/a/nested", "apps/**"))
        with self.assertRaises(ValueError):
            self.deps.workspace_pattern("app", "../app")

    def test_pnpm_yaml_ownership_is_explicitly_incomplete(self):
        self.write("package.json", {})
        self.write("pnpm-workspace.yaml", 'packages: ["apps/*"]\n')
        self.write("pnpm-lock.yaml", "lockfileVersion: 9.0\n")
        member = self.write("apps/site/package.json", {})
        c = self.collector()
        self.deps.check_lockfile(c, member)
        self.assertFalse(c.findings)
        self.assertTrue(c.not_run)

    def workflow(self, steps):
        path = self.write(".github/workflows/test.yml", "name: test\non: pull_request\njobs:\n  test:\n    steps:\n" + steps)
        c = self.collector()
        self.deps.check_workflow(c, path)
        return c

    def injection_findings(self, c):
        return [f for f in c.findings if "untrusted event text" in f["title"]]

    def test_safe_env_and_with_are_not_shell_interpolation(self):
        c = self.workflow('''      - name: safe
        env:
          TITLE: ${{ github.event.pull_request.title }}
          run: ${{ github.event.pull_request.body }}
        run: printf '%s\\n' "$TITLE"
      - uses: actions/example@0000000000000000000000000000000000000000
        with:
          text: ${{ github.event.pull_request.title }}
''')
        self.assertFalse(self.injection_findings(c))
        self.assertFalse(c.not_run)

    def test_inline_literal_folded_and_quoted_run_interpolations_are_detected(self):
        for step in ('      - run: echo "${{ github.event.pull_request.title }}"\n',
                     '      - run: |\n          echo "${{ github.event.pull_request.title }}"\n',
                     '      - run: >-\n          echo "${{ github.event.pull_request.title }}"\n',
                     '      - "run": echo "${{ github.event.pull_request.title }}"\n'):
            with self.subTest(step=step):
                self.assertEqual(len(self.injection_findings(self.workflow(step))), 1)

    def test_non_run_scalar_examples_and_comments_are_not_executed_scripts(self):
        c = self.workflow('''      - name: safe
        env:
          EXAMPLE: |
            run: echo "${{ github.event.pull_request.title }}"
        run: echo safe
        # run: echo "${{ github.event.pull_request.title }}"
''')
        self.assertFalse(self.injection_findings(c))

    def test_flow_style_steps_and_aliases_are_explicitly_incomplete(self):
        for steps in ('      - run: *script\n',):
            self.assertTrue(self.workflow(steps).not_run)
        c = self.collector()
        path = self.write("workflow.yml", 'jobs: {test: {steps: [{run: echo safe}]}}\n')
        # A flow collection at the root is also recorded as unsupported.
        list(self.deps.workflow_run_lines(c, path, '{"jobs": {}}'))
        self.assertTrue(c.not_run)


if __name__ == "__main__":
    unittest.main()
