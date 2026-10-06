"""Offline security regressions. Audit subprocesses are always mocked."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


def import_module(path: Path, name: str) -> ModuleType:
    if not path.is_file():
        raise FileNotFoundError(f"Required script not found: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finding(location: str = "main.py:1") -> dict:
    return {
        "id": "D-001", "title": "Synthetic review fixture",
        "severity": "High", "confidence": "Confirmed", "location": location,
        "package": "synthetic-package", "version": "1.0.0",
        "validation": {"verdict": "Unverified", "method": "auto"},
    }


class SecurityScanRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scripts = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts"
        cls.deps = import_module(scripts / "deps_scan.py", "tested_deps_scan")
        cls.renderer = import_module(scripts / "render.py", "tested_renderer")

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="security-scan-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def load_finding(self, f: dict, **meta) -> dict:
        data = {"meta": {"project": "Synthetic fixture", "date": "2026-10-06", **meta},
                "findings": [f]}
        p = self.root / "findings.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return self.renderer.load(p)

    def test_01_composer_audit_disables_plugins(self) -> None:
        lock = self.root / "composer.lock"
        lock.write_text('{"packages": [], "packages-dev": []}', encoding="utf-8")
        collector = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/synthetic/composer"), \
             patch.object(self.deps, "run", return_value=(0, '{"advisories": {}, "abandoned": {}}', "")) as run:
            self.deps.audit_composer(collector, self.root, lock)
        argv = run.call_args.args[0]
        self.assertIn("--no-plugins", argv, "Read-only audit must not load installed Composer plugins")

    def test_02_npm_error_json_is_not_a_clean_audit(self) -> None:
        collector = self.deps.Collector(self.root)
        error = json.dumps({"error": {"code": "EAUDITNOLOCK", "summary": "Synthetic audit error"}})
        with patch.object(self.deps.shutil, "which", return_value="/synthetic/npm"), \
             patch.object(self.deps, "run", return_value=(1, error, "")):
            self.deps.audit_npm(collector, self.root, self.root / "package-lock.json")
        self.assertTrue(collector.not_run, "Audit error was silently converted to zero findings")

    def test_03_uv_lock_does_not_audit_the_host_environment(self) -> None:
        collector = self.deps.Collector(self.root)
        with patch.object(self.deps, "audit_osv", return_value=set()), \
             patch.object(self.deps, "audit_simple") as audit:
            self.deps.audits(collector, self.root, [self.root / "uv.lock"])
        bad_calls = [c for c in audit.call_args_list if c.args[3] == ["pip-audit", "-f", "json"]]
        self.assertFalse(bad_calls, "A lockfile scan must name a supported project/file, or record not_run")

    def test_04_review_verdict_does_not_cross_project_paths(self) -> None:
        old = finding("apps/A/package-lock.json")
        old["validation"] = {"verdict": "NotApplicable", "method": "review", "evidence": "Only app A was reviewed"}
        p = self.root / "findings.json"
        p.write_text(json.dumps({"findings": [old]}), encoding="utf-8")
        new = finding("apps/B/package-lock.json")
        result = {"findings": [new], "not_run": [], "inventory": []}
        self.deps.merge_into(p, result)
        merged = json.loads(p.read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(merged["validation"]["verdict"], "Unverified", "App A's exclusion was copied to app B")

    def test_05_source_link_rejects_non_http_scheme(self) -> None:
        # Inert URI only; no browser is started and no JavaScript is executed.
        try:
            data = self.load_finding(finding(), source_url="javascript:void(0)//synthetic")
            self.renderer.attach_sources(data, None)
            markup = self.renderer.refs_html(data["findings"][0])
        except self.renderer.SchemaError:
            return  # Rejecting at either stage is an acceptable fix.
        self.assertNotIn("href='javascript:", markup.lower(), "Unsafe scheme reached an HTML href")

    def test_06_source_excerpt_does_not_expose_connection_password(self) -> None:
        # Not a real credential or a real service.
        marker = "SYNTHETIC_PASSWORD_NOT_A_REAL_SECRET"
        (self.root / ".env").write_text(
            'APP_MODE=test\nDATABASE_URL="postgresql://fixture:' + marker + '@db.invalid/example"\n',
            encoding="utf-8")
        data = self.load_finding(finding(".env:1"))
        self.renderer.attach_sources(data, self.root)
        excerpt = json.dumps(data["findings"][0].get("snippet", {}))
        self.assertNotIn(marker, excerpt, "Automatic context embedding disclosed a connection-string password")

    def test_07_pip_parser_handles_list_json(self) -> None:
        collector = self.deps.Collector(self.root)
        try:
            self.deps.parse_pip_audit(collector, [{"name": "synthetic", "version": "1.0", "vulns": []}], self.root)
        except AttributeError as exc:
            self.fail(f"The intended list-format fallback raises instead: {exc}")

    def test_08_parent_path_source_excerpt_is_blocked(self) -> None:
        repo = self.root / "repo"
        repo.mkdir()
        (self.root / "outside.txt").write_text("SYNTHETIC_PRIVATE_CONTENT", encoding="utf-8")
        data = self.load_finding(finding("../outside.txt:1"))
        self.renderer.attach_sources(data, repo)
        self.assertNotIn("snippet", data["findings"][0])

    def test_09_html_text_is_escaped(self) -> None:
        self.assertEqual(self.renderer.esc('<b title="example">'), '&lt;b title=&quot;example&quot;&gt;')

    def test_composer_disables_scripts_and_accepts_php_empty_maps(self):
        lock = self.root / "composer.lock"
        lock.write_text('{"packages": []}', encoding="utf-8")
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/composer"), \
             patch.object(self.deps, "run", return_value=(0, '{"advisories": [], "abandoned": []}', "")) as run:
            self.deps.audit_composer(c, self.root, lock)
        self.assertIn("--no-scripts", run.call_args.args[0])
        self.assertFalse(c.not_run)

    def test_composer_rejects_error_or_missing_result(self):
        for code, payload in [(1, {"error": "fixture"}), (0, {}), (0, []), (9, {"advisories": {}})]:
            with self.subTest(code=code, payload=payload):
                c = self.deps.Collector(self.root)
                with patch.object(self.deps.shutil, "which", return_value="/tools/composer"), \
                     patch.object(self.deps, "run", return_value=(code, json.dumps(payload), "")):
                    self.deps.audit_composer(c, self.root, self.root / "composer.lock")
                self.assertTrue(c.not_run)

    def test_npm_clean_audit_is_accepted(self):
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/npm"), \
             patch.object(self.deps, "run", return_value=(0, '{"vulnerabilities": {}}', "")):
            self.deps.audit_npm(c, self.root, self.root / "package-lock.json")
        self.assertFalse(c.findings)
        self.assertFalse(c.not_run)

    def test_npm_findings_exit_one_is_not_an_error(self):
        payload = {"vulnerabilities": {"fixture": {"severity": "high", "range": "<2",
                   "via": [{"title": "Fixture", "url": "https://example.invalid/advisory/fixture"}]}}}
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/npm"), \
             patch.object(self.deps, "run", return_value=(1, json.dumps(payload), "")):
            self.deps.audit_npm(c, self.root, self.root / "package-lock.json")
        self.assertEqual(len(c.findings), 1)
        self.assertEqual(c.findings[0]["severity"], "High")
        self.assertFalse(c.not_run)

    def test_npm_bad_results_are_not_clean(self):
        cases = [(0, "{}"), (0, "[]"), (0, "null"), (0, "not json"),
                 (0, '{"error": {}, "vulnerabilities": {}}'),
                 (1, '{"vulnerabilities": {}}'), (2, '{"vulnerabilities": {}}'),
                 (None, ""), (0, '{"vulnerabilities": {"x": null}}')]
        for code, payload in cases:
            with self.subTest(code=code, payload=payload):
                c = self.deps.Collector(self.root)
                with patch.object(self.deps.shutil, "which", return_value="/tools/npm"), \
                     patch.object(self.deps, "run", return_value=(code, payload, "SYNTHETIC_SECRET")):
                    self.deps.audit_npm(c, self.root, self.root / "package-lock.json")
                self.assertTrue(c.not_run)
                self.assertNotIn("SYNTHETIC_SECRET", json.dumps(c.not_run))

    def test_requirements_use_only_normalized_pins_without_pip(self):
        path = self.root / "requirements.txt"
        path.write_text("# comment\nfixture == 1.2.3 # pinned\n", encoding="utf-8")
        c = self.deps.Collector(self.root)
        seen = []
        def run(cmd, cwd):
            self.assertIn("--no-deps", cmd)
            self.assertIn("--disable-pip", cmd)
            input_path = Path(cmd[cmd.index("-r") + 1])
            self.assertNotEqual(input_path, path)
            seen.append(input_path.read_text(encoding="utf-8"))
            return 0, '{"dependencies": [{"name": "fixture", "version": "1.2.3", "vulns": []}]}', ""
        with patch.object(self.deps.shutil, "which", return_value="/tools/pip-audit"), \
             patch.object(self.deps, "run", side_effect=run):
            self.deps.audit_requirements(c, self.root, path)
        self.assertEqual(seen, ["fixture==1.2.3\n"])
        self.assertFalse(c.not_run)

    def test_unsafe_requirements_never_invoke_auditor(self):
        for line in ["fixture>=1", "fixture==1.*", "-r other.txt", "-e .", "fixture @ https://example.invalid/pkg",
                     "--extra-index-url https://example.invalid", "fixture==1; os_name == 'posix'", "fixture[extra]==1"]:
            with self.subTest(line=line):
                path = self.root / "requirements.txt"
                path.write_text(line + "\n", encoding="utf-8")
                c = self.deps.Collector(self.root)
                with patch.object(self.deps, "run") as run:
                    self.deps.audit_requirements(c, self.root, path)
                run.assert_not_called()
                self.assertTrue(c.not_run)

    def test_python_locks_are_reported_as_not_run(self):
        for name in ("uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock"):
            with self.subTest(name=name):
                c = self.deps.Collector(self.root)
                with patch.object(self.deps, "audit_osv", return_value=set()), patch.object(self.deps, "run") as run:
                    self.deps.audits(c, self.root, [self.root / name])
                run.assert_not_called()
                self.assertTrue(any(name in x["reason"] for x in c.not_run))

    def test_osv_coverage_does_not_skip_an_uncovered_python_file(self):
        covered = self.root / "package-lock.json"
        path = self.root / "requirements-dev.txt"
        c = self.deps.Collector(self.root)
        with patch.object(self.deps, "audit_osv", return_value={covered}), \
             patch.object(self.deps, "audit_requirements") as audit:
            self.deps.audits(c, self.root, [covered, path])
        audit.assert_called_once_with(c, self.root, path)

    def test_pip_parser_accepts_list_and_object_findings(self):
        items = [{"name": "fixture", "version": "1.0", "vulns": [{"id": "PYSEC-FIXTURE", "fix_versions": ["2.0"]}]}]
        for payload in (items, {"dependencies": items}):
            c = self.deps.Collector(self.root)
            self.deps.parse_pip_audit(c, payload, self.root / "requirements.txt")
            self.assertEqual(len(c.findings), 1)
            self.assertEqual(c.findings[0]["location"], "requirements.txt")

    def test_pip_skipped_dependency_is_not_run(self):
        c = self.deps.Collector(self.root)
        self.deps.parse_pip_audit(c, [{"name": "fixture", "skip_reason": "fixture"}], self.root)
        self.assertTrue(c.not_run)

    def test_pip_malformed_payload_is_rejected(self):
        for payload in (None, {}, {"dependencies": None}, [None], [{"name": "fixture", "vulns": None}]):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.deps.parse_pip_audit(self.deps.Collector(self.root), payload, self.root)

    def test_simple_audit_rolls_back_partial_malformed_results(self):
        c = self.deps.Collector(self.root)
        payload = [{"name": "fixture", "vulns": [{"id": "PYSEC-FIXTURE"}]}, None]
        with patch.object(self.deps.shutil, "which", return_value="/tools/pip-audit"), \
             patch.object(self.deps, "run", return_value=(1, json.dumps(payload), "")):
            self.deps.audit_simple(c, self.root, "pip-audit", ["pip-audit"], self.root, self.deps.parse_pip_audit)
        self.assertFalse(c.findings)
        self.assertTrue(c.not_run)

    def test_rescan_keeps_review_history_not_stale_exclusion(self):
        old = finding("apps/A/package-lock.json")
        old["validation"] = {"verdict": "NotApplicable", "method": "review", "evidence": "Prior revision only"}
        path = self.root / "findings.json"
        path.write_text(json.dumps({"findings": [old]}), encoding="utf-8")
        new = finding("apps/A/package-lock.json")
        self.deps.merge_into(path, {"findings": [new], "not_run": []})
        result = json.loads(path.read_text(encoding="utf-8"))["findings"][0]
        self.assertEqual(result["validation"]["verdict"], "Unverified")
        self.assertEqual(result["previous_validation"]["verdict"], "NotApplicable")

    def test_different_advisory_does_not_inherit_review_history(self):
        old = finding()
        old["advisory_ids"] = ["OLD-FIXTURE"]
        old["validation"] = {"verdict": "Valid", "method": "review", "evidence": "Prior advisory"}
        path = self.root / "findings.json"
        path.write_text(json.dumps({"findings": [old]}), encoding="utf-8")
        new = finding()
        new["advisory_ids"] = ["NEW-FIXTURE"]
        self.deps.merge_into(path, {"findings": [new], "not_run": []})
        result = json.loads(path.read_text(encoding="utf-8"))["findings"][0]
        self.assertNotIn("previous_validation", result)

    def test_safe_source_url_is_retained_and_path_encoded(self):
        data = self.load_finding(finding("src/with space#hash.py:4-6"), source_url="https://example.invalid/blob/revision")
        self.renderer.attach_sources(data, None)
        self.assertEqual(data["findings"][0]["source_link"],
                         "https://example.invalid/blob/revision/src/with%20space%23hash.py#L4-L6")

    def test_unsafe_source_urls_are_rejected(self):
        urls = ["javascript:void(0)", "data:text/plain,fixture", "file:///fixture", "//example.invalid",
                "https:///missing-host", "https://user:password@example.invalid", "https://example.invalid\n",
                "https://example.invalid\\x", "https://example.invalid:99999", 42]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(self.renderer.SchemaError):
                self.load_finding(finding(), source_url=url)

    def test_input_cannot_inject_derived_source_link_or_snippet(self):
        f = finding()
        f.update(source_link="javascript:void(0)", snippet={"lines": ["SYNTHETIC_SECRET"]})
        data = self.load_finding(f)
        self.assertNotIn("source_link", data["findings"][0])
        self.assertNotIn("snippet", data["findings"][0])

    def test_render_sinks_reject_unsafe_source_links(self):
        data = self.load_finding(finding())
        data["findings"][0]["source_link"] = "javascript:void(0)"
        with self.assertRaises(self.renderer.SchemaError):
            self.renderer.refs_html(data["findings"][0])
        with self.assertRaises(self.renderer.SchemaError):
            self.renderer.render_dashboard(data, self.renderer.LABELS["en"], "en")

    def test_reference_urls_use_same_validation(self):
        f = finding()
        f["references"] = [{"url": "https://user:password@example.invalid"}]
        with self.assertRaises(self.renderer.SchemaError):
            self.load_finding(f)

    def test_sensitive_files_are_not_embedded(self):
        for name in (".env.local", ".npmrc", ".netrc", "auth.json", "fixture.pem", "id_ed25519"):
            with self.subTest(name=name):
                (self.root / name).write_text("SYNTHETIC_SECRET", encoding="utf-8")
                data = self.load_finding(finding(name + ":1"))
                self.renderer.attach_sources(data, self.root)
                self.assertNotIn("snippet", data["findings"][0])

    def test_sensitive_symlink_target_is_not_embedded(self):
        (self.root / ".env").write_text("SYNTHETIC_SECRET", encoding="utf-8")
        (self.root / "alias.py").symlink_to(self.root / ".env")
        data = self.load_finding(finding("alias.py:1"))
        self.renderer.attach_sources(data, self.root)
        self.assertNotIn("snippet", data["findings"][0])

    def test_private_key_middle_line_is_not_embedded(self):
        content = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "SYNTHETIC_SECRET\n" * 12 + "-----END OPENSSH PRIVATE KEY-----\n"
        (self.root / "config.py").write_text(content, encoding="utf-8")
        data = self.load_finding(finding("config.py:8"))
        self.renderer.attach_sources(data, self.root)
        self.assertNotIn("snippet", data["findings"][0])

    def test_secret_finding_has_no_excerpt(self):
        (self.root / "config.py").write_text("SYNTHETIC_SECRET", encoding="utf-8")
        f = finding("config.py:1")
        f["category"] = "Secrets"
        data = self.load_finding(f)
        self.renderer.attach_sources(data, self.root)
        self.assertNotIn("snippet", data["findings"][0])

    def test_connection_credentials_and_quoted_secrets_are_redacted(self):
        for line in ['DATABASE_URL="postgresql://fixture:SYNTHETIC_SECRET@db.invalid/example"',
                     'password = "SYNTHETIC_SECRET with spaces"', "token = 'SYNTHETIC_SECRET'"]:
            with self.subTest(line=line):
                self.assertNotIn("SYNTHETIC_SECRET", self.renderer.redact(line))
                self.assertNotIn("with spaces", self.renderer.redact(line))

    def test_escaped_quoted_secret_is_fully_redacted(self):
        line = 'password = "prefix\\"SYNTHETIC_SECRET"'
        self.assertNotIn("SYNTHETIC_SECRET", self.renderer.redact(line))

    def test_requirements_failures_name_original_input(self):
        path = self.root / "requirements.txt"
        path.write_text("fixture==1.0\n", encoding="utf-8")
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/pip-audit"), \
             patch.object(self.deps, "run", return_value=(2, "", "fixture")):
            self.deps.audit_requirements(c, self.root, path)
        self.assertIn("requirements.txt", c.not_run[0]["reason"])
        self.assertNotIn("security-scan-pins-", c.not_run[0]["reason"])

    def test_normal_source_is_still_embedded(self):
        (self.root / "app.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")
        data = self.load_finding(finding("app.py:2"))
        self.renderer.attach_sources(data, self.root)
        self.assertEqual(data["findings"][0]["snippet"]["lines"], ["value = 1", "print(value)"])

    def test_strict_returns_nonzero_for_incomplete_audit(self):
        result = {"findings": [], "inventory": [], "not_run": [{"tool": "fixture", "reason": "not installed"}]}
        with patch.object(self.deps, "scan", return_value=result):
            status = self.deps.main([str(self.root), "--audit", "--strict", "--out", str(self.root / "deps.json")])
        self.assertEqual(status, 3)
        self.assertTrue((self.root / "deps.json").exists())

    def test_strict_allows_completed_audit(self):
        with patch.object(self.deps, "scan", return_value={"findings": [], "inventory": [], "not_run": []}):
            status = self.deps.main([str(self.root), "--audit", "--strict", "--out", str(self.root / "deps.json")])
        self.assertEqual(status, 0)

    def test_sample_renders_in_both_languages(self):
        sample = Path(__file__).resolve().parents[1] / "examples/findings.sample.json"
        for lang in ("ja", "en"):
            out = self.root / lang
            self.assertEqual(self.renderer.main([str(sample), "--out", str(out), "--no-pdf", "--lang", lang]), 0)
            self.assertTrue((out / "dashboard.html").is_file())
            self.assertTrue((out / "assessment.html").is_file())


if __name__ == "__main__":
    unittest.main()
