"""Follow-up review regressions: inert local inputs; all audit tools mocked."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location("review_" + name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


class ReviewHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deps = load_script("deps_scan")
        cls.renderer = load_script("render")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-review-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.root = self.base / "repo"
        self.root.mkdir()

    def write(self, name, content="{}"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def collector(self):
        return self.deps.Collector(self.root)

    def osv_result(self, lock, vulnerabilities=None):
        return {"results": [{"source": {"path": str(lock), "type": "lockfile"}, "packages": [
            {"package": {"name": "fixture", "version": "1.0", "ecosystem": "npm"},
             "vulnerabilities": vulnerabilities if vulnerabilities is not None else [
                 {"id": "GHSA-FIXTURE", "summary": "Synthetic advisory", "aliases": ["CVE-FIXTURE"]}],
             "groups": [{"ids": ["GHSA-FIXTURE"], "max_severity": "8.0"}]}]}]}

    def audit_osv(self, lock, code, payload):
        c = self.collector()
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", return_value=(code, json.dumps(payload), "SYNTHETIC_STDERR_SECRET")):
            covered = self.deps.audit_osv(c, self.root, [lock])
        return c, covered

    def report(self, findings):
        data = {"meta": {"project": "Fixture", "date": "2026-10-06"}, "findings": findings}
        path = self.base / "findings.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return self.renderer.load(path)

    def finding(self, title):
        return {"id": "F-001", "title": title, "location": "source.py:1", "severity": "High",
                "confidence": "Confirmed", "validation": {"verdict": "Unverified"}}

    def test_registry_credentials_never_reach_json_or_html(self):
        marker = "SYNTHETIC_REGISTRY_SECRET"
        self.write(".npmrc", f"registry=https://fixture:{marker}@registry.example.invalid/npm?token={marker}\n")
        result = self.deps.scan(self.root, False)
        self.assertTrue(result["findings"])
        self.assertNotIn(marker, json.dumps(result))
        data = self.report(result["findings"])
        self.renderer.attach_sources(data, self.root)
        for lang in ("ja", "en"):
            for render in (self.renderer.render_dashboard, self.renderer.render_assessment_html):
                self.assertNotIn(marker, render(data, self.renderer.LABELS[lang], lang))

    def test_npm_lock_authority_does_not_echo_userinfo(self):
        marker = "SYNTHETIC_LOCK_SECRET"
        lock = self.write("package-lock.json", json.dumps({"resolved": f"https://user:{marker}@mirror.invalid/pkg"}))
        c = self.collector()
        self.deps.check_npm_lock(c, lock)
        self.assertTrue(c.findings)
        self.assertNotIn(marker, json.dumps(c.findings))
        self.assertIn("mirror.invalid", json.dumps(c.findings))

    def test_dependency_urls_are_sanitized_across_ecosystems(self):
        marker = "SYNTHETIC_SOURCE_SECRET"
        url = f"https://user:{marker}@packages.invalid/archive?signature={marker}#{marker}"
        self.write("package.json", json.dumps({"dependencies": {"fixture": url}}))
        self.write("composer.json", json.dumps({"repositories": [{"type": "vcs", "url": url}]}))
        self.write("requirements.txt", "fixture @ " + url)
        self.write("Gemfile", "source '" + url + "'\n")
        result = self.deps.scan(self.root, False)
        self.assertGreaterEqual(len(result["findings"]), 4)
        self.assertNotIn(marker, json.dumps(result))

    def test_requirement_source_lines_are_not_copied(self):
        self.write("requirements.txt", "password=SYNTHETIC_NON_URL_SECRET\n")
        result = self.deps.scan(self.root, False)
        self.assertTrue(result["findings"])
        self.assertNotIn("SYNTHETIC_NON_URL_SECRET", json.dumps(result))

    def test_references_and_manual_history_are_sanitized(self):
        marker = "SYNTHETIC_REFERENCE_SECRET"
        url = f"https://user:{marker}@advisories.invalid/fixture?key={marker}#{marker}"
        c = self.collector()
        lock = self.write("package-lock.json")
        self.deps.vuln(c, "high", "fixture", "1", ["GHSA-FIXTURE"], url, lock, "fixture",
                       refs=[{"url": url, "title": url}])
        self.assertNotIn(marker, json.dumps(c.findings))
        path = self.base / "findings.json"
        old = copy.deepcopy(c.findings[0])
        old["validation"] = {"verdict": "Valid", "method": "review", "evidence": url}
        path.write_text(json.dumps({"findings": [old]}), encoding="utf-8")
        self.deps.merge_into(path, {"findings": c.findings, "not_run": []})
        merged = json.loads(path.read_text())
        self.assertIn("previous_validation", merged["findings"][0])
        self.assertNotIn(marker, path.read_text())

    def test_plain_urls_survive_and_invalid_authorities_fail_closed(self):
        url = "https://github.com/advisories/GHSA-FIXTURE"
        self.assertEqual(self.deps.redact_urls(url), url)
        self.assertNotIn("SYNTHETIC_SECRET", self.deps.redact_urls("https://u:SYNTHETIC_SECRET@[broken"))

    def test_review_4192003348_apostrophe_urls_redact_complete_token(self):
        # https://github.com/simota/security-scan/pull/2#discussion_r4192003348
        secret = "SYNTHETIC_BEFORE'SYNTHETIC_AFTER"
        cases = [
            (f"https://user:{secret}@example.invalid/path", "https://example.invalid/path"),
            (f"https://{secret}:password@example.invalid/path", "https://example.invalid/path"),
            (f"https://user:123'{secret}@example.invalid/path", "https://example.invalid/path"),
            (f"https://example.invalid/path?token={secret}", "https://example.invalid/path"),
            (f"https://example.invalid/path#{secret}", "https://example.invalid/path"),
            (f"git+https://user:{secret}@example.invalid/repo.git", "git+https://example.invalid/repo.git"),
            (f"https://user:{secret}@[::1]:8443/path", "https://[::1]:8443/path"),
            (f"https://user:{secret}@[broken", "[redacted URL]"),
        ]
        for url, expected in cases:
            with self.subTest(url=url):
                actual = self.deps.redact_urls(url)
                self.assertEqual(actual, expected)
                self.assertNotIn("SYNTHETIC_BEFORE", actual)
                self.assertNotIn("SYNTHETIC_AFTER", actual)
                self.assertEqual(self.deps.redact_urls(actual), actual)

    def test_url_redaction_preserves_plain_paths_and_quoted_context(self):
        plain = "https://example.invalid/releases/it's-ready"
        encoded = "https://user:SYNTHETIC%27SECRET@example.invalid/path?token=SYNTHETIC#fragment"
        secret = "https://user:SYNTHETIC_BEFORE'SYNTHETIC_AFTER@example.invalid/path?token=fixture"
        invalid = "https://user:SYNTHETIC_BEFORE'SYNTHETIC_AFTER@[broken"
        for url, expected in ((plain, plain), (encoded, "https://example.invalid/path"),
                              (secret, "https://example.invalid/path"), (invalid, "[redacted URL]")):
            for quote in ("", "'", '"'):
                with self.subTest(url=url, quote=quote):
                    actual = self.deps.redact_urls(f"See {quote}{url}{quote} next")
                    self.assertEqual(actual, f"See {quote}{expected}{quote} next")
                    self.assertEqual(self.deps.redact_urls(actual), actual)
        self.assertEqual(self.deps.redact_urls("https://example.invalid/path'"),
                         "https://example.invalid/path'")

    def test_apostrophe_credentials_never_reach_json_or_html(self):
        secret = "SYNTHETIC_BEFORE'SYNTHETIC_AFTER"
        url = f"https://user:{secret}@packages.invalid/archive?token={secret}#{secret}"
        self.write(".npmrc", "registry=" + url + "\n")
        self.write("package.json", json.dumps({"dependencies": {"fixture": url}}))
        self.write("composer.json", json.dumps({"repositories": [{"type": "vcs", "url": url}]}))
        result = self.deps.scan(self.root, False)
        self.assertTrue(any(f["location"].startswith(".npmrc:") for f in result["findings"]))
        self.assertTrue(any("fetched outside the registry" in f["title"] for f in result["findings"]))
        self.assertTrue(any("composer repository" in f["title"] for f in result["findings"]))
        data = self.report(result["findings"])
        self.renderer.attach_sources(data, self.root)
        outputs = [json.dumps(result)]
        for lang in ("ja", "en"):
            for render in (self.renderer.render_dashboard, self.renderer.render_assessment_html):
                outputs.append(render(data, self.renderer.LABELS[lang], lang))
        for output in outputs:
            self.assertNotIn("SYNTHETIC_BEFORE", output)
            self.assertNotIn("SYNTHETIC_AFTER", output)

    def test_apostrophe_urls_are_sanitized_in_references_and_history(self):
        secret = "SYNTHETIC_BEFORE'SYNTHETIC_AFTER"
        url = f"https://user:{secret}@advisories.invalid/fixture?key={secret}#{secret}"
        c = self.collector()
        lock = self.write("package-lock.json")
        self.deps.vuln(c, "high", "fixture", "1", ["GHSA-FIXTURE"], url, lock, "fixture",
                       refs=[{"url": url, "title": url}])
        self.assertTrue(c.findings[0]["references"])
        self.assertEqual(c.findings[0]["references"][0]["url"], "https://advisories.invalid/fixture")
        generated = json.dumps(c.findings)
        path = self.base / "findings.json"
        old = copy.deepcopy(c.findings[0])
        old["validation"] = {"verdict": "Valid", "method": "review", "evidence": url}
        path.write_text(json.dumps({"findings": [old]}), encoding="utf-8")
        self.deps.merge_into(path, {"findings": c.findings, "not_run": []})
        merged = json.loads(path.read_text())
        self.assertIn("previous_validation", merged["findings"][0])
        for output in (generated, path.read_text()):
            self.assertNotIn("SYNTHETIC_BEFORE", output)
            self.assertNotIn("SYNTHETIC_AFTER", output)

    def test_apostrophe_urls_are_sanitized_in_nested_output(self):
        url = "https://example.invalid/path?token=SYNTHETIC_BEFORE'SYNTHETIC_AFTER"
        data = {url: [url, {"inventory": url}], "count": 1}
        expected = {"https://example.invalid/path": ["https://example.invalid/path",
                    {"inventory": "https://example.invalid/path"}], "count": 1}
        self.assertEqual(self.deps.safe_output(data), expected)
        self.assertEqual(self.deps.safe_output(expected), expected)

    def test_source_excerpt_redacts_complete_apostrophe_urls(self):
        secret = "SYNTHETIC_BEFORE'SYNTHETIC_AFTER"
        for url in (f"https://user:{secret}@example.invalid/path",
                    f"https://example.invalid/path?token={secret}",
                    f"https://example.invalid/path#{secret}"):
            for quote in ("", "'", '"'):
                with self.subTest(url=url, quote=quote):
                    line = f"url = {quote}{url}{quote}"
                    actual = self.renderer.redact(line)
                    self.assertEqual(actual, f"url = {quote}https://example.invalid/path{quote}")
                    self.assertNotIn("SYNTHETIC_BEFORE", actual)
                    self.assertNotIn("SYNTHETIC_AFTER", actual)
                    self.assertEqual(self.renderer.redact(actual), actual)

    def test_symlink_requirements_never_read_outside_checkout(self):
        outside = self.base / "outside.txt"
        outside.write_text("SYNTHETIC_OUTSIDE_CONTENT", encoding="utf-8")
        (self.root / "requirements.txt").symlink_to(outside)
        result = self.deps.scan(self.root, False)
        self.assertFalse(result["findings"])
        self.assertNotIn("SYNTHETIC_OUTSIDE_CONTENT", json.dumps(result))
        self.assertTrue(any("requirements.txt" in item["reason"] for item in result["not_run"]))
        self.assertEqual(self.deps.read(self.root / "requirements.txt"), "")

    def test_symlink_dirs_and_source_files_are_not_indexed(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "code.py").write_text("SYNTHETIC_PRIVATE_SOURCE", encoding="utf-8")
        (self.root / "linked-dir").symlink_to(outside, target_is_directory=True)
        (self.root / "code.py").symlink_to(outside / "code.py")
        self.assertEqual(list(self.deps.walk(self.root)), [])
        self.assertEqual(self.deps.source_index(self.root), [])
        result = self.deps.scan(self.root, False)
        self.assertEqual(sum(n["tool"] == "file scan" for n in result["not_run"]), 2)

    def test_broken_internal_and_cyclic_links_are_reported(self):
        normal = self.write("real.txt", "safe")
        (self.root / "alias.txt").symlink_to(normal)
        (self.root / "broken.txt").symlink_to(self.root / "missing")
        (self.root / "loop.txt").symlink_to(self.root / "loop.txt")
        skipped = []
        self.assertEqual(list(self.deps.walk(self.root, skipped)), [normal])
        self.assertEqual(len(skipped), 3)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_non_regular_files_are_skipped_without_opening(self):
        os.mkfifo(self.root / "requirements.txt")
        result = self.deps.scan(self.root, False)
        self.assertFalse(result["findings"])
        self.assertTrue(any("requirements.txt" in n["reason"] for n in result["not_run"]))

    def test_audit_rejects_outside_symlink_and_traversal_operands(self):
        outside = self.base / "outside.lock"
        outside.write_text("{}", encoding="utf-8")
        link = self.root / "package-lock.json"
        link.symlink_to(outside)
        for path in (outside, link, self.root / ".." / "outside.lock"):
            c = self.collector()
            with patch.object(self.deps, "run") as run:
                self.deps.audit_npm(c, self.root, path)
                self.deps.audit_requirements(c, self.root, path)
            run.assert_not_called()
            self.assertTrue(c.not_run)

    def test_audit_rechecks_symlink_replacement_before_osv(self):
        lock = self.write("package-lock.json")
        outside = self.base / "outside.lock"
        outside.write_text("{}", encoding="utf-8")
        files = list(self.deps.walk(self.root))
        lock.unlink()
        lock.symlink_to(outside)
        c = self.collector()
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run") as run:
            covered = self.deps.audit_osv(c, self.root, files)
        run.assert_not_called()
        self.assertFalse(covered)
        self.assertTrue(c.not_run)

    def test_symlink_config_blocks_fallback_tool(self):
        outside = self.base / "external-config"
        outside.write_text("SYNTHETIC_CONFIG_SECRET", encoding="utf-8")
        for lock_name, config_name, audit in (
                ("package-lock.json", ".npmrc", self.deps.audit_npm),
                ("composer.lock", "auth.json", self.deps.audit_composer)):
            lock = self.write(lock_name)
            (self.root / config_name).symlink_to(outside)
            c = self.collector()
            with patch.object(self.deps, "run") as run:
                audit(c, self.root, lock)
            run.assert_not_called()
            self.assertTrue(c.not_run)

    def test_symlink_lock_does_not_satisfy_lockfile_check(self):
        self.write("package.json")
        outside = self.base / "outside.lock"
        outside.write_text("{}", encoding="utf-8")
        (self.root / "package-lock.json").symlink_to(outside)
        result = self.deps.scan(self.root, False)
        self.assertTrue(any("has no lockfile" in f["title"] for f in result["findings"]))

    def test_osv_uses_private_empty_config_not_target_exclusions(self):
        lock = self.write("package-lock.json")
        local_config = self.write("osv-scanner.toml", '[[PackageOverrides]]\nignore = true\n')
        c = self.collector()
        seen = []
        def run(cmd, cwd):
            config = Path(cmd[cmd.index("--config") + 1])
            self.assertNotEqual(config, local_config)
            self.assertNotIn(self.root, config.parents)
            text = config.read_text()
            self.assertTrue(all(not line.strip() or line.lstrip().startswith("#") for line in text.splitlines()))
            self.assertEqual(cmd[cmd.index("-L") + 1], str(lock))
            seen.append(config)
            return 1, json.dumps(self.osv_result(lock)), ""
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", side_effect=run):
            covered = self.deps.audit_osv(c, self.root, [lock])
        self.assertEqual(covered, {lock})
        self.assertEqual(len(c.findings), 1)
        self.assertTrue(all(not path.exists() for path in seen))
        self.assertEqual(local_config.read_text(), '[[PackageOverrides]]\nignore = true\n')

    def test_bun_lock_is_inventory_and_osv_input(self):
        self.write("package.json")
        lock = self.write("bun.lock")
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", return_value=(0, '{"results": []}', "")) as run:
            result = self.deps.scan(self.root, True)
        self.assertEqual(run.call_count, 1)
        self.assertIn(str(lock), run.call_args.args[0])
        self.assertFalse(result["not_run"])
        self.assertFalse(any("has no lockfile" in f["title"] for f in result["findings"]))
        self.assertTrue(any(i["lockfile"] == "bun.lock" and i["ecosystem"] == "npm" for i in result["inventory"]))

    def test_strict_fails_when_bun_format_is_unsupported(self):
        self.write("package.json")
        self.write("bun.lock")
        out = self.base / "deps.json"
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", return_value=(2, "", "SYNTHETIC_TOOL_SECRET")):
            code = self.deps.main([str(self.root), "--audit", "--strict", "--out", str(out)])
        self.assertEqual(code, 3)
        data = json.loads(out.read_text())
        self.assertTrue(any("bun.lock" in n["reason"] for n in data["not_run"]))
        self.assertNotIn("SYNTHETIC_TOOL_SECRET", out.read_text())

    def test_legacy_bun_and_known_unhandled_inputs_are_not_silent(self):
        for name in ("bun.lockb", "requirements.lock", "pom.xml", "gradle.lockfile", "pyproject.toml"):
            with self.subTest(name=name):
                # A pyproject.toml counts only when it declares dependencies.
                path = self.write(name, '[project]\ndependencies = ["fixture"]\n' if name == "pyproject.toml" else "{}")
                c = self.collector()
                with patch.object(self.deps, "audit_osv", return_value=set()):
                    self.deps.audits(c, self.root, [path])
                self.assertTrue(any(name in item["reason"] for item in c.not_run))

    def test_osv_clean_and_findings_results_are_accepted(self):
        lock = self.write("package-lock.json")
        for code, payload, count in [(0, {"results": []}, 0),
                                     (0, self.osv_result(lock, []), 0),
                                     (1, self.osv_result(lock), 1)]:
            c, covered = self.audit_osv(lock, code, payload)
            self.assertEqual(covered, {lock})
            self.assertEqual(len(c.findings), count)
            self.assertFalse(c.not_run)

    def test_osv_bad_envelopes_never_grant_coverage(self):
        lock = self.write("package-lock.json")
        for code, payload in [(0, {}), (0, []), (0, None), (0, {"results": None}),
                              (0, {"error": {}, "results": []}), (1, {"error": "fixture"}),
                              (0, {"errors": ["fixture"], "results": []}),
                              (1, {"results": []}), (2, {"results": []}),
                              (0, self.osv_result(lock)), (0, {"results": [None]})]:
            with self.subTest(code=code, payload=payload):
                c, covered = self.audit_osv(lock, code, payload)
                self.assertFalse(covered)
                self.assertFalse(c.findings)
                self.assertTrue(c.not_run)
                self.assertNotIn("SYNTHETIC_STDERR_SECRET", json.dumps(c.not_run))

    def test_osv_invalid_json_and_timeout_are_not_clean(self):
        lock = self.write("package-lock.json")
        for code, out in [(0, "not json"), (None, "")]:
            c = self.collector()
            with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
                 patch.object(self.deps, "run", return_value=(code, out, "SYNTHETIC_SECRET")):
                self.assertFalse(self.deps.audit_osv(c, self.root, [lock]))
            self.assertTrue(c.not_run)
            self.assertNotIn("SYNTHETIC_SECRET", json.dumps(c.not_run))

    def test_osv_nested_malformed_results_roll_back_partial_findings(self):
        lock = self.write("package-lock.json")
        malformed = [None, {}, {"id": None}, {"id": "fixture", "aliases": [None]},
                     {"id": "fixture", "references": [None]},
                     {"id": "fixture", "affected": [None]}]
        for bad in malformed:
            data = self.osv_result(lock)
            data["results"][0]["packages"][0]["vulnerabilities"].append(bad)
            c, covered = self.audit_osv(lock, 1, data)
            self.assertFalse(covered)
            self.assertFalse(c.findings)
            self.assertTrue(c.not_run)

    def test_osv_does_not_trust_a_different_source_path(self):
        lock = self.write("package-lock.json")
        data = self.osv_result(self.base / "outside.lock")
        c, covered = self.audit_osv(lock, 1, data)
        self.assertFalse(covered)
        self.assertFalse(c.findings)
        self.assertTrue(c.not_run)

    def test_one_osv_failure_does_not_grant_other_file_coverage(self):
        a = self.write("a/uv.lock")
        b = self.write("b/uv.lock")
        c = self.collector()
        responses = [(0, '{"results": []}', ""), (1, '{"error": "fixture"}', "")]
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", side_effect=responses) as run:
            covered = self.deps.audit_osv(c, self.root, [a, b])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(covered, {a})
        self.assertTrue(any("b/uv.lock" in n["reason"] for n in c.not_run))

    def test_failed_osv_allows_npm_fallback(self):
        lock = self.write("package-lock.json")
        c = self.collector()
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", return_value=(1, '{"error": "fixture"}', "")), \
             patch.object(self.deps, "audit_npm") as npm:
            self.deps.audits(c, self.root, [lock])
        npm.assert_called_once_with(c, self.root, lock)
        self.assertTrue(c.not_run)

    def test_dashboard_json_escapes_all_html_script_delimiters(self):
        for title in ("<!--<script>", "</script>", "<!--<SCRIPT>", "<script>日本語 & test"):
            data = self.report([self.finding(title)])
            data["findings"][0]["snippet"] = {"start": 1, "hit": [1, 1], "lines": [title]}
            markup = self.renderer.render_dashboard(data, self.renderer.LABELS["ja"], "ja")
            raw = re.search(r'<script id="data" type="application/json">(.*?)</script>', markup, re.S).group(1)
            self.assertNotIn("<", raw)
            decoded = json.loads(raw)
            self.assertEqual(decoded["findings"][0]["title"], title)
            self.assertEqual(decoded["findings"][0]["snippet"]["lines"], [title])

    @unittest.skipUnless(os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1", "opt-in Chromium smoke test")
    def test_dashboard_draws_hostile_text_in_real_browser(self):
        exe = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not exe:
            self.skipTest("Chrome/Chromium not installed")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is required for the optional browser smoke test")
        title = "<!--<script> INERT_REVIEW_FIXTURE"
        data = self.report([self.finding(title)])
        data["findings"][0]["snippet"] = {"start": 1, "hit": [1, 1], "lines": [title]}
        markup = self.renderer.render_dashboard(data, self.renderer.LABELS["en"], "en")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=exe, headless=True, timeout=15000)
            try:
                page = browser.new_page()
                page.route("**/*", lambda route: route.abort())
                page.set_content(markup, wait_until="domcontentloaded")
                self.assertEqual(page.locator("tr.row").count(), 1)
                self.assertIn(title, page.locator("tr.row").inner_text())
                page.locator("tr.row").click()
                self.assertIn(title, page.locator(".snippet").inner_text())
                self.assertEqual(page.locator("script").count(), 2)
            finally:
                browser.close()



if __name__ == "__main__":
    unittest.main()
