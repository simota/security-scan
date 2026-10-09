"""Static-check regressions for deps_scan.py parsers and the --into merge."""
import importlib.util
import json
from pathlib import Path
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


class DepsScanReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deps = load_script("deps_scan")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-deps-review-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def titles(self):
        return [f["title"] for f in self.deps.scan(self.root, False)["findings"]]

    def test_non_object_json_manifests_are_incomplete_not_a_crash(self):
        for name, value in (("package.json", "[]"), ("package.json", '{"dependencies": ["a"]}'),
                            ("package-lock.json", "[]"), ("composer.lock", "[]"),
                            ("composer.json", "[1]"), ("package-lock.json", "[" * 100000)):
            with self.subTest(name=name, value=value[:20]):
                for old in self.root.iterdir():
                    old.unlink()
                self.write(name, value)
                result = self.deps.scan(self.root, False)
                self.assertIsInstance(result["findings"], list)

    def test_bom_package_json_is_still_checked(self):
        self.write("package.json", "\ufeff" + json.dumps({"dependencies": {"left": "*"}}))
        self.assertTrue(any("left floats" in t for t in self.titles()))

    def test_npm_ranges_and_sources(self):
        self.write("package.json", {"dependencies": {
            "bounded": ">=1.2.0 <2.0.0", "either": "^1.0.0 || >=2", "star-alt": "1.x || *", "upper": "X",
            "lab": "gitlab:owner/x", "bucket": "bitbucket:owner/y", "ssh": "git@github.com:owner/z.git",
            "caret": "^1.2.3"}})
        titles = self.titles()
        for name in ("either", "star-alt", "upper"):
            self.assertTrue(any(f"{name} floats" in t for t in titles), name)
        for name in ("lab", "bucket", "ssh"):
            self.assertTrue(any(f"{name} is fetched outside" in t for t in titles), name)
        self.assertFalse(any("bounded" in t or "caret" in t for t in titles))

    def test_npmrc_lookalike_host_and_credentials(self):
        self.write(".npmrc", "registry=https://registry.npmjs.org.evil.invalid/\n"
                             "//registry.npmjs.org/:_auth=SYNTHETICVALUE\n")
        self.write("sub/.yarnrc.yml", 'npmRegistryServer: "https://mirror.invalid"\nnpmAuthToken: SYNTHETIC\n')
        findings = self.deps.scan(self.root, False)["findings"]
        hosts = [f for f in findings if "points all packages" in f["title"]]
        creds = [f for f in findings if "literal registry credential" in f["title"]]
        self.assertEqual(len(hosts), 2)
        self.assertEqual(len(creds), 2)

    def test_python_editable_vcs_find_links_and_names(self):
        self.write("dev-requirements.txt", "-e git+https://example.invalid/pkg.git#egg=pkg\n"
                                           "--find-links https://example.invalid/wheels\n-e .\n")
        self.write("requirements/base.txt", "django\n")
        findings = self.deps.scan(self.root, False)["findings"]
        by_loc = {(f["location"], f["title"]) for f in findings}
        self.assertIn(("dev-requirements.txt:1", "Python dependency fetched from a URL (see source location)"), by_loc)
        self.assertTrue(any(t.startswith("pip --find-links") for _, t in by_loc))
        self.assertIn(("requirements/base.txt:1", "Python requirement not pinned (see source location)"), by_loc)
        self.assertFalse(any(loc == "dev-requirements.txt:3" for loc, _ in by_loc))

    def test_gemfile_hash_rocket_and_blocks(self):
        self.write("Gemfile", "gem 'rails', :git => 'https://example.invalid/rails.git'\n"
                              "git 'https://example.invalid/x.git' do\n  gem 'x'\nend\ngem 'ok', '~> 1.0'\n")
        locations = [f["location"] for f in self.deps.scan(self.root, False)["findings"]
                     if "outside rubygems" in f["title"]]
        self.assertEqual(locations, ["Gemfile:1", "Gemfile:2"])

    def test_gomod_replace_block(self):
        self.write("go.mod", "module x\n\nreplace (\n\texample.invalid/a => ../a\n"
                             "\texample.invalid/b => example.invalid/c v1.0.0\n)\n")
        locations = [f["location"] for f in self.deps.scan(self.root, False)["findings"] if "replaces" in f["title"]]
        self.assertEqual(locations, ["go.mod:4"])

    def test_composer_object_repositories_private_registry_and_unbounded(self):
        self.write("composer.json", {"repositories": {"priv": {"type": "vcs", "url": "https://example.invalid/r"},
                                                      "mirror": {"type": "composer", "url": "https://pkgs.invalid"}},
                                     "require": {"php": ">=8.1", "acme/open": ">=2.0", "acme/dev": "^1.0@dev",
                                                 "acme/ok": "^2.0", "phpunit/phpunit": ">=9 <10"}})
        titles = self.titles()
        self.assertTrue(any("type vcs" in t for t in titles))
        self.assertTrue(any("type composer" in t for t in titles))
        floats = sorted(t.split()[2] for t in titles if " floats " in t)
        self.assertEqual(floats, ["acme/dev", "acme/open"])

    def test_workflow_quoted_on_comment_uses_and_composite_actions(self):
        self.write(".github/workflows/a.yml", '"on": [push, pull_request_target]\njobs:\n  j:\n    steps:\n'
                                             '      # uses: evil/thing@main\n'
                                             '      - run: echo "uses: foo/bar@v1"\n')
        self.write("action.yml", "runs:\n  using: composite\n  steps:\n    - uses: evil/act@main\n")
        findings = self.deps.scan(self.root, False)["findings"]
        self.assertTrue(any("pull_request_target" in f["title"] for f in findings))
        unpinned = sorted(f["location"] for f in findings if f["title"].startswith("action "))
        self.assertEqual(unpinned, ["action.yml:4"])

    def test_dockerfile_stage_names_are_not_images(self):
        self.write("Dockerfile", "FROM golang:1.22 AS builder\nRUN true\nFROM builder AS test\nFROM debian\n")
        titles = self.titles()
        self.assertFalse(any("builder" in t for t in titles))
        self.assertTrue(any("debian" in t for t in titles))

    def test_tool_only_pyproject_needs_no_lockfile(self):
        self.write("pyproject.toml", "[tool.black]\nline-length = 100\n")
        self.assertFalse(self.titles())
        self.write("pyproject.toml", '[project]\nname = "x"\ndependencies = ["requests"]\n')
        self.assertIn("pyproject.toml has no lockfile", self.titles())

    def test_integrity_check_ignores_package_names(self):
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "node_modules/webpack-subresource-integrity": {"version": "1.0.0"}}})
        self.assertIn("package-lock.json has no integrity hashes", self.titles())

    def test_go_sum_is_covered_with_its_go_mod(self):
        mod, total = self.write("go.mod", "module x\n"), self.write("go.sum", "")
        c = self.deps.Collector(self.root)
        with patch.object(self.deps, "audit_osv", return_value={mod}):
            self.deps.audits(c, self.root, [mod, total])
        self.assertFalse(c.not_run)

    def test_locations_sort_numerically(self):
        self.write("requirements.txt", "".join(f"pkg{i}\n" for i in range(1, 12)))
        locations = [f["location"] for f in self.deps.scan(self.root, False)["findings"]]
        self.assertEqual(locations, [f"requirements.txt:{i}" for i in range(1, 12)])

    def test_into_preserves_code_finding_urls(self):
        report = self.write("findings.json", {"findings": [
            {"id": "F-001", "title": "Search injection", "request": "GET https://app.invalid/search?q=1%27--"}],
            "limitations": ["See https://app.invalid/page?id=7"]})
        new = {"id": "D-001", "title": "x https://u:SYNTHETIC@h.invalid/p?t=1", "location": "a"}
        self.deps.merge_into(report, {"findings": [new], "not_run": []})
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(data["findings"][0]["request"], "GET https://app.invalid/search?q=1%27--")
        self.assertEqual(data["limitations"], ["See https://app.invalid/page?id=7"])
        self.assertNotIn("SYNTHETIC", json.dumps(data))

    def test_vulnerable_lockfile_path_is_relative(self):
        lock = self.write("package-lock.json", {"lockfileVersion": 3, "packages": {}})
        c = self.deps.Collector(self.root)
        self.deps.vuln(c, "high", "left", "1.0.0", ["GHSA-0000-0000-0000"], "s", lock, "fixture")
        self.assertEqual(c.findings[0]["lockfile"], "package-lock.json")
        self.deps.triage(c, self.root)
        self.assertIn("validation", c.findings[0])


class DepsScanSecondReviewTests(unittest.TestCase):
    """Second-round regressions: audit parsing, workflow sinks and --into writes."""
    # Borrow the fixture helpers without re-running the first class's tests.
    setUpClass = DepsScanReviewTests.__dict__["setUpClass"]
    setUp = DepsScanReviewTests.setUp
    write = DepsScanReviewTests.write
    titles = DepsScanReviewTests.titles

    def osv(self, lock, vulnerabilities, groups, code=1):
        payload = {"results": [{"source": {"path": str(lock), "type": "lockfile"}, "packages": [
            {"package": {"name": "fixture", "version": "1.0", "ecosystem": "PyPI"},
             "vulnerabilities": vulnerabilities, "groups": groups}]}]}
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", return_value=(code, json.dumps(payload), "")):
            self.deps.audit_osv(c, self.root, [lock])
        return c

    def test_npm_user_and_global_config_are_different_files(self):
        lock = self.write("package-lock.json", {"lockfileVersion": 3, "packages": {}})
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/npm"), \
             patch.object(self.deps, "run", return_value=(0, '{"vulnerabilities": {}}', "")) as run:
            self.deps.audit_npm(c, self.root, lock)
        argv = run.call_args.args[0]
        user = next(a for a in argv if a.startswith("--userconfig="))
        globalconfig = next(a for a in argv if a.startswith("--globalconfig="))
        self.assertNotEqual(user.split("=", 1)[1], globalconfig.split("=", 1)[1])

    def test_prose_in_requirements_directory_is_not_a_requirements_file(self):
        self.write("requirements/README.txt", "Requirement files for this project.\n")
        self.write("requirements/base.txt", "django\n")
        locations = [f["location"] for f in self.deps.scan(self.root, False)["findings"]]
        self.assertEqual(locations, ["requirements/base.txt:1"])

    def test_legacy_poetry_and_uv_dev_dependencies_need_a_lockfile(self):
        for text in ("[tool.poetry]\nname='x'\n[tool.poetry.dev-dependencies]\npytest='*'\n",
                     "[tool.uv]\ndev-dependencies = ['pytest']\n"):
            with self.subTest(text=text):
                self.write("pyproject.toml", text)
                self.assertIn("pyproject.toml has no lockfile", self.titles())

    def test_setup_files_with_install_requires_are_inventoried(self):
        self.write("setup.cfg", "[flake8]\nmax-line-length = 100\n")
        self.assertFalse(self.titles())
        self.write("setup.py", "setup(install_requires=['django'])\n")
        self.assertIn("setup.py has no lockfile", self.titles())

    def test_tool_only_pyproject_is_not_an_unaudited_input(self):
        project = self.write("pyproject.toml", "[tool.black]\nline-length = 100\n")
        c = self.deps.Collector(self.root)
        with patch.object(self.deps, "audit_osv", return_value=set()):
            self.deps.audits(c, self.root, [project])
        self.assertFalse(c.not_run)

    def test_scoped_yarn_registry_and_platform_packages(self):
        self.write(".yarnrc.yml", 'npmScopes:\n  acme:\n    npmRegistryServer: "https://npm.acme.invalid"\n')
        self.write("composer.json", {"require": {"ext-json": "*", "php": ">=8.1", "lib-icu": ""}})
        titles = [t for t in self.titles() if "lockfile" not in t]
        self.assertEqual(titles, [".yarnrc.yml points a scope at \"https://npm.acme.invalid\""])

    def test_editable_bzr_and_flow_style_uses(self):
        self.write("requirements.txt", "-e bzr+https://example.invalid/pkg#egg=pkg\n")
        self.write(".github/workflows/a.yml", "jobs:\n  j:\n    steps:\n      - {uses: actions/cache@v3}\n")
        titles = self.titles()
        self.assertIn("Python dependency fetched from a URL (see source location)", titles)
        self.assertIn("action actions/cache@v3 is pinned to a mutable tag, not a commit SHA", titles)

    def workflow_findings(self, step):
        self.write(".github/workflows/a.yml", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                                             "    steps:\n" + step)
        return [f for f in self.deps.scan(self.root, False)["findings"] if f["title"].startswith("untrusted")]

    def test_github_script_and_single_quoted_runs_are_sinks(self):
        cases = {
            "github-script": "      - uses: actions/github-script@" + "0" * 40 + "\n        with:\n"
                             "          script: |\n            console.log('${{ github.event.issue.title }}')\n",
            "single-quoted": "      - run: 'echo ${{ format(''}} {0}'', github.event.issue.title) }}'\n",
            "author email": "      - run: echo ${{ github.event.head_commit.author.email }}\n",
            "workflow_run branch": "      - run: echo ${{ github.event.workflow_run.head_branch }}\n",
        }
        for name, step in cases.items():
            with self.subTest(name):
                self.assertEqual(len(self.workflow_findings(step)), 1)

    def test_malicious_alias_group_dedupe_and_git_fix_ranges(self):
        lock = self.write("poetry.lock", "")
        vulnerabilities = [
            {"id": "GHSA-0000-0000-0000", "summary": "s", "aliases": ["MAL-2025-1"],
             "affected": [{"package": {"name": "fixture"}, "ranges": [
                 {"type": "GIT", "events": [{"fixed": "0123456789abcdef0123456789abcdef01234567"}]},
                 {"type": "ECOSYSTEM", "events": [{"fixed": "1.2.4"}]}]}]},
            {"id": "PYSEC-2024-9", "summary": "s", "aliases": []}]
        groups = [{"ids": ["GHSA-0000-0000-0000", "PYSEC-2024-9"], "max_severity": "5.0"}]
        c = self.osv(lock, vulnerabilities, groups)
        self.assertEqual(len(c.findings), 1)
        finding = c.findings[0]
        self.assertTrue(finding["malicious"])
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["fix"], "Upgrade to 1.2.4")
        self.assertIn("PYSEC-2024-9", finding["advisory_ids"])

    def test_composer_audit_tolerates_null_dev_packages(self):
        lock = self.write("composer.lock", {"packages": [{"name": "acme/x", "version": "1.0"}], "packages-dev": None})
        advisories = {"advisories": {"acme/x": [{"advisoryId": "PKSA-1", "title": "t", "severity": "high"}]}}
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/composer"), \
             patch.object(self.deps, "run", return_value=(1, json.dumps(advisories), "")):
            self.deps.audit_composer(c, self.root, lock)
        self.assertEqual([f["version"] for f in c.findings], ["1.0"])

    def test_triage_needles_are_imports_and_other_ecosystems_are_unknown(self):
        self.write("app.js", "const level = 'debug';\n")
        self.write("app.py", "import jinja2\n")
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {}})
        self.write("requirements.txt", "jinja2==2.0\n")
        c = self.deps.Collector(self.root)
        self.deps.vuln(c, "high", "debug", "1.0", ["GHSA-1"], "s", self.root / "package-lock.json", "t")
        self.deps.vuln(c, "high", "jinja2", "2.0", ["PYSEC-1"], "s", self.root / "requirements.txt", "t")
        self.deps.triage(c, self.root)
        self.assertEqual([f["validation"]["referenced"] for f in c.findings], ["no", "unknown"])

    def test_lockfile_git_sources_and_pnpm_tarballs(self):
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {"node_modules/b": {
            "resolved": "git+ssh://git@github.com/owner/b.git#0123", "integrity": "sha512-x"}}})
        self.write("pnpm-lock.yaml", "packages:\n  x@1.0.0:\n    resolution: {tarball: https://pkgs.invalid/x.tgz}\n")
        titles = self.titles()
        self.assertIn("lockfile resolves a package from git or a local path, not a registry", titles)
        self.assertIn("lockfile resolves packages from non-default host pkgs.invalid", titles)

    def test_into_requires_the_file_and_respects_the_writer_lock(self):
        missing = self.root / "out" / "findings.json"
        with patch.object(sys, "stderr"), patch.object(sys, "stdout"):
            self.assertEqual(self.deps.main([str(self.root), "--into", str(missing)]), 2)
        report = self.write("findings.json", {"findings": []})
        lock = report.with_name(report.name + ".workflow.lock")
        lock.write_text("busy")
        with patch.object(sys, "stderr"), patch.object(sys, "stdout"):
            self.assertEqual(self.deps.main([str(self.root), "--into", str(report)]), 2)
        self.assertEqual(json.loads(report.read_text()), {"findings": []})
        lock.unlink()
        with patch.object(sys, "stderr"), patch.object(sys, "stdout"):
            self.assertEqual(self.deps.main([str(self.root), "--into", str(report)]), 0)
        self.assertIn("dependency_scan", json.loads(report.read_text()))


if __name__ == "__main__":
    unittest.main()
