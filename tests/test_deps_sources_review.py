"""deps_scan.py: dependency sources the documented checks cover but earlier parsers missed."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location("sources_" + name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


BERRY_HEADER = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"


class DepsSourcesReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deps = load_script("deps_scan")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-deps-sources-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve() / "repo"
        self.root.mkdir()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def findings(self):
        return [(f["location"], f["title"]) for f in self.deps.scan(self.root, False)["findings"]]

    def test_yarn_berry_git_and_url_resolutions_are_flagged(self):
        self.write("yarn.lock", BERRY_HEADER + "\n".join((
            '"evil@git+https://github.com/attacker/evil.git#main":',
            '  version: 1.0.0',
            '  resolution: "evil@https://github.com/attacker/evil.git#commit=0123456789abcdef"',
            '',
            '"left-pad@https://attacker.example/left-pad-1.3.0.tgz":',
            '  resolution: "left-pad@https://attacker.example/left-pad-1.3.0.tgz"',
            '',
            '"@scope/ssh@git+ssh://git@example.com/o/r.git":',
            '  resolution: "@scope/ssh@git+ssh://git@example.com/o/r.git#commit=abc"',
            '')))
        found = self.findings()
        self.assertIn(("yarn.lock:7", "lockfile resolves a package from git or a local path, not a registry"), found)
        self.assertIn(("yarn.lock:10", "lockfile resolves packages from non-default host attacker.example"), found)
        self.assertFalse(any("github.com" in title for _, title in found), found)

    def test_yarn_berry_registry_workspace_and_patch_resolutions_stay_clean(self):
        self.write("yarn.lock", BERRY_HEADER + "\n".join((
            '"lodash@npm:^4.17.21":',
            '  resolution: "lodash@npm:4.17.21"',
            '"@babel/core@npm:^7.0.0":',
            '  resolution: "@babel/core@npm:7.24.0"',
            '"app@workspace:.":',
            '  resolution: "app@workspace:."',
            '"resolve@patch:resolve@npm%3A^1.22.1#~builtin<compat/resolve>":',
            '  resolution: "resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8"',
            '')))
        self.assertEqual(self.findings(), [])

    def test_npm_shrinkwrap_without_integrity_is_flagged(self):
        self.write("npm-shrinkwrap.json", {"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1.0.0"}}})
        self.assertIn(("npm-shrinkwrap.json", "npm-shrinkwrap.json has no integrity hashes"), self.findings())

    def test_requirements_direct_references_and_outside_paths(self):
        (self.root / "libs" / "inside").mkdir(parents=True)
        self.write("requirements.txt", "\n".join((
            "evil@https://attacker.example/evil-1.0.tar.gz --hash=sha256:" + "a" * 64,
            "other[extra]@https://attacker.example/other.tar.gz",
            "spaced @ git+https://example.com/o/r",
            "file:///opt/src/evil",
            "../outside-lib",
            "/opt/wheels/evil-1.0-py3-none-any.whl",
            "-e ../outside-editable",
            "./libs/inside",
            "-e .[dev]",
            "-e libs/inside",
            "pinned==1.0 --hash=sha256:" + "b" * 64,
            "")))
        url = "Python dependency fetched from a URL (see source location)"
        path = "Python dependency installed from a path outside the checkout (see source location)"
        self.assertEqual(sorted(self.findings()), [
            ("requirements.txt:1", url), ("requirements.txt:2", url), ("requirements.txt:3", url),
            ("requirements.txt:4", url), ("requirements.txt:5", path), ("requirements.txt:6", path),
            ("requirements.txt:7", path)])

    def test_cargo_manifest_and_lock_sources(self):
        (self.root / "crates" / "inner").mkdir(parents=True)
        self.write("Cargo.toml", "\n".join((
            '[package]', 'name = "app"', 'authors = ["A <a@b.example>"]', '',
            '[dependencies]',
            'serde = { version = "1", features = ["derive"] }  # bounded',
            'star = "*"',
            'evil = { git = "https://github.com/attacker/evil", branch = "main" }',
            'inner = { path = "crates/inner" }',
            'outside = { path = "../outside" }',
            'shared = { workspace = true }', '',
            '[dependencies.sub]', 'git = "https://example.com/sub.git"', '',
            "[target.'cfg(unix)'.dependencies]", 'nix = { version = "*" }', '',
            '[dev-dependencies.ok]', 'version = "1.2"', '')))
        self.write("Cargo.lock", "\n".join((
            '[[package]]', 'name = "serde"', 'source = "registry+https://github.com/rust-lang/crates.io-index"',
            '[[package]]', 'name = "evil"', 'source = "git+https://github.com/attacker/evil?branch=main#abc"',
            '[[package]]', 'name = "x"', 'source = "sparse+https://registry.example/index/"', '')))
        self.assertEqual(sorted(self.findings()), [
            ("Cargo.lock:6", "lockfile resolves a package from git or a local path, not a registry"),
            ("Cargo.lock:9", "lockfile resolves packages from non-default host registry.example"),
            ("Cargo.toml:10", "cargo dependency outside is fetched outside the registry (path outside the checkout)"),
            ("Cargo.toml:14", "cargo dependency sub is fetched outside the registry (git)"),
            ("Cargo.toml:17", "cargo dependency nix floats to any version (*)"),
            ("Cargo.toml:7", "cargo dependency star floats to any version (*)"),
            ("Cargo.toml:8", "cargo dependency evil is fetched outside the registry (git)")])

    def test_python_manifest_sources(self):
        (self.root / "libs" / "inside").mkdir(parents=True)
        self.write("pyproject.toml", "\n".join((
            '[project]', 'name = "x"', 'authors = [{name = "A", email = "a@b.example"}]',
            'dependencies = [', '  "requests>=2",', '  "evil @ git+https://github.com/attacker/evil",', ']',
            '[project.optional-dependencies]', 'dev = ["tool@ https://example.com/tool.whl"]',
            '[project.urls]', 'home = "https://example.com"', '',
            '[tool.poetry.dependencies]', 'python = "*"', 'flask = "*"',
            'lib = { git = "https://github.com/x/lib.git" }', '',
            '[tool.uv.sources]', 'other = { path = "../../outside" }', 'local = { path = "libs/inside" }', '')))
        self.write("Pipfile", "\n".join((
            '[[source]]', 'url = "https://pypi.org/simple"', '[packages]', 'requests = "*"',
            'evil = {git = "https://github.com/attacker/evil.git", ref = "main"}',
            '"quoted" = {path = "./libs/inside"}', '')))
        found = [f for f in self.findings() if "has no lockfile" not in f[1]]
        self.assertEqual(sorted(found), [
            ("Pipfile:5", "python dependency evil is fetched outside the registry (git)"),
            ("pyproject.toml:15", "python dependency flask floats to any version (*)"),
            ("pyproject.toml:16", "python dependency lib is fetched outside the registry (git)"),
            ("pyproject.toml:19", "python dependency other is fetched outside the registry (path outside the checkout)"),
            ("pyproject.toml:6", "python dependency evil is fetched outside the registry (URL)"),
            ("pyproject.toml:9", "python dependency tool is fetched outside the registry (URL)")])

    def test_composer_lock_inventory_keeps_only_version_values(self):
        nested = {}
        for _ in range(900):  # deep enough to overflow safe_output on Python < 3.12
            nested = {"a": nested}
        self.write("composer.lock", {
            "packages": [{"name": "laravel/framework", "version": {"x": nested}}],
            "platform": {"php": "^8.1", "ext-json": "*", "deep": nested, "flag": True}})
        result = self.deps.scan(self.root, False)
        inventory = next(x for x in result["inventory"] if x.get("ecosystem") == "composer")
        self.assertEqual(inventory["platform"], {"php": "^8.1", "ext-json": "*"})
        self.assertEqual(inventory["notable"], {"laravel/framework": None})


if __name__ == "__main__":
    unittest.main()
