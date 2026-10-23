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
            ("requirements.txt:4", path), ("requirements.txt:5", path), ("requirements.txt:6", path),
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

    def test_toml_dotted_keys_pipfile_file_and_poetry_constraint_arrays(self):
        (self.root / "dist").mkdir()
        self.write("Cargo.toml", "\n".join((
            '[package]', 'name = "app"', '',
            '[dependencies]',
            'evil.git = "https://github.com/attacker/evil"',
            'star.version = "*"',
            'outside.path = "../../elsewhere"',
            'tokio.workspace = true',
            'serde.version = "1"',
            'serde.features = ["derive"]',
            '"quoted".git = "https://example.com/q.git"',
            'field."git" = "https://example.com/f.git"', '')))
        self.write("Pipfile", "\n".join((
            '[packages]',
            'archive = {file = "https://example.com/archive/main.zip"}',
            'wheel = {file = "./dist/pkg.whl"}',
            'far = {file = "/opt/elsewhere/pkg.whl"}', '')))
        self.write("pyproject.toml", "\n".join((
            '[project]', 'name = "x"', '',
            '[tool.uv.sources]', 'foo.git = "https://github.com/a/foo"', '',
            '[tool.poetry.dependencies]',
            'multi = [',
            '  { version = "1.0", python = "<3.8" },',
            '  { git = "https://github.com/a/multi.git", python = ">=3.8" },',
            ']',
            'one = [{ version = "1.0", python = "<3.8" }, { version = "*", python = ">=3.8" }]',
            'after = "1.2"', '')))
        found = [f for f in self.findings() if "has no lockfile" not in f[1]]
        self.assertEqual(sorted(found), [
            ("Cargo.toml:11", "cargo dependency quoted is fetched outside the registry (git)"),
            ("Cargo.toml:12", "cargo dependency field is fetched outside the registry (git)"),
            ("Cargo.toml:5", "cargo dependency evil is fetched outside the registry (git)"),
            ("Cargo.toml:6", "cargo dependency star floats to any version (*)"),
            ("Cargo.toml:7", "cargo dependency outside is fetched outside the registry (path outside the checkout)"),
            ("Pipfile:2", "python dependency archive is fetched outside the registry (URL)"),
            ("Pipfile:4", "python dependency far is fetched outside the registry (path outside the checkout)"),
            ("pyproject.toml:10", "python dependency multi is fetched outside the registry (git)"),
            ("pyproject.toml:12", "python dependency one floats to any version (*)"),
            ("pyproject.toml:5", "python dependency foo is fetched outside the registry (git)")])

    def test_cargo_patch_and_replace_sources(self):
        (self.root / "vendor" / "inner").mkdir(parents=True)
        self.write("Cargo.toml", "\n".join((
            '[package]', 'name = "app"', '',
            '[patch.crates-io]',
            'serde = { git = "https://github.com/attacker/serde" }',
            'inner = { path = "vendor/inner" }', '',
            '[patch."https://github.com/rust-lang/crates.io-index"]',
            'log = { path = "../../outside/log" }', '',
            '[patch.crates-io.rand]', 'git = "https://example.com/rand.git"', '',
            '[replace]',
            '"libc:0.2.0" = { git = "https://github.com/attacker/libc" }', '')))
        found = [f for f in self.findings() if "has no lockfile" not in f[1]]
        self.assertEqual(sorted(found), [
            ("Cargo.toml:12", "cargo dependency rand is fetched outside the registry (git)"),
            ("Cargo.toml:15", "cargo dependency libc:0.2.0 is fetched outside the registry (git)"),
            ("Cargo.toml:5", "cargo dependency serde is fetched outside the registry (git)"),
            ("Cargo.toml:9", "cargo dependency log is fetched outside the registry (path outside the checkout)")])

    def test_piped_shell_forms_and_arg_defaults_in_dockerfiles(self):
        self.write("Dockerfile", "\n".join((
            "ARG BASE", "ARG NODE=node:20",
            "FROM ${BASE:-node} AS one", "FROM ${NODE} AS two", "FROM ${MISSING:-python:3.12}",
            "RUN curl -fsSL https://example.com/install.sh \\", "    # fetch the installer", "    | bash -",
            "RUN curl https://example.com/i | sudo -E bash", "RUN wget -qO- https://example.com/i | /bin/sh",
            "RUN apt-get install -y curl | tee log", "RUN echo hi | shasum", "")))
        piped = "remote script piped into a shell during build"
        self.assertEqual(sorted(self.findings()), [
            ("Dockerfile:10", piped), ("Dockerfile:3", "base image node is not pinned"),
            ("Dockerfile:8", piped), ("Dockerfile:9", piped)])

    def test_dockerfile_comment_ending_in_backslash_does_not_swallow_the_next_instruction(self):
        self.write("Dockerfile", "# a note \\\nFROM node\n")
        self.assertEqual(self.findings(), [("Dockerfile:2", "base image node is not pinned")])

    def test_multiline_gem_declarations(self):
        self.write("Gemfile", "\n".join((
            'source "https://rubygems.org"', '', 'gem "evil",', '    git: "https://github.com/attacker/evil",',
            '    branch: "main"', 'gem "other",', '  github: "attacker/other"', 'gem "rails",', '  "~> 7.1"',
            'gem "single", git: "https://github.com/attacker/single"', '')))
        self.write("Gemfile.lock", "")
        title = "gem fetched outside rubygems (see source location)"
        self.assertEqual(sorted(self.findings()), [("Gemfile:10", title), ("Gemfile:3", title), ("Gemfile:6", title)])

    def test_composer_floating_alternatives_and_stability_case(self):
        self.write("composer.lock", {"packages": []})
        self.write("composer.json", {"minimum-stability": "rc", "require": {
            "php": ">=8.1", "a/a": "*@beta", "b/b": "^1.0 || *", "c/c": "2.x-dev", "d/d": "^1.2@RC",
            "e/e": "1.0.*", "g/g": "^2.0|^3.0", "h/h": ">=1.0 <2.0"}})
        titles = [title for _, title in self.findings()]
        self.assertEqual(sorted(titles), [
            "composer dependency a/a floats (*@beta)", "composer dependency b/b floats (^1.0 || *)",
            "composer dependency c/c floats (2.x-dev)", "composer minimum-stability is rc without prefer-stable"])

    def test_package_source_spellings_and_plaintext_python_and_composer_sources(self):
        self.write("cfg/pip.conf", "[global]\nEXTRA_INDEX_URL = https://internal.example/simple\n"
                   "find_links: https://files.example/wheels\ntrusted_host = internal.example\n"
                   "index-url = https://pypi.org/simple\n")
        self.write("Pipfile", '[[source]]\nurl = "http://pypi.internal.example/simple"\nverify_ssl = false\n')
        self.write("Pipfile.lock", "{}")
        self.write("pyproject.toml", '[project.urls]\nHomepage = "http://example.com"\n'
                   '[[tool.poetry.source]]\nname = "x"\nurl = "http://pypi.internal.example/simple"\n')
        self.write("poetry.lock", "")
        self.write("composer.json", {"homepage": "http://example.com", "config": {"secure-http": False,
                                                                               "disable-tls": True},
                                     "repositories": [{"type": "composer", "url": "http://packages.example.com"}]})
        self.write("composer.lock", {"packages": []})
        found = [f for f in self.findings() if "composer repository of type" not in f[1]]
        self.assertEqual(sorted(found), [
            ("Pipfile:2", "Pipfile fetches code over plaintext http://"),
            ("Pipfile:3", "Pipfile disables TLS verification for a package source"),
            ("cfg/pip.conf:2", "pip config adds a second index beside PyPI"),
            ("cfg/pip.conf:3", "pip --find-links adds a package source beside the index"),
            ("cfg/pip.conf:4", "pip.conf disables TLS verification for a package source"),
            ("composer.json:1", "composer.json allows package downloads over plaintext http:// (secure-http: false)"),
            ("composer.json:1", "composer.json disables TLS verification for a package source"),
            ("composer.json:1", "composer.json fetches code over plaintext http://"),
            ("pyproject.toml:5", "pyproject.toml fetches code over plaintext http://")])

    def test_npm_aliases_dist_tags_and_bare_outside_paths(self):
        (self.root / "libs" / "inside").mkdir(parents=True)
        self.write("app/package-lock.json", {"lockfileVersion": 3, "packages": {}})
        self.write("app/package.json", {"dependencies": {
            "a": "npm:lodash@*", "b": "npm:lodash", "c": "npm:@scope/x@latest", "d": "next",
            "e": "../../outside/lib", "f": "/opt/shared/lib", "g": "~/lib", "h": "portal:/opt/x",
            "ok1": "npm:lodash@^4.17.21", "ok2": "v1.2.3", "ok3": "1.x", "ok4": "../libs/inside",
            "ok5": "workspace:*", "ok6": "^1.0.0", "ok7": "file:../libs/inside", "ok8": "portal:../libs/inside"}})
        titles = sorted(title for _, title in self.findings() if "integrity" not in title)
        self.assertEqual(titles, [
            "npm dependency a floats to any version (npm:lodash@*)",
            "npm dependency b floats to any version (npm:lodash)",
            "npm dependency c floats to any version (npm:@scope/x@latest)",
            "npm dependency d floats to any version (next)",
            "npm dependency e is fetched outside the registry (../../outside/lib)",
            "npm dependency f is fetched outside the registry (/opt/shared/lib)",
            "npm dependency g is fetched outside the registry (~/lib)",
            "npm dependency h is fetched outside the registry (portal:/opt/x)"])

    def test_docker_container_action_image(self):
        self.write("a/action.yml", "name: x\nruns:\n  using: docker\n  image: docker://alpine:3.19\n")
        self.write("b/action.yml", "name: y\nruns:\n  using: docker\n  image: Dockerfile\n")
        self.write("c/action.yaml", "name: z\nruns:\n  using: docker\n  image: 'docker://alpine@sha256:%s'\n" % ("0" * 64))
        self.assertEqual(self.findings(), [("a/action.yml:4", "workflow container image alpine:3.19 is not pinned to a digest")])

    def test_file_urls_inside_the_checkout_are_first_party(self):
        (self.root / "libs" / "foo").mkdir(parents=True)
        self.write("requirements.txt", "-e file:.\n-e file:./libs/foo#egg=foo\nfile:./libs/foo\n"
                   "file:///opt/src/x\n-e file:../outside\npkg @ file:///${PROJECT_ROOT}/libs/foo\n")
        self.write("pyproject.toml", '[project]\ndependencies = ["sub @ file:///${PROJECT_ROOT}/libs/foo", '
                   '"o @ file:///opt/o", "u @ https://example.com/u.whl"]\n')
        self.write("pdm.lock", "")
        path = "Python dependency installed from a path outside the checkout (see source location)"
        self.assertEqual(sorted(self.findings()), [
            ("pyproject.toml:2", "python dependency o is fetched outside the registry (path outside the checkout)"),
            ("pyproject.toml:2", "python dependency u is fetched outside the registry (URL)"),
            ("requirements.txt:4", path), ("requirements.txt:5", path)])

    def test_dockerfile_escape_directive_and_physical_pipe_line(self):
        self.write("Dockerfile", "\n".join((
            "# escape=`", "FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS build", "COPY t c:\\",
            "RUN dir c:\\", "RUN curl https://example.com/i `", "  | sh", "FROM mcr.microsoft.com/dotnet/runtime", "")))
        self.write("linux/Dockerfile", "\n".join((
            "FROM debian:12", "RUN apt-get update \\", " && apt-get install -y curl \\",
            " && curl -fsSL https://get.example.com | sh", "")))
        piped = "remote script piped into a shell during build"
        self.assertEqual(sorted(self.findings()), [
            ("Dockerfile:6", piped), ("Dockerfile:7", "base image mcr.microsoft.com/dotnet/runtime is not pinned"),
            ("linux/Dockerfile:4", piped)])

    def test_plaintext_urls_count_only_in_package_source_tables(self):
        self.write("pyproject.toml", "\n".join((
            "[tool.semantic_release.remote]", 'url = "http://git.example.com/org/repo.git"',
            "[project.urls]", 'url = "http://example.com"',
            "[[tool.poetry.source]]", 'name = "x"', 'url = "http://pypi.internal.example/simple"',
            "[[ tool.uv.index ]]", 'url = "http://index.example/simple"', "")))
        self.write("poetry.lock", "")
        self.assertEqual(sorted(self.findings()), [
            ("pyproject.toml:7", "pyproject.toml fetches code over plaintext http://"),
            ("pyproject.toml:9", "pyproject.toml fetches code over plaintext http://")])

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
