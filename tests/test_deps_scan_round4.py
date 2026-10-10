"""Round-4 regressions for deps_scan.py: trigger parsing, traversal, source configs and false positives."""
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
    spec = importlib.util.spec_from_file_location("round4_" + name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


SHA = "0" * 40
CHECKOUT = "      - uses: actions/checkout@" + SHA + "\n"


class DepsScanRound4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deps = load_script("deps_scan")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-deps-r4-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path

    def scan(self):
        return self.deps.scan(self.root, False)

    def found(self):
        return [(f["severity"], f["location"], f["title"]) for f in self.scan()["findings"]]

    def titles(self, needle=""):
        return [t for _, _, t in self.found() if needle in t]

    def reasons(self):
        return [n["reason"] for n in self.scan()["not_run"]]

    def workflow(self, body, name="w.yml"):
        return self.write(".github/workflows/" + name, body)

    # ---- security ----

    def test_escaped_trigger_name_is_privileged_and_incomplete(self):
        self.workflow('on:\n  "pull_request\\x5ftarget":\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
                      + CHECKOUT + "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")
        result = self.scan()
        self.assertTrue(any(f["severity"] == "High" for f in result["findings"]), result["findings"])
        self.assertTrue(any("escaped trigger names require manual review" in n["reason"] for n in result["not_run"]))

    def test_control_characters_in_paths_render(self):
        render = load_script("render")
        self.write("a\nb/package.json", {"dependencies": {"left": "1.0.0"}})
        findings = self.scan()["findings"]
        self.assertTrue(findings)
        self.assertTrue(all("\n" not in f["location"] and "\n" not in f["title"] for f in findings))
        report = self.root.parent / (self.root.name + "-report.json")
        self.addCleanup(lambda: report.unlink() if report.exists() else None)
        report.write_text(json.dumps({"meta": {"project": "p", "date": "2026-01-01"}, "findings": findings}),
                          encoding="utf-8")
        self.assertEqual(len(render.load(report)["findings"]), len(findings))

    def test_oversized_file_is_not_read_and_is_named(self):
        self.write("requirements.txt", "left\n" * 100)
        with patch.object(self.deps, "MAX_READ", 64, create=True):
            result = self.scan()
        self.assertFalse(result["findings"])
        self.assertTrue(any(n["reason"].startswith("requirements.txt:") and "not read" in n["reason"]
                            for n in result["not_run"]), result["not_run"])

    def test_pruned_directory_with_manifest_is_named(self):
        self.write("build/package.json", {"dependencies": {"left": "*"}})
        self.write("dist/readme.txt", "x")
        reasons = [r for r in self.reasons() if "skipped directory" in r]
        self.assertEqual(len(reasons), 1)
        self.assertTrue(reasons[0].startswith("build:") and "package.json" in reasons[0])

    # ---- regressions from the last PR ----

    def test_compose_named_workflow_is_checked_as_workflow(self):
        for name in ("docker-compose.yml", "compose.yml", "compose-test.yml"):
            with self.subTest(name=name):
                self.workflow("on: push\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n", name)
                self.assertTrue(any(name in loc and "mutable tag" in t for _, loc, t in self.found()))

    def test_github_script_gating_after_with_and_case_insensitive(self):
        for step in ("      - with:\n          script: console.log('${{ github.event.issue.title }}')\n"
                     "        uses: actions/github-script@v7\n",
                     "      - uses: Actions/GitHub-Script@v7\n        with:\n"
                     "          script: console.log('${{ github.event.issue.title }}')\n"):
            with self.subTest(step=step):
                self.workflow("on: issues\njobs:\n  j:\n    steps:\n" + step)
                self.assertTrue(self.titles("untrusted event text"))

    def test_composite_actions_outside_github_are_followed(self):
        self.workflow("on: pull_request_target\njobs:\n  j:\n    steps:\n      - uses: ./actions/one\n")
        self.write("actions/one/action.yml", "runs:\n  using: composite\n  steps:\n    - uses: ./actions/two\n")
        self.write("actions/two/action.yml", "runs:\n  using: composite\n  steps:\n"
                   "    - uses: actions/checkout@" + SHA + "\n      with:\n"
                   "        ref: ${{ github.event.pull_request.head.sha }}\n")
        self.assertTrue(any(s == "High" and loc.startswith("actions/two/") for s, loc, _ in self.found()))

    def test_more_untrusted_refs_and_with_before_uses(self):
        refs = ("refs/pull/${{ github.event.pull_request.number }}/merge", "refs/pull/${{ github.event.number }}/head",
                "${{ github.event.pull_request.merge_commit_sha }}")
        for ref in refs:
            with self.subTest(ref=ref):
                self.workflow("on: pull_request_target\njobs:\n  j:\n    steps:\n" + CHECKOUT
                              + "        with:\n          ref: " + ref + "\n")
                self.assertTrue(any(s == "High" for s, _, _ in self.found()))
        self.workflow("on: pull_request_target\njobs:\n  j:\n    steps:\n      - with:\n"
                      "          ref: ${{ github.event.pull_request.head.sha }}\n"
                      "        uses: actions/checkout@" + SHA + "\n")
        self.assertIn(("High", ".github/workflows/w.yml:6", "pull_request_target workflow checks out the pull request's code"),
                      self.found())

    def test_multiline_flow_triggers(self):
        for on in ("on: [push,\n  pull_request_target]\n", "on: {push: {},\n  pull_request_target: {}}\n"):
            with self.subTest(on=on):
                self.workflow(on + "jobs:\n  j:\n    steps:\n" + CHECKOUT)
                self.assertTrue(self.titles("triggers on pull_request_target"))

    def test_gradle_metadata_urls_apply_from_and_lone_tls_off(self):
        self.write("build.gradle", "publishing {\n  publications {\n    maven(MavenPublication) {\n"
                   "      pom {\n        url = 'http://docs.example/'\n        licenses {\n          license {\n"
                   "            url = 'http://license.example/'\n          }\n        }\n      }\n    }\n  }\n}\n"
                   "apply from: 'http://scripts.example/x.gradle'\n"
                   "repositories {\n  maven {\n    url 'http://repo.example/'\n  }\n}\n")
        self.write("settings.gradle", "allowInsecureProtocol = true\n")
        found = sorted(loc for s, loc, _ in self.found() if s == "Medium")
        self.assertEqual(found, ["build.gradle:15", "build.gradle:18", "settings.gradle:1"])

    def test_nuget_comments_scope_and_mapping_patterns(self):
        sources = ('<packageSources>\n<add key="a" value="https://a.example/v3" />\n'
                   '<add key="b" value="https://api.nuget.org/v3/index.json" />\n</packageSources>\n')
        cases = {
            "<!-- <packageSourceMapping> -->\n": True,
            "<packageSourceMapping>\n<packageSource key=\"a\"><package pattern=\"*\" /></packageSource>\n"
            "<packageSource key=\"b\"><package pattern=\"*\" /></packageSource>\n</packageSourceMapping>\n": True,
            "<packageSourceMapping>\n<packageSource key=\"a\"><package pattern=\"Contoso.*\" /></packageSource>\n"
            "<packageSource key=\"b\"><package pattern=\"*\" /></packageSource>\n</packageSourceMapping>\n": False,
        }
        title = "nuget.config mixes several package sources without packageSourceMapping"
        for extra, flagged in cases.items():
            with self.subTest(extra=extra):
                self.write("nuget.config", "<configuration>\n" + sources + extra + "</configuration>\n")
                self.assertEqual(title in self.titles(), flagged)
        self.write("nuget.config", '<configuration>\n<!--\n<packageSources><add key="x" value="https://x" />\n-->\n'
                   '<packageSources>\n<add key="a" value="https://a.example/v3" />\n</packageSources>\n'
                   '<config><add key="globalPackagesFolder" value="p" /></config>\n</configuration>\n')
        self.assertNotIn(title, self.titles())

    def test_pom_multiline_comments_keep_line_numbers(self):
        self.write("pom.xml", "<project>\n<!--\n  <repositories><repository>\n    <url>http://old.example/</url>\n"
                   "  </repository></repositories>\n-->\n<repositories>\n  <repository>\n"
                   "    <url>http://nexus.example/</url>\n  </repository>\n</repositories>\n</project>\n")
        self.assertEqual([loc for s, loc, _ in self.found() if s == "Medium"], ["pom.xml:9"])

    def test_npmrc_proxy_keys_are_not_sources(self):
        self.write(".npmrc", "proxy=http://proxy.example:8080\nhttps-proxy=http://proxy.example:8080\n"
                   "http_proxy=http://p.example\nregistry=http://registry.example/\n")
        self.write(".yarnrc.yml", "httpProxy: http://proxy.example:8080\n")
        self.assertEqual([loc for s, loc, _ in self.found() if s == "Medium"], [".npmrc:4"])

    def test_gemfile_inline_comments(self):
        self.write("Gemfile.lock", "GEM\n")
        self.write("Gemfile", 'source "https://rubygems.org"\ngem "rails" # see http://rubyonrails.org\n'
                   'gem "x", "1.0" # path: "../x"\ngem "y", git: "git://example.invalid/y.git"\n')
        self.assertEqual(sorted(loc for s, loc, _ in self.found() if s == "Medium"), ["Gemfile:4", "Gemfile:4"])

    def test_compose_image_forms(self):
        self.write("compose.yml", "x-db: &db\n  image: shared:latest\nservices:\n  pg:\n    image: &pg postgres\n"
                   "  alias:\n    image: *pg\n  folded:\n    image: >-\n      nginx\n  app:\n    build: .\n"
                   "    image: myapp\n  env:\n    image: redis:7\n    environment:\n      image: notanimage\n"
                   "    labels:\n      image: nolabel\n")
        self.assertEqual(self.titles("compose image"), ["compose image postgres is not pinned"])

    def test_dockerfile_arg_scope_after_first_from(self):
        self.write("Dockerfile", "ARG BASE=node\nFROM alpine:3.19\nARG BASE=ubuntu:22.04\nFROM ${BASE}\n")
        self.assertEqual(self.titles("base image"), ["base image node is not pinned"])

    def test_requirements_extra_index_tls_local_index_and_yarnrc(self):
        self.write("requirements.txt", "--extra-index-url http://pkgs.example/simple\n-i http://localhost:8080/simple\n")
        self.write(".yarnrc", "strict-ssl false\n")
        found = self.found()
        self.assertIn(("Medium", "requirements.txt:1", "pip --extra-index-url mixes a second index with PyPI"), found)
        self.assertIn(("Medium", "requirements.txt:1",
                       "pip installs from a source without TLS verification (see source location)"), found)
        self.assertFalse([f for f in found if f[1] == "requirements.txt:2" and f[0] != "Info"])
        self.assertIn(("Medium", ".yarnrc:1", ".yarnrc disables TLS verification for a package source"), found)

    # ---- real-repository false positives ----

    def test_package_json_without_dependencies_needs_no_lockfile(self):
        self.write("a/package.json", {"name": "a", "scripts": {"x": "y"}, "peerDependencies": {"r": "^1"}})
        self.write("b/package.json", {"devDependencies": {"left": "1.0.0"}})
        self.assertEqual([loc for _, loc, t in self.found() if "no lockfile" in t], ["b/package.json"])

    def test_pnpm_block_workspace_membership(self):
        self.write("package.json", {"dependencies": {"left": "1.0.0"}})
        self.write("pnpm-lock.yaml", "lockfileVersion: 9.0\n")
        self.write("pnpm-workspace.yaml", "catalog:\n  x: 1\npackages:\n  # comment\n  - 'packages/*'\n"
                   "  - \"apps/**\"\n  - '!apps/legacy/**'\n")
        dep = {"dependencies": {"left": "1.0.0"}}
        for name in ("packages/a", "apps/x/y", "apps/legacy/z", "tools/t"):
            self.write(name + "/package.json", dep)
        result = self.scan()
        missing = sorted(f["location"] for f in result["findings"] if "no lockfile" in f["title"])
        self.assertEqual(missing, ["apps/legacy/z/package.json", "tools/t/package.json"])
        self.assertFalse([n for n in result["not_run"] if n["tool"] == "workspace discovery"])

    def test_npm_relative_local_specs_are_first_party(self):
        self.write("package.json", {"dependencies": {
            "a": "file:./a", "b": "link:../b", "c": "./c", "d": "file:d", "e": "file:/abs/e", "f": "owner/repo"}})
        flagged = sorted(t.split()[2] for t in self.titles("fetched outside the registry"))
        self.assertEqual(flagged, ["e", "f"])

    def test_dollar_slash_local_action(self):
        self.workflow("on: push\njobs:\n  j:\n    steps:\n      - uses: $/.github/actions/setup\n")
        self.assertFalse(self.titles("has no version"))

    def test_download_artifact_requires_run_id(self):
        head = "on: workflow_run\njobs:\n  j:\n    steps:\n"
        cases = ((head + "      - uses: actions/download-artifact@" + SHA + "\n        with:\n          name: x\n", False),
                 (head + "      - uses: actions/download-artifact@" + SHA + "\n        with:\n"
                  "          run-id: ${{ github.event.workflow_run.id }}\n", True),
                 (head + "      - uses: dawidd6/action-download-artifact@" + SHA + "\n", True))
        for body, flagged in cases:
            with self.subTest(body=body):
                self.workflow(body)
                self.assertEqual(bool(self.titles("downloads artifacts")), flagged)

    def test_peer_dependency_ranges_do_not_float(self):
        self.write("package.json", {"peerDependencies": {"react": ">=16"}, "dependencies": {"x": ">=1"}})
        self.assertEqual(self.titles("floats"), ["npm dependency x floats to any version (>=1)"])

    def test_gemfile_path_only_outside_checkout(self):
        self.write("Gemfile.lock", "GEM\n")
        self.write("Gemfile", 'gem "a", path: "tools/a"\ngem "b", path: "../b"\ngem "c", :path => "/opt/c"\n'
                   'path "engines" do\nend\n')
        self.assertEqual(sorted(loc for _, loc, t in self.found() if "outside rubygems" in t), ["Gemfile:2", "Gemfile:3"])

    def test_inside_symlink_to_non_input_is_quiet(self):
        real = self.write("docs/README.md", "x")
        (self.root / "README.md").symlink_to(real)
        (self.root / "requirements.txt").symlink_to(real)
        (self.root / "outside.md").symlink_to(self.root.parent)
        reasons = [r for r in self.reasons() if "skipped symlink" in r]
        self.assertEqual(sorted(r.split(":")[0] for r in reasons), ["outside.md", "requirements.txt"])

    def test_workflow_container_images(self):
        self.workflow("on: push\njobs:\n  a:\n    container: node:20\n    services:\n      db:\n"
                      "        image: postgres@sha256:" + "a" * 64 + "\n      cache:\n        image: redis\n"
                      "    steps:\n      - uses: docker://alpine:latest\n  b:\n    container:\n"
                      "      image: ${{ matrix.image }}\n  c:\n    container:\n      image: ubuntu:24.04\n")
        self.assertEqual(sorted(loc for _, loc, t in self.found() if "container image" in t),
                         [".github/workflows/w.yml:11", ".github/workflows/w.yml:17", ".github/workflows/w.yml:4",
                          ".github/workflows/w.yml:9"])

    def test_workflow_run_trigger_line_skips_comments(self):
        self.workflow("# runs after workflow_run of CI\non:\n  # workflow_run below\n  workflow_run:\n"
                      "    workflows: [CI]\njobs: {}\n")
        self.assertIn(("Medium", ".github/workflows/w.yml:4", "workflow triggers on workflow_run"), self.found())

    def test_scalar_event_paths_are_resolved(self):
        for expression in ("github.event.after", "github.event.before", "github.event.workflow_run.id",
                           "github.event.workflow_run.head_sha", "github.event.pull_request.head.sha",
                           "github.event.pull_request.base.sha", "github.event.pull_request.head.repo.fork",
                           "github.event.pull_request.number", "github.run_attempt"):
            with self.subTest(expression=expression):
                self.workflow("on: push\njobs:\n  j:\n    steps:\n      - run: echo ${{ " + expression + " }}\n")
                self.assertFalse([r for r in self.reasons() if "unresolved github event" in r])
        self.workflow("on: push\njobs:\n  j:\n    steps:\n      - run: echo ${{ github.event.ref }}\n")
        self.assertTrue([r for r in self.reasons() if "unresolved github event" in r])

    def test_double_quoted_escapes_only_when_they_can_hide_text(self):
        for run, expected in (('"printf \'a\\tb\\n\' \\"${{ github.sha }}\\""', False),
                              ('"echo \\x24{{ github.event.issue.title }}"', True),
                              ('"echo ${{ github.sha }} \\\n  done"', True)):
            with self.subTest(run=run):
                self.workflow("on: push\njobs:\n  j:\n    steps:\n      - run: " + run + "\n")
                self.assertEqual(any("double-quoted run escapes" in r for r in self.reasons()), expected)

    def test_shell_checkout_of_pr_head_in_privileged_workflow(self):
        steps = ("      - run: gh pr checkout ${{ github.event.pull_request.number }}\n",
                 "      - env:\n          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}\n"
                 "        run: |\n          git fetch origin \"${HEAD_SHA}\"\n          git checkout FETCH_HEAD\n",
                 "      - run: git fetch origin pull/${{ github.event.pull_request.number }}/head:pr\n")
        for step in steps:
            with self.subTest(step=step):
                self.workflow("on: [pull_request_target, workflow_run]\njobs:\n  j:\n    steps:\n" + step)
                self.assertTrue(any(s == "High" and "in a run step" in t for s, _, t in self.found()))
        self.workflow("on: pull_request_target\njobs:\n  j:\n    steps:\n      - run: git checkout main\n")
        self.assertFalse([f for f in self.found() if f[0] == "High"])
        self.workflow("on: pull_request\njobs:\n  j:\n    steps:\n      - run: gh pr checkout 1\n")
        self.assertFalse([f for f in self.found() if f[0] == "High"])

    def test_pwn_request_confirmed_when_later_step_runs_checkout(self):
        head = ("on: pull_request_target\njobs:\n  j:\n    steps:\n" + CHECKOUT
                + "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")
        for later, confidence in (("      - run: npm ci && npm test\n", "Confirmed"),
                                  ("      - run: echo done\n", "Suspected")):
            with self.subTest(later=later):
                self.workflow(head + later)
                findings = self.scan()["findings"]
                high = [f for f in findings if f["severity"] == "High"]
                self.assertEqual([f["confidence"] for f in high], [confidence])
                self.assertFalse([f for f in findings if "triggers on pull_request_target" in f["title"]])
        self.workflow(head + "  other:\n    steps:\n      - run: make\n")
        self.assertEqual([f["confidence"] for f in self.scan()["findings"] if f["severity"] == "High"], ["Suspected"])

    def test_not_audited_limitation_counts_pinned_packages(self):
        self.write("requirements.txt", "a==1.0\nb==2.0\nc>=1\n")
        self.write("Cargo.lock", "[[package]]\nname = \"x\"\n\n[[package]]\nname = \"y\"\n")
        reason = next(n["reason"] for n in self.scan()["not_run"] if n["tool"] == "vulnerability audit")
        self.assertTrue(reason.startswith("not requested (--audit)"))
        self.assertIn("advisories not matched for 4 pinned packages", reason)


if __name__ == "__main__":
    unittest.main()
