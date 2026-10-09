"""Third-round deps_scan checks: privileged workflows, plaintext sources, images."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_deps_scan_review import DepsScanReviewTests


class SupplyChainReviewTests(unittest.TestCase):
    # Borrow the fixture helpers without re-running the borrowed class's tests.
    setUpClass = DepsScanReviewTests.__dict__["setUpClass"]
    setUp = DepsScanReviewTests.setUp
    write = DepsScanReviewTests.write

    def findings(self):
        return [(f["severity"], f["location"], f["title"]) for f in self.deps.scan(self.root, False)["findings"]]

    def test_pwn_request_checkout_artifacts_and_runners(self):
        sha = "0" * 40
        self.write(".github/workflows/prt.yml",
                   "on:\n  pull_request_target:\n    types: [opened]\npermissions: write-all\njobs:\n  build:\n"
                   "    runs-on: self-hosted\n    steps:\n      - uses: actions/checkout@" + sha + "\n        with:\n"
                   "          ref: ${{ github.event.pull_request.head.sha }}\n  call:\n"
                   "    uses: ./.github/workflows/reuse.yml\n")
        self.write(".github/workflows/reuse.yml",
                   "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - uses: actions/checkout@" + sha + "\n        with:\n          ref: ${{ github.head_ref }}\n")
        self.write(".github/workflows/wr.yml",
                   "on:\n  workflow_run:\n    workflows: [CI]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - uses: actions/download-artifact@" + sha + "\n")
        self.write(".github/workflows/safe.yml",
                   "on: pull_request\njobs:\n  j:\n    runs-on: [self-hosted]\n    steps:\n"
                   "      - uses: actions/checkout@" + sha + "\n        with:\n"
                   "          ref: ${{ github.event.pull_request.head.sha }}\n")
        found = self.findings()
        self.assertIn(("High", ".github/workflows/prt.yml:11", "pull_request_target workflow checks out the pull request's code"), found)
        self.assertIn(("High", ".github/workflows/reuse.yml:8", "pull_request_target workflow checks out the pull request's code"), found)
        self.assertIn(("Medium", ".github/workflows/prt.yml:7", "pull_request_target job runs on a self-hosted runner"), found)
        self.assertIn(("Medium", ".github/workflows/prt.yml:4", "workflow grants permissions: write-all"), found)
        self.assertIn(("Medium", ".github/workflows/wr.yml:2", "workflow triggers on workflow_run"), found)
        self.assertIn(("Medium", ".github/workflows/wr.yml:8", "workflow_run workflow downloads artifacts from the triggering run"), found)
        self.assertFalse([f for f in found if "safe.yml" in f[1]])

    def test_external_secrets_inherit(self):
        self.write(".github/workflows/a.yml", "on: push\njobs:\n  rel:\n    uses: other/ci/.github/workflows/r.yml@" + "0" * 40 +
                   "\n    secrets: inherit\n  local:\n    uses: ./.github/workflows/b.yml\n    secrets: inherit\n")
        titles = [t for _, _, t in self.findings()]
        self.assertEqual(sum("every secret is passed" in t for t in titles), 1)

    def test_plaintext_sources_and_tls_off(self):
        self.write("pom.xml", "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  <url>http://www.example.org/</url>\n"
                              "  <repositories>\n    <repository>\n      <url>http://nexus.example/m2/</url>\n"
                              "    </repository>\n  </repositories>\n</project>\n")
        self.write(".gitmodules", '[submodule "a"]\n  url = git://example.invalid/a.git\n[submodule "b"]\n  url = https://example.invalid/b.git\n')
        self.write(".npmrc", "strict-ssl=false\n")
        self.write("requirements.txt", "--trusted-host pypi.example\n")
        self.write("build.gradle", "repositories { maven { url 'http://repo.example/' } }\ndescription = 'see http://docs.example'\n")
        self.write("pyproject.toml", '[project]\nname = "x"\n[project.urls]\nHomepage = "http://example.org"\n')
        self.write("uv.lock", "")
        locations = sorted(loc for sev, loc, t in self.findings() if sev == "Medium")
        self.assertEqual(locations, [".gitmodules:2", ".npmrc:1", "build.gradle:1", "pom.xml:5", "requirements.txt:1"])

    def test_pypirc_pip_conf_and_nuget_sources(self):
        self.write(".pypirc", "[pypi]\nusername = __token__\npassword = pypi-SYNTHETIC\n")
        self.write("pip.conf", "[global]\nextra-index-url = https://pkgs.example/simple\n")
        self.write("nuget.config", "<configuration><packageSources>\n<add key=\"a\" value=\"https://a.example/v3\" />\n"
                                   "<add key=\"b\" value=\"https://api.nuget.org/v3/index.json\" />\n</packageSources></configuration>\n")
        titles = [t for _, _, t in self.findings()]
        self.assertIn(".pypirc contains a literal upload credential", titles)
        self.assertIn("pip config adds a second index beside PyPI", titles)
        self.assertIn("nuget.config mixes several package sources without packageSourceMapping", titles)

    def test_dockerfile_arg_base_add_url_and_compose_images(self):
        self.write("Dockerfile", "ARG BASE=node:latest\nFROM ${BASE}\nADD https://example.invalid/x.tgz /x\n"
                                 "ADD --checksum=sha256:00 https://example.invalid/y.tgz /y\n")
        self.write("compose.yaml", "services:\n  a:\n    image: nginx\n  b:\n    image: redis:7.2@sha256:00\n"
                                   "  c:\n    image: ${REGISTRY}/app:${TAG}\n  d:\n    image: ghcr.io/org/app:1.4\n")
        found = [(loc, t) for _, loc, t in self.findings()]
        self.assertIn(("Dockerfile:2", "base image node:latest is not pinned"), found)
        self.assertIn(("Dockerfile:3", "build downloads a remote file with ADD and no --checksum"), found)
        self.assertNotIn("Dockerfile:4", [loc for loc, _ in found])
        self.assertEqual([loc for loc, t in found if t.startswith("compose image")], ["compose.yaml:3"])

    def test_git_sources_in_pnpm_and_yarn_lockfiles(self):
        cases = {
            "pnpm-lock.yaml": "packages:\n  a@1.0.0:\n    resolution: {commit: abc, repo: https://github.com/u/r.git, type: git}\n",
            "yarn.lock": 'a@github:u/r:\n  resolved "https://codeload.github.com/u/r/tar.gz/abc"\n',
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                for old in list(self.root.iterdir()):
                    old.unlink()
                self.write(name, text)
                titles = [t for _, _, t in self.findings()]
                self.assertIn("lockfile resolves a package from git or a local path, not a registry", titles)
        for old in list(self.root.iterdir()):
            old.unlink()
        self.write("pnpm-lock.yaml", "packages:\n  x@1.0.0:\n    resolution: {tarball: 'https://pkgs.invalid/x.tgz'}\n")
        self.assertIn("lockfile resolves packages from non-default host pkgs.invalid", [t for _, _, t in self.findings()])

    def test_script_inputs_of_other_actions_are_data(self):
        expr = "${{ github.event.issue.title }}"
        self.write(".github/workflows/a.yml",
                   "on: issues\njobs:\n  call:\n    uses: ./.github/workflows/b.yml\n    with:\n      script: " + expr + "\n"
                   "  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: other/action@" + "0" * 40 + "\n"
                   "        with:\n          script: " + expr + "\n"
                   "      - name: real\n        uses: actions/github-script@" + "0" * 40 + "\n"
                   "        with:\n          script: console.log('" + expr + "')\n")
        locations = [loc for _, loc, t in self.findings() if t.startswith("untrusted")]
        self.assertEqual(locations, [".github/workflows/a.yml:16"])

    def test_osv_group_keeps_fix_versions_from_every_alias(self):
        lock = self.write("poetry.lock", "")
        payload = {"results": [{"source": {"path": str(lock), "type": "lockfile"}, "packages": [
            {"package": {"name": "fixture", "version": "1.0", "ecosystem": "PyPI"},
             "vulnerabilities": [
                 {"id": "GHSA-aaaa-aaaa-aaaa", "summary": "s"},
                 {"id": "PYSEC-1", "summary": "s", "affected": [{"package": {"name": "fixture"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.2.6"}]}]}],
                  "references": [{"type": "FIX", "url": "https://github.com/o/r/commit/abc"}]}],
             "groups": [{"ids": ["GHSA-aaaa-aaaa-aaaa", "PYSEC-1"], "max_severity": "7.5"}]}]}]}
        c = self.deps.Collector(self.root)
        with patch.object(self.deps.shutil, "which", return_value="/tools/osv-scanner"), \
             patch.object(self.deps, "run", return_value=(1, json.dumps(payload), "")):
            self.deps.audit_osv(c, self.root, [lock])
        self.assertEqual(len(c.findings), 1)
        self.assertEqual(c.findings[0]["fix"], "Upgrade to 1.2.6")
        self.assertIn("https://github.com/o/r/commit/abc", [r["url"] for r in c.findings[0]["references"]])

    def test_this_repository_stays_clean(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(self.deps.scan(root, False)["findings"], [])


if __name__ == "__main__":
    unittest.main()
