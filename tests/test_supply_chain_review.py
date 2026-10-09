"""Third-round deps_scan checks: privileged workflows, plaintext sources, images."""
from pathlib import Path
import unittest

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

    def test_this_repository_stays_clean(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(self.deps.scan(root, False)["findings"], [])


if __name__ == "__main__":
    unittest.main()
