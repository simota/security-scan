"""Round-5 regressions: secret detection for captures, linear workflow/config regexes,
fetch-only PR heads, compose extension fields, npm paths leaving the checkout, Gradle
repository blocks, pnpm BOM, canonical merge ids and the no-PDF limitation."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_run_contract import git
from test_security_scan import import_module

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import render  # noqa: E402

META = {"project": "demo", "date": "2026-10-10", "assessor": "Test host (model)"}
FINDING = {"id": "F-001", "title": "Order detail lacks an owner check", "severity": "High",
           "confidence": "Confirmed", "category": "Actor and tenant", "location": "src/orders.py:2",
           "actor": "any signed-in user", "request": "GET /orders/{order_id}",
           "impact": "reads another user's order", "fix": "scope the query to the caller", "status": "Open",
           "validation": {"verdict": "Valid", "method": "review", "evidence": "handler reads by id only"}}
NO_LEDGER = "invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)"
SHA = "0" * 40
PRT = "on: pull_request_target\njobs:\n  j:\n    runs-on: x\n    steps:\n"
LIMIT = 2.0  # Seconds; the quadratic forms took tens of seconds at these sizes.
# Synthetic token-shaped strings, not real credentials.
GHP = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"


def quiet(function, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = function(*args)
    return code, out.getvalue(), err.getvalue()


class Temp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-round5-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, value):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return path


class SecretInSourceTests(unittest.TestCase):
    def test_ordinary_files_are_not_secret(self):
        for rel, text in (("package.json", '{\n  "dependencies": {\n    "jsonwebtoken": "^9.0.2"\n  }\n}\n'),
                          (".github/workflows/ci.yml", "permissions:\n  id-token: write\n  contents: read\n"),
                          (".github/workflows/ci.yml", "jobs:\n  call:\n    uses: o/r/.github/workflows/x.yml@v1\n"
                                                       "    secrets: inherit\n"),
                          ("config/database.yml", "production:\n  password: <%= ENV['DB_PASSWORD'] %>\n"),
                          ("pyproject.toml", '[tool.poetry.dependencies]\ntokenizers = "^0.15"\n'),
                          ("app/auth.py", 'TOKEN_TYPE = "Bearer"\n'),
                          ("app/forms.py", 'password_label = "Password"\nhint = {"password": "Enter your password"}\n'),
                          ("app/keys.py", 'if pem.startswith("-----BEGIN PRIVATE KEY-----"):\n    pass\n'),
                          ("src/routes.js", 'const PASSWORD_RESET_PATH = "/password/reset";\n'
                                            'const resetPassword = "/password/reset/{token}";\n'),
                          ("deploy.sh", 'export GITHUB_TOKEN="$(gh auth token)"\nexport API_KEY=${API_KEY:-}\n'),
                          ("src/login.js", "const password = req.body.password;\n")):
            with self.subTest(rel=rel, text=text):
                self.assertFalse(render.secret_in_source(rel, text))

    def test_secret_assignments_in_shell_docker_env_and_typed_code(self):
        for rel, text in ((".envrc", "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n"),
                          ("Dockerfile", "FROM alpine:3.19\nENV API_TOKEN=synthetic0token0value\n"),
                          ("deploy.sh", "export DEPLOY_PASSWORD=synthetic-pw-0000\n"),
                          ("env.production", "DB_PASSWORD=hunter2hunter2\n"),
                          ("app/settings.py", 'secret_key: str = "django-insecure-abcdefghijklmnop"\n'),
                          ("src/client.js", 'const apiKey = "abcd1234efgh5678";\n'),
                          ("README.md", "Use " + GHP + " for the demo\n"),
                          ("notes.txt", "aws AKIA" + "ABCDEFGHIJKLMNOP" + " key\n"),
                          ("sa.json", '{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0B\\n"}'),
                          ("key.txt", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx1234567890abcd\n"),
                          ("settings.yml", "password: synthetic-value\n")):
            with self.subTest(rel=rel):
                self.assertTrue(render.secret_in_source(rel, text))


class CaptureRecheckTests(Temp):
    @classmethod
    def setUpClass(cls):
        cls.capture = import_module(SCRIPTS / "evidence_capture.py", "round5_capture")

    def test_recapture_rechecks_without_the_secret_scan(self):
        repo = self.tmp / "app"
        (repo / "src").mkdir(parents=True)
        (repo / "src/orders.py").write_text("def show(order_id):\n    return Order.get(order_id)\n")
        git(repo, "init", "-q")
        git(repo, "add", ".")
        git(repo, "commit", "-q", "-m", "init")
        out = self.tmp / "out"
        out.mkdir()
        findings = out / "findings.json"
        findings.write_text(json.dumps({"meta": META, "findings": [FINDING]}))
        first = self.capture.capture(repo, findings, ["src/orders.py"])
        before = findings.read_bytes()
        # A file captured by an earlier (looser) rule set must still recheck.
        with patch.object(self.capture, "secret_in_source", return_value=True):
            self.assertEqual(self.capture.capture(repo, findings, ["src/orders.py"]), first)
            self.assertEqual(findings.read_bytes(), before)


class DepsScanRound5Tests(Temp):
    @classmethod
    def setUpClass(cls):
        cls.deps = import_module(SCRIPTS / "deps_scan.py", "round5_deps")

    def found(self):
        return [(f["severity"], f["location"], f["title"]) for f in self.deps.scan(self.tmp, False)["findings"]]

    def titles(self, needle=""):
        return [t for _, _, t in self.found() if needle in t]

    def workflow(self, body):
        return self.write(".github/workflows/w.yml", body)

    def timed(self, label, function):
        started = time.monotonic()
        function()
        self.assertLess(time.monotonic() - started, LIMIT, label)

    def test_regexes_stay_linear_on_adversarial_inputs(self):
        cases = {
            "blank lines in privileged workflow": (".github/workflows/w.yml", PRT + "      - run: echo hi\n" + "\n" * 40000),
            "git words": (".github/workflows/w.yml", PRT + "      - run: " + "git " * 40000 + "\n"),
            "blank lines in a run after a head checkout": (
                ".github/workflows/w.yml", PRT + "      - uses: actions/checkout@" + SHA + "\n        with:\n"
                "          ref: ${{ github.head_ref }}\n      - run: |\n" + "\n" * 40000 + "          npm ci\n"),
            "unclosed expressions in a double-quoted run": (".github/workflows/w.yml",
                                                            PRT + '      - run: "' + "${{ " * 20000 + '"\n'),
            "long space run without a colon": ("compose.yml", "a" + " " * 60000 + "b\n"),
            "unclosed packageSources tags": ("nuget.config", "<configuration>" + "<packageSources " * 20000),
        }
        for label, (name, text) in cases.items():
            with self.subTest(label=label):
                shutil.rmtree(self.tmp)
                self.write(name, text)
                self.timed(label, lambda: self.deps.scan(self.tmp, False))
        lock = self.write("gradle.lockfile", "a:" * 3000 + "\n")
        self.timed("gradle.lockfile colons", lambda: self.deps.pinned_count(lock))
        self.timed("blank lines before a build command", lambda: self.deps.EXECUTES_CHECKOUT.search("\n" * 40000))

    def test_fetching_the_pr_head_alone_is_not_a_checkout(self):
        for run in ("git fetch origin ${{ github.event.pull_request.base.ref }} && "
                    "git diff ${{ github.event.pull_request.head.sha }}",
                    "git fetch origin pull/${{ github.event.pull_request.number }}/head && git diff HEAD FETCH_HEAD",
                    "git fetch origin ${{ github.head_ref }}:pr && git checkout main"):
            with self.subTest(run=run):
                self.workflow(PRT + "      - uses: actions/checkout@" + SHA + "\n      - run: " + run + "\n")
                self.assertFalse([f for f in self.found() if f[0] == "High"])
        for run in ("git fetch origin ${{ github.head_ref }} && git reset --hard FETCH_HEAD",
                    "git fetch origin pull/${{ github.event.number }}/head:pr\n          git switch pr",
                    "git -C src pull origin ${{ github.head_ref }}",
                    "git fetch origin ${{ github.head_ref }} && git worktree add pr FETCH_HEAD"):
            with self.subTest(run=run):
                self.workflow(PRT + "      - run: |\n          " + run + "\n")
                self.assertTrue(any(s == "High" and "in a run step" in t for s, _, t in self.found()))

    def test_compose_extension_field_images_are_checked(self):
        self.write("docker-compose.yml", "x-base: &base\n  image: nginx\n  restart: always\nx-built:\n  build: .\n"
                   "  image: local\nservices:\n  web:\n    <<: *base\n  api:\n    image: redis:7\n")
        self.assertEqual(self.found(), [("Low", "docker-compose.yml:2", "compose image nginx is not pinned")])

    def test_npm_local_paths_outside_the_checkout_are_external(self):
        self.write("package.json", {"dependencies": {"a": "file:../other-repo/lib", "b": "link:../sibling",
                                                     "c": "file:./packages/c", "d": "./d"}})
        self.write("packages/web/package.json", {"dependencies": {"e": "file:../c", "f": "link:../../../out"}})
        flagged = sorted(t.split()[2] for t in self.titles("fetched outside the registry"))
        self.assertEqual(flagged, ["a", "b", "f"])

    def test_gradle_repository_blocks(self):
        http = "fetches code over plaintext http://"
        for body, flagged in (("repositories.maven { url 'http://repo.example.com/m2' }\n", True),
                              ("repositories\n{\n    maven { url 'http://repo.example.com/m2' }\n}\n", True),
                              ("repositories {\n  def x = \"}\"\n  maven { url 'http://repo.example.com/m2' }\n}\n", True),
                              ("allprojects { repositories { mavenCentral() } ext { site = 'http://example.com/d' }\n}\n",
                               False),
                              ("allprojects { repositories { mavenCentral() }\n  ext { site = 'http://example.com/d' }\n}\n",
                               False),
                              ("repositories.mavenCentral()\ndependencies {\n  // 'http://example.com'\n"
                               "  ext.site = 'http://example.com/d'\n}\n", False)):
            with self.subTest(body=body):
                self.write("build.gradle", body)
                self.assertEqual(bool(self.titles(http)), flagged)

    def test_pnpm_workspace_with_bom(self):
        path = self.write("pnpm-workspace.yaml", "\ufeffpackages:\n  - packages/*\n")
        self.assertEqual(self.deps.pnpm_packages(path), ["packages/*"])


class MergeIdTests(Temp):
    @classmethod
    def setUpClass(cls):
        cls.tool = import_module(SCRIPTS / "findings.py", "round5_findings")

    def test_noncanonical_finding_ids_are_refused(self):
        out = self.write("findings.json", {"meta": META, "findings": [FINDING]})
        before = out.read_bytes()
        dep = {"title": "hand-written dep", "severity": "High", "confidence": "Confirmed",
               "location": "package.json:1", "category": "Dependencies and platform", "status": "Open",
               "validation": {"verdict": "Valid", "evidence": "x", "method": "manual"}}
        for identifier in ("d-001", " D-001", "D-001 ", "\uff24-001", "D-\u0661\u0662\u0663", "F-1", "f-002"):
            with self.subTest(identifier=identifier):
                frag = self.write("frag.json", {"findings": [dict(dep, id=identifier)]})
                code, _, err = quiet(self.tool.main, ["merge", str(out), str(frag)])
                self.assertEqual(code, 1, err)
                self.assertIn("must be F-NNN", err)
                self.assertEqual(out.read_bytes(), before)
        frag = self.write("frag.json", {"findings": [dict(FINDING, id="F-002", location="src/orders.py:1")]})
        self.assertEqual(quiet(self.tool.main, ["merge", str(out), str(frag)])[0], 0)


class NoPdfLimitationTests(Temp):
    @classmethod
    def setUpClass(cls):
        cls.contract = import_module(SCRIPTS / "contract_check.py", "round5_contract")

    def limits(self, pdf):
        data = {"findings": [], "limitations": [NO_LEDGER, "assessment.pdf not produced: no PDF engine"]}
        return [p for p in self.contract.check(data, self.tmp, pdf=pdf) if p.startswith("limitations:")]

    def test_no_pdf_limitation_contradicts_a_produced_pdf(self):
        self.assertEqual(self.limits(False), [])
        (self.tmp / "assessment.pdf").write_bytes(b"%PDF-1.4\n")
        contradictory = self.limits(True)
        self.assertEqual(len(contradictory), 1, contradictory)
        self.assertIn("assessment.pdf exists", contradictory[0])


if __name__ == "__main__":
    unittest.main()
