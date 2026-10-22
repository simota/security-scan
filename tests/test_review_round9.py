"""Round 9: credential leaks, identity gates, capture/verify agreement and render robustness."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_run_contract as fixture
from test_run_contract import SCRIPTS
from test_security_scan import import_module

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples/findings.sample.json"


class UrlCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.urls = import_module(SCRIPTS / "url_redaction.py", "round9_url_redaction")

    def test_token_user_name_under_a_vcs_or_websocket_scheme_is_a_credential(self):
        for url in ("git+https://Zx81Kq0PmW3vT7sLr2Qe@git.example.com/acme/lib.git#egg=lib",
                    "svn+https://Zx81Kq0PmW3vT7sLr2Qe@svn.example.com/repo",
                    "wss://Zx81Kq0PmW3vT7sLr2Qe@socket.example.com/feed"):
            with self.subTest(url=url):
                self.assertTrue(self.urls.has_url_credentials(url))
                self.assertNotIn("Zx81Kq0PmW3vT7sLr2Qe", self.urls.redact_urls(url))
        # ssh's user name is an account, not a secret.
        for url in ("git+ssh://git@github.com/o/r.git", "ssh://git@github.com/o/r"):
            self.assertFalse(self.urls.has_url_credentials(url), url)

    def test_double_and_partly_encoded_userinfo_is_a_credential(self):
        for text in ("GET /login?next=https%253A%252F%252Fadmin%253AS3cretPW%2540db.internal%252F 302",
                     "next=https%3A//admin:S3cretPW@db.internal/",
                     "next=https:%2F%2Fadmin:S3cretPW@db.internal/x"):
            with self.subTest(text=text):
                self.assertTrue(self.urls.has_url_credentials(text))
                self.assertNotIn("S3cretPW", self.urls.redact_urls(text))
        for text in ("next=https%3A%2F%2Fexample.com%2Fpath", "see https%3A//example.com/a",
                     "next=https%253A%252F%252Fexample.com%252F"):
            with self.subTest(text=text):
                self.assertFalse(self.urls.has_url_credentials(text))
                self.assertEqual(self.urls.redact_urls(text), text)


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verification = import_module(SCRIPTS / "verification.py", "round9_verification")

    def test_unassigned_default_ignorable_code_points_do_not_make_a_new_identity(self):
        identity = self.verification.identity
        for suffix in ("⁥", "￰", "￸", "\U000e0000", "\U000e0002", "\U000e0080", "\U000e01f0",
                       "\U000e0fff"):
            with self.subTest(code_point=hex(ord(suffix))):
                self.assertEqual(identity("alice" + suffix), identity("alice"))
        self.assertNotEqual(identity("Ann Lee"), identity("AnnLee"))


class CaptureExternalStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = import_module(SCRIPTS / "evidence_capture.py", "round9_capture")
        cls.contract = import_module(SCRIPTS / "contract_check.py", "round9_contract")

    setUp = fixture.RunContractTests.setUp
    base = fixture.RunContractTests.base

    def test_alternates_grafts_and_promisor_packs_are_refused_before_pinning(self):
        self.findings.write_text(json.dumps(self.base()), encoding="utf-8")
        original = self.findings.read_bytes()
        git_dir = self.repo / ".git"
        (git_dir / "objects/pack").mkdir(parents=True, exist_ok=True)
        for marker in ("objects/info/alternates", "info/grafts", "objects/pack/pack-0.promisor"):
            with self.subTest(marker=marker):
                path = git_dir / marker
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("")
                with self.assertRaisesRegex(self.capture.CaptureError, "not self-contained"):
                    self.capture.capture(self.repo, self.findings, ["src/orders.py"])
                self.assertEqual(self.findings.read_bytes(), original)
                path.unlink()
        self.capture.capture(self.repo, self.findings, ["src/orders.py"])  # a standalone clone still works


class RenderRobustnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.render = import_module(SCRIPTS / "render.py", "round9_render")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-round9-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        self.data = json.loads(SAMPLE.read_text(encoding="utf-8"))

    def run_render(self, data, *extra, name="findings.json"):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        out = self.tmp / ("out-" + name)
        done = subprocess.run([sys.executable, str(SCRIPTS / "render.py"), str(path), "--out", str(out),
                               "--no-pdf", *extra], capture_output=True, text=True, timeout=60,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertNotIn("Traceback", done.stderr)
        return done, out

    def test_credentials_in_reference_query_names_and_pass_parameters_are_dropped(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
        token = "ghp_" + "A1b2C3d4E5" * 4
        hrefs = {f"https://ci.example.invalid/artifact?{jwt}": "https://ci.example.invalid/artifact",
                 f"https://ci.example.invalid/download?{token}": "https://ci.example.invalid/download",
                 "https://h.example.invalid/login?user=svc&pass=Hunter2pw": "https://h.example.invalid/login?user=svc",
                 "https://h.example.invalid/x?db_pass=Hunter2pw&page=2": "https://h.example.invalid/x?page=2",
                 "https://nvd.example.invalid/detail?CVE-2021-44228": "https://nvd.example.invalid/detail?CVE-2021-44228"}
        for url, expected in hrefs.items():
            with self.subTest(url=url):
                self.assertEqual(self.render.public_href(url), expected)
        self.data["findings"][0]["references"] = [{"type": "web", "url": u} for u in hrefs]
        done, out = self.run_render(self.data)
        self.assertEqual(done.returncode, 0, done.stderr)
        for page in ("dashboard.html", "assessment.html"):
            text = (out / page).read_text(encoding="utf-8")
            for secret in (jwt, token, "Hunter2pw"):
                self.assertNotIn(secret, text)

    def test_credentials_in_reference_paths_and_invisible_characters_are_refused(self):
        for url in ("https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/" + "X" * 24,
                    "https://api.telegram.org/bot123456789:AA" + "h" * 33 + "/getMe",
                    "https://h.inv\u009balid/a", "https://h.invalid/report‮FDP.exe",
                    "https://h.invalid/a b", "https://h.invalid/a​b"):
            with self.subTest(url=url):
                data = copy.deepcopy(self.data)
                data["findings"][0]["references"] = [{"type": "web", "url": url}]
                done, out = self.run_render(data)
                self.assertEqual(done.returncode, 2, done.stdout)
                self.assertIn("references[0].url", done.stderr)
                self.assertFalse(out.exists())
        for location in ("src/a\u0085b.py:1", "src/report‮yp.py:1"):
            with self.subTest(location=location):
                data = copy.deepcopy(self.data)
                data["findings"][0]["location"] = location
                done, _ = self.run_render(data)
                self.assertEqual(done.returncode, 2, done.stdout)
                self.assertIn("location", done.stderr)

    def test_versionless_three_pass_key_is_legacy_data_not_the_opt_in(self):
        data = copy.deepcopy(self.data)
        data.pop("schema_version", None)
        data["three_pass"] = {"note": "legacy extension"}
        data["findings"][0]["id"] = "SEC-1"
        done, _ = self.run_render(data)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_unreadable_excerpt_location_only_loses_its_excerpt(self):
        repo = self.tmp / "repo"
        (repo / "src").mkdir(parents=True)
        data = copy.deepcopy(self.data)
        data["findings"][0]["location"] = "src/" + "x" * 300 + ".py:2"
        done, out = self.run_render(data, "--repo", str(repo))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((out / "assessment.html").is_file())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_fifo_findings_path_is_refused_promptly(self):
        fifo = self.tmp / "pipe.json"
        os.mkfifo(fifo)
        done = subprocess.run([sys.executable, str(SCRIPTS / "render.py"), str(fifo), "--out", str(self.tmp / "o"),
                               "--no-pdf"], capture_output=True, text=True, timeout=10,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(done.returncode, 2)
        self.assertIn("not a regular file", done.stderr)


if __name__ == "__main__":
    unittest.main()
