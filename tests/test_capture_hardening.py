"""Offline capture regressions using only owned Git files, links and FIFOs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import evidence_capture as capture
import render


class CaptureHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="security-scan-capture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src/app.py").write_text("def check():\n    return True\n", encoding="utf-8")
        (self.repo / "src/other.py").write_text("value = 0\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("fixture.pipe\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("commit", "-qm", "inert fixture")
        self.out = self.root / "out"
        self.out.mkdir()
        self.findings = self.out / "findings.json"
        self.write({"meta": {"project": "Capture fixture", "date": "2026-10-07"},
                    "findings": []})

    def git(self, *args):
        return subprocess.run(
            [capture.GIT_BINARY, "-C", str(self.repo), "-c", "core.hooksPath=/dev/null",
             "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
             "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args],
            env=capture.GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True,
            check=True, timeout=10).stdout

    def write(self, data):
        self.findings.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def cli(self, *paths):
        # A regression must fail promptly, not leave the test process in a read.
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPTS / "evidence_capture.py"), str(self.repo),
             *paths, "--findings", str(self.findings)], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=5)

    def test_clean_capture_preserves_pin_and_repeated_bytes(self):
        first = capture.capture(self.repo, self.findings, ["src/app.py"])
        data = json.loads(self.findings.read_text(encoding="utf-8"))
        data["assessment"]["repository"] = "https://example.invalid/owned/repo"
        data["assessment"]["review_note"] = "Preserve the existing assessment identity"
        self.write(data)
        before = self.findings.read_bytes()
        again = capture.capture(self.repo, self.findings, ["src/app.py"])
        self.assertEqual(first, again)
        self.assertEqual(self.findings.read_bytes(), before)
        evidence = render.load(self.findings)["evidence"]
        self.assertEqual(len(evidence), 1)
        artifact = self.out / evidence[0]["location"]
        self.assertEqual(artifact.read_bytes(), (self.repo / "src/app.py").read_bytes())
        self.assertEqual(evidence[0]["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())

    def test_existing_uppercase_commit_pins_remain_unchanged(self):
        capture.capture(self.repo, self.findings, ["src/app.py"])
        data = json.loads(self.findings.read_text(encoding="utf-8"))
        data["assessment"]["commit"] = data["assessment"]["commit"].upper()
        data["meta"]["commit"] = data["meta"]["commit"].upper()
        data["evidence"][0]["commit"] = data["evidence"][0]["commit"].upper()
        self.write(data)
        before = self.findings.read_bytes()
        self.assertEqual(capture.capture(self.repo, self.findings, ["src/app.py"]),
                         {"src/app.py": "SRC-001"})
        self.assertEqual(self.findings.read_bytes(), before)

    def test_dirty_pin_rejected_before_changing_findings_or_artifacts(self):
        capture.capture(self.repo, self.findings, ["src/app.py"])
        data = json.loads(self.findings.read_text(encoding="utf-8"))
        (self.repo / "src/other.py").write_text("value = 1\n", encoding="utf-8")
        diff = hashlib.sha256(self.git("diff", "--binary", "--no-ext-diff", "--no-textconv")).hexdigest()
        data["assessment"].update(worktree="dirty", diff_sha256=diff)
        data["evidence"][0]["diff_sha256"] = diff
        claim = {"status": "supported", "reason": "Observed source", "evidence_ids": ["SRC-001"]}
        data["findings"] = [{
            "id": "F-001", "title": "Inert finding", "severity": "Low", "confidence": "Suspected",
            "location": "src/app.py:2", "validation": {"verdict": "Likely", "evidence": "Inert fixture"},
            "verification": {
                "reviewer": "fixture", "claims": {k: copy.deepcopy(claim) for k in
                    ("reachability", "preconditions", "defenses", "impact")},
                "falsification": [{"check": "Inert check", "result": "clear", "reason": "Observed",
                                   "evidence_ids": ["SRC-001"]}],
                "reviews": [], "run_ids": [],
                "environment": {"status": "not_required", "reason": "Static fixture", "evidence_ids": []},
            },
        }]
        self.write(data)
        render.load(self.findings)
        before = self.findings.read_bytes()
        artifact = self.out / data["evidence"][0]["location"]
        original_source = artifact.read_bytes()
        result = self.cli("src/app.py")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("clean assessment pin", result.stderr)
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertEqual(artifact.read_bytes(), original_source)
        render.load(self.findings)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "owned FIFO regression requires POSIX")
    def test_committed_symlink_to_owned_fifo_fails_without_blocking(self):
        os.mkfifo(self.repo / "fixture.pipe", 0o600)
        (self.repo / "blocked.py").symlink_to("fixture.pipe")
        self.git("add", "blocked.py")
        self.git("commit", "-qm", "inert source link")
        self.assertEqual(self.git("status", "--porcelain"), b"")
        before = self.findings.read_bytes()
        result = self.cli("blocked.py")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("unsafe or unsupported capture input", result.stderr)
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "owned FIFO regression requires POSIX")
    def test_direct_fifo_fails_without_blocking(self):
        path = self.repo / "src/app.py"
        path.unlink()
        os.mkfifo(path, 0o600)
        before = self.findings.read_bytes()
        result = self.cli("src/app.py")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("not_regular_file", result.stderr)
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())

    def test_symlinked_source_directory_is_rejected(self):
        (self.repo / "src").rename(self.repo / "actual-src")
        (self.repo / "src").symlink_to("actual-src", target_is_directory=True)
        before = self.findings.read_bytes()
        with self.assertRaises(capture.CaptureError):
            capture.capture(self.repo, self.findings, ["src/app.py"])
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())

    def test_committed_symlink_cannot_be_captured_as_a_regular_worktree_file(self):
        path = self.repo / "link.py"
        path.symlink_to("src/app.py")
        self.git("add", "link.py")
        self.git("commit", "-qm", "inert tracked link")
        path.unlink()
        path.write_text("src/app.py", encoding="utf-8")
        self.assertEqual(self.git("cat-file", "blob", "HEAD:link.py"), path.read_bytes())
        self.assertIn(b"T link.py", self.git("status", "--porcelain"))
        before = self.findings.read_bytes()
        result = self.cli("link.py")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("commit path is not a regular source file", result.stderr)
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())

    def test_literal_path_with_glob_characters_and_executable_mode_is_supported(self):
        path = self.repo / "src/app[1].py"
        path.write_text("# inert executable source fixture\n", encoding="utf-8")
        path.chmod(0o755)
        self.git("--literal-pathspecs", "add", "src/app[1].py")
        self.git("commit", "-qm", "inert executable fixture")
        mapping = capture.capture(self.repo, self.findings, ["src/app[1].py"])
        self.assertEqual(mapping, {"src/app[1].py": "SRC-001"})
        self.assertEqual((self.out / "evidence/source/src/app[1].py").read_bytes(), path.read_bytes())

    def test_oversized_source_is_rejected_before_any_blob_read(self):
        (self.repo / "src/app.py").write_bytes(b"x" * 4097)
        before = self.findings.read_bytes()
        with patch.object(capture, "MAX_FILE_BYTES", 4096), patch.object(capture, "git", wraps=capture.git) as git:
            with self.assertRaisesRegex(capture.CaptureError, "size_limit"):
                capture.capture(self.repo, self.findings, ["src/app.py"])
        self.assertFalse(any(call.args[1] == "cat-file" for call in git.call_args_list))
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())

    def test_oversized_blob_is_rejected_before_materializing_it(self):
        # The worktree may be smaller than the committed blob; bound both reads.
        (self.repo / "src/app.py").write_bytes(b"x" * 4097)
        self.git("add", "src/app.py")
        self.git("commit", "-qm", "inert oversized blob")
        (self.repo / "src/app.py").write_text("x\n", encoding="utf-8")
        before = self.findings.read_bytes()
        with patch.object(capture, "MAX_FILE_BYTES", 4096), patch.object(capture, "git", wraps=capture.git) as git:
            with self.assertRaisesRegex(capture.CaptureError, "Git object exceeds size limit"):
                capture.capture(self.repo, self.findings, ["src/app.py"])
        self.assertTrue(any(call.args[1:3] == ("cat-file", "-s") for call in git.call_args_list))
        self.assertFalse(any(call.args[1:3] == ("cat-file", "blob") for call in git.call_args_list))
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())

    def test_schema_upgrade_is_validated_before_writing_new_artifacts(self):
        data = json.loads(self.findings.read_text(encoding="utf-8"))
        data["evidence"] = [{"id": "old", "kind": "source", "source_path": "old.py",
                             "commit": self.git("rev-parse", "HEAD").decode().strip(),
                             "location": "old.py", "summary": "Legacy extension", "sha256": "invalid"}]
        self.write(data)
        before = self.findings.read_bytes()
        with self.assertRaisesRegex(capture.CaptureError, "schema"):
            capture.capture(self.repo, self.findings, ["src/app.py"])
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())

    def test_invalid_expert_record_is_rejected_before_adding_source(self):
        capture.capture(self.repo, self.findings, ["src/app.py"])
        data = json.loads(self.findings.read_text(encoding="utf-8"))
        data["expert"] = {"version": 99}
        self.write(data)
        before = self.findings.read_bytes()
        with self.assertRaisesRegex(capture.CaptureError, "expert.version"):
            capture.capture(self.repo, self.findings, ["src/other.py"])
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence/source/src/other.py").exists())

    def commit_file(self, rel, data):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.git("add", rel)
        self.git("commit", "-qm", "add " + rel)

    def test_utf16_source_is_secret_checked_in_its_own_encoding(self):
        text = '$env:AWS_ACCESS_KEY_ID = "AKIA' + 'IOSFODNN7EXAMPLE"\r\n'
        for codec in ("utf-16", "utf-16-le", "utf-16-be", "utf-32"):
            with self.subTest(codec=codec):
                rel = "deploy-%s.ps1" % codec
                self.commit_file(rel, text.encode(codec))
                with self.assertRaisesRegex(capture.CaptureError, "secret-looking"):
                    capture.capture(self.repo, self.findings, [rel])
        self.assertFalse((self.out / "evidence").exists())
        # A UTF-16 file without a secret is still captured.
        self.commit_file("notes.ps1", 'Write-Host "hello"\r\n'.encode("utf-16"))
        self.assertEqual(capture.capture(self.repo, self.findings, ["notes.ps1"]), {"notes.ps1": "SRC-001"})

    def test_capture_refuses_objects_the_verifier_cannot_snapshot(self):
        # git clone of a local path hardlinks the object files; the verifier refuses hardlinks.
        clone = self.root / "clone"
        subprocess.run([capture.GIT_BINARY, "clone", "-q", "--local", str(self.repo), str(clone)],
                       env=capture.GIT_ENV, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=10)
        objects = [p for p in (clone / ".git/objects").rglob("*") if p.is_file()]
        if not any(p.stat().st_nlink > 1 for p in objects):
            self.skipTest("filesystem did not hardlink the clone's objects")
        before = self.findings.read_bytes()
        with self.assertRaisesRegex(capture.CaptureError, "hardlinked_file.*--no-hardlinks"):
            capture.capture(clone, self.findings, ["src/app.py"])
        self.assertEqual(self.findings.read_bytes(), before)
        self.assertFalse((self.out / "evidence").exists())


class SecretGateFormsTests(unittest.TestCase):
    def test_secret_forms_that_must_be_refused(self):
        for rel, text in (
                ("src/tls.py", 'TLS = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n"\n'),
                ("src/tls.go", 'k := "-----BEGIN EC PRIVATE KEY-----\\nProc-Type: 4,ENCRYPTED\\nMIIEvQIBADANBgkqhkiG9w0B"\n'),
                ("config/initializers/secret_token.rb",
                 "Rails.application.config.secret_key_base = '" + "a3f9" * 32 + "'\n"),
                ("src/keys.py", 'private_key_pem = "MIIEvQIBADANBgkqhkiG9w0BAQEF"\n'),
                ("wp-config.php", "define( 'DB_PASSWORD', 'Xk9vQ2mLp7Rt' );\n"),
                ("settings.py", 'os.environ.setdefault("SECRET_KEY", "Xk9vQ2mLp7Rt8z")\n'),
                ("src/db.js", "const password = `Xk9vQ2mLp7Rt`;\n"),
                ("src/db.ts", "const password = `Xk9vQ2mLp7Rt`;\n")):
            with self.subTest(rel=rel):
                self.assertTrue(render.secret_in_source(rel, text))

    def test_non_secret_forms_stay_capturable(self):
        for rel, text in (
                ("config/initializers/secret_token.rb", "config.secret_key_base = ENV['SECRET_KEY_BASE']\n"),
                ("wp-config.php", "define( 'DB_PASSWORD', getenv('DB_PASSWORD') );\n"),
                ("wp-config.php", "define( 'DB_NAME', 'wordpress_production' );\n"),
                ("settings.py", 'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")\n'),
                ("src/db.js", "const password = `${process.env.DB_PASSWORD}`;\n"),
                ("src/form.js", "const passwordLabel = `Enter your password`;\n"),
                ("src/auth.py", 'token_url = "https://auth.example.com/oauth/token"\n'),
                ("src/pem.py", 'HEADER = "-----BEGIN PRIVATE KEY-----"\n'),
                # A second argument that names another variable, flag, field or code.
                ("settings.py", 'for var in ("SECRET_KEY", "DATABASE_URL"):\n'),
                ("cli.py", 'parser.add_argument("--token", "--github-token", help="GitHub token")\n'),
                ("app.py", 'raise AuthError("invalid_token", "TOKEN_EXPIRED")\n'),
                ("app.py", 'os.environ.get("API_TOKEN", "API_TOKEN_NOT_SET")\n'),
                ("forms.py", 'fields = ("password", "password2")\n'),
                ("i18n.js", 't("auth", "loginPage_title")\n'),
                # Outside JS/TS a backtick runs a command; its text is not the value.
                ("deploy.sh", "GITHUB_TOKEN=`cat ~/.config/gh/token`\n"),
                ("deploy.sh", "TOKEN=`vault kv get -field=token secret/app`\n"),
                ("Rakefile.rb", "secret = `openssl rand -hex 32`.strip\n"),
                ("build.pl", "my $token = `git config --get app.token`;\n")):
            with self.subTest(rel=rel, text=text):
                self.assertFalse(render.secret_in_source(rel, text))


if __name__ == "__main__":
    unittest.main()
