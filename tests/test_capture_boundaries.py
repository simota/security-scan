"""Bounded capture regressions using only owned temporary files and inert Git data."""
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import test_run_contract as fixture
from test_run_contract import SCRIPTS, git
from test_security_scan import import_module


class CaptureBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = import_module(SCRIPTS / "evidence_capture.py", "capture_boundary_tests")
        cls.contract = import_module(SCRIPTS / "contract_check.py", "capture_boundary_contract")

    setUp = fixture.RunContractTests.setUp
    base = fixture.RunContractTests.base

    def prepare(self):
        self.findings.write_text(json.dumps(self.base()), encoding="utf-8")
        return self.findings.read_bytes()

    def capture_one(self, path="src/orders.py"):
        return self.capture.capture(self.repo, self.findings, [path])

    def cli_refuses_promptly(self, path):
        done = subprocess.run([sys.executable, str(SCRIPTS / "evidence_capture.py"), str(self.repo),
                               path, "--findings", str(self.findings)],
                              capture_output=True, text=True, timeout=3)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertNotIn("Traceback", done.stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_clean_tracked_symlink_to_owned_fifo_is_never_followed(self):
        original = self.prepare()
        fifo = self.tmp / "owned-pipe"
        os.mkfifo(fifo)
        link = self.repo / "pipe-link"
        link.symlink_to(fifo)
        git(self.repo, "add", "pipe-link")
        git(self.repo, "commit", "-q", "-m", "inert symlink fixture")
        self.cli_refuses_promptly("pipe-link")
        self.assertEqual(self.findings.read_bytes(), original)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_fifo_replacing_tracked_regular_file_is_never_read(self):
        self.prepare()
        source = self.repo / "src/orders.py"
        source.unlink()
        os.mkfifo(source)
        self.cli_refuses_promptly("src/orders.py")

    def test_file_and_directory_links_and_hardlinks_are_refused(self):
        self.prepare()
        source = self.repo / "src/orders.py"
        saved = self.tmp / "saved.py"
        source.rename(saved)
        source.symlink_to(saved)
        with self.assertRaises(self.capture.CaptureError):
            self.capture_one()
        source.unlink()
        os.link(saved, source)
        with self.assertRaisesRegex(self.capture.CaptureError, "hardlinked"):
            self.capture_one()
        source.unlink()
        saved.rename(source)
        (self.repo / "src").rename(self.repo / "saved-src")
        (self.repo / "src").symlink_to("saved-src", target_is_directory=True)
        with self.assertRaises(self.capture.CaptureError):
            self.capture_one()

    def test_selected_root_aliases_are_canonicalized_but_children_stay_checked(self):
        self.prepare()
        repo_alias, out_alias = self.tmp / "repo-alias", self.tmp / "out-alias"
        repo_alias.symlink_to(self.repo, target_is_directory=True)
        out_alias.symlink_to(self.out, target_is_directory=True)
        result = self.capture.capture(repo_alias, out_alias / "findings.json", ["src/orders.py"])
        self.assertEqual(result, {"src/orders.py": "SRC-001"})

    def test_existing_record_and_artifact_are_rechecked_on_repeated_capture(self):
        self.prepare()
        self.capture_one()
        pristine = self.findings.read_bytes()
        artifact = self.out / "evidence/source/src/orders.py"
        source = artifact.read_bytes()
        for value in (b"changed\n", None):
            with self.subTest(value=value):
                if value is None:
                    artifact.unlink()
                else:
                    artifact.write_bytes(value)
                with self.assertRaises(self.capture.CaptureError):
                    self.capture_one()
                self.assertEqual(self.findings.read_bytes(), pristine)
                artifact.write_bytes(source)
        record = json.loads(pristine)
        record["evidence"][0]["sha256"] = "0" * 64
        self.findings.write_text(json.dumps(record))
        with self.assertRaisesRegex(self.capture.CaptureError, "record differs"):
            self.capture_one()

    def test_output_directory_and_existing_artifact_links_do_not_escape(self):
        original = self.prepare()
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        (self.out / "evidence").symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(self.capture.CaptureError):
            self.capture_one()
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertEqual(self.findings.read_bytes(), original)
        (self.out / "evidence").unlink()
        self.capture_one()
        artifact = self.out / "evidence/source/src/orders.py"
        artifact.unlink()
        artifact.symlink_to(self.repo / "src/orders.py")
        with self.assertRaises(self.capture.CaptureError):
            self.capture_one()

    def test_findings_symlink_is_refused(self):
        original = self.prepare()
        saved = self.tmp / "saved-findings.json"
        self.findings.rename(saved)
        self.findings.symlink_to(saved)
        with self.assertRaises(self.capture.CaptureError):
            self.capture_one()
        self.assertEqual(saved.read_bytes(), original)

    def test_oversized_worktree_and_cumulative_reads_fail_before_publication(self):
        original = self.prepare()
        with patch.object(self.capture, "MAX_FILE_BYTES", 4096):
            (self.repo / "src/orders.py").write_bytes(b"x" * 4097)
            with self.assertRaisesRegex(self.capture.CaptureError, "size_limit"):
                self.capture_one()
        self.assertEqual(self.findings.read_bytes(), original)
        (self.repo / "src/orders.py").write_text("def show(order_id):\n    return Order.get(order_id)\n")
        with patch.object(self.capture, "MAX_TOTAL_BYTES", 1):
            with self.assertRaisesRegex(self.capture.CaptureError, "total_read_limit"):
                self.capture_one()
        self.assertEqual(self.findings.read_bytes(), original)

    def test_oversized_git_object_preflight_prevents_blob_read(self):
        original = self.prepare()
        real_git = self.capture.git
        calls = []
        def bounded_git(repo, *args, **kwargs):
            calls.append(args)
            if args[:2] == ("cat-file", "-s"):
                return str(self.capture.MAX_FILE_BYTES + 1).encode()
            return real_git(repo, *args, **kwargs)
        with patch.object(self.capture, "git", side_effect=bounded_git):
            with self.assertRaisesRegex(self.capture.CaptureError, "Git object exceeds"):
                self.capture_one()
        self.assertFalse(any(args[:2] == ("cat-file", "blob") for args in calls))
        self.assertEqual(self.findings.read_bytes(), original)

    def test_git_stdout_is_bounded_even_when_preflight_was_inaccurate(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"123456789")
        os.close(write_fd)
        process = Mock(stdout=os.fdopen(read_fd, "rb"))
        process.poll.return_value = None
        process.wait.return_value = 0
        with patch.object(self.capture.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(self.capture.CaptureError, "output limit"):
                self.capture.git(self.repo, "cat-file", "blob", "0" * 40, limit=4)
        process.kill.assert_called_once()
        self.assertTrue(process.stdout.closed)

    def test_git_timeout_kills_process_without_waiting_for_unbounded_output(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        process = Mock(stdout=os.fdopen(read_fd, "rb"))
        process.poll.return_value = None
        process.wait.return_value = 0
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = []
        with patch.object(self.capture.subprocess, "Popen", return_value=process), \
                patch.object(self.capture.selectors, "DefaultSelector", return_value=selector):
            with self.assertRaisesRegex(self.capture.CaptureError, "time limit"):
                self.capture.git(self.repo, "cat-file", "blob", "0" * 40, limit=4)
        process.kill.assert_called_once()

    def test_dirty_pin_and_duplicate_paths_do_not_rewrite_assessment(self):
        self.prepare()
        self.capture.capture(self.repo, self.findings, ["src/orders.py", "src/orders.py"])
        data = json.loads(self.findings.read_text())
        self.assertEqual(len(data["evidence"]), 1)
        data["assessment"].update(worktree="dirty", diff_sha256="1" * 64)
        original = json.dumps(data)
        self.findings.write_text(original)
        with self.assertRaisesRegex(self.capture.CaptureError, "clean assessment pin"):
            self.capture_one()
        self.assertEqual(self.findings.read_text(), original)


if __name__ == "__main__":
    unittest.main()
