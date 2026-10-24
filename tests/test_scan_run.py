"""Real offline runner checkpoints, failed-stage isolation and process deadlines."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_security_scan import import_module
from test_run_contract import git

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts"
runner = import_module(SCRIPTS / "scan_run.py", "tested_scan_run")


class ScanRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="security-scan-run-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / "app"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("def hello():\n    return 'hello'\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "fixture")
        self.meta = self.fragment("meta.json", {"meta": {
            "project": "Runner fixture", "date": "2026-10-24", "assessor": "Test host (test model)"}})
        created = self.cli("init", self.repo, "--meta", self.meta, "--parent", self.base)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.root = Path(json.loads(created.stdout)["run"])
        self.out = self.root / "out"

    def fragment(self, name, value):
        path = self.base / name
        path.write_text(json.dumps(value))
        return path

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", str(SCRIPTS / "scan_run.py"), *map(str, args)],
                              capture_output=True, text=True, timeout=30)

    def invoke(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = runner.main(list(map(str, args)))
        return code, json.loads(out.getvalue()) if out.getvalue() else None

    def state(self):
        return json.loads((self.root / "state.json").read_text())

    def prepare_report(self):
        from contract_check import perspective_names
        captured = self.cli("capture", self.root, "app.py")
        self.assertEqual(captured.returncode, 0, captured.stderr)
        fragment = self.fragment("report-ready.json", {
            "perspectives": [{"name": name, "result": "Not checked - runner integration fixture"}
                             for name in perspective_names()],
            "limitations": ["invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)"]})
        self.assertEqual(self.cli("merge", self.root, fragment).returncode, 0)

    def test_finish_continues_after_offline_and_pdf_omissions_through_contract_check(self):
        self.prepare_report()
        finished = self.cli("finish", self.root, "--no-pdf")
        self.assertEqual(finished.returncode, 3, finished.stderr)
        result = json.loads(finished.stdout)
        self.assertEqual([(s["step"], s["exit_code"]) for s in result["steps"]],
                         [("inventory", 3), ("render", 3), ("check", 0)])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(self.state()["history"][-1]["step"], "finish")
        self.assertTrue((self.out / "dashboard.html").is_file())
        data = json.loads((self.out / "findings.json").read_text())
        self.assertFalse(data["dependency_scan"]["audit"])

    def test_finish_preserves_existing_inventory_without_scanning_again(self):
        self.prepare_report()
        self.assertEqual(self.cli("inventory", self.root).returncode, 3)
        before = (self.out / "deps.json").read_bytes()
        execute = runner.execute

        def no_rescan(script, argv, timeout, fd):
            self.assertNotEqual(script, "deps_scan.py", "finish must preserve recorded per-package review")
            return execute(script, argv, timeout, fd)

        with patch.object(runner, "execute", side_effect=no_rescan):
            code, result = self.invoke("finish", self.root, "--no-pdf")
        self.assertEqual(code, 3)
        self.assertEqual(result["steps"][0]["status"], "already_recorded")
        self.assertEqual((self.out / "deps.json").read_bytes(), before)

    def test_finish_returns_zero_when_every_selected_operation_and_contract_passes(self):
        self.prepare_report()
        # Model an already-recorded complete advisory result, without a provider call.
        scanner = import_module(SCRIPTS / "deps_scan.py", "finish_fixture_deps")
        deps = {"inventory": [], "findings": [], "not_run": []}
        scanner.merge_into(self.out / "findings.json", deps, audit=True)
        (self.out / "deps.json").write_text(json.dumps(deps))
        execute = runner.execute

        def successful_pdf(script, argv, timeout, fd):
            if script == "render.py" and "--no-pdf" not in argv:
                (Path(argv[argv.index("--out") + 1]) / "assessment.pdf").write_bytes(b"%PDF-fixture\n%%EOF")
                return 0
            return execute(script, argv, timeout, fd)

        with patch.object(runner, "execute", side_effect=successful_pdf):
            code, summary = self.invoke("finish", self.root)
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "complete")
        self.assertTrue(all(step["exit_code"] == 0 for step in summary["steps"]))
        self.assertEqual(summary["steps"][-1]["step"], "check")

    def test_finish_records_inventory_deadline_and_still_renders_without_automatically_retrying(self):
        self.prepare_report()
        execute, calls = runner.execute, []

        def inventory_timeout(script, argv, timeout, fd):
            if script == "deps_scan.py":
                calls.append(script)
                self.assertEqual(len(calls), 1, "failed inventory must not be retried by another finish")
                return 124
            return execute(script, argv, timeout, fd)

        with patch.object(runner, "execute", side_effect=inventory_timeout):
            code, result = self.invoke("finish", self.root, "--no-pdf")
            self.assertEqual(code, 2)
            self.assertEqual(result["steps"][0]["status"], "timed_out")
            self.assertEqual(result["steps"][-1]["step"], "check")
            self.assertNotEqual(result["steps"][-1]["exit_code"], 0)
            self.assertIn(runner.FINISH_LIMIT, (self.out / "assessment.html").read_text())
            code, resumed = self.invoke("finish", self.root, "--no-pdf")
            self.assertEqual(code, 2)
            self.assertEqual(resumed["steps"][0]["status"], "not_retried")
        self.assertEqual(len(calls), 1)
        # An explicit successful inventory makes a later finish remove the stale limit.
        self.assertEqual(self.cli("inventory", self.root).returncode, 3)
        completed = self.cli("finish", self.root, "--no-pdf")
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["steps"][-1]["exit_code"], 0)
        self.assertNotIn(runner.FINISH_LIMIT, (self.out / "assessment.html").read_text())

    def test_finish_keeps_contract_check_failure_and_render_failure_visible(self):
        self.prepare_report()
        self.assertEqual(self.cli("inventory", self.root).returncode, 3)
        execute = runner.execute

        def render_error(script, argv, timeout, fd):
            return 2 if script == "render.py" else execute(script, argv, timeout, fd)

        with patch.object(runner, "execute", side_effect=render_error):
            code, result = self.invoke("finish", self.root, "--no-pdf")
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "failed")
        self.assertEqual([s["step"] for s in result["steps"]], ["inventory", "render", "check"])
        self.assertEqual(result["steps"][1]["exit_code"], 2)
        self.assertNotEqual(result["steps"][2]["exit_code"], 0)

    def test_finish_does_not_hide_failed_refresh_behind_a_previous_inventory(self):
        self.prepare_report()
        self.assertEqual(self.cli("inventory", self.root).returncode, 3)
        with patch.object(runner, "execute", return_value=124):
            code, _ = self.invoke("inventory", self.root, "--audit")
        self.assertEqual(code, 124)
        result = self.cli("finish", self.root, "--no-pdf")
        self.assertEqual(result.returncode, 2, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["steps"][0], {"step": "inventory", "status": "not_retried", "exit_code": 124})
        self.assertEqual(summary["steps"][-1]["exit_code"], 0)
        self.assertIn(runner.FINISH_LIMIT, (self.out / "assessment.html").read_text())

    def test_finish_respects_current_interruption_but_not_previous_interruption(self):
        self.prepare_report()
        with patch.object(runner, "execute", side_effect=KeyboardInterrupt):
            code, result = self.invoke("finish", self.root, "--no-pdf")
        self.assertEqual(code, 130)
        self.assertEqual([s["step"] for s in result["steps"]], ["inventory"])
        resumed = self.cli("finish", self.root, "--no-pdf")
        self.assertEqual(resumed.returncode, 2, resumed.stderr)
        summary = json.loads(resumed.stdout)
        self.assertEqual(summary["steps"][0]["status"], "not_retried")
        self.assertEqual(summary["steps"][-1]["step"], "check")
        self.assertTrue((self.out / "assessment.html").is_file())

    def test_busy_status_is_readable_without_marking_live_work_interrupted(self):
        state = self.state()
        state["history"].append({"step": "render", "status": "running", "owner_pid": os.getpid()})
        runner.save(self.root, state)
        before = (self.root / "state.json").read_bytes()
        with runner.run_lock(self.root):
            result = self.cli("status", self.root)
        self.assertEqual(result.returncode, 3)
        snapshot = json.loads(result.stdout)
        self.assertTrue(snapshot["busy"])
        self.assertIsNone(snapshot["output_sha256"])
        self.assertEqual(snapshot["history"][-1]["status"], "running")
        self.assertEqual(snapshot["history"][-1]["owner_pid"], os.getpid())
        self.assertEqual((self.root / "state.json").read_bytes(), before)

    def test_init_uses_private_physical_directories_outside_repo(self):
        for path in (self.root, self.out, self.root / "scratch"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertEqual(self.root, self.root.resolve())
        self.assertNotIn(self.repo, self.root.parents)
        self.assertEqual(self.state()["history"][-1]["status"], "complete")
        self.assertEqual(sorted(p.name for p in self.repo.iterdir()), [".git", "app.py"])

    def test_init_resolves_symlinked_temp_parent_and_rejects_repository_parent(self):
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        created = self.cli("init", self.repo, "--meta", self.meta, "--parent", alias)
        self.assertEqual(created.returncode, 0, created.stderr)
        path = Path(json.loads(created.stdout)["run"])
        self.assertEqual(path.parent, self.base)
        denied = self.cli("init", self.repo, "--meta", self.meta, "--parent", self.repo)
        self.assertEqual(denied.returncode, 2)
        self.assertFalse(list(self.repo.glob("security-scan-run-*")))

    def test_offline_end_to_end_without_pdf_keeps_limits_and_passes_contract(self):
        from contract_check import perspective_names
        inventory = self.cli("inventory", self.root)
        self.assertEqual(inventory.returncode, 3, inventory.stderr)
        self.assertEqual(json.loads(inventory.stdout)["status"], "incomplete")
        data = json.loads((self.out / "findings.json").read_text())
        self.assertFalse(data["dependency_scan"]["audit"])
        self.assertTrue(any("not requested (--audit)" in x for x in data["limitations"]))
        captured = self.cli("capture", self.root, "app.py")
        self.assertEqual(captured.returncode, 0, captured.stderr)
        self.assertEqual((self.out / "evidence/source/app.py").read_bytes(), (self.repo / "app.py").read_bytes())
        report = self.fragment("report.json", {
            "perspectives": [{"name": name, "result": "Not checked - runner integration fixture"}
                             for name in perspective_names()],
            "limitations": ["invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)"]})
        self.assertEqual(self.cli("merge", self.root, report).returncode, 0)
        rendered = self.cli("render", self.root, "--no-pdf")
        self.assertEqual(rendered.returncode, 3, rendered.stderr)
        self.assertTrue((self.out / "dashboard.html").is_file())
        self.assertFalse((self.out / "assessment.pdf").exists())
        checked = self.cli("check", self.root)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        current = self.cli("status", self.root)
        self.assertEqual(current.returncode, 0, current.stderr)
        status = json.loads(current.stdout)
        self.assertEqual(status["history"][-1]["output_sha256"], status["output_sha256"])
        # A later record change invalidates the old checkpoint's digest.
        edit = self.fragment("edit.json", {"next_steps": ["review the synthetic application"]})
        self.assertEqual(self.cli("merge", self.root, edit).returncode, 0)
        status = json.loads(self.cli("status", self.root).stdout)
        check = next(e for e in reversed(status["history"]) if e["step"] == "check")
        self.assertNotEqual(check["output_sha256"], status["output_sha256"])

    def test_rejected_fragment_preserves_outputs_and_next_step_can_run(self):
        before = runner.tree_digest(self.out)
        bad = self.fragment("bad.json", {"schema_version": 2})
        rejected = self.cli("merge", self.root, bad)
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(runner.tree_digest(self.out), before)
        corrected = self.fragment("good.json", {"limitations": ["fixture only"]})
        resumed = self.cli("merge", self.root, corrected)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual([e["status"] for e in self.state()["history"]][-2:], ["failed", "complete"])

    def test_deadline_and_stale_child_lock_cannot_poison_published_record(self):
        before = runner.tree_digest(self.out)

        def timed_out(script, argv, timeout, fd):
            stage = Path(argv[argv.index("--into") + 1]).parent
            (stage / "findings.json.workflow.lock").write_text("interrupted child")
            (stage / "findings.json").write_text("partial")
            return 124

        with patch.object(runner, "execute", side_effect=timed_out):
            code, event = self.invoke("inventory", self.root)
        self.assertEqual(code, 124)
        self.assertEqual(event["status"], "timed_out")
        self.assertEqual(runner.tree_digest(self.out), before)
        self.assertFalse((self.out / "findings.json.workflow.lock").exists())
        self.assertEqual(self.cli("merge", self.root, self.meta).returncode, 0)

    def test_pdf_deadline_publishes_html_with_explicit_incomplete_result(self):
        real = runner.execute

        def pdf_timeout(script, argv, timeout, fd):
            if script == "render.py" and "--no-pdf" not in argv:
                return 124
            return real(script, argv, timeout, fd)

        with patch.object(runner, "execute", side_effect=pdf_timeout):
            code, event = self.invoke("render", self.root)
        self.assertEqual(code, 3)
        self.assertEqual(event["status"], "incomplete")
        self.assertTrue(any(c["exit_code"] == 124 for c in event["commands"]))
        self.assertTrue((self.out / "assessment.html").is_file())
        data = json.loads((self.out / "findings.json").read_text())
        self.assertIn("assessment.pdf not produced: PDF engine failed (runner deadline)", data["limitations"])
        self.assertIn("runner deadline", (self.out / "assessment.html").read_text())

    def test_successful_pdf_removes_old_missing_pdf_limitation(self):
        self.assertEqual(self.cli("render", self.root, "--no-pdf").returncode, 3)
        real = runner.execute

        def pdf_success(script, argv, timeout, fd):
            if script == "render.py" and "--no-pdf" not in argv:
                (Path(argv[argv.index("--out") + 1]) / "assessment.pdf").write_bytes(b"%PDF-fixture\n%%EOF")
                return 0
            return real(script, argv, timeout, fd)

        with patch.object(runner, "execute", side_effect=pdf_success):
            code, event = self.invoke("render", self.root)
        self.assertEqual(code, 0)
        self.assertEqual(event["status"], "complete")
        data = json.loads((self.out / "findings.json").read_text())
        self.assertFalse(any(x.startswith(runner.PDF_LIMIT) for x in data["limitations"]))

    def test_live_lock_returns_immediately_without_modifying_history(self):
        before = (self.root / "state.json").read_bytes()
        with runner.run_lock(self.root):
            started = time.monotonic()
            result = self.cli("inventory", self.root)
            self.assertEqual(result.returncode, 3)
            self.assertLess(time.monotonic() - started, 3)
        self.assertEqual((self.root / "state.json").read_bytes(), before)
        self.assertEqual(self.cli("status", self.root).returncode, 0)

    def test_child_retains_lock_after_parent_death_until_it_really_finishes(self):
        scripts = self.base / "fake-tools"
        scripts.mkdir()
        ready, release = self.base / "ready", self.base / "release"
        (scripts / "deps_scan.py").write_text(
            "import pathlib, time\n"
            f"pathlib.Path({str(ready)!r}).touch()\n"
            f"while not pathlib.Path({str(release)!r}).exists(): time.sleep(0.02)\n")
        launcher = self.base / "launcher.py"
        launcher.write_text(
            "import sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(SCRIPTS)!r})\nimport scan_run\n"
            f"scan_run.SCRIPTS = Path({str(scripts)!r})\n"
            f"raise SystemExit(scan_run.main(['inventory', {str(self.root)!r}]))\n")
        before = runner.tree_digest(self.out)
        with tempfile.TemporaryFile() as diagnostics:
            parent = subprocess.Popen([sys.executable, "-I", "-B", str(launcher)],
                                      stdout=diagnostics, stderr=diagnostics)
            try:
                until = time.monotonic() + 5
                while not ready.exists() and parent.poll() is None and time.monotonic() < until:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "child failed to start")
                parent.send_signal(signal.SIGKILL)
                parent.wait(timeout=5)
                # The parent is terminal, but its child is still live.
                self.assertEqual(self.cli("status", self.root).returncode, 3)
            finally:
                release.touch()
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=5)
            until = time.monotonic() + 5
            while True:
                result = self.cli("status", self.root)
                if result.returncode != 3 or time.monotonic() >= until:
                    break
                time.sleep(0.02)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(runner.tree_digest(self.out), before)
        self.assertEqual(self.state()["history"][-1]["status"], "interrupted")

    def test_preflight_does_not_execute_optional_tools_or_retry_history(self):
        with patch.object(runner, "execute") as execute:
            code, result = self.invoke("preflight", self.root)
            self.assertEqual(code, 0)
            execute.assert_not_called()
        self.assertEqual(result["writable"], {"out": True, "scratch": True})
        self.assertIn("pdf_candidate_available", result)
        self.assertIn("osv-scanner", result["audit_tools_available"])
        self.assertEqual(len(self.state()["history"]), 1)

    def test_interrupted_publication_restores_previous_output_and_records_gap(self):
        digest = runner.tree_digest(self.out)
        self.out.rename(self.root / ".previous-out")
        state = self.state()
        state["history"].append({"step": "capture", "status": "running"})
        runner.save(self.root, state)
        recovered = self.cli("status", self.root)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(runner.tree_digest(self.out), digest)
        self.assertEqual(self.state()["history"][-1]["status"], "interrupted")
        self.assertFalse((self.root / ".previous-out").exists())

    def test_external_edit_during_stage_is_not_overwritten(self):
        original = runner.tree_digest(self.out)
        staged = self.root / "scratch/staged"
        import shutil
        shutil.copytree(self.out, staged)
        (self.out / "findings.json").write_text("external edit")
        with self.assertRaisesRegex(ValueError, "changed during"):
            runner.publish(self.root, staged, original)
        self.assertEqual((self.out / "findings.json").read_text(), "external edit")

    def test_symlink_fifo_and_hardlink_outputs_are_rejected_without_reading(self):
        target = self.base / "sentinel"
        target.write_text("do not change")
        link = self.out / "unexpected"
        link.symlink_to(target)
        self.assertEqual(self.cli("inventory", self.root).returncode, 2)
        link.unlink()
        os.mkfifo(link)
        self.assertEqual(self.cli("inventory", self.root).returncode, 2)
        link.unlink()
        os.link(target, link)
        self.assertEqual(self.cli("inventory", self.root).returncode, 2)
        self.assertEqual(target.read_text(), "do not change")

    def test_child_timeout_is_real_and_never_counts_as_success(self):
        fake = self.base / "deadline.py"
        fake.write_text("import signal, time\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\ntime.sleep(30)\n")
        with runner.run_lock(self.root) as fd, patch.object(runner, "SCRIPTS", self.base):
            start = time.monotonic()
            self.assertEqual(runner.execute("deadline.py", [], 0.1, fd), 124)
            self.assertLess(time.monotonic() - start, 3)
        # The child inherited the lock and must be gone for this to succeed.
        with runner.run_lock(self.root):
            pass

    def assert_descendant_lock_released(self, mode, expected):
        ready, release = self.base / "descendant-ready", self.base / "descendant-release"
        script = self.base / "descendant.py"
        script.write_text(
            "import os, pathlib, signal, sys, time\n"
            f"ready = pathlib.Path({str(ready)!r})\n"
            f"release = pathlib.Path({str(release)!r})\n"
            "signal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n"
            "if os.fork() == 0:\n"
            "    signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            "    ready.write_text(str(os.getpid()))\n"
            "    while not release.exists(): time.sleep(0.01)\n"
            "    os._exit(0)\n"
            "while not ready.exists(): time.sleep(0.01)\n"
            f"mode = {mode!r}\n"
            "if mode == 'timeout': time.sleep(30)\n"
            "sys.exit(2 if mode == 'failed' else 0)\n")
        try:
            with runner.run_lock(self.root) as fd, patch.object(runner, "SCRIPTS", self.base):
                code = runner.execute(script.name, [], 0.5, fd)
            self.assertEqual(code, expected)
            self.assertTrue(ready.exists(), "descendant did not reach its lock-holding state")
            until = time.monotonic() + 2
            while True:
                result = self.cli("status", self.root)
                if result.returncode != 3 or time.monotonic() >= until:
                    break
                time.sleep(0.02)
            self.assertEqual(result.returncode, 0, "a surviving descendant still holds the run lock")
        finally:
            # Release an intentionally surviving fixture even when an assertion fails.
            release.touch()
            until = time.monotonic() + 3
            while self.cli("status", self.root).returncode == 3 and time.monotonic() < until:
                time.sleep(0.02)

    def test_successful_leader_does_not_leave_descendant_holding_lock(self):
        self.assert_descendant_lock_released("success", 0)

    def test_failed_leader_does_not_leave_descendant_holding_lock(self):
        self.assert_descendant_lock_released("failed", 2)

    def test_timeout_cleans_descendant_when_leader_exits_on_interrupt(self):
        self.assert_descendant_lock_released("timeout", 124)

    def test_timeout_validation_rejects_nonfinite_and_nonpositive_values(self):
        for value in ("nan", "inf", "0", "-1", "3601"):
            with self.subTest(value=value):
                result = self.cli("inventory", self.root, "--timeout", value)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
