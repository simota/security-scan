"""Offline integrity tests with inert local Git blobs; never execute target code."""
import copy
import hashlib
import json
import os
from pathlib import Path
import pickle
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import evidence_integrity as integrity


@unittest.skipUnless(os.name == "posix" and Path(integrity.GIT_BINARY).is_file(), "POSIX and trusted Git required")
class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.artifacts = self.root / "evidence"
        self.artifacts.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic verifier test")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "src").mkdir()
        self.content = b"inert fixture source, never executed\n"
        (self.repo / "src/fixture.txt").write_bytes(self.content)
        self.git("add", "src/fixture.txt")
        self.git("commit", "-qm", "synthetic baseline")
        self.commit = self.git("rev-parse", "HEAD").strip()
        (self.artifacts / "source.txt").write_bytes(self.content)
        self.data = {"schema_version": 2, "assessment": {"repository": "synthetic-local", "commit": self.commit, "worktree": "clean"},
                     "evidence": [{"id": "source", "kind": "source", "commit": self.commit, "location": "source.txt", "source_path": "src/fixture.txt", "sha256": hashlib.sha256(self.content).hexdigest(), "summary": "Synthetic fixture"}],
                     "test_runs": [], "findings": []}

    def git(self, *args):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
        return subprocess.run([integrity.GIT_BINARY, *args], cwd=self.repo, env=env, capture_output=True, text=True, check=True, timeout=10).stdout

    def verify(self, **kw):
        return integrity.verify_evidence(self.data, self.artifacts, kw.pop("repository", self.repo), **kw)

    def item(self, **kw):
        return self.verify(**kw).receipt["items"][0]

    def runtime(self):
        self.data["evidence"][0]["kind"] = "runtime"
        self.data["evidence"][0].pop("source_path")

    def test_loose_source_hash_and_git_commit_match(self):
        result = self.verify()
        self.assertEqual(result.receipt["status"], "matched")
        self.assertEqual(result.receipt["items"][0]["source"], "matched")
        self.assertEqual(result.receipt["items"][0]["observed_size"], len(self.content))
        self.assertTrue(result.matches(self.data))
        self.assertEqual(integrity.provenance_state(self.data, ["source"], result)["status"], "checked")
        self.assertEqual(self.verify().receipt, result.receipt)
        self.assertEqual(len(result.receipt["engine_sha256"]), 64)

    def test_receipt_is_sanitized_and_does_not_mutate_input(self):
        original = copy.deepcopy(self.data)
        encoded = json.dumps(self.verify().receipt)
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn(self.content.decode().strip(), encoded)
        self.assertNotIn("src/fixture.txt", encoded)
        self.assertEqual(original, self.data)

    def test_receipt_is_historical_and_cannot_construct_live_context(self):
        result = self.verify()
        stored = json.loads(json.dumps(result.receipt))
        self.assertEqual(integrity.provenance_state(self.data, ["source"], stored)["status"], "declared")
        with self.assertRaises(integrity.EvidenceError):
            integrity.VerificationResult(stored)
        with self.assertRaises(TypeError):
            pickle.dumps(result)
        result.receipt["items"][0]["source"] = "fake"
        self.assertEqual(result.receipt["items"][0]["source"], "matched")

    def test_binding_stales_relevant_changes_only(self):
        result = self.verify()
        for field in ("assessment", "evidence", "test_runs", "evidence_integrity"):
            modified = copy.deepcopy(self.data)
            modified[field] = {} if field == "evidence_integrity" else {"changed": True}
            self.assertFalse(result.matches(modified), field)
        self.data["findings"] = [{"id": "new", "verification_workflow": "changed"}]
        self.assertTrue(result.matches(self.data))
        self.data["evidence"][0]["summary"] = "changed"
        self.assertEqual(integrity.provenance_state(self.data, ["source"], result)["status"], "incomplete")
        self.assertEqual(integrity.provenance_state(self.data, ["source"], result)["reasons"], ["context_stale"])

    def test_runtime_hash_does_not_attest_revision_or_execute_command(self):
        self.runtime()
        sentinel = self.root / "executed"
        self.data["test_runs"] = [{"command": "touch " + str(sentinel)}]
        with patch.object(integrity.subprocess, "Popen", side_effect=AssertionError("no Git needed")):
            result = self.verify(repository=None)
        self.assertEqual(result.receipt["items"][0]["source"], "declared")
        self.assertEqual(integrity.provenance_state(self.data, ["source"], result)["status"], "checked")
        self.assertFalse(sentinel.exists())

    def test_environment_bytes_also_leave_revision_declared(self):
        self.runtime()
        self.data["evidence"][0]["kind"] = "environment"
        self.assertEqual(self.item(repository=None)["reason"], "bytes_matched_revision_declared")

    def test_source_needs_explicit_source_path_and_repository(self):
        self.assertEqual(self.item(repository=None)["reason"], "repository_required")
        del self.data["evidence"][0]["source_path"]
        self.assertEqual(self.item()["reason"], "source_path_required")

    def test_dirty_source_is_not_verified(self):
        self.data["evidence"][0]["diff_sha256"] = "a" * 64
        self.assertEqual(self.item()["reason"], "dirty_source_unsupported")

    def test_uncommitted_worktree_does_not_change_pinned_evidence(self):
        (self.repo / "src/fixture.txt").write_text("different uncommitted data")
        self.assertEqual(self.item()["source"], "matched")

    def test_missing_wrong_hash_and_wrong_git_source(self):
        (self.artifacts / "source.txt").unlink()
        self.assertEqual(self.item()["reason"], "file_missing")
        (self.artifacts / "source.txt").write_text("different")
        item = self.item()
        self.assertEqual(item["reason"], "sha256_mismatch")
        self.assertNotIn("observed_sha256", item)
        self.data["evidence"][0]["sha256"] = hashlib.sha256(b"different").hexdigest()
        self.assertEqual(self.item()["reason"], "git_source_bytes_mismatch")

    def test_unknown_commit_noncommit_and_missing_git_path(self):
        record = self.data["evidence"][0]
        record["commit"] = "f" * 40
        self.assertEqual(self.item()["reason"], "git_object_unavailable")
        record["commit"] = self.git("rev-parse", "HEAD:src/fixture.txt").strip()
        self.assertIn(self.item()["reason"], ("git_object_unavailable", "git_object_identity_mismatch"))
        record["commit"] = self.commit
        record["source_path"] = "missing"
        self.assertEqual(self.item()["reason"], "git_source_path_missing")

    def test_rejects_unsafe_artifact_paths_without_read(self):
        record = self.data["evidence"][0]
        for path in ("../outside", "/etc/passwd", "https://example.invalid/a", "file:///etc/passwd", "source.txt:1-2", "a/./b", "a//b", "a/../b", "C:\\file", "nul\x00"):
            with self.subTest(path=path):
                record["location"] = path
                self.assertEqual(self.item()["reason"], "unsafe_path")

    def test_source_paths_never_interpret_git_revision_syntax(self):
        for path in ("HEAD:src/fixture.txt", ":(top)src", "../fixture", "/src/fixture.txt"):
            self.data["evidence"][0]["source_path"] = path
            self.assertEqual(self.item()["reason"], "unsafe_path")

    def test_symlink_artifact_and_parent_are_rejected(self):
        original = self.artifacts / "source.txt"
        original.rename(self.artifacts / "actual.txt")
        original.symlink_to("actual.txt")
        self.assertEqual(self.item()["reason"], "unsafe_path")
        self.data["evidence"][0]["location"] = "sub/actual.txt"
        (self.artifacts / "sub").symlink_to(self.artifacts, target_is_directory=True)
        self.assertEqual(self.item()["reason"], "unsafe_path")
        linkroot = self.root / "linked-root"
        linkroot.symlink_to(self.artifacts, target_is_directory=True)
        result = integrity.verify_evidence(self.data, linkroot, self.repo)
        self.assertEqual(result.receipt["status"], "incomplete")

    def test_hardlink_fifo_directory_are_rejected(self):
        artifact = self.artifacts / "source.txt"
        os.link(artifact, self.artifacts / "another")
        self.assertEqual(self.item()["reason"], "hardlinked_file")
        (self.artifacts / "another").unlink()
        artifact.unlink()
        os.mkfifo(artifact)
        self.assertEqual(self.item()["reason"], "not_regular_file")
        artifact.unlink()
        artifact.mkdir()
        self.assertEqual(self.item()["reason"], "not_regular_file")

    def test_oversize_and_total_byte_caps(self):
        with patch.object(integrity, "MAX_FILE_BYTES", len(self.content) - 1):
            self.assertEqual(self.item()["reason"], "size_limit")
        with patch.object(integrity, "MAX_TOTAL_BYTES", 1):
            self.assertEqual(self.item()["reason"], "total_read_limit")
        with patch.object(integrity, "MAX_SNAPSHOT_BYTES", 1):
            self.assertEqual(self.item()["reason"], "size_limit")

    def test_failed_reads_still_debit_shared_artifact_budget(self):
        self.runtime()
        self.content = b"a" * 1024
        self.data["evidence"] = []
        for index in range(3):
            name = "artifact-" + str(index)
            (self.artifacts / name).write_bytes(self.content)
            self.data["evidence"].append({"id": name, "kind": "runtime", "commit": self.commit, "location": name, "summary": "inert", "sha256": hashlib.sha256(self.content).hexdigest()})
        real_read, consumed = integrity.os.read, []
        def growing(fd, count):
            block = real_read(fd, count)
            consumed.append(len(block))
            with (self.artifacts / "artifact-0").open("ab") as f:
                f.write(b"more")
            return block
        with patch.object(integrity, "MAX_TOTAL_BYTES", 1024), patch.object(integrity.os, "read", side_effect=growing):
            result = self.verify(repository=None)
        self.assertLessEqual(sum(consumed), 1024)
        self.assertEqual(result.receipt["status"], "incomplete")
        self.assertEqual(result.receipt["items"][0]["reason"], "file_changed")
        self.assertTrue(all(i["reason"] == "total_read_limit" for i in result.receipt["items"][1:]))

    def test_final_revalidation_uses_same_total_read_budget(self):
        self.runtime()
        with patch.object(integrity, "MAX_TOTAL_BYTES", len(self.content)):
            item = self.item(repository=None)
        self.assertEqual(item["reason"], "total_read_limit")
        self.assertNotIn("observed_sha256", item)
        with patch.object(integrity, "MAX_TOTAL_BYTES", 2 * len(self.content)):
            self.assertEqual(self.item(repository=None)["bytes"], "matched")

    def test_final_revalidation_catches_early_cross_file_changes(self):
        self.runtime()
        other = copy.deepcopy(self.data["evidence"][0])
        other.update(id="z-later", location="later.txt")
        self.data["evidence"].append(other)
        (self.artifacts / "later.txt").write_bytes(self.content)
        real_read, fired = integrity._Root.read, []
        def changing(root, path, *args, **kwargs):
            result = real_read(root, path, *args, **kwargs)
            if path == "later.txt" and not fired:
                fired.append(True)
                (self.artifacts / "source.txt").write_bytes(b"later alteration")
            return result
        with patch.object(integrity._Root, "read", changing):
            result = self.verify(repository=None)
        item = result.receipt["items"][0]
        self.assertEqual(result.receipt["status"], "incomplete")
        self.assertEqual(item["reason"], "file_changed")
        self.assertNotIn("observed_sha256", item)
        self.assertNotIn("observed_size", item)

    def test_actual_artifact_mutation_and_path_replacement_are_rejected(self):
        real_read = integrity.os.read
        artifact = self.artifacts / "source.txt"
        fired = []
        def racing(fd, count):
            block = real_read(fd, count)
            if not fired:
                fired.append(True)
                artifact.write_bytes(self.content + b"changed")
            return block
        with patch.object(integrity.os, "read", side_effect=racing):
            self.assertEqual(self.item()["reason"], "file_changed")
        artifact.write_bytes(self.content)
        fired.clear()
        def replacing(fd, count):
            block = real_read(fd, count)
            if not fired:
                fired.append(True)
                artifact.rename(self.artifacts / "old")
                artifact.write_bytes(self.content)
            return block
        with patch.object(integrity.os, "read", side_effect=replacing):
            self.assertEqual(self.item()["reason"], "file_changed")

    def test_parent_directory_swap_is_rejected(self):
        sub = self.artifacts / "sub"
        sub.mkdir()
        (self.artifacts / "source.txt").rename(sub / "source.txt")
        self.data["evidence"][0]["location"] = "sub/source.txt"
        real_read, fired = integrity.os.read, []
        def swapping(fd, count):
            block = real_read(fd, count)
            if not fired:
                fired.append(True)
                sub.rename(self.artifacts / "old-sub")
                sub.mkdir()
                (sub / "source.txt").write_bytes(self.content)
            return block
        with patch.object(integrity.os, "read", side_effect=swapping):
            self.assertEqual(self.item()["reason"], "path_changed")

    def test_packed_objects_and_bare_repository(self):
        self.git("gc", "--prune=now", "--quiet")
        self.assertEqual(self.item()["source"], "matched")
        self.assertEqual(self.item(repository=self.repo / ".git")["source"], "matched")

    def test_no_target_config_hooks_replacements_or_environment_are_used(self):
        sentinel = self.root / "executed"
        hook = self.repo / ".git/hooks/post-checkout"
        hook.write_text("#!/bin/sh\ntouch '" + str(sentinel) + "'\n")
        hook.chmod(0o755)
        with (self.repo / ".git/config").open("a") as f:
            f.write("\n[include]\n path = /this/does/not/exist\n[core]\n fsmonitor = " + str(hook) + "\n[alias]\n cat-file = !touch " + str(sentinel) + "\n")
        poison = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": str(hook), "GIT_DIR": "/bad", "GIT_OBJECT_DIRECTORY": "/bad", "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/bad", "GIT_CONFIG": "/bad", "LD_PRELOAD": "/bad", "PATH": str(self.root)}
        with patch.dict(os.environ, poison):
            self.assertEqual(self.item()["source"], "matched")
        self.assertFalse(sentinel.exists())

    def test_alternates_promisor_and_grafts_fail_closed(self):
        for suffix in ("objects/info/alternates", "objects/info/http-alternates", "info/grafts"):
            path = self.repo / ".git" / suffix
            path.parent.mkdir(exist_ok=True)
            path.write_text("/outside-must-not-read")
            self.assertEqual(self.item()["reason"], "git_external_store_unsupported")
            path.unlink()
        path = self.repo / ".git/objects/pack/untrusted.promisor"
        path.write_text("")
        self.assertEqual(self.item()["reason"], "git_promisor_unsupported")

    def test_git_directory_file_and_symlink_object_are_unsupported(self):
        gitdir = self.repo / ".git"
        gitdir.rename(self.repo / "real-git")
        gitdir.write_text("gitdir: real-git\n")
        self.assertEqual(self.item()["reason"], "git_directory_file_unsupported")
        gitdir.unlink()
        (self.repo / "real-git").rename(gitdir)
        obj = next(p for p in (gitdir / "objects").glob("??/*") if p.is_file())
        actual = self.root / "actual-object"
        obj.rename(actual)
        obj.symlink_to(actual)
        self.assertEqual(self.item()["reason"], "unsafe_path")

    def test_git_symlink_blob_is_not_a_source(self):
        (self.repo / "src/link").symlink_to("fixture.txt")
        self.git("add", "src/link")
        self.git("commit", "-qm", "synthetic link")
        self.data["evidence"][0]["commit"] = self.git("rev-parse", "HEAD").strip()
        self.data["evidence"][0]["source_path"] = "src/link"
        self.assertEqual(self.item()["reason"], "git_source_not_regular")

    def test_replacement_refs_cannot_substitute_target_commit(self):
        (self.repo / "src/fixture.txt").write_bytes(b"different committed source")
        self.git("add", "src/fixture.txt")
        self.git("commit", "-qm", "replacement candidate")
        replacement = self.git("rev-parse", "HEAD").strip()
        self.git("replace", self.commit, replacement)
        self.assertEqual(self.item()["source"], "matched")

    def test_git_object_names_are_not_trusted_as_hashes(self):
        import zlib
        blob = self.git("rev-parse", "HEAD:src/fixture.txt").strip()
        forged = b"forged object bytes"
        path = self.repo / ".git/objects" / blob[:2] / blob[2:]
        path.chmod(0o600)
        path.write_bytes(zlib.compress(b"blob " + str(len(forged)).encode() + b"\0" + forged))
        (self.artifacts / "source.txt").write_bytes(forged)
        self.data["evidence"][0]["sha256"] = hashlib.sha256(forged).hexdigest()
        self.assertEqual(self.item()["reason"], "git_object_identity_mismatch")

    def test_gitlink_is_not_a_regular_committed_source(self):
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.commit + ",src/module")
        self.git("commit", "-qm", "inert gitlink")
        self.data["evidence"][0]["commit"] = self.git("rev-parse", "HEAD").strip()
        self.data["evidence"][0]["source_path"] = "src/module"
        self.assertEqual(self.item()["reason"], "git_source_not_regular")

    def test_git_hardlink_and_count_limit_are_rejected(self):
        obj = next(p for p in (self.repo / ".git/objects").glob("??/*") if p.is_file())
        os.link(obj, self.root / "object-link")
        self.assertEqual(self.item()["reason"], "hardlinked_file")
        (self.root / "object-link").unlink()
        with patch.object(integrity, "MAX_OBJECT_FILES", 1):
            self.assertEqual(self.item()["reason"], "object_count_limit")

    def test_global_deadline_reports_incomplete(self):
        with patch.object(integrity, "MAX_SECONDS", -1):
            self.assertEqual(self.item()["reason"], "time_limit")

    def test_malformed_assessment_and_nonfinite_json_are_sanitized(self):
        self.data["assessment"]["commit"] = int("1" * 40)
        with self.assertRaises(integrity.EvidenceError):
            self.verify()
        self.data["assessment"]["commit"] = self.commit
        self.data["test_runs"] = [{"untrusted": float("nan")}]
        with self.assertRaises(integrity.EvidenceError):
            self.verify()

    def test_sha256_repository(self):
        other = self.root / "sha256"
        other.mkdir()
        self.repo = other
        try:
            self.git("init", "--object-format=sha256", "-q")
        except subprocess.CalledProcessError:
            self.skipTest("Git lacks SHA-256 support")
        self.git("config", "user.name", "Synthetic")
        self.git("config", "user.email", "fixture@example.invalid")
        (other / "source.txt").write_bytes(self.content)
        self.git("add", "source.txt")
        self.git("commit", "-qm", "synthetic")
        commit = self.git("rev-parse", "HEAD").strip()
        self.data["assessment"]["commit"] = commit
        self.data["evidence"][0].update(commit=commit, source_path="source.txt")
        self.assertEqual(self.item()["source"], "matched")
        self.git("gc", "--prune=now", "--quiet")
        self.assertEqual(self.item()["source"], "matched")

    def test_selected_subset_does_not_upgrade_unchecked_records(self):
        other = copy.deepcopy(self.data["evidence"][0])
        other["id"] = "other"
        self.data["evidence"].append(other)
        result = self.verify(evidence_ids=["source"])
        self.assertEqual(result.receipt["selection"], ["source"])
        state = integrity.provenance_state(self.data, ["source", "other"], result)
        self.assertEqual(state["status"], "incomplete")
        self.assertEqual(state["reasons"], ["evidence_not_checked"])
        self.assertEqual(self.verify(evidence_ids=[]).receipt["status"], "incomplete")

    def test_invalid_schema_selection_and_unsupported_platform_fail_closed(self):
        for selection in (["missing"], ["source", "source"], "source"):
            with self.assertRaises(integrity.EvidenceError):
                self.verify(evidence_ids=selection)
        self.data["schema_version"] = 1
        with self.assertRaises(integrity.EvidenceError):
            self.verify()
        self.data["schema_version"] = 2
        with patch.object(integrity.os, "supports_dir_fd", set()):
            self.assertEqual(self.item()["reason"], "unsupported_platform")

    def test_git_timeout_output_limit_and_executable_failure(self):
        with patch.object(integrity, "GIT_TIMEOUT", -1):
            self.assertEqual(self.item()["reason"], "git_timeout")
        with patch.object(integrity, "GIT_BINARY", "/definitely/not/installed"):
            self.assertEqual(self.item()["reason"], "trusted_git_unavailable")
        # Commit bytes exceed a small object quota even though evidence fits.
        with patch.object(integrity, "MAX_FILE_BYTES", len(self.content)):
            self.assertEqual(self.item()["reason"], "git_object_size_limit")

    def test_cli_malformed_shapes_never_traceback_or_echo_input(self):
        findings = self.root / "private-findings.json"
        out = self.root / "private-receipt.json"
        command = [sys.executable, str(SCRIPTS / "evidence_integrity.py"), "verify", str(findings), "--root", str(self.artifacts), "--repository", str(self.repo), "--out", str(out)]
        private = "sensitive-input-must-not-appear"
        malformed = [None, [], 2, private, {"schema_version": 2}]
        for value in (None, {}, private, [None], [2], [private], [{}], [{"id": []}], [{"id": private, "validation": []}], [{"id": private, "validation": {"verdict": []}}]):
            data = copy.deepcopy(self.data)
            data["findings"] = value
            malformed.append(data)
        data = copy.deepcopy(self.data)
        data["meta"] = private
        malformed.append(data)
        data = copy.deepcopy(self.data)
        data["findings"] = [{"id": private}, {"id": private}]
        malformed.append(data)
        for index, value in enumerate(malformed):
            with self.subTest(index=index):
                findings.write_text(json.dumps(value))
                completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 2)
                self.assertNotIn("Traceback", completed.stderr)
                self.assertNotIn(private, completed.stderr)
                self.assertNotIn(str(self.root), completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertFalse(out.exists())

    def test_cli_strict_json_new_receipt_and_safe_errors(self):
        findings = self.root / "findings.json"
        findings.write_text(json.dumps(self.data))
        out = self.root / "receipt.json"
        command = [sys.executable, str(SCRIPTS / "evidence_integrity.py"), "verify", str(findings), "--root", str(self.artifacts), "--repository", str(self.repo), "--out", str(out)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(out.read_text())["status"], "matched")
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        before = out.read_bytes()
        repeated = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(repeated.returncode, 2)
        self.assertEqual(out.read_bytes(), before)
        out.unlink()
        findings.write_text('{"schema_version":2,"schema_version":2}')
        invalid = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("duplicate_json_key", invalid.stderr)
        self.assertNotIn(str(self.root), invalid.stderr)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
