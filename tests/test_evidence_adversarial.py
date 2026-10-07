"""Independent offline evidence-boundary regressions; inert bytes and local Git only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import evidence_integrity as evidence
import reproduction
import reproduction_runtime
import verification


@unittest.skipUnless(os.name == "posix" and Path("/usr/bin/git").is_file(), "POSIX and installed Git required")
class EvidenceAdversarialTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="evidence-adversarial-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo, self.artifacts = self.root / "repository", self.root / "artifacts"
        self.repo.mkdir()
        self.artifacts.mkdir()
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_AUTHOR_NAME": "Synthetic", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Synthetic", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                    "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
        self.git("init", "-q")
        self.body = b"INERT_PRIVATE_ARTIFACT_CONTENT\n"
        (self.repo / "source.txt").write_bytes(self.body)
        self.git("add", "source.txt")
        self.git("commit", "-qm", "synthetic first")
        self.first = self.git("rev-parse", "HEAD").strip()
        self.blob = self.git("rev-parse", "HEAD:source.txt").strip()
        (self.artifacts / "record.txt").write_bytes(self.body)
        self.data = {"schema_version": 2,
                     "assessment": {"repository": "synthetic", "commit": self.first, "worktree": "clean"},
                     "evidence": [{"id": "source", "kind": "source", "commit": self.first,
                                   "location": "record.txt", "source_path": "source.txt",
                                   "summary": "Synthetic artifact", "sha256": hashlib.sha256(self.body).hexdigest()}],
                     "test_runs": [], "findings": []}

    def git(self, *args):
        return subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
                              cwd=self.repo, env=self.env, check=True, text=True, capture_output=True, timeout=10).stdout

    def checked(self):
        return evidence.verify_evidence(self.data, self.artifacts, self.repo)

    def item(self):
        return self.checked().receipt["items"][0]

    def runtime(self):
        self.data["evidence"][0]["kind"] = "runtime"
        self.data["evidence"][0].pop("source_path", None)

    def second_commit(self):
        (self.repo / "source.txt").write_bytes(b"different inert committed bytes\n")
        self.git("add", "source.txt")
        self.git("commit", "-qm", "synthetic second")
        return self.git("rev-parse", "HEAD").strip()

    def test_real_other_commit_cannot_match_original_artifact(self):
        self.data["evidence"][0]["commit"] = self.second_commit()
        self.assertEqual(self.item()["reason"], "git_source_bytes_mismatch")

    def test_replace_refs_cannot_substitute_commit_tree(self):
        other = self.second_commit()
        replacements = self.repo / ".git/refs/replace"
        replacements.mkdir()
        (replacements / self.first).write_text(other + "\n")
        # Original bytes still work despite a real replacement ref.
        self.assertEqual(self.item()["source"], "matched")
        replacement = (self.repo / "source.txt").read_bytes()
        (self.artifacts / "record.txt").write_bytes(replacement)
        self.data["evidence"][0]["sha256"] = hashlib.sha256(replacement).hexdigest()
        self.assertEqual(self.item()["reason"], "git_source_bytes_mismatch")

    def test_loose_object_filename_is_not_identity_proof(self):
        forged = b"forged content with its own declared artifact digest\n"
        (self.artifacts / "record.txt").write_bytes(forged)
        self.data["evidence"][0]["sha256"] = hashlib.sha256(forged).hexdigest()
        obj = self.repo / ".git/objects" / self.blob[:2] / self.blob[2:]
        obj.unlink()
        obj.write_bytes(zlib.compress(b"blob " + str(len(forged)).encode() + b"\0" + forged))
        self.assertIn(self.item()["reason"], ("git_object_identity_mismatch", "git_object_unavailable"))
        self.assertEqual(self.checked().receipt["status"], "incomplete")

    def test_object_count_and_expanded_object_limits_fail_closed(self):
        with patch.object(evidence, "MAX_OBJECT_FILES", 1):
            self.assertEqual(self.item()["reason"], "object_count_limit")
        # A commit is larger than the short artifact even when stored compressed.
        with patch.object(evidence, "MAX_FILE_BYTES", len(self.body)):
            self.assertEqual(self.item()["reason"], "git_object_size_limit")

    def test_forged_pack_index_is_not_a_successful_lookup(self):
        self.git("gc", "--quiet", "--prune=now")
        idx = next((self.repo / ".git/objects/pack").glob("*.idx"))
        idx.unlink()
        idx.write_bytes(b"not a Git index")
        item = self.item()
        self.assertNotEqual(item["source"], "matched")
        self.assertNotIn("not a Git index", json.dumps(self.checked().receipt))

    def test_hardlinked_git_objects_fail_closed(self):
        obj = self.repo / ".git/objects" / self.blob[:2] / self.blob[2:]
        os.link(obj, self.root / "object-alias")
        self.assertEqual(self.item()["reason"], "hardlinked_file")

    def test_target_config_fifo_and_hook_symlink_are_never_opened(self):
        config = self.repo / ".git/config"
        config.unlink()
        os.mkfifo(config)
        (self.repo / ".git/hooks/post-checkout").symlink_to(self.root / "never-executed")
        self.assertEqual(self.item()["source"], "matched")

    def test_all_git_invocations_use_sanitized_private_repository(self):
        real_popen, calls = evidence.subprocess.Popen, []
        def checked_popen(command, **kwargs):
            calls.append((command, kwargs))
            self.assertEqual(command[0], "/usr/bin/git")
            self.assertEqual(kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(kwargs["env"]["GIT_CONFIG_COUNT"], "0")
            self.assertNotIn("LD_PRELOAD", kwargs["env"])
            self.assertNotIn("GIT_SSH_COMMAND", kwargs["env"])
            self.assertNotIn("SECRET_SENTINEL", kwargs["env"])
            self.assertNotEqual(kwargs["cwd"], str(self.repo))
            self.assertIn("protocol.allow=never", command)
            self.assertIn("cat-file", command)
            self.assertNotIn("fetch", command)
            return real_popen(command, **kwargs)
        with patch.dict(os.environ, {"LD_PRELOAD": "/bad", "GIT_SSH_COMMAND": "not-run", "SECRET_SENTINEL": "not-copied"}), \
                patch.object(evidence.subprocess, "Popen", side_effect=checked_popen):
            self.assertEqual(self.item()["source"], "matched")
        self.assertGreaterEqual(len(calls), 3)

    def test_missing_objects_never_start_network_helpers(self):
        self.data["evidence"][0]["commit"] = "f" * 40
        with (self.repo / ".git/config").open("a") as config:
            config.write("\n[remote \"origin\"]\n url = ssh://must-not-contact.invalid/repo\n promisor = true\n")
        commands, real_popen = [], evidence.subprocess.Popen
        def tracked(command, **kwargs):
            commands.append(command)
            return real_popen(command, **kwargs)
        with patch.object(evidence.subprocess, "Popen", side_effect=tracked):
            self.assertEqual(self.item()["reason"], "git_object_unavailable")
        self.assertTrue(commands)
        self.assertTrue(all("cat-file" in command and "fetch" not in command for command in commands))

    def test_socket_mode_is_rejected_without_content_read(self):
        # Inject only the stat result: this offline test opens no real socket.
        artifact_inode = (self.artifacts / "record.txt").stat().st_ino
        real_fstat = evidence.os.fstat
        def socket_stat(fd):
            result = real_fstat(fd)
            if result.st_ino == artifact_inode:
                fields = list(result)
                fields[0] = stat.S_IFSOCK | 0o600
                return os.stat_result(fields)
            return result
        self.runtime()
        with patch.object(evidence.os, "fstat", side_effect=socket_stat), \
                patch.object(evidence.os, "read", side_effect=AssertionError("socket must not be read")):
            self.assertEqual(self.item()["reason"], "not_regular_file")

    def test_hardlink_added_mid_read_is_rejected(self):
        real_read, changed = evidence.os.read, []
        def raced(fd, count):
            raw = real_read(fd, count)
            if raw and not changed:
                changed.append(True)
                os.link(self.artifacts / "record.txt", self.root / "late-alias")
            return raw
        with patch.object(evidence.os, "read", side_effect=raced):
            self.assertEqual(self.item()["reason"], "file_changed")

    def test_root_directory_replacement_mid_read_is_rejected(self):
        real_read, changed = evidence.os.read, []
        def raced(fd, count):
            raw = real_read(fd, count)
            if raw and not changed:
                changed.append(True)
                self.artifacts.rename(self.root / "original-artifacts")
                self.artifacts.mkdir()
                (self.artifacts / "record.txt").write_bytes(self.body)
            return raw
        with patch.object(evidence.os, "read", side_effect=raced):
            self.assertEqual(self.item()["reason"], "path_changed")

    def test_failed_reads_cannot_reset_total_artifact_byte_budget(self):
        self.runtime()
        body = b"x" * 1024
        self.data["evidence"] = []
        paths = {}
        for index in range(3):
            path = self.artifacts / (str(index) + ".txt")
            path.write_bytes(body)
            paths[path.stat().st_ino] = path
            self.data["evidence"].append({"id": str(index), "kind": "runtime", "commit": self.first,
                "location": path.name, "summary": "Synthetic", "sha256": hashlib.sha256(body).hexdigest()})
        real_read, total, changed = evidence.os.read, [0], set()
        def grow_once(fd, count):
            raw = real_read(fd, count)
            inode = os.fstat(fd).st_ino
            if inode in paths:
                total[0] += len(raw)
                if raw and inode not in changed:
                    changed.add(inode)
                    with paths[inode].open("ab") as output:
                        output.write(b"!")
            return raw
        with patch.object(evidence, "MAX_TOTAL_BYTES", len(body)), patch.object(evidence.os, "read", side_effect=grow_once):
            receipt = self.checked().receipt
        self.assertEqual(receipt["status"], "incomplete")
        # One sentinel byte may detect growth; a failed read cannot replenish the quota.
        self.assertLessEqual(total[0], len(body) + 1)

    def test_wrong_hash_does_not_publish_new_fingerprint_or_content(self):
        self.data["evidence"][0]["sha256"] = "0" * 64
        receipt = self.checked().receipt
        raw = json.dumps(receipt)
        self.assertNotIn(hashlib.sha256(self.body).hexdigest(), raw)
        self.assertNotIn(self.body.decode().strip(), raw)
        self.assertNotIn(str(self.root), raw)
        self.assertNotIn("observed_size", receipt["items"][0])

    def test_receipt_field_mutation_and_deserialization_have_no_authority(self):
        result = self.checked()
        receipt = result.receipt
        receipt["status"] = "matched"
        receipt["items"][0]["source"] = "anything"
        self.assertEqual(result.receipt["items"][0]["source"], "matched")
        forged = json.loads(json.dumps(receipt))
        state = evidence.provenance_state(self.data, ["source"], forged)
        self.assertEqual(state["status"], "declared")
        self.assertEqual(state["reasons"], ["recorded_receipt_only"])

    def test_missing_checked_selection_cannot_be_added_after_verification(self):
        result = self.checked()
        added = copy.deepcopy(self.data["evidence"][0])
        added["id"] = "later"
        self.data["evidence"].append(added)
        state = evidence.provenance_state(self.data, ["source", "later"], result)
        self.assertEqual(state["status"], "incomplete")
        self.assertEqual(state["reasons"], ["context_stale"])

    def structured_fixture(self):
        after = self.second_commit()
        text = (ROOT / "examples/findings.verification.sample.json").read_text()
        self.data = json.loads(text.replace("1" * 40, self.first).replace("2" * 40, after))
        self.data["evidence_integrity"] = {"required": True}
        for record in self.data["evidence"]:
            body = self.body if record["kind"] == "source" else ("Synthetic log " + record["id"]).encode()
            record["location"] = record["id"] + ".txt"
            record["sha256"] = hashlib.sha256(body).hexdigest()
            (self.artifacts / record["location"]).write_bytes(body)
            if record["kind"] == "source":
                record["source_path"] = "source.txt"
        return after

    def test_source_only_context_cannot_bypass_required_runtime_checks(self):
        self.structured_fixture()
        partial = evidence.verify_evidence(self.data, self.artifacts, self.repo, ["source-before"])
        finding = self.data["findings"][0]
        state = verification.derive_verification(self.data, integrity=partial)[finding["id"]]
        self.assertEqual(state["level"], "incomplete")
        self.assertEqual(state["retest"], "incomplete")
        self.assertIn("evidence_integrity_failed", state["gaps"])
        self.assertIn("evidence_not_checked", state["integrity"]["reasons"])

    def test_matching_bytes_cannot_upgrade_mocked_boundary(self):
        self.structured_fixture()
        self.data["test_runs"][0]["context"]["boundary"] = "mocked"
        state = verification.derive_verification(self.data, integrity=self.checked())[self.data["findings"][0]["id"]]
        self.assertEqual(state["integrity"]["status"], "checked")
        self.assertNotEqual(state["level"], "runtime_supported")
        self.assertNotEqual(state["retest"], "verified")
        self.assertIn("runtime_boundary_unverified", state["gaps"])

    def test_wrong_commit_evidence_cannot_satisfy_assessment_pin(self):
        after = self.structured_fixture()
        record = next(record for record in self.data["evidence"] if record["kind"] == "source")
        record["commit"] = after
        body = (self.repo / "source.txt").read_bytes()
        (self.artifacts / record["location"]).write_bytes(body)
        record["sha256"] = hashlib.sha256(body).hexdigest()
        self.assertEqual(self.checked().receipt["status"], "matched")
        # A real byte match at another commit still cannot satisfy this finding.
        with self.assertRaises(ValueError):
            verification.derive_verification(self.data, integrity=self.checked())

    def reseal_manifest(self, bundle, manifest, reidentify=False):
        if reidentify:
            identity = {key: value for key, value in manifest.items()
                        if key not in ("bundle_id", "namespace", "files", "fixture_sha256", "configuration_sha256")}
            manifest["bundle_id"] = reproduction_runtime.digest(reproduction_runtime.canonical(identity))
            manifest["namespace"] = "ss-" + manifest["bundle_id"][:20]
            manifest["fixture_sha256"] = reproduction_runtime.digest(
                reproduction_runtime.canonical(reproduction_runtime.fixture_data(manifest)))
        (bundle / "manifest.json").write_bytes(reproduction_runtime.canonical(manifest))
        seal = {"sha256": reproduction_runtime.digest(reproduction_runtime.canonical(manifest))}
        (bundle / "manifest.sha256.json").write_bytes(reproduction_runtime.canonical(seal))

    def test_removing_receipt_marker_cannot_disable_required_standalone_gate(self):
        after = self.structured_fixture()
        findings = self.root / "findings.json"
        findings.write_text(json.dumps(self.data))
        plan = json.loads((ROOT / "examples/reproduction.plan.sample.json").read_text())
        plan["after"]["commit"] = after
        bundle = self.root / "bundle"
        reproduction.generate(findings, self.data["findings"][0]["id"], plan, bundle,
                              evidence_root=self.artifacts, evidence_repository=self.repo)
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest.pop("evidence_receipt_sha256")
        # Recompute every public digest too: the policy gate must stand on its own.
        self.reseal_manifest(bundle, manifest, reidentify=True)
        (self.artifacts / "source-before.txt").unlink()
        completed = subprocess.run([sys.executable, "-I", "-S", str(bundle / "run.py"),
                                    "--findings", str(findings)], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotEqual(json.loads(completed.stdout).get("status"), "completed")
        with self.assertRaises(ValueError):
            reproduction.verify(bundle, findings, self.artifacts, self.repo)

    def test_malformed_required_policy_is_sanitized_by_standalone_runner(self):
        after = self.structured_fixture()
        findings = self.root / "findings.json"
        findings.write_text(json.dumps(self.data))
        plan = json.loads((ROOT / "examples/reproduction.plan.sample.json").read_text())
        plan["after"]["commit"] = after
        bundle = self.root / "bundle"
        reproduction.generate(findings, self.data["findings"][0]["id"], plan, bundle,
                              evidence_root=self.artifacts, evidence_repository=self.repo)
        original = json.loads((bundle / "manifest.json").read_text())
        for malformed in ([], {"schema_version": 2, "evidence_integrity": True}):
            with self.subTest(malformed=malformed):
                findings.write_text(json.dumps(malformed))
                manifest = copy.deepcopy(original)
                manifest["findings_sha256"] = reproduction_runtime.digest(findings.read_bytes())
                self.reseal_manifest(bundle, manifest, reidentify=True)
                completed = subprocess.run([sys.executable, "-I", "-S", str(bundle / "run.py"),
                                            "--findings", str(findings)], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("Traceback", completed.stderr)
                self.assertNotIn(str(self.root), completed.stderr)
                self.assertEqual(json.loads(completed.stdout).get("status"), "error")

    def seeded_checked_bundle(self):
        after = self.structured_fixture()
        findings = self.root / "findings.json"
        findings.write_text(json.dumps(self.data))
        plan = json.loads((ROOT / "examples/reproduction.plan.sample.json").read_text())
        plan["after"]["commit"] = after
        bundle = self.root / "bundle"
        reproduction.generate(findings, self.data["findings"][0]["id"], plan, bundle,
                              evidence_root=self.artifacts, evidence_repository=self.repo)
        manifest = reproduction.verify(bundle, findings, self.artifacts, self.repo)
        # Seed only the trusted inert SQLite fixture; no target code is imported.
        reproduction_runtime.seed(bundle, manifest)
        (self.artifacts / "source-before.txt").unlink()
        return bundle, findings

    def direct_cleanup(self, bundle, findings):
        return subprocess.run([sys.executable, "-I", "-S", str(bundle / "cleanup.py"),
                               "--findings", str(findings)], capture_output=True, text=True, timeout=10)

    def test_owned_cleanup_remains_available_when_external_source_disappears(self):
        bundle, findings = self.seeded_checked_bundle()
        unrelated = self.root / "unrelated.txt"
        unrelated.write_bytes(b"Unrelated file must survive")
        completed = self.direct_cleanup(bundle, findings)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "clean")
        self.assertNotIn("integrity", json.loads(completed.stdout))
        self.assertFalse((bundle / ".fixture").exists())
        self.assertEqual(unrelated.read_bytes(), b"Unrelated file must survive")
        repeated = self.direct_cleanup(bundle, findings)
        self.assertEqual(json.loads(repeated.stdout), {"status": "clean", "idempotent": True})

    def test_cleanup_refuses_unrelated_files_inside_owned_fixture(self):
        bundle, findings = self.seeded_checked_bundle()
        unrelated = bundle / ".fixture/unrelated.txt"
        unrelated.write_bytes(b"Not owned by the bundle")
        before = {path.name: path.read_bytes() for path in unrelated.parent.iterdir()}
        completed = self.direct_cleanup(bundle, findings)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stdout)["status"], "error")
        self.assertEqual({path.name: path.read_bytes() for path in unrelated.parent.iterdir()}, before)

    def test_cleanup_refuses_changed_database_despite_missing_source(self):
        bundle, findings = self.seeded_checked_bundle()
        database = bundle / ".fixture/fixture.sqlite3"
        changed = database.read_bytes() + b"Unexpected external mutation"
        database.write_bytes(changed)
        completed = self.direct_cleanup(bundle, findings)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stdout)["status"], "error")
        self.assertEqual(database.read_bytes(), changed)
        self.assertTrue((database.parent / "owner.json").exists())

    def test_byte_checks_do_not_claim_that_runtime_commands_executed(self):
        self.runtime()
        self.data["test_runs"] = [{"command": "touch MUST_NEVER_EXECUTE"}]
        with patch.object(evidence.subprocess, "Popen", side_effect=AssertionError("runtime data must not run")):
            receipt = self.checked().receipt
        self.assertEqual(receipt["items"][0]["source"], "declared")
        self.assertIn("execution", " ".join(receipt["limitations"]))


if __name__ == "__main__":
    unittest.main()
