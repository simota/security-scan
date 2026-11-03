"""File-boundary contracts and bounded filesystem work for absent scan inputs."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import deps_scan  # noqa: E402


class SafeFileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-safe-file-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.root = self.base / "checkout"
        self.root.mkdir()
        self.regular = self.root / "regular.txt"
        self.regular.write_text("fixture", encoding="utf-8")
        self.outside = self.base / "outside.txt"
        self.outside.write_text("outside fixture", encoding="utf-8")

    def test_regular_file_is_accepted_with_and_without_root(self):
        self.assertTrue(deps_scan.safe_file(self.regular))
        self.assertTrue(deps_scan.safe_file(self.regular, self.root))

    def test_missing_files_and_directories_are_rejected(self):
        for path in (self.root / "missing.lock", self.root):
            for root in (None, self.root):
                with self.subTest(path=path, root=root):
                    self.assertFalse(deps_scan.safe_file(path, root))

    def test_symlinks_and_broken_links_are_rejected(self):
        for name, target in (("inside-link", self.regular), ("outside-link", self.outside),
                             ("broken-link", self.root / "missing.txt")):
            link = self.root / name
            link.symlink_to(target)
            for root in (None, self.root):
                with self.subTest(name=name, root=root):
                    self.assertFalse(deps_scan.safe_file(link, root))

    def test_symlinked_parent_is_rejected_even_for_in_checkout_targets(self):
        directory = self.root / "real-directory"
        directory.mkdir()
        (directory / "file.txt").write_text("fixture", encoding="utf-8")
        for name, target, filename in (("inside-directory", directory, "file.txt"),
                                       ("outside-directory", self.base, "outside.txt")):
            link = self.root / name
            link.symlink_to(target, target_is_directory=True)
            with self.subTest(name=name):
                self.assertFalse(deps_scan.safe_file(link / filename, self.root))

    def test_outside_files_and_parent_traversal_are_rejected(self):
        for path in (self.outside, self.root / ".." / "outside.txt"):
            with self.subTest(path=path):
                self.assertFalse(deps_scan.safe_file(path, self.root))

    def test_relative_paths_and_lexical_parent_normalization_are_preserved(self):
        # Boundary checks have always normalized '..' before inspecting paths.
        # The nonexistent component is therefore irrelevant when a root is given.
        normalized = self.root / "missing-directory" / ".." / "regular.txt"
        relative = Path(os.path.relpath(normalized, Path.cwd()))
        self.assertTrue(deps_scan.safe_file(normalized, self.root))
        self.assertTrue(deps_scan.safe_file(relative, self.root))
        self.assertFalse(deps_scan.safe_file(normalized))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_non_regular_file_is_rejected(self):
        fifo = self.root / "named-pipe"
        os.mkfifo(fifo)
        self.assertFalse(deps_scan.safe_file(fifo))
        self.assertFalse(deps_scan.safe_file(fifo, self.root))

    def test_missing_candidates_have_depth_independent_filesystem_cost(self):
        deep = self.root.joinpath(*(f"level-{i}" for i in range(16)))
        deep.mkdir(parents=True)
        counts = []
        original_lstat = os.lstat
        for directory in (self.root, deep):
            with patch.object(deps_scan.os, "lstat", wraps=original_lstat) as lstat:
                self.assertFalse(deps_scan.safe_file(directory / "missing.lock", self.root))
                counts.append(lstat.call_count)
        # A missing candidate should not trigger metadata reads of every ancestor.
        # Check the operation budget rather than a machine-dependent time limit.
        self.assertLessEqual(counts[1], counts[0] + 2)

    def test_workspace_members_still_inherit_the_shared_lock(self):
        (self.root / "package.json").write_text(json.dumps({"workspaces": ["packages/*"]}), encoding="utf-8")
        lock = self.root / "package-lock.json"
        lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")
        collector = deps_scan.Collector(self.root)
        for i in range(12):
            member = self.root / "packages" / f"member-{i}" / "package.json"
            member.parent.mkdir(parents=True)
            member.write_text(json.dumps({"dependencies": {"react": "^18.0.0"}}), encoding="utf-8")
            self.assertEqual(deps_scan.matching_lockfiles(collector, member), [lock])
        self.assertEqual(collector.not_run, [])


if __name__ == "__main__":
    unittest.main()
