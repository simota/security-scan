"""Repeated source locations share work without sharing finding-specific decisions."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import render  # noqa: E402


class SourceExcerptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-scan-source-excerpts-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    @staticmethod
    def finding(identifier, location, category="Injection"):
        return {"id": identifier, "location": location, "category": category}

    def report(self, findings):
        return {"meta": {"source_url": "https://example.invalid/source"}, "findings": findings}

    def test_each_source_is_read_and_masked_once(self):
        for name in ("a.py", "b.py"):
            (self.root / name).write_text("value = 123\n" * 1000, encoding="utf-8")
        data = self.report([self.finding(str(i), f"{'a' if i % 2 else 'b'}.py:{i + 1}")
                            for i in range(500)])
        read_text, reads = Path.read_text, []

        def read_source(path, *args, **kwargs):
            reads.append(path)
            return read_text(path, *args, **kwargs)

        with mock.patch.object(Path, "read_text", new=read_source), \
                mock.patch.object(render, "mask_multiline", wraps=render.mask_multiline) as mask:
            render.attach_sources(data, self.root)
        self.assertCountEqual(reads, [self.root / "a.py", self.root / "b.py"])
        self.assertEqual(mask.call_count, 2)
        self.assertTrue(all(finding.get("snippet") for finding in data["findings"]))
        self.assertEqual([finding["id"] for finding in data["findings"]], list(map(str, range(500))))

    def test_grouping_preserves_order_ranges_and_finding_specific_secret_gates(self):
        (self.root / "a.py").write_bytes(b"first\r\nopaqueValue123456789\r\nthird\x0cstill-third\r\nfourth\r\n")
        (self.root / "b.py").write_text("other\n", encoding="utf-8")
        data = self.report([
            self.finding("normal", "a.py:2"),
            self.finding("other", "b.py:1"),
            self.finding("secret", "a.py:2", "Secrets"),
            self.finding("range", "a.py:3-4"),
            self.finding("past-end", "a.py:99"),
        ])
        expected = []
        for finding in data["findings"]:
            single = self.report([copy.deepcopy(finding)])
            render.attach_sources(single, self.root, context=0)
            expected.extend(single["findings"])
        render.attach_sources(data, self.root, context=0)
        self.assertEqual(data["findings"], expected)
        self.assertEqual(data["findings"][0]["snippet"]["lines"], ["opaqueValue123456789"])
        self.assertNotIn("snippet", data["findings"][2])
        self.assertEqual(data["findings"][2]["source_link"], "https://example.invalid/source/a.py#L2")
        self.assertEqual(data["findings"][3]["snippet"], {
            "start": 3, "hit": [3, 4], "lines": ["third\x0cstill-third", "fourth"], "truncated": False})
        self.assertNotIn("snippet", data["findings"][4])

    def test_shared_source_preserves_multiline_redaction_and_excerpt_limits(self):
        lines = ['jwt.encode(payload,', '  "not-a-real-signing-key")', "x" * 300]
        lines.extend("line " + str(i) for i in range(4, 251))
        (self.root / "a.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
        data = self.report([self.finding("masked", "a.py:2"),
                            self.finding("long-line", "a.py:3"),
                            self.finding("long-range", "a.py:1-250")])
        render.attach_sources(data, self.root, context=0)
        self.assertEqual(data["findings"][0]["snippet"]["lines"], ['  "********")'])
        self.assertEqual(data["findings"][1]["snippet"]["lines"], ["x" * 240])
        self.assertTrue(data["findings"][1]["snippet"]["truncated"])
        self.assertEqual(len(data["findings"][2]["snippet"]["lines"]), 200)
        self.assertTrue(data["findings"][2]["snippet"]["truncated"])
        self.assertNotIn("not-a-real-signing-key", str(data))

    def test_every_call_refreshes_successful_missing_and_sensitive_sources(self):
        source = self.root / "a.py"
        data = self.report([self.finding("first", "a.py:1"), self.finding("second", "a.py:1")])
        render.attach_sources(data, self.root, context=0)
        self.assertTrue(all("snippet" not in finding for finding in data["findings"]))
        for content in ("before\n", "after\n"):
            source.write_text(content, encoding="utf-8")
            render.attach_sources(data, self.root, context=0)
            self.assertEqual([finding["snippet"]["lines"] for finding in data["findings"]],
                             [[content.strip()], [content.strip()]])
        source.write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
        render.attach_sources(data, self.root, context=0)
        self.assertTrue(all("snippet" not in finding for finding in data["findings"]))
        source.write_text("safe again\n", encoding="utf-8")
        render.attach_sources(data, self.root, context=0)
        self.assertTrue(all(finding["snippet"]["lines"] == ["safe again"] for finding in data["findings"]))

    def test_shared_pinned_capture_is_verified_once_and_rechecked_on_the_next_call(self):
        commit = "a" * 40
        (self.root / ".git").mkdir()
        (self.root / "a.py").write_text("LATER WORKTREE\n", encoding="utf-8")
        evidence_root = self.root / "output"
        captured = evidence_root / "evidence/source/a.py"
        captured.parent.mkdir(parents=True)
        captured.write_bytes(b"ASSESSED\n")
        data = self.report([self.finding("first", "a.py:1"), self.finding("second", "a.py:1")])
        data["assessment"] = {"commit": commit, "worktree": "clean"}
        data["evidence"] = [{"kind": "source", "source_path": "a.py", "commit": commit,
                             "location": "evidence/source/a.py",
                             "sha256": hashlib.sha256(b"ASSESSED\n").hexdigest()}]
        with mock.patch.object(render, "_captured_source", wraps=render._captured_source) as capture, \
                mock.patch.object(render, "_commit_source", return_value=b"PINNED GIT\n") as git:
            render.attach_sources(data, self.root, context=0, evidence_dir=evidence_root)
            capture.assert_called_once_with(data, evidence_root, commit, "a.py")
            git.assert_not_called()
            self.assertTrue(all(finding["snippet"]["lines"] == ["ASSESSED"] for finding in data["findings"]))

            captured.write_bytes(b"TAMPERED\n")
            capture.reset_mock()
            render.attach_sources(data, self.root, context=0, evidence_dir=evidence_root)
            capture.assert_called_once_with(data, evidence_root, commit, "a.py")
            git.assert_called_once_with(self.root, commit, "a.py")
            self.assertTrue(all(finding["snippet"]["lines"] == ["PINNED GIT"] for finding in data["findings"]))

            git.reset_mock()
            git.return_value = None
            render.attach_sources(data, self.root, context=0, evidence_dir=evidence_root)
            git.assert_called_once_with(self.root, commit, "a.py")
            self.assertTrue(all("snippet" not in finding for finding in data["findings"]))


if __name__ == "__main__":
    unittest.main()
