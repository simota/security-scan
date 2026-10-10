"""Tests for guards that mutation testing showed no other test would catch."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import contract_check  # noqa: E402
import evidence_integrity as integrity  # noqa: E402
import findings as merge_tool  # noqa: E402
import render  # noqa: E402
import verification  # noqa: E402
import test_evidence_integrity as integrity_tests  # noqa: E402  (module import: its tests are not re-collected)


def load(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "findings.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return render.load(path)


class ReferenceEscapingTests(unittest.TestCase):
    def test_quote_in_a_reference_url_cannot_open_an_attribute(self):
        url = "https://example.invalid/a'onmouseover='alert(1)"
        data = load({"meta": {"project": "Synthetic", "date": "2026-10-10", "source_url": "https://example.invalid/r'x"},
                     "findings": [{"id": "D-001", "title": "t", "severity": "High", "confidence": "Confirmed",
                                   "location": "package-lock.json",
                                   "references": [{"type": "advisory", "url": url, "title": "t"}]}]})
        for lang in ("en", "ja"):
            page = render.render_assessment_html(data, render.LABELS[lang], lang)
            self.assertNotIn("'onmouseover=", page)
            self.assertIn("&#x27;onmouseover", page)


class PayloadRefusalTests(unittest.TestCase):
    LITERALS = ("<script>alert(1)</script>", "javascript:alert(1)", "<img onerror=x>", "1' OR '1'='1",
                "x UNION SELECT password", "../../etc/x", "a; rm -rf /", "$(curl evil)", "{{7*7}}",
                "http://169.254.169.254/latest", "cat /etc/passwd")

    def test_every_payload_alternative_in_every_prose_field(self):
        for field in merge_tool.PROSE:
            for literal in self.LITERALS:
                with self.subTest(field=field, literal=literal):
                    fragment = {"findings": [{"id": "F-001", field: "Example " + literal}]}
                    self.assertTrue(merge_tool.payload_problems(fragment, "frag"))

    def test_descriptions_of_the_attack_are_allowed(self):
        for text in ("Accepts javascript: URLs in the profile link", "Path traversal via ../ segments",
                     "SQL injection through the sort parameter", "Template injection in the email subject"):
            with self.subTest(text=text):
                self.assertFalse(merge_tool.payload_problems({"findings": [{"id": "F-001", "title": text}]}, "f"))


class SeverityOrderTests(unittest.TestCase):
    def order(self, *severities, listed=None):
        findings = [{"id": "F-%03d" % i, "severity": s} for i, s in enumerate(severities, 1)]
        if listed:
            findings = [findings[i] for i in listed]
        problems = contract_check.check({"findings": findings}, Path(tempfile.gettempdir()))
        return "F-*: number code findings in severity order (High first), then path and line" in problems

    def test_adjacent_severities_and_listing_order(self):
        for pair in (("Medium", "High"), ("Low", "Medium"), ("Info", "Low")):
            with self.subTest(pair=pair):
                self.assertTrue(self.order(*pair))
                self.assertFalse(self.order(*reversed(pair)))
        # Listing order in the file does not matter; the ID order does.
        self.assertFalse(self.order("High", "Medium", "Low", listed=[2, 0, 1]))


class IdentityCaseFoldingTests(unittest.TestCase):
    def test_full_case_folding(self):
        self.assertEqual(verification.identity("Strauß"), verification.identity("STRAUSS"))


@unittest.skipUnless(Path(integrity.GIT_BINARY).is_file(), "trusted Git required")
class EvidenceRecheckTests(unittest.TestCase):
    setUp = integrity_tests.EvidenceIntegrityTests.setUp
    git = integrity_tests.EvidenceIntegrityTests.git
    verify = integrity_tests.EvidenceIntegrityTests.verify

    def test_uppercase_recorded_digest_matches(self):
        self.data["evidence"][0]["sha256"] = self.data["evidence"][0]["sha256"].upper()
        self.assertEqual(self.verify().receipt["items"][0]["bytes"], "matched")

    def test_artifact_changed_during_git_work_is_unavailable(self):
        real = integrity._GitSnapshot.source
        artifact = self.artifacts / "source.txt"

        def change_then_read(snapshot, commit, path):
            artifact.write_bytes(b"changed during verification\n")
            return real(snapshot, commit, path)

        with patch.object(integrity._GitSnapshot, "source", change_then_read):
            item = self.verify().receipt["items"][0]
        self.assertEqual((item["bytes"], item["reason"]), ("unavailable", "file_changed"))

    def test_artifact_replaced_with_same_bytes_is_unavailable(self):
        real = integrity._GitSnapshot.source
        artifact = self.artifacts / "source.txt"

        def replace_then_read(snapshot, commit, path):
            content = artifact.read_bytes()
            artifact.unlink()
            artifact.write_bytes(content)  # Same bytes, new inode.
            return real(snapshot, commit, path)

        with patch.object(integrity._GitSnapshot, "source", replace_then_read):
            item = self.verify().receipt["items"][0]
        self.assertEqual((item["bytes"], item["reason"]), ("unavailable", "file_changed"))


if __name__ == "__main__":
    unittest.main()
