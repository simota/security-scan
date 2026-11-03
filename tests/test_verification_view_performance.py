"""Bound repeated display work without sharing security decisions across views."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import render  # noqa: E402


class VerificationViewTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
        self.finding = self.data["findings"][0]
        self.state = render.derive_verification(self.data)[self.finding["id"]]

    def view(self, lang="en"):
        return render.verification_view(self.data, self.finding, self.state, lang)

    def text(self, lang="en"):
        return "\n".join(item for section in self.view(lang)["sections"] for item in section["items"])

    def test_repeated_commits_and_hashes_are_redacted_once_per_view(self):
        commit = self.data["assessment"]["commit"]
        digest = self.data["evidence"][0]["sha256"]
        with patch.object(render, "redact", wraps=render.redact) as redact:
            text = self.text()
        inputs = [call.args[0] for call in redact.call_args_list]
        self.assertGreater(text.count(commit), 1)
        self.assertGreater(text.count(digest), 1)
        self.assertEqual(inputs.count(commit), 1)
        self.assertEqual(inputs.count(digest), 1)

    def test_later_views_reprocess_text_and_reflect_updated_records(self):
        commit = self.data["assessment"]["commit"]
        with patch.object(render, "redact", wraps=render.redact) as redact:
            before = self.text()
            self.data["evidence"][0]["summary"] = "Updated synthetic source observation."
            after = self.text()
        self.assertNotIn("Updated synthetic source observation.", before)
        self.assertIn("Updated synthetic source observation.", after)
        self.assertEqual([call.args[0] for call in redact.call_args_list].count(commit), 2)

    def test_non_hashable_display_values_are_converted_before_reuse(self):
        # The view retains its existing string conversion even when called
        # directly with values the document validator would reject.
        values = [{"note": "synthetic observation"}, ["synthetic", "observation"], 0, None]
        for value in values:
            with self.subTest(value=value):
                self.finding["verification"]["claims"]["reachability"]["reason"] = value
                claims = next(section for section in self.view()["sections"]
                              if section["title"] == render.LABELS["en"]["v_claims"])
                reachability = claims["items"][1]
                if value is None:
                    self.assertNotIn("None", reachability)
                    self.assertEqual(len(reachability.splitlines()), 2)
                else:
                    self.assertIn("\n" + str(value) + "\n", reachability)

    def test_sensitive_text_and_finding_specific_withholding_are_preserved(self):
        proof = self.finding["verification"]
        secret = "SYNTHETIC_DISPLAY_SECRET"
        for claim in proof["claims"].values():
            claim["reason"] = "password=" + secret
        proof["environment"]["reason"] = "-----BEGIN PRIVATE KEY-----"
        summary = "opaqueValue123456789"
        self.data["evidence"][0]["summary"] = summary
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                self.finding["category"] = "Input handling"
                ordinary = self.text(lang)
                self.assertIn(summary, ordinary)
                self.finding["category"] = "Secrets"
                sensitive = self.text(lang)
                self.assertNotIn(summary, sensitive)
                for text in (ordinary, sensitive):
                    self.assertNotIn(secret, text)
                    self.assertNotIn("-----BEGIN PRIVATE KEY-----", text)
                    self.assertIn("password=********", text)
                    self.assertIn(render.LABELS[lang]["v_withheld"], text)

    def test_many_distinct_values_do_not_retain_an_unbounded_text_cache(self):
        proof = self.finding["verification"]
        marker = "synthetic-cache-boundary-reviewer"
        proof["reviewer"] = marker
        check = proof["falsification"][0]
        proof["falsification"] = [dict(copy.deepcopy(check), reason="Synthetic observation %d" % i)
                                  for i in range(300)]
        # This value occurs before and after more than 256 distinct strings.
        proof["reviews"][0]["reviewer"] = marker
        with patch.object(render, "redact", wraps=render.redact) as redact:
            text = self.text()
        self.assertEqual(text.count(marker), 2)
        self.assertEqual([call.args[0] for call in redact.call_args_list].count(marker), 2)


if __name__ == "__main__":
    unittest.main()
