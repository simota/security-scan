"""Skip redaction and evidence work that cannot change a result, never the checks themselves."""
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import evidence_integrity as integrity  # noqa: E402
import render  # noqa: E402
import url_redaction  # noqa: E402
import verification  # noqa: E402


def full_redact_urls(text):
    """redact_urls without its early return: every pattern always runs."""
    module = url_redaction
    text = module.QUOTED_USERINFO_RE.sub("[redacted URL]", text)
    text = module.SCHEMELESS_USERINFO_RE.sub("//", text)
    text = module.ENCODED_URL_RE.sub(
        lambda m: "[redacted URL]" if module._encoded_secret(m.group()) else m.group(), text)
    # No URL_RE match is possible without ':'; URL_RE is checked on its own below.
    return text


def full_redact(line):
    """render.redact without the keyword shortcut: every keyed step always runs."""
    line = render.redact_urls(line)
    line = render.JWT_RE.sub("********", render.TOKEN_RE.sub("********", line))
    line = render.JWT_KEY_LITERAL.sub(render._mask_jwt_key, line)
    line = render._sub_keyed(line, render._QUOTED_TAIL,
                             lambda key, m: key + m.group(1) + m.group(2) + "********" + m.group(2))
    line = render._sub_keyed(line, render._SECRET_TAIL, lambda key, m: key + m.group(1) + "********")
    if render._KEY.search(line) or any(render._KEY_END.search(run.group())
                                       for run in render._KEY_RUN.finditer(line)):
        line = render._FALLBACK_LITERAL.sub(lambda m: m.group(1) + m.group(2) + "********" + m.group(2), line)
    return line


FRAGMENTS = [
    "pass", "PASS", "pwd", "Pwd", "passphrase", "password", "secret", "token", "TOKEN", "api_key",
    "api-key", "apikey", "private_key", "access-key", "credential", "ſecret", "apiKey",
    "toKen", ":", "=", "=>", ":=", '"', "'", " ", "_", ".", "-", "%", "%3A", "%253A", "%2F",
    "//", "https://", "u:p@h.example/x?q#f", "abcd1234", "eyJabcd.eyJabcd.sig", "ghp_" + "a" * 36,
    "Bearer abcdef0123456789xyz", "Authorization: ", "jwt.sign(x, 'k3y')",
    "os.environ.get('X', 'lit')", "|| 'v'", '?? "v"', " or 'v'", "\n", "\\", "\\/\\/", "x", "1",
    "[", "]", "(", ")", "@", ";", ",", "é", "日本",
]


class RedactionShortcutTests(unittest.TestCase):
    def lines(self, count=20000):
        generator = random.Random(20261103)
        for _ in range(count):
            yield "".join(generator.choice(FRAGMENTS) for _ in range(generator.randint(0, 14)))

    def test_redact_matches_full_pipeline(self):
        for line in self.lines():
            self.assertEqual(render.redact(line), full_redact(line), line)

    def test_redact_urls_matches_full_pipeline(self):
        for line in self.lines():
            if ":" in line or "%" in line:
                continue
            self.assertIsNone(url_redaction.URL_RE.search(line), line)
            self.assertEqual(url_redaction.redact_urls(line), full_redact_urls(line), line)
            self.assertEqual(url_redaction.redact_urls(line), line, line)

    def test_case_folded_and_short_keys_still_mask(self):
        # Unicode case folding (long s, Kelvin sign) and short names reach the keyed steps.
        for line, kept in (("ſecret=abcd1234", "ſecret="), ("apiKey: abcd1234", "apiKey: "),
                           ("db_pwd=abcd1234", "db_pwd="), ("PASS = 'hunter22'", "PASS = '"),
                           ("value = os.environ.get('DB_PASSWORD', 'fallback1')", "'DB_PASSWORD', '")):
            with self.subTest(line=line):
                masked = render.redact(line)
                self.assertIn(kept, masked)
                self.assertIn("********", masked)
                self.assertEqual(masked, full_redact(line))

    def test_unkeyed_credentials_still_mask_without_keyword(self):
        for line in ("see ghp_" + "a" * 36, "eyJhbGciOi.eyJzdWIiOi.c2ln", "https://user:pw@host.example/x?q=1",
                     "https%3A%2F%2Fuser%3Apw%40host.example"):
            with self.subTest(line=line):
                self.assertFalse(render._KEY_HINT.search(line))
                masked = render.redact(line)
                self.assertNotEqual(masked, line)
                self.assertEqual(masked, full_redact(line))

    def test_plain_lines_skip_keyed_scans(self):
        line = "Synthetic review found no compensating ownership guard."
        with patch.object(render, "_sub_keyed", wraps=render._sub_keyed) as keyed:
            self.assertEqual(render.redact(line), line)
        self.assertEqual(keyed.call_count, 0)


@unittest.skipUnless(os.name == "posix", "POSIX safe evidence reader required")
class SharedProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-scan-shared-provenance-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        data = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
        content = b"synthetic evidence\n"
        digest = hashlib.sha256(content).hexdigest()
        finding = data["findings"][0]
        data["findings"] = [dict(copy.deepcopy(finding), id="F-%03d" % (i + 1)) for i in range(12)]
        for index, record in enumerate(data["evidence"]):
            record["location"] = "evidence-%03d.txt" % index
            record["sha256"] = digest
            (self.root / record["location"]).write_bytes(content)
        self.data = render.validate_data(data)
        self.result = integrity.verify_evidence(self.data, self.root)

    def test_one_catalog_check_and_digest_per_derivation(self):
        with patch.object(integrity, "_catalog", wraps=integrity._catalog) as catalog, \
                patch.object(integrity, "declaration_digest", wraps=integrity.declaration_digest) as digest:
            states = verification.derive_verification(self.data, ValueError, self.result)
        self.assertEqual(catalog.call_count, 1)
        self.assertEqual(digest.call_count, 1)
        for finding in self.data["findings"]:
            expected = verification.integrity_state(self.data, states[finding["id"]]["evidence_ids"], self.result)
            self.assertEqual(states[finding["id"]]["integrity"], expected)
            self.assertEqual(expected["status"], "incomplete")  # No Git repository: sources stay unchecked.

    def test_each_derivation_rechecks_changed_declarations(self):
        before = verification.derive_verification(self.data, ValueError, self.result)
        self.data["evidence"][0]["summary"] = "Changed synthetic declaration."
        after = verification.derive_verification(self.data, ValueError, self.result)
        for state in before.values():
            self.assertNotIn("context_stale", state["integrity"]["reasons"])
        for state in after.values():
            self.assertEqual(state["integrity"]["reasons"], ["context_stale"])
        self.data["evidence"][0]["extra"] = float("nan")
        with self.assertRaises(integrity.EvidenceError) as raised:
            verification.derive_verification(self.data, ValueError, self.result)
        self.assertEqual(raised.exception.reason, "invalid_declarations")

    def test_shared_context_keeps_selection_errors_and_order(self):
        context = integrity._Provenance(self.data, self.result)
        identifiers = sorted(record["id"] for record in self.data["evidence"])
        with self.assertRaises(integrity.EvidenceError) as raised:
            context(["missing-evidence"])
        self.assertEqual(raised.exception.reason, "invalid_evidence_selection")
        self.assertEqual(context(identifiers[::-1]), integrity.provenance_state(self.data, identifiers, self.result))
        with self.assertRaises(integrity.EvidenceError) as raised:
            context(identifiers + identifiers[:1])
        self.assertEqual(raised.exception.reason, "invalid_evidence_selection")


if __name__ == "__main__":
    unittest.main()
