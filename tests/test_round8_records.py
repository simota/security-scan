"""Round-8 record regressions: secret masking and capture refusal for subscript keys,
Authorization values, provider prefixes, webhook URLs and positional JWT keys; excerpts
pinned to the assessed commit; Secrets findings tied to their own location's evidence;
attack strings in every merged prose field; second-language report stamps."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import contract_check  # noqa: E402
import evidence_capture  # noqa: E402
import findings as findings_tool  # noqa: E402
import render  # noqa: E402
import verification  # noqa: E402

GIT = "/usr/bin/git"
GIT_ENV = {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
CLAIMS = ("reachability", "preconditions", "defenses", "impact")
# Synthetic, non-functional values shaped like the formats under test.
KEY = "Zq8vN3pL0xW7rT2kYb5m"
HEX = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"

# Token-shaped strings are split so repository secret scanners do not flag the fixtures.
LEAKS = [
    f'app.config["SECRET_KEY"] = "{KEY}"',
    f"app.config['SECRET_KEY'] = '{KEY}'",
    f'os.environ["API_TOKEN"] = "{KEY}"',
    f'HEADERS = {{"Authorization": "Bearer {HEX}"}}',
    f'auth_header = "Bearer {HEX}"',
    'headers: { Authorization: "Basic dXNlcjpwYXNzd29yZDEyMzQ1Ng==" }',
    'key = "AIza' + 'SyA1234567890abcdefghijklmnopqrstuv"',
    'k = "sk-' + 'proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"',
    'k = "sk-' + 'ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"',
    'k = "sk_' + 'test_51HabcdefghijklmnopqrstuvwxYZ01"',
    'k = "npm' + '_abcdefghijklmnopqrstuvwxyz0123456789"',
    'k = "hf' + '_abcdefghijklmnopqrstuvwxyzABCDEFGH"',
    'k = "SG' + '.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"',
    'u = "https://hooks.' + 'slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"',
    'u = "https://discord.com/api/' + 'webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_ABCDEFG"',
    'u = "https://api.telegram.org/bot123456789:' + 'AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage"',
    f'jwt.sign(payload, "{KEY}")',
    f'jwt.sign({{ id: user.id, role: "admin" }}, "{KEY}", {{ expiresIn: "1h" }})',
    f'jwt.encode(payload, "{KEY}", algorithm="HS256")',
]
ORDINARY = [
    'token = request.headers.get("Authorization")',
    'headers.Authorization = `Bearer ${token}`',
    'headers["Authorization"] = "Bearer " + token',
    'const auth = req.headers.authorization',
    'if (auth.startsWith("Bearer ")) {',
    'scheme = "Bearer"',
    'jwt.sign(payload, process.env.JWT_SECRET)',
    'jwt.sign(payload, secret, { expiresIn: "1h" })',
    'jwt.encode(payload, key, algorithm="HS256")',
    'app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]',
    'os.environ["API_TOKEN"]',
    'description = "Authorization header is required for this endpoint"',
    'Use Basic authentication only over TLS.',
    'cache[user_id] = session_data',
    # Unquoted subscripts name a constant; the value is an error code (seen in real repositories).
    'errors[CONF_PASSWORD] = "invalid_auth"',
    'self._errors[CONF_API_TOKEN] = "invalid_api_token"',
    '# "scope": "EMEA-V1-Basic EMEA-V1-Anonymous",',
]


def git(repo, *args):
    return subprocess.run([GIT, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                           "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                          check=True, capture_output=True, env=GIT_ENV, timeout=30).stdout.decode()


class SecretFormatTests(unittest.TestCase):
    def test_leaks_are_masked_and_refused(self):
        for line in LEAKS:
            with self.subTest(line=line):
                masked = render.redact(line)
                self.assertIn("********", masked)
                for value in (KEY, HEX, "dXNlcjpwYXNzd29yZDEyMzQ1Ng", "AIzaSyA1234567890", "abcdefghijklmnopqrstuv",
                              "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "T00000000/B00000000"):
                    self.assertNotIn(value, masked)
                self.assertTrue(render.secret_in_source("src/app.py", line + "\n"))

    def test_ordinary_code_is_unchanged_and_capturable(self):
        for line in ORDINARY:
            with self.subTest(line=line):
                self.assertEqual(render.redact(line), line)
                self.assertFalse(render.secret_in_source("src/app.py", line + "\n"))

    def test_patterns_stay_linear_on_long_lines(self):
        for line in ("Bearer " + "a" * 200000, "jwt.sign(" + "a" * 200000, "1" * 200000 + ":AA",
                     'x["SECRET_KEY"' + "]" * 100000, "sk-" + "a-" * 100000, "SG." + "a" * 200000):
            started = time.monotonic()
            render.redact(line)
            render.secret_in_source("a.py", line)
            self.assertLess(time.monotonic() - started, 2.0, line[:20])

    def test_capture_refuses_a_subscript_secret_file(self):
        tmp = Path(tempfile.mkdtemp(prefix="security-scan-round8-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        repo = tmp / "app"
        (repo / "src").mkdir(parents=True)
        (repo / "src/app.py").write_text(f'from flask import Flask\napp = Flask(__name__)\n{LEAKS[0]}\n')
        git(repo, "init", "-q")
        git(repo, "add", ".")
        git(repo, "commit", "-q", "-m", "init")
        out = tmp / "out" / "findings.json"
        out.parent.mkdir()
        out.write_text(json.dumps({"meta": {"project": "p", "date": "2026-10-10"}, "findings": []}))
        with self.assertRaisesRegex(evidence_capture.CaptureError, "secret-looking"):
            evidence_capture.capture(repo, out, ["src/app.py"])
        self.assertFalse((out.parent / "evidence/source/src/app.py").exists())


class Pipeline(unittest.TestCase):
    """A captured, contract-shaped run in a real Git checkout."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-round8-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "app"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src/orders.py").write_text(
            "def show(order_id):\n    return Order.get(order_id)  # ASSESSED\n")
        (self.repo / "src/crypto.py").write_text("import hashlib\nDIGEST = hashlib.md5  # ASSESSED\n")
        (self.repo / "src/config.py").write_text("DEBUG = False  # ASSESSED\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "init")
        self.commit = git(self.repo, "rev-parse", "HEAD").strip()
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.findings = self.out / "findings.json"

    def finding(self, ident, location, category="Actor and tenant", verdict="Likely"):
        return {"id": ident, "title": "Synthetic " + ident, "severity": "High", "confidence": "Confirmed",
                "category": category, "location": location, "actor": "any signed-in user",
                "request": "GET /orders/{order_id}", "impact": "synthetic impact", "fix": "synthetic fix",
                "validation": {"verdict": verdict, "evidence": "read in source", "method": "review"}}

    def base(self, findings):
        names = contract_check.perspective_names()
        return {"meta": {"project": "Synthetic app", "date": "2026-10-10", "assessor": "Test host (model)"},
                "findings": findings,
                "perspectives": [{"name": n, "result": "N/A - synthetic"} for n in names],
                "checked_ok": [], "decisions": [], "next_steps": [],
                "limitations": ["assessment.pdf not produced: no PDF engine",
                                "invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)"]}

    def capture(self, findings, paths):
        self.findings.write_text(json.dumps(self.base(findings)))
        mapping = evidence_capture.capture(self.repo, self.findings, paths)
        return json.loads(self.findings.read_text()), mapping

    @staticmethod
    def verify(finding, ids):
        claim = {"status": "supported", "reason": "read in source", "evidence_ids": ids}
        finding["verification"] = {
            "reviewer": "unit-a", "claims": {k: dict(claim) for k in CLAIMS},
            "falsification": [{"check": "looked for a guard", "result": "clear", "reason": "none",
                               "evidence_ids": ids}],
            "reviews": [], "run_ids": [],
            "environment": {"status": "not_required", "reason": "bounded", "evidence_ids": []}}


class PinnedExcerptTests(Pipeline):
    def excerpt(self, data, location, evidence_dir=None, repo=None):
        data = copy.deepcopy(data)
        data["findings"] = [self.finding("F-001", location)]
        render.attach_sources(data, repo or self.repo, evidence_dir=evidence_dir)
        snippet = data["findings"][0].get("snippet")
        return "\n".join(snippet["lines"]) if snippet else None

    def test_excerpts_show_the_assessed_commit_not_later_edits(self):
        data, _ = self.capture([self.finding("F-001", "src/orders.py:2")], ["src/orders.py"])
        # Later commits and an uncommitted edit change every cited file.
        for name in ("orders.py", "crypto.py"):
            path = self.repo / "src" / name
            path.write_text(path.read_text().replace("ASSESSED", "LATER"))
        git(self.repo, "commit", "-qam", "later")
        (self.repo / "src/config.py").write_text("DEBUG = True  # UNCOMMITTED\n")
        # The evidence copy, then the commit blob when no copy was captured.
        self.assertIn("ASSESSED", self.excerpt(data, "src/orders.py:2", evidence_dir=self.out))
        self.assertIn("ASSESSED", self.excerpt(data, "src/crypto.py:2", evidence_dir=self.out))
        self.assertIn("ASSESSED", self.excerpt(data, "src/config.py:1", evidence_dir=self.out))
        # An evidence copy that no longer matches its hash is not used; Git still is.
        (self.out / "evidence/source/src/orders.py").write_text("def show():\n    TAMPERED\n")
        self.assertIn("ASSESSED", self.excerpt(data, "src/orders.py:2", evidence_dir=self.out))
        # A file absent at the assessed commit has no excerpt rather than a later one.
        (self.repo / "src/new.py").write_text("NEW = 1\n")
        self.assertIsNone(self.excerpt(data, "src/new.py:1", evidence_dir=self.out))

    def test_render_cli_uses_the_findings_directory_evidence(self):
        data, _ = self.capture([self.finding("F-001", "src/orders.py:2")], ["src/orders.py"])
        (self.repo / "src/orders.py").write_text("def show(order_id):\n    return Order.get(order_id)  # LATER\n")
        shutil.rmtree(self.repo / ".git")  # Not a checkout any more: the evidence copy still pins it.
        self.assertEqual(render.main([str(self.findings), "--out", str(self.out), "--repo", str(self.repo),
                                      "--no-pdf"]), 0)
        page = (self.out / "assessment.html").read_text()
        self.assertIn("ASSESSED", page)
        self.assertNotIn("LATER", page)

    def test_without_a_pin_or_a_checkout_the_working_tree_is_read(self):
        plain = self.tmp / "plain"
        (plain / "src").mkdir(parents=True)
        (plain / "src/orders.py").write_text("x = 1  # WORKTREE\n")
        data = {"meta": {}, "findings": []}
        self.assertIn("WORKTREE", self.excerpt(data, "src/orders.py:1", repo=plain))
        # A valid pin never falls back to the working tree: without a readable copy or blob, no excerpt.
        pinned = {"meta": {}, "findings": [],
                  "assessment": {"repository": "p", "commit": "1" * 40, "worktree": "clean"}}
        self.assertIsNone(self.excerpt(pinned, "src/orders.py:1", repo=plain))


class SecretsLocationTests(Pipeline):
    def test_secrets_finding_cannot_borrow_another_files_evidence(self):
        data, mapping = self.capture([self.finding("F-001", "src/orders.py:2"),
                                      self.finding("F-002", "src/settings.py:3", category="Secrets")],
                                     ["src/orders.py"])
        self.verify(data["findings"][1], [mapping["src/orders.py"]])
        data["findings"][1]["validation"]["verdict"] = "Valid"
        with self.assertRaisesRegex(render.SchemaError, "Secrets finding is Valid only"):
            render.validate_data(copy.deepcopy(data))
        data["findings"][1]["validation"]["verdict"] = "Likely"
        state = verification.derive_verification(data)["F-002"]
        self.assertEqual(state["level"], "incomplete")
        self.assertIn("claims_incomplete", state["gaps"])

    def test_secrets_finding_with_its_own_evidence_is_supported(self):
        data, mapping = self.capture([self.finding("F-001", "src/crypto.py:2", category="Secrets",
                                                   verdict="Valid")], ["src/crypto.py"])
        self.verify(data["findings"][0], [mapping["src/crypto.py"]])
        render.validate_data(copy.deepcopy(data))
        state = verification.derive_verification(data)["F-001"]
        self.assertNotIn("claims_incomplete", state["gaps"])
        self.assertEqual(state["gaps"], ["review_missing"])  # High: independent review still owed.
        # A location is one path:line, as contract_check requires.
        self.assertEqual(verification.location_paths("src/crypto.py:2"), {"src/crypto.py"})


class PayloadFieldTests(unittest.TestCase):
    def problems(self, fragment):
        return findings_tool.payload_problems(fragment, "frag.json")

    def test_attack_strings_are_refused_in_every_prose_field(self):
        attack = "<script>alert(1)</script>"
        finding = {"id": "F-001", "references": [{"type": "article", "url": "https://e.invalid/", "title": attack}]}
        cases = [
            {"limitations": [attack]}, {"decisions": [attack]}, {"next_steps": [attack]},
            {"checked_ok": [attack]},
            {"perspectives": [{"name": "Input handling", "result": "No issues", "note": attack}]},
            {"perspectives": [{"name": "Input handling", "result": "' OR '1'='1"}]},
            {"meta": {"scope": "src/ ../../../etc/passwd"}},
            {"findings": [finding]},
            {"findings": [{"id": "F-001", "verification": {"claims": {"impact": {"reason": attack}}}}]},
            {"findings": [{"id": "F-001", "verification": {"falsification": [{"check": attack}]}}]},
            {"findings": [{"id": "F-001", "verification": {"exclusion": {"reason": "{{7*7}}"}}}]},
            {"findings": [{"id": "F-001", "verification": {"reviews": [{"reason": attack}]}}]},
        ]
        for fragment in cases:
            with self.subTest(fragment=fragment):
                self.assertTrue(self.problems(fragment))

    def test_contract_lines_and_ordinary_prose_pass(self):
        fragment = {
            "meta": {"project": "Sample App", "scope": "src/ (API and web)", "method": "static source review, read-only"},
            "limitations": ["assessment.pdf not produced: no PDF engine",
                            "assessment.pdf not produced: PDF engine failed (exit 1)",
                            "invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)",
                            "Dependency audit not run: npm audit (no network)"],
            "decisions": ["Decide whether 'admin' or 'member' may export orders"],
            "next_steps": ["Re-run with --audit once registry access is available"],
            "perspectives": [{"name": "Input handling", "result": "No issues", "note": "1 suspected finding ruled out"}],
            "findings": [{"id": "F-001", "references": [{"type": "cwe", "url": "https://cwe.mitre.org/x",
                                                         "title": "CWE-639: Authorization Bypass"}],
                          "verification": {"claims": {"impact": {"reason": "reads ../config once"}}}}],
        }
        self.assertEqual(self.problems(fragment), [])


class SecondLanguageTests(Pipeline):
    def test_allowed_language_directory_pages_must_be_current(self):
        import deps_scan
        data, mapping = self.capture([self.finding("F-001", "src/orders.py:2")], ["src/orders.py"])
        self.verify(data["findings"][0], [mapping["src/orders.py"]])
        self.findings.write_text(json.dumps(data))
        deps_scan.merge_into(self.findings, {"findings": [], "not_run": []}, audit=True)
        (self.out / "deps.json").write_text('{"inventory": [], "findings": [], "not_run": []}\n')
        for args in ([], ["--lang", "ja", "--out", str(self.out / "ja")]):
            argv = [str(self.findings), "--out", str(self.out), "--no-pdf", *args]
            self.assertEqual(render.main(argv), 0)
        data = json.loads(self.findings.read_text())
        self.assertEqual(contract_check.check(data, self.out, pdf=False, allow=["ja"]), [])
        # A later change re-rendered only for the primary pages leaves the copy stale.
        data["decisions"] = ["Decide who may export orders"]
        self.findings.write_text(json.dumps(data))
        self.assertEqual(render.main([str(self.findings), "--out", str(self.out), "--no-pdf"]), 0)
        problems = contract_check.check(data, self.out, pdf=False, allow=["ja"])
        self.assertTrue(any("ja/dashboard.html was not rendered from the current findings.json" in p
                            for p in problems), problems)
        # A language copy missing one page is incomplete, not quietly accepted.
        self.assertEqual(render.main([str(self.findings), "--out", str(self.out / "ja"), "--lang", "ja", "--no-pdf"]), 0)
        (self.out / "ja" / "assessment.html").unlink()
        problems = contract_check.check(data, self.out, pdf=False, allow=["ja"])
        self.assertTrue(any(p.startswith("ja/assessment.html: missing") for p in problems), problems)


class CodexRound8RecordTests(unittest.TestCase):
    def test_word_like_literal_jwt_keys_are_refused(self):
        for line in ('jwt.sign(payload, "supersecret")', "jwt.encode(payload, 'secret', algorithm='HS256')"):
            with self.subTest(line=line):
                self.assertTrue(render.secret_in_source("src/auth.js", line + "\n"))
        self.assertFalse(render.secret_in_source("src/auth.js", "jwt.sign(payload, process.env.JWT_SECRET)\n"))

    def test_letter_only_authorization_values_are_masked_and_refused(self):
        for line in ('headers = {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz"}',
                     "Authorization: Basic YWFhOmJiYmJiYmJiYmJiYmJiYg=="):
            with self.subTest(line=line):
                self.assertTrue(render.secret_in_source("src/client.py", line + "\n"))
                secret = line.split()[-1].strip('"}')
                self.assertNotIn(secret, render.redact(line))
        for line in ('headers["Authorization"] = "Bearer " + token', "headers.Authorization = `Bearer ${token}`"):
            with self.subTest(line=line):
                self.assertFalse(render.secret_in_source("src/client.py", line + "\n"))
                self.assertEqual(render.redact(line), line)


class CodexRound8bRecordTests(Pipeline):
    JWT = 'const t = jwt.sign(\n  payload,\n  "supersecret"\n);\n'
    AUTH = 'headers = {\n    "Authorization":\n        "Bearer abcdefghijklmnopqrstuvwxyz",\n}\n'

    def snippet(self, data, location, repo, evidence_dir=None):
        data = copy.deepcopy(data)
        data["findings"] = [self.finding("F-001", location)]
        render.attach_sources(data, repo, evidence_dir=evidence_dir)
        return data["findings"][0].get("snippet")

    def test_multiline_jwt_key_and_authorization_value_are_refused_and_masked(self):
        for text, secret in ((self.JWT, "supersecret"), (self.AUTH, "abcdefghijklmnopqrstuvwxyz")):
            with self.subTest(text=text):
                self.assertTrue(render.secret_in_source("src/client.js", text))
                masked = render.mask_multiline(text)
                self.assertNotIn(secret, masked)
                self.assertEqual(masked.count("\n"), text.count("\n"))
                plain = self.tmp / "plain"
                (plain / "src").mkdir(parents=True, exist_ok=True)
                (plain / "src/client.js").write_text(text)
                snippet = self.snippet({"meta": {}, "findings": []}, "src/client.js:3", plain)
                self.assertEqual(len(snippet["lines"]), len(text.splitlines()))
                self.assertNotIn(secret, "\n".join(snippet["lines"]))
        for text in ('jwt.sign(\n  payload,\n  process.env.JWT_SECRET\n)\n',
                     '"Authorization":\n  "Bearer " + token\n'):
            self.assertFalse(render.secret_in_source("src/client.js", text))
            self.assertEqual(render.mask_multiline(text), text)

    def test_multiline_patterns_stay_linear(self):
        for text in ("jwt.sign(" + " " * 200000, ("jwt.sign(" + " " * 39) * 5000, "jwt.sign(a," + " \n" * 100000,
                     ("Authorization:" + "\n" * 39) * 4000, "Authorization:" + " " * 200000 + "Bearer"):
            started = time.monotonic()
            render.mask_multiline(text)
            render.secret_in_source("a.js", text)
            self.assertLess(time.monotonic() - started, 1.0, text[:20])

    def test_jwt_key_after_a_call_or_nested_object_payload_is_refused_and_masked(self):
        for text in ('jwt.sign(makePayload(user), "supersecret")\n', 'jwt.sign({ id: id(u), n: f(x) }, "supersecret")\n',
                     'const t = jwt.sign(\n  build(user),\n  "supersecret"\n);\n'):
            with self.subTest(text=text):
                self.assertTrue(render.secret_in_source("src/auth.js", text))
                self.assertNotIn("supersecret", render.mask_multiline(text))
                self.assertNotIn("supersecret", render.redact(text) if text.count("\n") == 1 else render.mask_multiline(text))
        self.assertFalse(render.secret_in_source("src/auth.js", "jwt.sign(makePayload(user), process.env.KEY)\n"))

    def test_short_authorization_values_are_masked_but_placeholders_are_kept(self):
        basic = "dXNl" + "cjpwYXNz"
        for line in ("Authorization: Basic " + basic, '{"Authorization": "Bearer ' + basic + '"}'):
            with self.subTest(line=line):
                self.assertTrue(render.secret_in_source("src/client.py", line + "\n"))
                self.assertNotIn(basic, render.redact(line))
                self.assertNotIn(basic, render.mask_multiline(line))
        for line in ("Authorization: Bearer <token>", "Authorization: Bearer {token}", "Authorization: Bearer $TOKEN",
                     "Authorization: Bearer xxxx", "Authorization: Bearer YOUR_TOKEN", '"Authorization": "Bearer " + jwt',
                     "Authorization: Bearer abc${x}", "Authorization: Basic btoa(creds)",
                     "// mentions Authorization: Bearer header explicitly", "prefer it for Authorization: Bearer flows; not"):
            with self.subTest(line=line):
                self.assertFalse(render.secret_in_source("src/client.py", line + "\n"))
                self.assertEqual(render.redact(line), line)
                self.assertEqual(render.mask_multiline(line), line)

    def test_spaced_subscript_secret_keys_are_refused_and_masked(self):
        value = "abcd" + "efgh1234"
        for line in ('app.config["SECRET_KEY" ] = "' + value + '"', "app.config[ 'SECRET_KEY' ] = '" + value + "'",
                     'os.environ["API_TOKEN"\t] = "' + value + '"'):
            with self.subTest(line=line):
                self.assertTrue(render.secret_in_source("src/settings.py", line + "\n"))
                self.assertNotIn(value, render.redact(line))

    def test_nested_jwt_and_short_authorization_patterns_stay_linear(self):
        for text in ("jwt.sign(" + "(x)" * 66000, "jwt.sign(" + "((x)" * 50000, ("jwt.sign((a,") * 20000,
                     "jwt.sign(" + ("(" + "x" * 150 + "(" + "y" * 150) * 600, "Authorization: Bearer " + "aaaa+" * 40000,
                     ("Authorization: Bearer " + "a" * 50 + "+") * 4000, "Authorization: Bearer " + "A_" * 100000,
                     "Authorization: Bearer abcd" + " " * 200000 + "x", ("Authorization: Bearer ab" + " " * 40) * 4000):
            started = time.monotonic()
            render.mask_multiline(text)
            render.secret_in_source("a.js", text)
            render.redact(text)
            self.assertLess(time.monotonic() - started, 1.0, text[:20])

    def test_valid_pin_without_checkout_or_matching_copy_omits_the_excerpt(self):
        data, _ = self.capture([self.finding("F-001", "src/orders.py:2")], ["src/orders.py"])
        shutil.rmtree(self.repo / ".git")
        (self.repo / "src/orders.py").write_text("def show(order_id):\n    return 1  # LATER\n")
        self.assertIsNotNone(self.snippet(data, "src/orders.py:2", self.repo, evidence_dir=self.out))
        (self.out / "evidence/source/src/orders.py").write_text("def show():\n    TAMPERED\n")
        self.assertIsNone(self.snippet(data, "src/orders.py:2", self.repo, evidence_dir=self.out))
        self.assertIsNone(self.snippet(data, "src/config.py:1", self.repo, evidence_dir=self.out))


class CodexRound8dRecordTests(unittest.TestCase):
    def test_keyword_jwt_keys_are_refused_and_masked(self):
        key = "super" + "secret"
        for text in ('jwt.encode(payload, key="' + key + '")', "jwt.encode(payload, key='" + key + "')",
                     'jwt.encode(payload, secret="' + key + '")', 'jwt.encode(payload, signing_key="' + key + '")',
                     'jwt.encode(payload, algorithm="HS256", key="' + key + '")',
                     'jwt.decode(token, key="' + key + '", algorithms=["HS256"])',
                     'jwt.decode(token, algorithms=["ES256", "HS256"], key="' + key + '")',
                     'jwt.encode(\n    payload,\n    algorithm="HS256",\n    key="' + key + '",\n)'):
            with self.subTest(text=text):
                self.assertTrue(render.secret_in_source("src/auth.py", text + "\n"))
                self.assertNotIn(key, render.mask_multiline(text))
                if "\n" not in text:
                    self.assertNotIn(key, render.redact(text))
        for text in ("jwt.encode(payload, key=settings.SECRET)", 'jwt.encode(payload, key=os.environ["JWT_KEY"])',
                     'jwt.encode(payload, key=os.environ["JWT_KEY"], algorithm="HS256")', 'jwt.encode(payload, algorithm="HS256")',
                     'jwt.decode(\n    token, algorithms=["ES256", "HS256"], options={"verify_signature": False}\n)'):
            with self.subTest(text=text):
                self.assertFalse(render.secret_in_source("src/auth.py", text + "\n"))
                self.assertEqual(render.mask_multiline(text), text)
                self.assertEqual(render.redact(text), text)

    def test_keyword_jwt_pattern_stays_linear(self):
        for text in ("jwt.encode(a" + ", b=c" * 40000, "jwt.encode(a" + ", b=" + "x" * 200000, ("jwt.encode(a, b=(x), ") * 10000,
                     "jwt.encode(a, key=" + " " * 200000, "jwt.encode(a" + (", b=" + "(" * 2) * 40000,
                     "jwt.encode(a" + ", b=[" * 40000, "jwt.encode(a, b=[" + "x" * 200000):
            started = time.monotonic()
            render.mask_multiline(text)
            render.secret_in_source("a.py", text)
            render.redact(text)
            self.assertLess(time.monotonic() - started, 1.0, text[:20])


if __name__ == "__main__":
    unittest.main()
