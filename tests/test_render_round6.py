"""render.py round-6 review regressions: excerpt secrets, URL userinfo, link
queries, payload projection, PDF diagnostics, output symlinks, dashboard
responsiveness, copy fallback, priority list, guidance and English plurals."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import contract_check  # noqa: E402
import render  # noqa: E402
import url_redaction  # noqa: E402
from url_redaction import redact_urls  # noqa: E402

BROWSER = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"
GITHUB = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
SLACK = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
JWT = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxIn0.c2lnbmF0dXJl"


def finding(fid="F-001", **extra):
    base = {"id": fid, "title": "Synthetic " + fid, "severity": "High", "confidence": "Confirmed",
            "category": "Input handling", "location": "src/app.py:2"}
    base.update(extra)
    return base


def report(findings, **extra):
    data = {"meta": {"project": "Synthetic", "date": "2026-10-10"}, "findings": findings}
    data.update(extra)
    return data


def payload(dashboard):
    return json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>', dashboard, re.S).group(1))


def quiet(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(*args)
    return code, out.getvalue(), err.getvalue()


class TempDir(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-r6-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def write(self, rel, text):
        path = self.root / "repo" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def excerpts(self, findings):
        data = render.validate_data(report(findings))
        render.attach_sources(data, self.root / "repo")
        return {f["id"]: f.get("snippet") for f in data["findings"]}


class ExcerptSecretTests(TempDir):
    def test_known_tokens_and_jwts_are_masked_anywhere_in_a_line(self):
        for line in ('const octokit = new Octokit({ auth: "' + GITHUB + '" });',
                     'const slack = new WebClient("' + SLACK + '");',
                     'fetch(url, { headers: { Authorization: "Bearer ' + JWT + '" } });',
                     "curl -H 'X: " + GITHUB + "' https://api.invalid"):
            with self.subTest(line=line):
                masked = render.redact(line)
                for secret in (GITHUB, SLACK, JWT, "eyJzdWIi"):
                    self.assertNotIn(secret, masked)
                self.assertIn("********", masked)

    def test_string_prefixes_fallback_defaults_and_short_password_names(self):
        cases = {
            'SECRET_KEY = b"django-insecure-real-secret-key-value"': "django-insecure",
            "API_TOKEN = r'raw-token-value-1234'": "raw-token-value",
            'DB_PASSWORD = os.environ.get("DB_PASSWORD", "Prod-Db-Pa55w0rd!")': "Prod-Db",
            "password = os.getenv('X', 'Fallback-Pa55')": "Fallback-Pa55",
            "token = ENV['API_TOKEN'] || 'lit-secret-value'": "lit-secret-value",
            'api_key = settings.key or "lit-secret-value"': "lit-secret-value",
            "const secret = process.env.S ?? 'lit-secret-value';": "lit-secret-value",
            "pass=hunter2-secret": "hunter2",
            "db_pwd: abc12345-secret": "abc12345",
            'mysql -u app --pwd="Hunter2-secret"': "Hunter2",
        }
        for line, secret in cases.items():
            with self.subTest(line=line):
                self.assertNotIn(secret, render.redact(line))

    def test_ordinary_code_is_not_masked(self):
        for line in ("def view(request):", "    return render(request, 'orders.html', {'rows': rows})",
                     "bypass = check_permissions(user)", "passed = count > 3", "compass_heading = 270",
                     "value = os.environ.get('LOG_LEVEL', 'info')", "name = user.name or 'anonymous'"):
            with self.subTest(line=line):
                self.assertEqual(render.redact(line), line)

    def test_reviewer_repository_has_no_secret_in_any_output(self):
        self.write("src/gh.js", "// GitHub client\nconst octokit = new Octokit({ auth: \"" + GITHUB + "\" });\n"
                   "const slack = new WebClient(\"" + SLACK + "\");\n"
                   "fetch(url, { headers: { Authorization: \"Bearer " + JWT + "\" } });\n")
        self.write("src/settings.py", "import os\nDB_PASSWORD = os.environ.get(\"DB_PASSWORD\", \"Prod-Db-Pa55w0rd!\")\n"
                   "SECRET_KEY = b\"django-insecure-real-secret-key-value\"\n"
                   "DATABASE_URL = \"postgres://app:5432/SuperSecret@db/app\"\n")
        self.write(".pgpass", "db.internal:5432:app:app:Pr0dPassw0rd\n")
        self.write(".docker/config.json", '{"auths":{"registry.example.com":{"auth":"dXNlcjpodW50ZXIyaHVudGVyMg=="}}}\n')
        self.write(".htpasswd", "admin:$apr1$SALTSALT$HtpasswdHashValue\n")
        self.write("infra/terraform.tfstate", '{"password": "TfStateSecret"}\n')
        self.write("infra/prod.tfvars", 'db_password = "TfVarsSecret"\n')
        findings = [finding("F-001", location="src/gh.js:2"), finding("F-002", location="src/settings.py:2"),
                    finding("F-003", location=".docker/config.json:1"), finding("F-004", location=".pgpass:1"),
                    finding("F-005", location=".htpasswd:1"), finding("F-006", location="infra/terraform.tfstate:1"),
                    finding("F-007", location="infra/prod.tfvars:1")]
        source = self.root / "findings.json"
        source.write_text(json.dumps(report(findings)), encoding="utf-8")
        code, _, err = quiet(render.main, [str(source), "--out", str(self.root / "out"), "--repo",
                                           str(self.root / "repo"), "--no-pdf"])
        self.assertEqual(code, 0, err)
        text = "".join((self.root / "out" / name).read_text(encoding="utf-8")
                       for name in ("dashboard.html", "assessment.html"))
        for secret in (GITHUB, SLACK, JWT, "eyJzdWIi", "Prod-Db-Pa55w0rd", "django-insecure", "SuperSecret",
                       "dXNlcjpodW50ZXIy", "Pr0dPassw0rd", "HtpasswdHashValue", "TfStateSecret", "TfVarsSecret"):
            self.assertNotIn(secret, text)
        snippets = {f["id"]: f.get("snippet") for f in payload((self.root / "out/dashboard.html").read_text())["findings"]}
        # Ordinary files keep a (masked) excerpt; credential files are withheld.
        self.assertIn("const slack = new WebClient(", "\n".join(snippets["F-001"]["lines"]))
        self.assertIn("import os", snippets["F-002"]["lines"])
        for fid in ("F-003", "F-004", "F-005", "F-006", "F-007"):
            self.assertIsNone(snippets[fid], fid)

    def test_new_sensitive_paths(self):
        for path in (".docker/config.json", "home/.pgpass", "web/.htpasswd", "terraform.tfstate",
                     "env/prod.tfvars", "terraform.tfstate.backup", "x/.dockercfg"):
            with self.subTest(path=path):
                self.assertTrue(render.sensitive_path(path))
                self.assertTrue(render.secret_in_source(path, "anything"))
        self.assertFalse(render.sensitive_path("src/config.json"))

    def test_secrets_category_keeps_crypto_excerpt_but_withholds_bare_values(self):
        self.write("app.py", "import hashlib\n\ndef digest(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n")
        self.write("keys.py", "LOOKUP = {\n    'k': 'Zx9QmW4tR7uY2pL8',\n}\n")
        self.write("bare.py", "SYNTHETIC_SECRET\n")
        snippets = self.excerpts([finding("F-001", category="Secrets", location="app.py:4"),
                                  finding("F-002", category="Secrets", location="keys.py:2"),
                                  finding("F-003", category="Secrets", location="bare.py:1")])
        self.assertIn("    return hashlib.md5(pw.encode()).hexdigest()", snippets["F-001"]["lines"])
        self.assertIsNone(snippets["F-002"])
        self.assertIsNone(snippets["F-003"])


class UrlUserinfoTests(unittest.TestCase):
    LEAKS = {
        "postgres://app:5432/SuperSecret@db/app": "SuperSecret",
        "https://svc:2024/Qx9+abc=@db.internal/x": "Qx9+abc",
        "https://user:/s3cr3t@host/x": "s3cr3t",
        "redis://default:1234#Abcd@cache:6379": "Abcd",
        'url = "https://user:p"ssw0rd@host/x"': "ssw0rd",
        'u = "//user:pw-secret@host/path"': "pw-secret",
        "next=https%3A%2F%2Fuser%3Apw-secret%40host%2Fx": "pw-secret",
    }

    def test_passwords_with_delimiters_quotes_and_encodings_are_removed(self):
        for text, secret in self.LEAKS.items():
            with self.subTest(text=text):
                cleaned = redact_urls(text)
                self.assertNotIn(secret, cleaned)
                self.assertNotIn(secret, render.redact(text))
                self.assertEqual(redact_urls(cleaned), cleaned)
                self.assertTrue(url_redaction.has_url_credentials(text))
                self.assertTrue(render.secret_in_source("src/app.py", text))

    def test_ordinary_at_signs_in_paths_are_kept(self):
        for url in ("https://registry.npmjs.org/@scope/pkg", "https://pkg.go.dev/golang.org/x/net@v0.17.0",
                    "https://medium.com/@author/post", "git+ssh://git@github.com/org/repo.git"):
            with self.subTest(url=url):
                self.assertEqual(redact_urls(url), url.replace("git@", ""))
        for text in ("https://registry.npmjs.org/@scope/pkg", "// contact admin@example.com"):
            self.assertFalse(render.secret_in_source("src/app.py", text))


class LinkQueryTests(TempDir):
    def data(self):
        return render.validate_data(report(
            [finding("F-001", location="src/api/orders.py:42",
                     references=["https://gitlab.example.com/api/v4/jobs/2/artifacts?private_token=glpat-ZYXWVUTSRQPONMLKJIHG",
                                 {"url": "https://h.invalid/cb?page=2&sig=SIGNATURE_VALUE#access_token=" + JWT,
                                  "title": "see https://h.invalid/x?token=TITLE_TOKEN_VALUE"},
                                 "https://example.invalid/a?x=1&y=2#L10-L20"])],
            meta={"project": "Synthetic", "date": "2026-10-10",
                  "source_url": "https://gitlab.example.com/grp/app/-/blob/abc123?private_token=glpat-ABCDEFGHIJKLMNOPQRST"}))

    def test_tokens_in_queries_never_reach_links_or_payload(self):
        data = self.data()
        render.attach_sources(data, None)
        self.assertEqual(data["findings"][0]["source_link"],
                         "https://gitlab.example.com/grp/app/-/blob/abc123/src/api/orders.py#L42")
        for lang in ("en", "ja"):
            dashboard = render.render_dashboard(data, render.LABELS[lang], lang)
            assessment = render.render_assessment_html(data, render.LABELS[lang], lang)
            for text in (dashboard, assessment):
                for secret in ("glpat-", "private_token", "SIGNATURE_VALUE", "eyJzdWIi", "TITLE_TOKEN_VALUE"):
                    self.assertNotIn(secret, text)
                # Ordinary parameters and line anchors survive.
                self.assertIn("https://example.invalid/a?x=1&amp;y=2#L10-L20"
                              if text is assessment else "https://example.invalid/a?x=1&y=2#L10-L20", text)
                self.assertIn("https://h.invalid/cb?page=2", text)
            self.assertEqual(payload(dashboard)["meta"]["source_url"], "https://gitlab.example.com/grp/app/-/blob/abc123")


class PayloadProjectionTests(unittest.TestCase):
    def test_validation_extension_keys_stay_out_of_the_dashboard(self):
        data = render.validate_data(report([finding(
            validation={"verdict": "Valid", "evidence": "Route has no owner check", "method": "review",
                        "raw_http": "Cookie: session=SECRETSESSION123"},
            previous_validation={"verdict": "Likely", "evidence": "older", "scanner_dump": {"api_key": "HIDDENAPIKEY"}})]))
        dashboard = render.render_dashboard(data, render.LABELS["en"], "en")
        for secret in ("SECRETSESSION123", "HIDDENAPIKEY", "raw_http", "scanner_dump"):
            self.assertNotIn(secret, dashboard)
        shown = payload(dashboard)["findings"][0]
        self.assertEqual(shown["validation"], {"verdict": "Valid", "evidence": "Route has no owner check", "method": "review"})
        self.assertEqual(shown["previous_validation"], {"verdict": "Likely", "evidence": "older"})


class AnchorIndexTests(unittest.TestCase):
    def test_anchor_lookup_is_constant_time_and_tracks_reordering(self):
        findings = [{"id": "F-%05d" % i} for i in range(20000)]
        data = {"findings": findings}
        started = time.monotonic()
        anchors = [render.finding_anchor(data, f) for f in findings]
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(anchors[0], "finding-1")
        self.assertEqual(anchors[-1], "finding-20000")
        findings.reverse()
        self.assertEqual(render.finding_anchor(data, findings[0]), "finding-1")
        other = {"findings": [findings[5]]}
        self.assertEqual(render.finding_anchor(other, findings[5]), "finding-1")
        self.assertEqual(render.finding_anchor(data, findings[5]), "finding-6")


@unittest.skipIf(os.name == "nt", "POSIX shell fixture")
class PdfDiagnosticTests(TempDir):
    def fake_chrome(self, body):
        tool = self.root / "bin" / "chrome"
        tool.parent.mkdir(exist_ok=True)
        tool.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        tool.chmod(0o755)
        return tool

    def html(self):
        page = self.root / "a.html"
        page.write_text("<p>x</p>", encoding="utf-8")
        return page

    def test_root_adds_no_sandbox_and_failure_keeps_stderr(self):
        log = self.root / "args"
        chrome = self.fake_chrome(f'echo "$@" > "{log}"; echo "Running as root without --no-sandbox is not supported" >&2; exit 1')
        failures = []
        with patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(chrome.parent)}), \
             patch.object(render.os, "geteuid", return_value=0, create=True):
            self.assertIsNone(render.to_pdf(self.html(), self.root / "a.pdf", failures))
        self.assertIn("--no-sandbox", log.read_text())
        self.assertEqual(len(failures), 1)
        engine, reason, tail = failures[0]
        self.assertEqual(engine, "chrome")
        self.assertIn("exited with status 1", reason)
        self.assertIn("as root", reason)
        self.assertIn("not supported", tail)
        with patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(chrome.parent)}), \
             patch.object(render.os, "geteuid", return_value=1000, create=True):
            render.to_pdf(self.html(), self.root / "a.pdf", [])
        self.assertNotIn("--no-sandbox", log.read_text())

    def test_timeout_is_reported_and_configurable(self):
        chrome = self.fake_chrome("exec " + (shutil.which("sleep") or "/bin/sleep") + " 30")
        failures = []
        started = time.monotonic()
        with patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(chrome.parent),
                                     "SECURITY_SCAN_PDF_TIMEOUT": "1"}):
            self.assertIsNone(render.to_pdf(self.html(), self.root / "a.pdf", failures))
        self.assertLess(time.monotonic() - started, 20)
        self.assertIn("timed out after 1 s", failures[0][1])
        with patch.dict(os.environ, {"SECURITY_SCAN_PDF_TIMEOUT": ""}):
            self.assertEqual(render.pdf_timeout(0), 120)
            self.assertEqual(render.pdf_timeout(1000), 170)
            self.assertEqual(render.pdf_timeout(10 ** 6), 900)
        with patch.dict(os.environ, {"SECURITY_SCAN_PDF_TIMEOUT": "45"}):
            self.assertEqual(render.pdf_timeout(10 ** 6), 45)

    def test_failed_engine_message_is_distinct_and_accepted_by_contract_check(self):
        chrome = self.fake_chrome('echo "boom: GPU process crashed" >&2; exit 5')
        source = self.root / "findings.json"
        source.write_text(json.dumps(report([finding()])), encoding="utf-8")
        with patch.dict(os.environ, {"CHROME": str(chrome), "PATH": str(chrome.parent)}):
            code, _, err = quiet(render.main, [str(source), "--out", str(self.root / "out")])
        self.assertEqual(code, 3)
        self.assertNotIn("no PDF engine found", err)
        self.assertIn("PDF engine failed", err)
        self.assertIn("GPU process crashed", err)
        self.assertIn("--no-pdf", err)
        limitation = re.search(r"'(assessment\.pdf not produced: PDF engine failed \([^']*\))'", err).group(1)
        self.assertIn(contract_check.NO_PDF, limitation.lower())
        problems = contract_check.check({"findings": [], "limitations": [limitation]}, self.root / "out", pdf=False)
        self.assertFalse([p for p in problems if "assessment.pdf not produced" in p], problems)
        with patch.object(render, "to_pdf", return_value=None):
            code, _, err = quiet(render.main, [str(source), "--out", str(self.root / "out")])
        self.assertEqual(code, 3)
        self.assertIn("no PDF engine found", err)
        self.assertIn("--repo <repo>", err)
        self.assertIn("--no-pdf", err)


class OutputSymlinkTests(TempDir):
    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_planted_symlinks_are_refused_and_targets_untouched(self):
        source = self.root / "findings.json"
        source.write_text(json.dumps(report([finding()])), encoding="utf-8")
        victim = self.root / "victim.txt"
        for name in ("dashboard.html", "assessment.html", "assessment.pdf"):
            with self.subTest(name=name):
                out = self.root / ("out-" + name)
                out.mkdir()
                victim.write_text("original", encoding="utf-8")
                (out / name).symlink_to(victim)
                code, _, err = quiet(render.main, [str(source), "--out", str(out), "--no-pdf"])
                self.assertEqual(code, 2)
                self.assertIn("symlink", err)
                self.assertEqual(victim.read_text(encoding="utf-8"), "original")
                self.assertTrue((out / name).is_symlink())

    def test_regular_outputs_are_replaced_atomically(self):
        source = self.root / "findings.json"
        source.write_text(json.dumps(report([finding()])), encoding="utf-8")
        out = self.root / "out"
        out.mkdir()
        (out / "dashboard.html").write_text("stale", encoding="utf-8")
        code, _, err = quiet(render.main, [str(source), "--out", str(out), "--no-pdf"])
        self.assertEqual(code, 0, err)
        self.assertIn("<!doctype html>", (out / "dashboard.html").read_text(encoding="utf-8"))
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["assessment.html", "dashboard.html"])


def review_only_report():
    sample = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
    data = copy.deepcopy(sample)
    target = data["findings"][0]
    target["status"] = "Open"
    target.pop("remediation", None)
    target["verification"].pop("reviews", None)
    data["findings"] = [target]
    return render.validate_data(data)


class GuidanceAndWordingTests(unittest.TestCase):
    def test_review_only_gap_gets_reviewer_guidance(self):
        data = review_only_report()
        state = render.derive_verification(data, render.SchemaError)["F-001"]
        self.assertEqual(state["gaps"], ["review_missing"])
        self.assertTrue(render.review_only_gap(data["findings"][0], state))
        for lang in ("en", "ja"):
            labels = render.LABELS[lang]
            assessment = render.render_assessment_html(data, labels, lang)
            self.assertIn(render.ASSESSMENT_LABELS[lang]["a_verify_review_action"], assessment)
            self.assertTrue(labels["verify_review_note"])
            self.assertIn("verify_review_note", render.render_dashboard(data, labels, lang))

    def test_excluded_records_do_not_show_open_status(self):
        data = render.validate_data(report([finding("F-001"), finding(
            "F-002", validation={"verdict": "FalsePositive", "evidence": "Constant input"})]))
        for lang in ("en", "ja"):
            assessment = render.render_assessment_html(data, render.LABELS[lang], lang)
            section = assessment[assessment.index("id='excluded-findings'"):]
            state = re.search(r"<table class='finding-state'>.*?</table>", section, re.S).group(0)
            self.assertNotIn("<td>Open</td>", state)
            self.assertIn("<td>" + render.LABELS[lang]["excluded_short"] + "</td>", state)

    def test_english_singular_forms(self):
        data = render.validate_data(report([finding("F-001"), finding(
            "F-002", validation={"verdict": "FalsePositive", "evidence": "Constant input"})]))
        assessment = render.render_assessment_html(data, render.LABELS["en"], "en")
        self.assertIn("1 non-excluded finding in total", assessment)
        self.assertIn("1 excluded finding is retained separately.", assessment)
        self.assertIn("1 non-excluded finding remains Unverified across all statuses.", assessment)
        self.assertNotIn("1 excluded findings", assessment)
        model = {"verification_counts": {"static": 0, "runtime": 0, "pending": 2, "retested": 1}}
        sentence = "".join(str(p.get("count", p.get("text"))) for p in render.verification_summary_parts(model, render.LABELS["en"]))
        self.assertIn("1 fix has a complete retest record.", sentence)
        self.assertEqual(render.LABELS["en"]["risk_summary_one"], "1 open High / Medium finding needs attention.")
        # Japanese has no plural forms: its text is unchanged.
        ja = render.render_assessment_html(data, render.LABELS["ja"], "ja")
        self.assertIn("除外対象を除く指摘は計1件", ja)
        model["verification_counts"]["retested"] = 2
        sentence = "".join(str(p.get("count", p.get("text"))) for p in render.verification_summary_parts(model, render.LABELS["en"]))
        self.assertIn("2 fixes have complete retest records.", sentence)


class DashboardScriptTests(unittest.TestCase):
    def test_search_is_debounced_details_are_lazy_and_copy_falls_back(self):
        script = render.DASHBOARD
        self.assertIn("setTimeout(draw,150)", script)
        self.assertIn("function fillDetails(dt,f,anchor)", script)
        self.assertIn(".catch(function(){return copyFallback(text);})", script)


@unittest.skipUnless(BROWSER, "opt-in Chromium interaction test")
class DashboardBrowserTests(unittest.TestCase):
    def start_browser(self):
        exe = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not exe:
            self.fail("Required Chrome/Chromium not installed; set CHROME to its executable")
        from playwright.sync_api import sync_playwright
        manager = sync_playwright().start()
        self.addCleanup(manager.stop)
        browser = manager.chromium.launch(executable_path=exe, headless=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page(service_workers="block")
        page.set_default_timeout(10000)
        page.route("**/*", lambda route: route.abort())
        return page

    def test_browser_large_register_lazy_details_debounced_search_priority_and_copy_fallback(self):
        page = self.start_browser()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        findings = [finding("F-%03d" % i, title="Record number %d" % i, severity="High" if i < 6 else "Medium")
                    for i in range(1, 400)]
        findings.append(finding("D-001", title="Dependency record", severity="Medium"))
        data = render.validate_data(report(findings))
        labels = render.LABELS["en"]
        page.goto("about:blank")
        page.set_content(render.render_dashboard(data, labels, "en"), wait_until="domcontentloaded")
        # The Clipboard API exists but is denied: copying must still succeed.
        page.evaluate("""() => {
            Object.defineProperty(window, 'isSecureContext', {value: true});
            Object.defineProperty(navigator, 'clipboard', {value: {writeText: () => Promise.reject(new Error('denied'))}});
            document.addEventListener('copy', e => { window.copied = e.target.value; });
        }""")
        self.assertEqual(page.locator("tr.row").count(), 400)
        # Unexpanded rows carry no detail content.
        self.assertEqual(page.locator("tr.detail .copy-finding").count(), 0)
        # Every open High in a part is listed, not only the first four.
        self.assertEqual(page.locator("#priority-code + .priority-list .priority-item").count(), 5)
        # Debounced search: one redraw after typing pauses.
        page.locator("#f-q").fill("Record number 7")
        page.wait_for_function("document.querySelectorAll('tr.row').length < 400")
        self.assertEqual(page.locator("tr.row").count(), 11)
        page.locator("#reset").click()
        self.assertEqual(page.locator("tr.row").count(), 400)
        # A hash link expands and focuses the row and builds its details.
        anchor = render.finding_anchor(data, data["findings"][200])
        page.evaluate("anchor => { window.location.hash = anchor; }", anchor)
        page.wait_for_function("anchor => document.getElementById(anchor + '-detail') && !document.getElementById(anchor + '-detail').hidden", arg=anchor)
        detail = page.locator("#" + anchor + "-detail")
        self.assertTrue(detail.locator(".verification-record").is_visible())
        self.assertEqual(page.evaluate("document.activeElement.className"), "finding-toggle")
        detail.locator(".copy-finding").click()
        page.get_by_role("button", name=labels["copied"], exact=True).wait_for()
        self.assertTrue(page.evaluate("window.copied").startswith("## " + data["findings"][200]["id"]))
        self.assertEqual(page.locator("tr.detail .copy-finding").count(), 1)
        # Collapsing and re-expanding keeps a single detail tree.
        toggle = page.locator("#" + anchor + " .finding-toggle")
        toggle.click()
        toggle.click()
        self.assertEqual(detail.locator(".verification-record").count(), 1)
        self.assertEqual(errors, [])

    def test_browser_singular_summary_and_more_high_note(self):
        page = self.start_browser()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("about:blank")
        data = render.validate_data(report([finding("F-001", severity="Medium")]))
        page.set_content(render.render_dashboard(data, render.LABELS["en"], "en"), wait_until="domcontentloaded")
        self.assertIn("1 open High / Medium finding needs attention.", page.locator("#summary").inner_text())
        many = render.validate_data(report([finding("F-%03d" % i) for i in range(1, 16)]))
        page.set_content(render.render_dashboard(many, render.LABELS["en"], "en"), wait_until="domcontentloaded")
        self.assertEqual(page.locator("#priority-code + .priority-list .priority-item").count(), 12)
        self.assertIn("3 more open High findings in this part", page.locator("#priority").inner_text())
        review = review_only_report()
        page.set_content(render.render_dashboard(review, render.LABELS["en"], "en"), wait_until="domcontentloaded")
        page.locator(".finding-toggle").click()
        self.assertIn(render.LABELS["en"]["verify_review_note"], page.locator(".action-guidance").inner_text())
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
