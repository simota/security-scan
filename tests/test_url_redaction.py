"""URL redaction regressions using inert source text and offline report rendering."""
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import render
import deps_scan
from url_redaction import redact_urls


class UrlRedactionTests(unittest.TestCase):
    def test_no_path_lock_urls_keep_only_hosts_in_scans_and_reports(self):
        markers = ("SYNTHETIC_LOCK_USERINFO", "SYNTHETIC_LOCK_QUERY", "SYNTHETIC_LOCK_FRAGMENT")
        urls = [
            "https://mirror.invalid?token=" + markers[1] + "#" + markers[2],
            "https://mirror.invalid#" + markers[2],
            "https://user:" + markers[0] + "@mirror.invalid:8443?token=" + markers[1],
            "https://user:" + markers[0] + "@[::1]:8443?token=" + markers[1] + "#" + markers[2],
        ]
        for filename in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock"):
            for url in urls:
                with self.subTest(filename=filename, url=url), tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    repository = base / "repository"
                    repository.mkdir()
                    quoted = json.dumps(url)
                    text = ('fixture@1.0.0:\n  resolved ' + quoted + '\n' if filename == "yarn.lock"
                            else '{"dependencies":{"fixture":{"resolved":' + quoted + '}}}')
                    (repository / filename).write_text(text, encoding="utf-8")
                    result = deps_scan.scan(repository, False)
                    host_findings = [f for f in result["findings"] if "non-default host" in f["title"]]
                    self.assertEqual(len(host_findings), 1)
                    host = "::1" if "[::1]" in url else "mirror.invalid"
                    self.assertTrue(host_findings[0]["title"].endswith("host " + host))
                    for marker in markers:
                        self.assertNotIn(marker, json.dumps(result))
                    findings = base / "findings.json"
                    findings.write_text(json.dumps({
                        "meta": {"project": "Synthetic lock URLs", "date": "2026-10-07"},
                        "findings": result["findings"],
                    }), encoding="utf-8")
                    data = render.load(findings)
                    render.attach_sources(data, repository)
                    for language in ("ja", "en"):
                        for renderer in (render.render_dashboard, render.render_assessment_html):
                            html = renderer(data, render.LABELS[language], language)
                            self.assertIn(host, html)
                            for marker in markers:
                                self.assertNotIn(marker, html)

    def test_lock_url_host_parsing_handles_json_escapes_and_invalid_authorities(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "package-lock.json"
            lock.write_text('{"resolved":"https:\\/\\/REGISTRY.NPMJS.ORG?token=SYNTHETIC_QUERY"}',
                            encoding="utf-8")
            result = deps_scan.scan(root, False)
            self.assertFalse(any("non-default host" in f["title"] for f in result["findings"]))
            self.assertNotIn("SYNTHETIC_QUERY", json.dumps(result))
            for authority in ("[broken", "mirror.invalid:bad", "mirror.invalid%3Ftoken=SYNTHETIC_QUERY"):
                lock.write_text(json.dumps({"resolved": "https://" + authority}), encoding="utf-8")
                result = deps_scan.scan(root, False)
                self.assertTrue(any(n["tool"] == "lockfile URL scan" for n in result["not_run"]))
                self.assertNotIn("SYNTHETIC_QUERY", json.dumps(result))

    def test_urls_adjacent_to_unicode_or_underscore_are_fully_redacted(self):
        for prefix in ("接続先", "参照", "é", "Ω", "Ж", "_"):
            for scheme in ("https", "git+https", "HTTP"):
                with self.subTest(prefix=prefix, scheme=scheme):
                    text = (prefix + scheme + "://user:SYNTHETIC_PASSWORD@host.invalid/path"
                            "?signature=SYNTHETIC_QUERY#SYNTHETIC_FRAGMENT")
                    actual = redact_urls(text)
                    self.assertEqual(actual, prefix + scheme.lower() + "://host.invalid/path")
                    self.assertEqual(redact_urls(actual), actual)

    def test_leading_punctuation_and_digits_do_not_hide_url_secrets(self):
        prefixes = ("参考...", "参考-", "See ...", ".", "-", "+", "1", "42.", "--2+")
        for prefix in prefixes:
            for scheme in ("https", "git+https", "HTTP"):
                for quote in ("", "'", '"'):
                    with self.subTest(prefix=prefix, scheme=scheme, quote=quote):
                        text = (prefix + quote + scheme + "://user:SYNTHETIC_PASSWORD@host.invalid/path"
                                "?signature=SYNTHETIC_QUERY#SYNTHETIC_FRAGMENT" + quote)
                        actual = redact_urls(text)
                        self.assertEqual(actual, prefix + quote + scheme.lower() + "://host.invalid/path" + quote)
                        self.assertEqual(redact_urls(actual), actual)

    def test_adjacent_quoted_urls_do_not_leak_later_credentials(self):
        marker = "SYNTHETIC_SECOND_CREDENTIAL"
        for separator in ("','", "';'", "'),('", ",", " "):
            for scheme in ("https", "git+https", "HTTP"):
                with self.subTest(separator=separator, scheme=scheme):
                    text = ("urls = ['https://public.invalid/a" + separator
                            + scheme + "://user:" + marker + "@private.invalid/pkg']")
                    actual = redact_urls(text)
                    self.assertNotIn(marker, actual)
                    self.assertEqual(redact_urls(actual), actual)

    def test_multiple_authorities_and_ambiguous_embedded_urls_stay_private(self):
        markers = ("SYNTHETIC_FIRST_CREDENTIAL", "SYNTHETIC_SECOND_CREDENTIAL",
                   "SYNTHETIC_THIRD_CREDENTIAL")
        urls = ["https://user:" + marker + "@host.invalid/pkg" for marker in markers]
        cases = [
            "urls = ['" + "','".join(urls) + "']",
            "https://public.invalid/nested/" + urls[1],
            "https://public.invalid/a','https://" + markers[1] + "@private.invalid/pkg",
            "https://public.invalid/a','https://user:" + markers[1] + "@[broken",
            "https://public.invalid/a','https://user:" + markers[1] + "@private.invalid:bad/pkg",
        ]
        for text in cases:
            with self.subTest(text=text):
                actual = redact_urls(text)
                for marker in markers:
                    self.assertNotIn(marker, actual)
                self.assertEqual(redact_urls(actual), actual)

    def test_adjacent_queries_and_fragments_are_removed_together_with_userinfo(self):
        markers = ("SYNTHETIC_CREDENTIAL", "SYNTHETIC_QUERY", "SYNTHETIC_FRAGMENT")
        text = ("urls = ['https://public.invalid/a','https://user:" + markers[0]
                + "@private.invalid/pkg?token=" + markers[1] + "#" + markers[2] + "']")
        actual = redact_urls(text)
        for marker in markers:
            self.assertNotIn(marker, actual)
        self.assertEqual(redact_urls(actual), actual)

    def test_internal_apostrophes_do_not_split_a_secret(self):
        secret = "SYNTHETIC_BEFORE'SYNTHETIC_AFTER"
        cases = [
            (f"https://user:{secret}@host.invalid/path", "https://host.invalid/path"),
            (f"https://{secret}:password@host.invalid/path", "https://host.invalid/path"),
            (f"git+https://user:{secret}@host.invalid/repo.git", "git+https://host.invalid/repo.git"),
            (f"https://user:{secret}@[::1]:8443/path", "https://[::1]:8443/path"),
            (f"https://host.invalid/path?token={secret}", "https://host.invalid/path"),
            (f"https://host.invalid/path#{secret}", "https://host.invalid/path"),
            (f"https://user:{secret}@[broken", "[redacted URL]"),
        ]
        for url, expected in cases:
            for quote in ("", "'", '"'):
                with self.subTest(url=url, quote=quote):
                    actual = redact_urls(f"See {quote}{url}{quote} next")
                    self.assertEqual(actual, f"See {quote}{expected}{quote} next")
                    self.assertEqual(redact_urls(actual), actual)
        adjacent = "['https://public.invalid/a','https://user:" + secret + "@host.invalid/path']"
        actual = redact_urls(adjacent)
        self.assertNotIn("SYNTHETIC_BEFORE", actual)
        self.assertNotIn("SYNTHETIC_AFTER", actual)

    def test_single_public_url_keeps_its_path_and_quoted_context(self):
        for url in ("https://host.invalid/pkg", "https://host.invalid/releases/it's-ready"):
            for quote in ("", "'", '"'):
                with self.subTest(url=url, quote=quote):
                    text = f"See {quote}{url}{quote} next"
                    self.assertEqual(redact_urls(text), text)

    def test_attached_source_stays_redacted_in_japanese_and_english_reports(self):
        markers = ("SYNTHETIC_LATER_CREDENTIAL", "SYNTHETIC_QUERY", "SYNTHETIC_FRAGMENT",
                   "SYNTHETIC_BEFORE", "SYNTHETIC_AFTER")
        source = (
            "urls = ['https://public.invalid/a','https://user:" + markers[0]
            + "@private.invalid/pkg']\n"
            + "more = ['https://public.invalid/a','https://user:" + markers[0]
            + "@private.invalid/pkg?token=" + markers[1] + "#" + markers[2] + "']\n"
            + "single = 'https://user:" + markers[3] + "'" + markers[4] + "@single.invalid/path'\n"
            + "note = 'source-marker-safe'\n"
        )
        with tempfile.TemporaryDirectory(prefix="security-scan-url-redaction-") as directory:
            base = Path(directory)
            repository = base / "repository"
            repository.mkdir()
            (repository / "url_fixture.py").write_text(source, encoding="utf-8")
            findings = base / "findings.json"
            findings.write_text(json.dumps({
                "meta": {"project": "Synthetic URL redaction", "date": "2026-10-06"},
                "findings": [{"id": "F-URL", "title": "Synthetic URL source fixture",
                              "location": "url_fixture.py:1-4", "severity": "Info",
                              "confidence": "Suspected", "validation": {"verdict": "Unverified"}}],
            }), encoding="utf-8")
            data = render.load(findings)
            render.attach_sources(data, repository, context=0)
            snippet = data["findings"][0]["snippet"]
            self.assertEqual(len(snippet["lines"]), 4)
            self.assertIn("source-marker-safe", "\n".join(snippet["lines"]))
            for marker in markers:
                self.assertNotIn(marker, json.dumps(snippet))
            for language in ("ja", "en"):
                for renderer in (render.render_dashboard, render.render_assessment_html):
                    with self.subTest(language=language, renderer=renderer.__name__):
                        html = renderer(data, render.LABELS[language], language)
                        self.assertIn("url_fixture.py", html)
                        self.assertIn("source-marker-safe", html)
                        self.assertIn("https://single.invalid/path", html)
                        for marker in markers:
                            self.assertNotIn(marker, html)

    def test_unicode_adjacent_url_is_redacted_in_merged_history_and_source_reports(self):
        markers = ("SYNTHETIC_URL_PASSWORD", "SYNTHETIC_URL_QUERY", "SYNTHETIC_URL_FRAGMENT")
        evidence = ("接続先https://user:" + markers[0] + "@host.invalid/path?signature="
                    + markers[1] + "#" + markers[2])
        with tempfile.TemporaryDirectory(prefix="security-scan-unicode-urls-") as directory:
            root = Path(directory)
            source = root / "url_fixture.py"
            source.write_text("# " + evidence + "\n", encoding="utf-8")
            finding = {"id": "D-001", "title": "Synthetic URL fixture", "severity": "Info",
                       "confidence": "Suspected", "location": "url_fixture.py:1",
                       "category": "Dependencies and platform"}
            previous = dict(finding, validation={"verdict": "NotApplicable", "method": "review",
                                                "evidence": evidence})
            report = root / "findings.json"
            report.write_text(json.dumps({"meta": {"project": "Synthetic URL fixture", "date": "2026-10-06"},
                                          "findings": [previous]}), encoding="utf-8")
            deps_scan.merge_into(report, {"findings": [finding], "inventory": [], "not_run": []}, audit=False)
            merged = report.read_text(encoding="utf-8")
            self.assertIn("previous_validation", merged)
            self.assertIn("接続先https://host.invalid/path", merged)
            for marker in markers:
                self.assertNotIn(marker, merged)
            data = render.load(report)
            render.attach_sources(data, root, context=0)
            self.assertEqual(data["findings"][0]["snippet"]["lines"], ["# 接続先https://host.invalid/path"])
            for language in ("ja", "en"):
                for renderer in (render.render_dashboard, render.render_assessment_html):
                    with self.subTest(language=language, renderer=renderer.__name__):
                        html = renderer(data, render.LABELS[language], language)
                        self.assertIn("接続先https://host.invalid/path", html)
                        for marker in markers:
                            self.assertNotIn(marker, html)


if __name__ == "__main__":
    unittest.main()
