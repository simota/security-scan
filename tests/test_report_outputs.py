"""Report-only regressions using synthetic data; no target audit is performed.

The mandatory suite uses the standard library. Set SECURITY_SCAN_BROWSER_TEST=1
and CHROME to opt into real, offline Chromium interaction checks.
"""
import copy
from html.parser import HTMLParser
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


class Element:
    def __init__(self, tag, attrs=(), parent=None):
        self.tag = tag
        self.attrs = dict(attrs)
        self.parent = parent
        self.children = []

    def text(self):
        return "".join(child.text() if isinstance(child, Element) else child
                       for child in self.children)

    def find_all(self, tag=None, **attrs):
        matches = []
        for child in self.children:
            if isinstance(child, Element):
                if (tag is None or child.tag == tag) and all(
                        child.attrs.get(key) == value for key, value in attrs.items()):
                    matches.append(child)
                matches.extend(child.find_all(tag, **attrs))
        return matches

    def find(self, tag=None, **attrs):
        matches = self.find_all(tag, **attrs)
        if len(matches) != 1:
            raise AssertionError(f"Expected one {tag or 'element'} {attrs}, found {len(matches)}")
        return matches[0]


class ReportHTML(HTMLParser):
    """Small structural reader, not a browser or an HTML conformance checker."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
            "meta", "param", "source", "track", "wbr"}

    def __init__(self, markup):
        super().__init__(convert_charrefs=True)
        self.root = Element("document")
        self.current = self.root
        self.feed(markup)
        self.close()

    def handle_starttag(self, tag, attrs):
        node = Element(tag, attrs, self.current)
        self.current.children.append(node)
        if tag not in self.VOID:
            self.current = node

    def handle_endtag(self, tag):
        node = self.current
        while node.parent is not None:
            if node.tag == tag:
                self.current = node.parent
                return
            node = node.parent

    def handle_data(self, data):
        self.current.children.append(data)


class ReportOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts/render.py"
        spec = importlib.util.spec_from_file_location("report_output_renderer", script)
        cls.renderer = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(script.parent)] + sys.path):
            spec.loader.exec_module(cls.renderer)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-reports-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def finding(self, id="F-001", severity="High", confidence="Confirmed",
                status="Open", verdict="Unverified", **fields):
        return {"id": id, "title": "Synthetic finding " + id, "severity": severity,
                "confidence": confidence, "status": status, "location": "src/fixture.py:12",
                "category": "Synthetic review", "impact": "Synthetic impact",
                "fix": "Synthetic fix direction",
                "validation": {"verdict": verdict, "method": "review",
                               "evidence": "Synthetic evidence for " + verdict}, **fields}

    def report(self, findings=(), **fields):
        data = {"meta": {"project": "Synthetic report", "date": "2026-10-06"},
                "findings": list(findings), **fields}
        path = self.root / "findings.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return self.renderer.load(path)

    def output(self, data, lang="en"):
        labels = self.renderer.LABELS[lang]
        dashboard = self.renderer.render_dashboard(data, labels, lang)
        assessment = self.renderer.render_assessment_html(data, labels, lang)
        return ReportHTML(dashboard).root, ReportHTML(assessment).root

    def payload(self, dashboard):
        script = dashboard.find("script", id="data")
        self.assertEqual(script.attrs["type"], "application/json")
        self.assertNotIn("<", script.text(), "JSON must not close or alter its HTML script element")
        return json.loads(script.text())

    def mixed_report(self):
        return self.report([
            self.finding("H-fix", verdict="Valid", category="__proto__", title="Fix fixture"),
            self.finding("H-verify", confidence="Suspected", category="Normal category"),
            self.finding("M-fixed", severity="Medium", status="Fixed", verdict="Likely",
                         category="constructor"),
            self.finding("L-accepted", severity="Low", status="Accepted", category="toString"),
            self.finding("X-excluded", verdict="FalsePositive", category="Excluded-only category"),
            self.finding("X-not-applicable", severity="Info", status="Accepted",
                         verdict="NotApplicable", category="Other excluded category"),
        ])

    def test_action_model_covers_every_verdict_confidence_and_status(self):
        r = self.renderer
        combinations = list(itertools.product(r.VERDICTS, r.CONFIDENCES, r.STATUSES))
        data = self.report([self.finding(f"M-{i:03d}", verdict=verdict,
                                        confidence=confidence, status=status)
                            for i, (verdict, confidence, status) in enumerate(combinations)])
        original = copy.deepcopy(data)
        model = r.report_model(data)
        queued = {item["finding"]["id"]: item for item in model["queue"]}
        for finding in data["findings"]:
            with self.subTest(verdict=finding["verdict"], confidence=finding["confidence"],
                              status=finding["status"]):
                included_open = finding["verdict"] not in r.EXCLUDED and finding["status"] == "Open"
                self.assertEqual(finding["id"] in queued, included_open)
                expected = ("fix_now" if finding["status"] == "Open"
                            and finding["verdict"] == "Valid"
                            and finding["confidence"] == "Confirmed" else "verify_first")
                self.assertEqual(r.action_kind(finding), expected)
                if included_open:
                    self.assertEqual(queued[finding["id"]]["action"], expected)
        self.assertEqual({k: v for k, v in model.items() if k != "queue"}, {
            "open_count": 12, "fix_now": 1, "verify_first": 11,
            "fixed": 12, "accepted": 12, "excluded": 18,
            "unverified": 9, "unverified_high": 9,
        })
        self.assertEqual(data, original, "Deriving actions must not rewrite evidence or verdicts")

    def test_priority_is_severity_first_then_readiness_then_id(self):
        data = self.report([
            self.finding("L-fix", severity="Low", verdict="Valid"),
            self.finding("A-verify"), self.finding("Z-fix", verdict="Valid"),
            self.finding("B-verify"),
            self.finding("M-verify", severity="Medium", verdict="Likely"),
            self.finding("M-fix", severity="Medium", verdict="Valid"),
            self.finding("Fixed", status="Fixed", verdict="Valid"),
            self.finding("Excluded", verdict="FalsePositive"),
        ])
        expected = ["Z-fix", "A-verify", "B-verify", "M-fix", "M-verify", "L-fix"]
        model = self.renderer.report_model(data)
        self.assertEqual([item["finding"]["id"] for item in model["queue"]], expected)
        dashboard, assessment = self.output(data)
        self.assertEqual([item["finding"]["id"] for item in self.payload(dashboard)["report"]["queue"]],
                         expected)
        self.assertEqual([a.text() for a in assessment.find(id="priority-queue").find_all("a")],
                         expected)

    def test_excluded_records_do_not_inflate_included_counts_or_queue(self):
        data = self.mixed_report()
        counts = self.renderer.stats(data)
        self.assertEqual(counts["excluded"], 2)
        self.assertEqual(counts["open_hm"], 2)
        for key in ("severity", "confidence", "category", "status"):
            self.assertEqual(sum(counts[key].values()), 4, key)
        # Validation distribution deliberately accounts for every retained record.
        self.assertEqual(sum(counts["verdict"].values()), 6)
        model = self.renderer.report_model(data)
        self.assertEqual((model["open_count"], model["fixed"], model["accepted"]), (2, 1, 1))
        self.assertEqual((model["unverified"], model["unverified_high"]), (2, 1))
        _, assessment = self.output(data)
        excluded = assessment.find(id="excluded-findings")
        self.assertEqual(len(excluded.find_all("article")), 2)
        register = assessment.find(id="finding-register").text()
        self.assertNotIn("X-excluded", register)
        self.assertNotIn("X-not-applicable", register)
        self.assertIn("X-excluded", excluded.text())
        self.assertIn("Synthetic evidence for FalsePositive", excluded.text())

    def test_dashboard_and_assessment_share_report_counts_in_both_languages(self):
        data = self.mixed_report()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                dashboard, assessment = self.output(data, lang)
                payload = self.payload(dashboard)
                expected = {**payload["report"], "open_hm": payload["open_hm"]}
                metrics = assessment.find_all(**{"data-report-count": "open_count"})
                self.assertTrue(metrics, "Assessment should expose the displayed count basis")
                for key in ("open_count", "fix_now", "verify_first", "open_hm"):
                    metric = assessment.find(**{"data-report-count": key})
                    self.assertEqual(int(metric.text()), expected[key], key)
                self.assertEqual(payload["report"], self.renderer.report_model(data))
                self.assertEqual(payload["open_hm"], self.renderer.stats(data)["open_hm"])
                self.assertEqual(assessment.find("html").attrs["lang"], lang)

    def test_anchors_are_safe_unique_and_consistent_across_outputs_and_input_order(self):
        ids = ["__proto__", "constructor", "toString", "x'\" ] # <svg/onload=fixture>",
               "日本語 / path:1", "</script><!--<script>INERT"]
        findings = [self.finding(id, verdict="Valid") for id in ids]
        data = self.report(findings)
        first = {f["id"]: self.renderer.finding_anchor(data, f) for f in data["findings"]}
        reordered = self.report(reversed(findings))
        second = {f["id"]: self.renderer.finding_anchor(reordered, f) for f in reordered["findings"]}
        self.assertEqual(first, second)
        self.assertEqual(len(set(first.values())), len(ids))
        for anchor in first.values():
            self.assertRegex(anchor, r"^finding-[A-Za-z0-9_-]+$")
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            self.assertEqual(payload["anchors"], first)
            all_ids = [node.attrs["id"] for node in assessment.find_all() if "id" in node.attrs]
            self.assertEqual(len(all_ids), len(set(all_ids)))
            for anchor in first.values():
                self.assertEqual(assessment.find(id=anchor).tag, "article")
            for link in assessment.find_all("a"):
                if link.attrs.get("href", "").startswith("#"):
                    self.assertIn(link.attrs["href"][1:], all_ids)

    def test_hostile_content_stays_text_in_dashboard_and_assessment(self):
        hostile = "</script><svg onload='INERT'>日本語 & \"quoted\"</svg><!--"
        finding = self.finding(hostile, title=hostile, category=hostile, location=hostile,
                               actor=hostile, request=hostile, impact=hostile, fix=hostile,
                               validation={"verdict": "Valid", "evidence": hostile, "method": hostile},
                               references=[{"url": "https://example.invalid/a?x=1&y=2",
                                            "title": hostile, "type": hostile}])
        data = self.report([finding], meta={"project": hostile, "date": "2026-10-06",
                                           "scope": hostile, "method": hostile},
                           perspectives=[{"name": hostile, "result": hostile, "note": hostile}],
                           limitations=[hostile], checked_ok=[hostile], decisions=[hostile],
                           next_steps=[hostile])
        data["findings"][0]["snippet"] = {"start": 11, "hit": [12, 12], "lines": [hostile, hostile]}
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                dashboard, assessment = self.output(data, lang)
                self.assertEqual(len(dashboard.find_all("script")), 2)
                self.assertFalse(assessment.find_all("script"))
                for document in (dashboard, assessment):
                    self.assertFalse(document.find_all("svg"))
                    self.assertFalse(document.find_all("img"))
                    self.assertFalse(any(key.lower().startswith("on")
                                         for node in document.find_all() for key in node.attrs))
                payload = self.payload(dashboard)
                self.assertEqual(payload["meta"]["project"], hostile)
                self.assertEqual(payload["findings"][0]["title"], hostile)
                self.assertEqual(payload["findings"][0]["snippet"]["lines"], [hostile, hostile])
                article = assessment.find("article")
                self.assertIn(hostile, article.text())
                self.assertEqual(article.find("a", href="https://example.invalid/a?x=1&y=2").text(), hostile)

    def test_empty_reports_preserve_unknown_coverage_and_security_caveats(self):
        data = self.report()
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                dashboard, assessment = self.output(data, lang)
                payload = self.payload(dashboard)
                self.assertFalse(payload["report"]["queue"])
                self.assertEqual(payload["report"]["open_count"], 0)
                self.assertFalse(payload["perspectives"])
                self.assertFalse(payload["limitations"])
                labels = self.renderer.LABELS[lang]
                self.assertTrue(payload["labels"]["coverage_missing"])
                self.assertTrue(payload["labels"]["limitations_empty"])
                self.assertIn("coverage_note", [n.attrs.get("data-l") for n in dashboard.find_all()])
                a_labels = {**self.renderer.ASSESSMENT_LABELS[lang], **labels}
                for key in ("a_uncertainty", "a_limits_empty", "a_coverage_empty",
                            "a_queue_empty", "a_checks_empty"):
                    self.assertIn(a_labels[key], assessment.text())
                self.assertFalse(assessment.find_all("article"))

    def test_partial_coverage_keeps_blank_results_explicit_and_limits_visible(self):
        limitation = "Synthetic runtime and deployment checks were not performed."
        data = self.report(perspectives=[{"name": "Synthetic perspective", "result": "", "note": ""}],
                           limitations=[limitation])
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            self.assertEqual(payload["perspectives"][0]["result"], "")
            self.assertEqual(payload["limitations"], [limitation])
            coverage = assessment.find(id="recorded-coverage")
            self.assertIn("Synthetic perspective", coverage.text())
            unknown = self.renderer.ASSESSMENT_LABELS[lang]["a_not_recorded"]
            self.assertGreaterEqual(coverage.text().count(unknown), 2)
            self.assertIn(limitation, assessment.find(id="executive-summary").text())

    def test_closed_or_excluded_only_reports_have_no_action_queue(self):
        for findings in ([self.finding(status="Fixed", verdict="Valid")],
                         [self.finding(status="Accepted", verdict="Unverified")],
                         [self.finding(verdict="FalsePositive")], []):
            with self.subTest(findings=findings):
                data = self.report(findings)
                dashboard, assessment = self.output(data)
                payload = self.payload(dashboard)
                self.assertEqual(payload["report"]["open_count"], 0)
                self.assertEqual(payload["report"]["fix_now"], 0)
                self.assertEqual(payload["report"]["verify_first"], 0)
                self.assertFalse(assessment.find(id="priority-queue").find_all("a"))
                self.assertIn(self.renderer.ASSESSMENT_LABELS["en"]["a_queue_empty"], assessment.text())

    def test_assessment_keeps_full_long_fix_and_evidence_in_details(self):
        fix = "Synthetic remediation " * 45 + "END_OF_COMPLETE_FIX"
        evidence = "Synthetic evidence " * 65 + "END_OF_COMPLETE_EVIDENCE"
        data = self.report([self.finding(verdict="Valid", fix=fix,
                                        validation={"verdict": "Valid", "evidence": evidence})])
        _, assessment = self.output(data)
        detail = assessment.find(id=self.renderer.finding_anchor(data, data["findings"][0]))
        self.assertIn(fix, detail.text())
        self.assertIn(evidence, detail.text())
        self.assertNotIn("END_OF_COMPLETE_FIX", assessment.find(id="priority-queue").text())

    def test_missing_validation_defaults_to_verify_first_without_invented_evidence(self):
        finding = self.finding(fix="")
        finding.pop("validation")
        finding.pop("status")
        data = self.report([finding])
        self.assertEqual(data["findings"][0]["verdict"], "Unverified")
        self.assertEqual(data["findings"][0]["status"], "Open")
        self.assertEqual(data["findings"][0]["validation"]["evidence"], "")
        dashboard, assessment = self.output(data)
        self.assertEqual(self.payload(dashboard)["report"]["queue"][0]["action"], "verify_first")
        article = assessment.find("article")
        self.assertIn(self.renderer.ASSESSMENT_LABELS["en"]["a_evidence_missing"], article.text())
        self.assertIn(self.renderer.ASSESSMENT_LABELS["en"]["a_fix_missing"], article.text())

    def test_source_truncation_is_disclosed_and_preserves_secret_redaction(self):
        secret = "SYNTHETIC_REPORT_SECRET"
        cases = [(["short synthetic line"] * 200, False),
                 (["short synthetic line"] * 201, True),
                 (["x" * 240], False), (["x" * 241], True),
                 ([f'password="{secret}" # ' + "x" * 350], True)]
        for lines, truncated in cases:
            with self.subTest(line_count=len(lines), line_length=len(lines[0])):
                source = self.root / "fixture.py"
                source.write_text("\n".join(lines), encoding="utf-8")
                data = self.report([self.finding(location=f"fixture.py:1-{len(lines)}")])
                self.renderer.attach_sources(data, self.root, context=0)
                snippet = data["findings"][0]["snippet"]
                self.assertEqual(snippet["truncated"], truncated)
                self.assertLessEqual(len(snippet["lines"]), 200)
                self.assertTrue(all(len(line) <= 240 for line in snippet["lines"]))
                self.assertNotIn(secret, json.dumps(data))
                if secret in lines[0]:
                    self.assertIn("********", snippet["lines"][0])
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    self.assertEqual(self.payload(dashboard)["findings"][0]["snippet"]["truncated"], truncated)
                    self.assertEqual(self.renderer.LABELS[lang]["snippet_truncated"] in
                                     assessment.find("article").text(), truncated)

    def test_historical_validation_is_visible_but_does_not_change_current_counts(self):
        for old_verdict in ("Valid", "FalsePositive"):
            with self.subTest(previous_verdict=old_verdict):
                data = self.report([self.finding(validation={"verdict": "Unverified", "evidence": ""})])
                before = self.renderer.report_model(data)
                old_evidence = "<svg>INERT_HISTORICAL_EVIDENCE</svg>"
                data["findings"][0]["previous_validation"] = {
                    "verdict": old_verdict, "evidence": old_evidence, "method": "old review"}
                model = self.renderer.report_model(data)
                self.assertEqual({k: v for k, v in model.items() if k != "queue"},
                                 {k: v for k, v in before.items() if k != "queue"})
                self.assertEqual(model["queue"][0]["action"], "verify_first")
                self.assertEqual(model["excluded"], 0)
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    self.assertEqual(self.payload(dashboard)["report"]["fix_now"], 0)
                    article = assessment.find("article")
                    self.assertIn(self.renderer.LABELS[lang]["previous_validation"], article.text())
                    self.assertIn(self.renderer.LABELS[lang]["history_note"], article.text())
                    self.assertIn(old_evidence, article.text())
                    self.assertFalse(assessment.find_all("svg"))
                    self.assertNotIn(old_evidence, assessment.find(id="executive-summary").text())

    def test_dashboard_filter_controls_have_labels_and_live_results(self):
        dashboard, _ = self.output(self.mixed_report())
        payload = self.payload(dashboard)
        controls = ["f-scope", "f-sev", "f-conf", "f-cat", "f-status", "f-verdict", "f-sort", "f-q"]
        for id in controls:
            with self.subTest(control=id):
                control = dashboard.find(id=id)
                self.assertEqual(control.parent.tag, "label")
                label = control.parent.find("span").attrs["data-l"]
                self.assertTrue(payload["labels"][label].strip())
        results = dashboard.find(id="result-count")
        self.assertEqual(results.attrs.get("role"), "status")
        self.assertEqual(results.attrs.get("aria-live"), "polite")
        self.assertEqual(dashboard.find(id="reset").attrs["type"], "button")
        self.assertEqual(dashboard.find(id="coverage").tag, "details")
        self.assertEqual(len(dashboard.find(id="coverage").find_all("summary")), 1)
        self.assertEqual(dashboard.find("noscript").find("a").attrs["href"], "assessment.html")

    def test_dashboard_script_has_safe_category_counting_and_expansion_structure(self):
        dashboard, _ = self.output(self.mixed_report())
        payload = self.payload(dashboard)
        categories = {finding["category"] for finding in payload["findings"]}
        self.assertTrue({"__proto__", "constructor", "toString", "Excluded-only category"} <= categories)
        script = next(node.text() for node in dashboard.find_all("script") if node.attrs.get("id") != "data")
        # These guards also run without optional browser dependencies. Behavioral
        # coverage of the same contracts lives in the browser tests below.
        self.assertIn("Object.create(null)", script)
        self.assertNotIn(".innerHTML", script)
        self.assertIn("'aria-expanded'", script)
        self.assertIn("'aria-controls'", script)
        self.assertIn("stopPropagation()", script)
        self.assertIn("hashchange", script)
        self.assertEqual(set(payload["excluded_verdicts"]), {"FalsePositive", "NotApplicable"})

    def test_template_tokens_inside_report_data_are_not_substituted_again(self):
        tokens = "__DATA__ __TITLE__ __LANG__ __NOSCRIPT__ __ASSESSMENT__"
        data = self.report([self.finding(tokens, title=tokens)],
                           meta={"project": tokens, "date": "2026-10-06"})
        dashboard, assessment = self.output(data)
        self.assertEqual(dashboard.find("title").text(), "Security Findings - " + tokens)
        self.assertEqual(len(dashboard.find_all("script")), 2)
        payload = self.payload(dashboard)
        self.assertEqual(payload["meta"]["project"], tokens)
        self.assertEqual(payload["findings"][0]["title"], tokens)
        self.assertIn(tokens, assessment.find("title").text())

    def test_missing_fixes_do_not_instruct_closed_or_excluded_records_to_remediate(self):
        data = self.report([
            self.finding("FIXED", status="Fixed", verdict="Valid", fix=""),
            self.finding("ACCEPTED", status="Accepted", verdict="Valid", fix=""),
            self.finding("EXCLUDED", verdict="FalsePositive", fix=""),
        ])
        for lang in ("en", "ja"):
            _, assessment = self.output(data, lang)
            for article in assessment.find_all("article"):
                self.assertNotIn(self.renderer.ASSESSMENT_LABELS[lang]["a_fix_missing"], article.text())
                self.assertIn(self.renderer.ASSESSMENT_LABELS[lang]["a_not_recorded"], article.text())

    def start_browser(self):
        exe = os.environ.get("CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
        if not exe:
            self.skipTest("Chrome/Chromium not installed")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is required for optional browser tests")
        manager = sync_playwright().start()
        self.addCleanup(manager.stop)
        browser = manager.chromium.launch(executable_path=exe, headless=True, timeout=15000)
        self.addCleanup(browser.close)
        page = browser.new_page()
        page.route("**/*", lambda route: route.abort())
        return page

    @unittest.skipUnless(os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1", "opt-in Chromium interaction test")
    def test_browser_keyboard_filters_reset_excluded_categories_and_hash_navigation(self):
        page = self.start_browser()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        data = self.mixed_report()
        page.set_content(self.renderer.render_dashboard(data, self.renderer.LABELS["en"], "en"),
                         wait_until="domcontentloaded")
        self.assertEqual(page.locator("tr.row").count(), 4)
        totals_before = page.locator("#cards").inner_text()
        for category in ("__proto__", "constructor", "toString"):
            bar = page.locator("#c-cat .bar").filter(has=page.locator(".t", has_text=re.compile("^" + re.escape(category) + "$")))
            self.assertEqual(bar.locator(".v").inner_text(), "1")
        toggle = page.get_by_role("button", name=re.compile("^Fix fixture"))
        detail = page.locator("#" + toggle.get_attribute("aria-controls"))
        toggle.focus()
        for key, expected in (("Enter", True), ("Space", False), ("Space", True), ("Enter", False)):
            toggle.press(key)
            self.assertEqual(toggle.get_attribute("aria-expanded"), str(expected).lower())
            self.assertEqual(detail.is_visible(), expected)
        for control, selected in (("f-sev", "High"), ("f-conf", "Confirmed"), ("f-cat", "__proto__"),
                                  ("f-status", "Open"), ("f-verdict", "Valid")):
            page.locator("#" + control).select_option(selected)
        page.get_by_label("Search", exact=True).fill("Fix fixture")
        self.assertEqual(page.locator("tr.row").count(), 1)
        page.get_by_label("Search", exact=True).fill("SYNTHETIC_NO_MATCH")
        self.assertEqual(page.locator("tr.row").count(), 0)
        self.assertIn("No findings match", page.locator("#rows").inner_text())
        page.get_by_role("button", name="Clear filters", exact=True).click()
        self.assertEqual(page.locator("tr.row").count(), 4)
        self.assertEqual(page.locator("#f-q").input_value(), "")
        page.locator("#f-scope").select_option("excluded")
        page.locator("#f-cat").select_option("Excluded-only category")
        self.assertEqual(page.locator("tr.row").count(), 1)
        self.assertIn("X-excluded", page.locator("tr.row").inner_text())
        page.locator("#f-verdict").select_option("FalsePositive")
        self.assertEqual(page.locator("#f-scope").input_value(), "all")
        self.assertEqual(page.locator("tr.row").count(), 1)
        page.get_by_role("button", name="Clear filters", exact=True).click()
        self.assertEqual(page.locator("#f-scope").input_value(), "included")
        page.locator("#f-sev").select_option("Low")
        target = next(f for f in data["findings"] if f["id"] == "X-excluded")
        anchor = self.renderer.finding_anchor(data, target)
        page.evaluate("anchor => { window.location.hash = anchor; }", anchor)
        page.wait_for_function("anchor => document.getElementById(anchor)?.querySelector('button').getAttribute('aria-expanded') === 'true'", arg=anchor)
        self.assertEqual(page.locator("#f-sev").input_value(), "")
        self.assertEqual(page.locator("#f-scope").input_value(), "all")
        self.assertTrue(page.locator("#" + anchor + "-detail").is_visible())
        self.assertEqual(page.locator("#cards").inner_text(), totals_before)
        self.assertFalse(errors)

    @unittest.skipUnless(os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1", "opt-in Chromium mobile test")
    def test_browser_mobile_long_hostile_text_does_not_overflow_or_execute(self):
        page = self.start_browser()
        page.set_viewport_size({"width": 375, "height": 812})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        hostile = "</script><svg onload='INERT'>日本語 & \"quoted\"</svg>"
        long_text = "SYNTHETIC_UNBROKEN_TEXT" * 35
        data = self.report([self.finding(hostile, title=hostile + long_text, impact=long_text,
                                        location=long_text + ":12", category="__proto__", verdict="Valid")],
                           meta={"project": long_text, "date": "2026-10-06", "scope": long_text})
        data["findings"][0]["snippet"] = {"start": 12, "hit": [12, 12], "lines": [hostile + long_text],
                                          "truncated": True}
        page.set_content(self.renderer.render_dashboard(data, self.renderer.LABELS["en"], "en"),
                         wait_until="domcontentloaded")
        page.locator(".finding-toggle").click()
        self.assertIn(hostile, page.locator(".snippet").inner_text())
        self.assertIn(self.renderer.LABELS["en"]["snippet_truncated"], page.locator("tr.detail").inner_text())
        self.assertEqual(page.locator("svg").count(), 0)
        self.assertEqual(page.locator("script").count(), 2)
        self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"))
        self.assertFalse(errors)


if __name__ == "__main__":
    unittest.main()
