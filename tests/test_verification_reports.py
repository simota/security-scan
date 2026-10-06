"""Synthetic verification report contracts, including real offline browser/PDF QA.

No application test, advisory scan or external request is run by this module.
Browser/PDF checks remain opt-in locally and mandatory in the strict CI runner.
"""
import copy
import json
import os
from pathlib import Path
import unittest

import test_ci_report_artifacts as pdf_helpers
import test_report_outputs as report_helpers


REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "examples/findings.verification.sample.json"
BROWSER_TESTS = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"


def fixture():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def mixed_fixture():
    """Keep runtime, static-only and legacy evidence intentionally distinct."""
    data = fixture()
    runtime = data["findings"][0]
    runtime["id"] = "R-runtime"
    static = copy.deepcopy(runtime)
    static.update(id="S-static", title="Synthetic static-only finding", status="Open")
    static["verification"]["run_ids"] = []
    static.pop("remediation")
    legacy = copy.deepcopy(static)
    legacy.update(id="L-legacy", title="Synthetic legacy finding")
    legacy.pop("verification")
    excluded = copy.deepcopy(runtime)
    excluded.update(id="X-excluded", title="Synthetic excluded verification record")
    excluded["validation"]["verdict"] = "FalsePositive"
    excluded["verification"]["claims"]["preconditions"]["status"] = "contradicted"
    excluded["verification"]["exclusion"] = {
        "basis": "condition_absent", "reason": "Synthetic excluded-condition evidence.",
        "evidence_ids": ["source-before"],
    }
    excluded["verification"]["run_ids"] = []
    excluded.pop("remediation")
    data["findings"] = [runtime, static, legacy, excluded]
    return data


def proof_texts(data):
    """Independent source assertions, beyond comparing two renderer outputs."""
    finding = data["findings"][0]
    verification = finding["verification"]
    yield verification["reviewer"]
    for claim in verification["claims"].values():
        yield claim["reason"]
    for check in verification["falsification"]:
        yield check["check"]
        yield check["reason"]
    for review in verification["reviews"]:
        yield review["reviewer"]
        yield review["reason"]
    yield verification["environment"]["reason"]
    for evidence in data["evidence"]:
        for key in ("id", "commit", "location", "summary", "sha256"):
            yield evidence[key]
    for run in data["test_runs"]:
        for key in ("id", "case_id", "commit", "command", "expected", "observed", "recorded_at"):
            yield run[key]
        for key in ("configuration", "fixture", "test_version"):
            yield run["context"][key]


def view_texts(view):
    yield view["level"]
    yield view["retest"]
    yield from view["gaps"]
    for section in view["sections"]:
        yield section["title"]
        yield from section["items"]


class VerificationReportTests(unittest.TestCase):
    # Reuse only helpers, never inherit the old TestCase and rediscover its tests.
    setUp = report_helpers.ReportOutputTests.setUp
    output = report_helpers.ReportOutputTests.output
    payload = report_helpers.ReportOutputTests.payload
    start_browser = report_helpers.ReportOutputTests.start_browser
    save_browser_artifact = report_helpers.ReportOutputTests.save_browser_artifact

    @classmethod
    def setUpClass(cls):
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)

    def load_data(self, data):
        source = self.root / "verification.json"
        source.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return self.renderer.load(source)

    def test_static_runtime_and_legacy_records_keep_distinct_readiness(self):
        data = self.load_data(mixed_fixture())
        before = copy.deepcopy(data)
        model = self.renderer.report_model(data)
        states = model["verification"]
        self.assertEqual(states["S-static"]["level"], "static_supported")
        self.assertEqual(states["R-runtime"]["level"], "runtime_supported")
        self.assertEqual(states["L-legacy"]["level"], "legacy")
        self.assertTrue(states["L-legacy"]["gaps"], "Legacy evidence gaps must be explicit")
        self.assertEqual(states["R-runtime"]["retest"], "verified")
        self.assertNotEqual(states["S-static"]["retest"], "verified")
        self.assertEqual(model["verification_counts"], {"static": 1, "runtime": 1, "pending": 1, "retested": 1})
        actions = {item["finding"]["id"]: item["action"] for item in model["queue"]}
        self.assertEqual(actions, {"S-static": "fix_now", "L-legacy": "verify_first"})
        self.assertEqual((model["fixed"], model["excluded"]), (1, 1))
        self.assertEqual(data, before, "Derived verification must not mutate the source record")
        self.assertEqual(data["findings"][0]["validation"]["verdict"], "Valid")

    def test_verification_counts_and_verdicts_agree_across_reports(self):
        source = mixed_fixture()
        data = self.load_data(source)
        verdicts = {f["id"]: f["validation"]["verdict"] for f in source["findings"]}
        expected = self.renderer.report_model(data)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                dashboard, assessment = self.output(data, lang)
                payload = self.payload(dashboard)
                self.assertEqual(payload["report"], expected)
                self.assertEqual(set(payload["verification_views"]), set(verdicts))
                self.assertEqual({f["id"]: f["verdict"] for f in payload["findings"]}, verdicts)
                self.assertEqual({f["id"]: f["validation"]["verdict"] for f in payload["findings"]}, verdicts)
                dashboard.find(id="verification-summary")
                summary = assessment.find(id="verification-summary")
                for kind, count in expected["verification_counts"].items():
                    self.assertEqual(int(summary.find(**{"data-verification-count": kind}).text()), count)
                for finding in data["findings"]:
                    article = assessment.find(id=self.renderer.finding_anchor(data, finding))
                    record = article.find(**{"class": "verification-record"})
                    for text in view_texts(payload["verification_views"][finding["id"]]):
                        self.assertIn(text, record.text())
                self.assertIn("X-excluded", assessment.find(id="excluded-findings").text())

    def test_curated_views_keep_the_complete_verification_proof_in_both_languages(self):
        source = fixture()
        data = self.load_data(source)
        localized = {}
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                dashboard, assessment = self.output(data, lang)
                payload = self.payload(dashboard)
                view = payload["verification_views"][source["findings"][0]["id"]]
                localized[lang] = view
                text = "\n".join(view_texts(view))
                self.assertTrue(view["sections"])
                for proof in proof_texts(source):
                    self.assertIn(proof, text)
                    self.assertIn(proof, assessment.find("article").text())
                self.assertNotIn("verification", payload["findings"][0])
                self.assertNotIn("remediation", payload["findings"][0])
                self.assertEqual(payload["findings"][0]["_verification"], payload["report"]["verification"]["F-001"])
        self.assertNotEqual(localized["en"]["level"], localized["ja"]["level"])
        self.assertNotEqual(localized["en"]["retest"], localized["ja"]["retest"])

    def test_execution_context_fields_keep_individual_lines_for_pdf_extraction(self):
        source = fixture()
        data = self.load_data(source)
        for lang in ("en", "ja"):
            dashboard, _ = self.output(data, lang)
            view = self.payload(dashboard)["verification_views"]["F-001"]
            runs = next(section for section in view["sections"]
                        if section["title"] == self.renderer.LABELS[lang]["v_runs"])
            for item in runs["items"]:
                lines = item.splitlines()
                self.assertIn("test_version=security-tests-v1", lines)
                self.assertIn("configuration=synthetic-in-memory-v1", lines)
                self.assertIn("fixture=two-fake-tenants-v1", lines)

    def test_fixed_status_and_incomplete_controls_never_count_as_verified_retests(self):
        for missing, expected_retest, gap in (
            ("remediation", "fix_claimed", "retest_missing"),
            ("positive_control_run_ids", "incomplete", "retest_control_missing"),
            ("regression_run_ids", "incomplete", "retest_regression_missing"),
        ):
            with self.subTest(missing=missing):
                source = fixture()
                finding = source["findings"][0]
                if missing == "remediation":
                    finding.pop("remediation")
                else:
                    finding["remediation"][missing] = []
                data = self.load_data(source)
                model = self.renderer.report_model(data)
                state = model["verification"][finding["id"]]
                self.assertEqual(state["level"], "runtime_supported")
                self.assertEqual(state["retest"], expected_retest)
                self.assertIn(gap, state["gaps"])
                self.assertEqual(model["verification_counts"]["retested"], 0)
                self.assertEqual(model["fixed"], 1)
                self.assertEqual(data["findings"][0]["validation"]["verdict"], "Valid")
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    payload = self.payload(dashboard)
                    self.assertEqual(payload["report"], model)
                    view = payload["verification_views"][finding["id"]]
                    self.assertTrue(view["gaps"])
                    for value in (view["retest"], *view["gaps"]):
                        self.assertIn(value, assessment.find("article").text())

    def test_input_derived_verification_injection_never_promotes_a_finding(self):
        source = mixed_fixture()
        clean = self.load_data(copy.deepcopy(source))
        source["_verification"] = {"level": "runtime_supported", "retest": "verified"}
        for finding in source["findings"]:
            finding["_verification"] = {"level": "runtime_supported", "retest": "verified", "gaps": []}
        injected = self.load_data(source)
        self.assertEqual(self.renderer.report_model(injected), self.renderer.report_model(clean))
        for lang in ("en", "ja"):
            clean_dashboard, clean_assessment = self.output(clean, lang)
            dashboard, assessment = self.output(injected, lang)
            self.assertEqual(self.payload(dashboard), self.payload(clean_dashboard))
            self.assertEqual(assessment.text(), clean_assessment.text())

    def test_legacy_string_note_renders_safely_without_verification_credit(self):
        source = fixture()
        source.pop("schema_version")
        for key in ("assessment", "evidence", "test_runs"):
            source.pop(key)
        finding = source["findings"][0]
        finding.pop("remediation")
        finding["status"] = "Open"
        hostile = "<svg onload='INERT_LEGACY'>historical verification text 日本語</svg>"
        finding["verification"] = hostile + " password=LEGACY_SECRET https://old-user:LEGACY_URL_SECRET@example.invalid/legacy"
        data = self.load_data(source)
        model = self.renderer.report_model(data)
        self.assertEqual(model["verification"][finding["id"]]["level"], "legacy")
        self.assertEqual(model["verification_counts"], {"static": 0, "runtime": 0, "pending": 1, "retested": 0})
        self.assertEqual(model["queue"][0]["action"], "verify_first")
        self.assertEqual(data["findings"][0]["validation"]["verdict"], "Valid")
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            view = payload["verification_views"][finding["id"]]
            note = "\n".join(view_texts(view))
            self.assertIn(hostile, note)
            self.assertIn(hostile, assessment.find("article").text())
            self.assertIn(self.renderer.LABELS[lang]["v_legacy_note"], note)
            self.assertTrue(view["gaps"])
            for document in (dashboard, assessment):
                self.assertFalse(document.find_all("svg"))
            for text in (json.dumps(payload), assessment.text()):
                for secret in ("LEGACY_SECRET", "LEGACY_URL_SECRET", "old-user"):
                    self.assertNotIn(secret, text)
                self.assertIn("********", text)
                self.assertIn("https://example.invalid/legacy", text)

    def test_version_one_opaque_extensions_do_not_crash_or_promote_reports(self):
        for version in (None, 1):
            for opaque in ({"opaque": "V1_EXTENSION_MUST_NOT_RENDER"}, ["V1_EXTENSION_MUST_NOT_RENDER"], None):
                with self.subTest(version=version, opaque=opaque):
                    source = fixture()
                    if version is None:
                        source.pop("schema_version")
                    else:
                        source["schema_version"] = version
                    for key in ("assessment", "evidence", "test_runs"):
                        source[key] = copy.deepcopy(opaque)
                    finding = source["findings"][0]
                    finding["status"] = "Open"
                    finding["verification"] = {"level": "runtime_supported", "retest": "verified", "opaque": opaque}
                    finding["remediation"] = {"commit": "not-a-commit", "opaque": opaque}
                    data = self.load_data(source)
                    model = self.renderer.report_model(data)
                    self.assertEqual(model["verification"][finding["id"]]["level"], "legacy")
                    self.assertEqual(model["verification_counts"], {"static": 0, "runtime": 0, "pending": 1, "retested": 0})
                    self.assertEqual(model["queue"][0]["action"], "verify_first")
                    for lang in ("en", "ja"):
                        dashboard, assessment = self.output(data, lang)
                        payload = self.payload(dashboard)
                        self.assertEqual(payload["report"], model)
                        self.assertFalse(payload["verification_views"][finding["id"]]["sections"])
                        self.assertNotIn("V1_EXTENSION_MUST_NOT_RENDER", json.dumps(payload))
                        self.assertNotIn("V1_EXTENSION_MUST_NOT_RENDER", assessment.text())

    def test_exclusion_and_resolved_disagreement_proof_remain_visible(self):
        source = mixed_fixture()
        runtime = source["findings"][0]
        review = runtime["verification"]["reviews"][0]
        review["conclusion"] = "disagree"
        review["reason"] = "Synthetic reviewer initially questioned the ownership trace."
        review["resolution"] = {
            "reviewer": review["reviewer"],
            "reason": "Synthetic dissenting reviewer resolved the question using the complete source trace.",
            "evidence_ids": ["source-before"],
        }
        exclusion = source["findings"][-1]["verification"]["exclusion"]
        data = self.load_data(source)
        self.assertEqual(self.renderer.report_model(data)["verification"][runtime["id"]]["level"], "runtime_supported")
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            views = self.payload(dashboard)["verification_views"]
            expected = {
                runtime["id"]: (review["reason"], review["resolution"]["reason"], review["resolution"]["reviewer"]),
                "X-excluded": (exclusion["basis"], exclusion["reason"], "source-before"),
            }
            for finding_id, proofs in expected.items():
                finding = next(f for f in data["findings"] if f["id"] == finding_id)
                article = assessment.find(id=self.renderer.finding_anchor(data, finding))
                for proof in proofs:
                    self.assertIn(proof, "\n".join(view_texts(views[finding_id])))
                    self.assertIn(proof, article.text())

    def test_private_evidence_and_run_ids_are_redacted_everywhere_in_reports(self):
        source = fixture()
        source["findings"][0]["status"] = "Open"  # Exercise the priority-queue copy too.
        suffix = (" password=ID_SECRET_VALUE "
                  "https://id-user:ID_URL_SECRET@example.invalid/record?token=ID_QUERY_SECRET#ID_FRAGMENT_SECRET")
        replacements = {record["id"]: record["id"] + suffix
                        for record in source["evidence"] + source["test_runs"]}

        def replace_ids(value, field=None):
            if isinstance(value, dict):
                return {key: replace_ids(item, key) for key, item in value.items()}
            if isinstance(value, list):
                return [replace_ids(item, field) for item in value]
            reference_fields = ("id", "evidence_ids", "run_ids", "before_run_id", "after_run_id",
                                "positive_control_run_ids", "regression_run_ids")
            return replacements.get(value, value) if field in reference_fields and isinstance(value, str) else value

        data = self.load_data(replace_ids(source))
        model = self.renderer.report_model(data)
        self.assertEqual(len(model["queue"]), 1)
        for state in model["verification"].values():
            self.assertEqual(set(state), {"level", "retest", "gaps"})
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            self.assertEqual(payload["report"], model)
            for text in (json.dumps(payload, ensure_ascii=False), assessment.text()):
                for secret in ("ID_SECRET_VALUE", "id-user", "ID_URL_SECRET", "ID_QUERY_SECRET", "ID_FRAGMENT_SECRET"):
                    self.assertNotIn(secret, text)
                self.assertIn("********", text)
                self.assertIn("https://example.invalid/record", text)
            view = payload["verification_views"]["F-001"]
            proof = "\n".join(view_texts(view))
            for original_id in replacements:
                self.assertIn(original_id + " password=********", proof)

    def test_extra_claim_metadata_is_not_interpreted_as_a_claim(self):
        clean = self.load_data(fixture())
        for extension in ("CLAIM_EXTENSION_MUST_NOT_RENDER", {"opaque": "CLAIM_EXTENSION_MUST_NOT_RENDER"}, None):
            with self.subTest(extension=extension):
                source = fixture()
                source["findings"][0]["verification"]["claims"]["metadata"] = extension
                data = self.load_data(source)
                self.assertEqual(self.renderer.report_model(data), self.renderer.report_model(clean))
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    clean_dashboard, clean_assessment = self.output(clean, lang)
                    self.assertEqual(self.payload(dashboard), self.payload(clean_dashboard))
                    self.assertEqual(assessment.text(), clean_assessment.text())

    def test_windows_sensitive_evidence_path_withholds_its_summary(self):
        source = fixture()
        source["evidence"][0]["location"] = r".ssh\id_ed25519:1"
        source["evidence"][0]["summary"] = "WINDOWS_SENSITIVE_SUMMARY_MUST_NOT_RENDER"
        data = self.load_data(source)
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            for text in (json.dumps(payload, ensure_ascii=False), assessment.text()):
                self.assertNotIn("WINDOWS_SENSITIVE_SUMMARY_MUST_NOT_RENDER", text)
                self.assertIn(self.renderer.LABELS[lang]["v_withheld"], text)

    def test_unresolved_verdicts_and_contradicted_exclusions_remain_explicit(self):
        for verdict in ("Unverified", "Likely", "Unlikely", "FalsePositive"):
            with self.subTest(verdict=verdict):
                if verdict == "FalsePositive":
                    source = mixed_fixture()
                    finding = source["findings"][-1]
                    finding["verification"]["run_ids"] = ["before"]
                    source["findings"] = [finding]
                    expected_gap = "runtime_contradiction"
                else:
                    source = fixture()
                    finding = source["findings"][0]
                    finding["validation"]["verdict"] = verdict
                    finding.pop("remediation")
                    expected_gap = "verdict_unresolved"
                finding["status"] = "Open"
                data = self.load_data(source)
                model = self.renderer.report_model(data)
                state = model["verification"][finding["id"]]
                self.assertEqual(state["level"], "incomplete")
                self.assertIn(expected_gap, state["gaps"])
                self.assertEqual(model["verification_counts"]["runtime"], 0)
                self.assertEqual(model["verification_counts"]["retested"], 0)
                self.assertEqual(data["findings"][0]["validation"]["verdict"], verdict)
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    payload = self.payload(dashboard)
                    self.assertEqual(payload["findings"][0]["verdict"], verdict)
                    view = payload["verification_views"][finding["id"]]
                    for text in (view["level"], *view["gaps"]):
                        self.assertIn(text, assessment.find("article").text())

    def hostile_fixture(self):
        data = mixed_fixture()
        hostile = "</script><svg onload='window.VERIFICATION_INJECTED=1'>日本語 & \"proof\"</svg>"
        secret = "password=SECRET_PROOF_VALUE https://audit-user:URL_PROOF_SECRET@example.invalid/proof?token=QUERY_PROOF_SECRET#FRAGMENT_PROOF_SECRET"
        suffix = " " + hostile + " " + secret
        # Every newly displayed text shape must go through the same safe path.
        for finding in data["findings"]:
            verification = finding.get("verification")
            if not verification:
                continue
            verification["reviewer"] += suffix
            for claim in verification["claims"].values():
                claim["reason"] += suffix
            verification["claims"]["impact"]["reason"] += " " + "UNBROKEN_VERIFICATION_PROOF" * 35
            for check in verification["falsification"]:
                check["check"] += suffix
                check["reason"] += suffix
            for review in verification["reviews"]:
                review["reviewer"] += suffix
                review["reason"] += suffix
            verification["environment"]["reason"] += suffix
        for evidence in data["evidence"]:
            evidence["summary"] += suffix
            evidence["location"] += suffix
        for run in data["test_runs"]:
            for key in ("command", "expected", "observed"):
                run[key] += suffix
            for key in ("configuration", "fixture", "test_version"):
                run["context"][key] += suffix
        return data, hostile

    def assert_safe_proof(self, text):
        for secret in ("SECRET_PROOF_VALUE", "audit-user", "URL_PROOF_SECRET", "QUERY_PROOF_SECRET", "FRAGMENT_PROOF_SECRET"):
            self.assertNotIn(secret, text)
        self.assertIn("********", text)
        self.assertIn("https://example.invalid/proof", text)

    def test_new_proof_text_is_html_safe_and_secrets_are_redacted(self):
        source, hostile = self.hostile_fixture()
        data = self.load_data(source)
        for lang in ("en", "ja"):
            with self.subTest(lang=lang):
                dashboard, assessment = self.output(data, lang)
                payload = self.payload(dashboard)
                self.assertEqual(len(dashboard.find_all("script")), 2)
                self.assertFalse(assessment.find_all("script"))
                for document in (dashboard, assessment):
                    self.assertFalse(document.find_all("svg"))
                    self.assertFalse(any(key.lower().startswith("on")
                                         for node in document.find_all() for key in node.attrs))
                # Check the entire serialized payload too: raw proof must not leak
                # beside a redacted view or through the priority queue.
                self.assert_safe_proof(json.dumps(payload, ensure_ascii=False))
                self.assert_safe_proof(assessment.text())
                for finding_id in ("S-static", "R-runtime", "X-excluded"):
                    self.assertIn(hostile, "\n".join(view_texts(payload["verification_views"][finding_id])))
                self.assertIn(hostile, assessment.text())

    @unittest.skipUnless(BROWSER_TESTS, "opt-in Chromium verification interaction test")
    def test_browser_verification_records_both_languages_mobile(self):
        page = self.start_browser()
        page.set_viewport_size({"width": 375, "height": 812})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        source, hostile = self.hostile_fixture()
        data = self.load_data(source)
        expected = self.renderer.report_model(data)
        for lang in ("en", "ja"):
            labels = self.renderer.LABELS[lang]
            dashboard, _ = self.output(data, lang)
            views = self.payload(dashboard)["verification_views"]
            for output, markup in (
                ("dashboard", self.renderer.render_dashboard(data, labels, lang)),
                ("assessment", self.renderer.render_assessment_html(data, labels, lang)),
            ):
                with self.subTest(lang=lang, output=output):
                    page.goto("about:blank")
                    page.set_content(markup, wait_until="domcontentloaded")
                    self.assertEqual(page.locator("html").get_attribute("lang"), lang)
                    summary = page.locator("#verification-summary")
                    self.assertTrue(summary.is_visible())
                    for kind, count in expected["verification_counts"].items():
                        self.assertEqual(int(summary.locator(f'[data-verification-count="{kind}"]').inner_text()), count)
                    if output == "dashboard":
                        page.locator("#f-scope").select_option("all")
                        self.assertEqual(page.locator("tr.row").count(), len(data["findings"]))
                    for finding in data["findings"]:
                        anchor = self.renderer.finding_anchor(data, finding)
                        if output == "dashboard":
                            toggle = page.locator("#" + anchor + " .finding-toggle")
                            toggle.click()
                            self.assertEqual(toggle.get_attribute("aria-expanded"), "true")
                            detail = page.locator("#" + toggle.get_attribute("aria-controls"))
                        else:
                            detail = page.locator("#" + anchor)
                        record = detail.locator(".verification-record")
                        self.assertTrue(record.is_visible())
                        text = record.inner_text()
                        for proof in view_texts(views[finding["id"]]):
                            self.assertIn(proof, text)
                        if finding["id"] != "L-legacy":
                            self.assertIn(hostile, text)
                            self.assert_safe_proof(text)
                        self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"))
                    self.assertEqual(page.locator("svg").count(), 0)
                    self.assertEqual(page.locator("script").count(), 2 if output == "dashboard" else 0)
                    self.assertIsNone(page.evaluate("window.VERIFICATION_INJECTED"))
                    self.save_browser_artifact(page, lang + "-verification-" + output + "-375px")
                    self.assertFalse(errors)


@unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium verification PDF tests")
class VerificationPDFTests(unittest.TestCase):
    setUp = pdf_helpers.ReportArtifactTests.setUp
    normalized = staticmethod(pdf_helpers.ReportArtifactTests.normalized)
    render_pdf = pdf_helpers.ReportArtifactTests.render_pdf

    @classmethod
    def setUpClass(cls):
        pdf_helpers.ReportArtifactTests.setUpClass.__func__(cls)
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)

    def check_verification_pdf(self, lang):
        source = fixture()
        data = self.renderer.load(SAMPLE)
        labels = self.renderer.LABELS[lang]
        dashboard = report_helpers.ReportHTML(self.renderer.render_dashboard(data, labels, lang)).root
        payload = json.loads(dashboard.find("script", id="data").text())
        text, pages = self.render_pdf(SAMPLE, lang, lang + "-verification-sample")
        self.assertGreaterEqual(pages, 1)
        extracted = self.normalized(text)
        for value in (source["meta"]["project"], source["findings"][0]["title"],
                      source["findings"][0]["validation"]["evidence"], *source["limitations"]):
            self.assertIn(self.normalized(value), extracted)
        for value in proof_texts(source):
            self.assertIn(self.normalized(value), extracted)
        for view in payload["verification_views"].values():
            for value in view_texts(view):
                self.assertIn(self.normalized(value), extracted)

    def test_english_verification_sample_pdf(self):
        self.check_verification_pdf("en")

    def test_japanese_verification_sample_pdf(self):
        self.check_verification_pdf("ja")


if __name__ == "__main__":
    unittest.main()
