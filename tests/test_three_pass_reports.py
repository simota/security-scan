"""Three-pass report projections from synthetic, manually submitted observations.

No provider API, target scan, application test or recorded command is executed.
"""
import copy
import importlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import test_ci_report_artifacts as pdf_helpers
import test_report_outputs as report_helpers
import test_verification_reports as verification_helpers

BROWSER_TESTS = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"
HOSTILE = "</script><svg onload='window.THREE_PASS_INJECTED=1'>日本語 & \"scope\"</svg>"
SECRET = (" password=THREE_PASS_SECRET https://three-pass-user:THREE_PASS_URL_SECRET@example.invalid/scope"
          "?token=THREE_PASS_QUERY_SECRET#THREE_PASS_FRAGMENT_SECRET")
OPAQUE = "THREE_PASS_PRIVATE_EXTENSION_MUST_NOT_RENDER"


def fixture(workflow, *, stop_after="decision", hostile=False, missing_scope=False, challenge_result="clear"):
    data = verification_helpers.fixture()
    finding = data["findings"][0]
    proof = finding.pop("verification")
    finding.pop("remediation")
    finding["status"] = "Open"
    finding["validation"] = {"verdict": "Unverified", "evidence": "Synthetic candidate awaiting review."}
    suffix = " " + HOSTILE + SECRET if hostile else ""
    cell_id = "tenant-cell" + suffix
    data["three_pass"] = {
        "version": 1,
        "coverage": [
            {"id": cell_id, "perspective": "Actor and tenant" + suffix, "target": "Synthetic detail route" + suffix},
            {"id": "zero-candidate-cell", "perspective": "Synthetic other routes", "target": "Zero-candidate scoped routes"},
            {"id": "na-cell", "perspective": "Synthetic uploads", "target": "No upload surface in the scoped fixture"},
        ],
        "discovery": {"actor": "synthetic-discoverer" + suffix,
                      "summary": "DISCOVERY_PROOF: synthetic scoped discovery. 発見時の確認記録" + suffix,
                      "checks": [
                          {"coverage_id": cell_id, "status": "checked", "reason": "DISCOVERY_CELL: synthetic source trace" + suffix,
                           "evidence_ids": ["source-before"], "finding_ids": ["F-001"]},
                          {"coverage_id": "zero-candidate-cell", "status": "checked", "reason": "ZERO_CANDIDATE_PROOF: no candidate recorded here.",
                           "evidence_ids": ["source-before"], "finding_ids": []},
                          {"coverage_id": "na-cell", "status": "not_applicable", "reason": "NA_PROOF: synthetic source inventory supports exclusion of upload routes.",
                           "evidence_ids": ["source-before"], "finding_ids": []},
                      ]},
    }
    if stop_after == "missing":
        # Keep an otherwise sufficient old proof: profile workflow still gates readiness.
        finding["verification"] = proof
        finding["validation"]["verdict"] = "Valid"
        return data
    workflow.initialize(data, finding["id"], "synthetic-coordinator", "Synthetic three-pass review.")
    if stop_after == "initialize":
        return data
    outputs = [
        {"stage": "conditions", "actor": proof["reviewer"], "status": "complete",
         "summary": "CONDITIONS_PROOF: synthetic conditions verified. 成立条件の確認", "evidence_ids": ["source-before"],
         "claims": proof["claims"], "environment": proof["environment"]},
        {"stage": "falsification", "actor": proof["reviews"][0]["reviewer"], "status": "complete",
         "summary": "CHALLENGE_PROOF: synthetic independent negative checks. 独立した反証", "evidence_ids": ["source-before"],
         "checks": [{**copy.deepcopy(proof["falsification"][0]), "claim": claim, "check": "Negative check for " + claim}
                    for claim in ("reachability", "preconditions", "defenses", "impact")],
         "reviews": proof["reviews"],
         "coverage_checks": [{"coverage_id": row["id"], "result": challenge_result, "reason": "SCOPE_CHALLENGE: synthetic independent scope review." + suffix,
                              "evidence_ids": ["source-before"]} for row in data["three_pass"]["coverage"]
                             if not missing_scope or row["id"] == cell_id]},
        {"stage": "decision", "actor": "synthetic-decider", "status": "complete",
         "summary": "DECISION_PROOF: synthetic evidence-based decision. 証拠による判定", "evidence_ids": ["source-before"],
         "run_ids": [], "validation": {"verdict": "Valid", "method": "synthetic manual sequence", "evidence": "Synthetic source evidence supports the scoped finding."}},
    ]
    for output in outputs:
        output["input_digest"] = workflow.derive_workflow(data, finding)["input_digest"]
        workflow.submit(data, finding["id"], output)
        if stop_after == output["stage"]:
            break
    return data


def view_texts(view):
    for key in ("status", "note", "safety"):
        yield view[key]
    yield from view["gaps"]
    for item in view["passes"]:
        for key in ("title", "status", "count"):
            yield item[key]
        yield from item["gaps"]
    for section in view["sections"]:
        yield section["title"]
        yield from section["items"]


class ThreePassReportTests(unittest.TestCase):
    setUp = report_helpers.ReportOutputTests.setUp
    output = report_helpers.ReportOutputTests.output
    payload = report_helpers.ReportOutputTests.payload
    start_browser = report_helpers.ReportOutputTests.start_browser
    save_browser_artifact = report_helpers.ReportOutputTests.save_browser_artifact

    @classmethod
    def setUpClass(cls):
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)
        with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1] / "skills/security-scan/scripts")] + sys.path):
            importlib.import_module("render")
        cls.workflow = sys.modules["verification_workflow"]

    def load_data(self, data):
        path = self.root / "three-pass.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return self.renderer.load(path)

    def assert_safe(self, text):
        for secret in ("THREE_PASS_SECRET", "three-pass-user", "THREE_PASS_URL_SECRET", "THREE_PASS_QUERY_SECRET", "THREE_PASS_FRAGMENT_SECRET"):
            self.assertNotIn(secret, text)
        self.assertIn("********", text)
        self.assertIn("https://example.invalid/scope", text)

    def test_three_pass_counts_and_gaps_agree_in_both_languages(self):
        for stage in ("initialize", "conditions", "falsification", "decision"):
            with self.subTest(stage=stage):
                data = self.load_data(fixture(self.workflow, stop_after=stage))
                expected = self.renderer.report_model(data)
                self.assertEqual(expected["three_pass"]["status"], "complete" if stage == "decision" else "held")
                self.assertEqual(expected["three_pass"]["passes"][0]["completed"], 3)
                self.assertEqual(expected["three_pass"]["passes"][1]["completed"], int(stage != "initialize"))
                self.assertEqual(expected["three_pass"]["passes"][2]["completed"], int(stage == "decision"))
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    payload = self.payload(dashboard)
                    self.assertEqual(payload["report"], expected)
                    view = payload["three_pass_view"]
                    for doc in (dashboard, assessment):
                        summary = doc.find(id="three-pass-summary")
                        for text in view_texts(view):
                            self.assertIn(text, summary.text())
                        self.assertEqual(len(summary.find_all(**{"class": "three-pass-stage"})), 3)
                    self.assertEqual(bool(view["gaps"]), stage != "decision")

    def test_profile_without_workflow_cannot_borrow_ready_proof(self):
        data = self.load_data(fixture(self.workflow, stop_after="missing"))
        model = self.renderer.report_model(data)
        self.assertEqual(model["verification"]["F-001"]["level"], "runtime_supported")
        self.assertEqual(model["workflows"]["F-001"]["status"], "not_started")
        self.assertEqual(model["fix_now"], 0)
        self.assertEqual(model["queue"][0]["action"], "verify_first")
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            self.assertIn(self.renderer.LABELS[lang]["w_not_started"], assessment.text())
            self.assertTrue(self.payload(dashboard)["three_pass_view"]["gaps"])

    def test_zero_candidates_are_held_and_scope_gaps_do_not_erase_individual_readiness(self):
        source = fixture(self.workflow, stop_after="missing")
        source["findings"] = []
        source["three_pass"]["discovery"]["checks"][0]["finding_ids"] = []
        data = self.load_data(source)
        self.assertEqual(self.renderer.report_model(data)["three_pass"]["status"], "held")
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            expected = self.renderer.LABELS[lang]["p_gap_three_pass_no_candidates"]
            self.assertIn(expected, dashboard.text())
            self.assertIn(expected, assessment.text())
        data = self.load_data(fixture(self.workflow, missing_scope=True))
        model = self.renderer.report_model(data)
        self.assertEqual(model["three_pass"]["status"], "held")
        self.assertEqual(model["fix_now"], 1)
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            view = self.payload(dashboard)["three_pass_view"]
            self.assertIn("zero-candidate-cell", "\n".join(view["passes"][2]["gaps"]))
            self.assertIn("na-cell", "\n".join(view["passes"][2]["gaps"]))
            self.assertIn(view["status"], assessment.text())

    def test_held_and_conflicting_challenges_keep_claims_and_scope_evidence_visible(self):
        for result, status in (("unresolved", "held"), ("contradiction", "conflict")):
            source = fixture(self.workflow, stop_after="falsification", challenge_result=result, hostile=True)
            data = self.load_data(source)
            self.assertEqual(self.renderer.report_model(data)["workflows"]["F-001"]["status"], status)
            for lang in ("en", "ja"):
                dashboard, assessment = self.output(data, lang)
                payload = self.payload(dashboard)
                view = payload["three_pass_view"]
                profile_text = "\n".join(view_texts(view))
                self.assertIn("SCOPE_CHALLENGE", profile_text)
                self.assertIn("source-before", profile_text)
                self.assertIn(self.renderer.LABELS[lang]["v_" + result], profile_text)
                self.assertIn(self.renderer.LABELS[lang]["w_" + status], profile_text)
                self.assert_safe(profile_text)
                proof = "\n".join(verification_helpers.view_texts(payload["verification_views"]["F-001"]))
                for claim in ("reachability", "preconditions", "defenses", "impact"):
                    claim_label = self.renderer.LABELS[lang]["p_claim"] + ": " + self.renderer.LABELS[lang]["v_" + claim]
                    self.assertIn(claim_label, proof)
                    self.assertIn(claim_label, assessment.text())
                for doc in (dashboard, assessment):
                    self.assertIn("SCOPE_CHALLENGE", doc.find(id="three-pass-summary").text())

    def test_profile_drift_blocks_readiness_and_remains_visible(self):
        source = fixture(self.workflow)
        source["three_pass"]["coverage"][0]["target"] = "Changed scoped target"
        data = self.load_data(source)
        model = self.renderer.report_model(data)
        self.assertEqual(model["workflows"]["F-001"]["status"], "stale")
        self.assertEqual(model["three_pass"]["status"], "held")
        self.assertEqual(model["fix_now"], 0)
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            self.assertIn(self.renderer.LABELS[lang]["w_stale"], assessment.text())
            self.assertIn("Changed scoped target", dashboard.text())

    def test_profile_text_is_redacted_escaped_and_extensions_are_never_embedded(self):
        source = fixture(self.workflow, hostile=True)
        source["_three_pass"] = {"secret": OPAQUE, "status": "complete"}
        source["findings"][0]["opaque"] = {"private": OPAQUE}
        # A legal unknown claim extension must stay private, including in old history.
        source["findings"][0]["verification"]["claims"]["impact"]["opaque"] = OPAQUE
        data = self.load_data(source)
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            serialized = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn(OPAQUE, serialized)
            self.assertNotIn(OPAQUE, assessment.text())
            self.assert_safe(serialized)
            self.assert_safe(assessment.text())
            self.assertEqual(set(payload["report"]["three_pass"]), {"status", "passes"})
            self.assertNotIn("three_pass", {key: value for key, value in payload.items() if key != "report"})
            self.assertIn(HOSTILE, "\n".join(view_texts(payload["three_pass_view"])))
            for doc in (dashboard, assessment):
                self.assertFalse(doc.find_all("svg"))
                self.assertFalse(any(key.lower().startswith("on") for node in doc.find_all() for key in node.attrs))
            self.assertEqual(len(dashboard.find_all("script")), 2)
            self.assertFalse(assessment.find_all("script"))
        invalid = copy.deepcopy(source)
        invalid["three_pass"]["opaque"] = OPAQUE
        with self.assertRaises(self.renderer.SchemaError):
            self.load_data(invalid)

    def test_discovery_evidence_ids_and_historical_snapshots_are_safe(self):
        source = fixture(self.workflow, hostile=True)
        evidence = copy.deepcopy(source["evidence"][0])
        evidence["id"] = "extra-discovery-source" + SECRET
        source["evidence"].append(evidence)
        source["three_pass"]["discovery"]["checks"][0]["evidence_ids"] = [evidence["id"]]
        source["three_pass"]["discovery"]["summary"] = "CURRENT_DISCOVERY_RECHECK"
        data = self.load_data(source)
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            view = self.payload(dashboard)["three_pass_view"]
            text = "\n".join(view_texts(view))
            self.assertIn("CURRENT_DISCOVERY_RECHECK", text)
            self.assertIn("DISCOVERY_PROOF", text)
            self.assertIn(self.renderer.LABELS[lang]["p_history"], text)
            self.assert_safe(text)
            for doc in (dashboard, assessment):
                self.assertIn("extra-discovery-source", doc.find(id="three-pass-summary").text())
                self.assert_safe(doc.find(id="three-pass-summary").text())

    def test_legacy_and_default_reports_have_no_profile_output(self):
        for legacy in (False, True):
            source = verification_helpers.fixture()
            if legacy:
                source.pop("schema_version")
                source["three_pass"] = {"private": OPAQUE}
            data = self.load_data(source)
            self.assertNotIn("three_pass", self.renderer.report_model(data))
            for lang in ("en", "ja"):
                dashboard, assessment = self.output(data, lang)
                self.assertNotIn("three_pass_view", self.payload(dashboard))
                self.assertFalse(dashboard.find_all(id="three-pass-summary"))
                self.assertFalse(assessment.find_all(id="three-pass-summary"))
                self.assertNotIn(OPAQUE, json.dumps(self.payload(dashboard)))

    @unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium three-pass interaction test")
    def test_browser_three_pass_summary_both_languages_mobile(self):
        page = self.start_browser()
        page.set_viewport_size({"width": 375, "height": 812})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        for state in ("complete", "missing", "stale", "scope_gap"):
            source = fixture(self.workflow, hostile=True, stop_after="missing" if state == "missing" else "decision", missing_scope=state == "scope_gap")
            if state == "stale":
                source["three_pass"]["discovery"]["summary"] += " changed"
            data = self.load_data(source)
            for lang in ("en", "ja"):
                labels = self.renderer.LABELS[lang]
                view = self.renderer.three_pass_view(data, lang)
                for output, markup in (("dashboard", self.renderer.render_dashboard(data, labels, lang)),
                                       ("assessment", self.renderer.render_assessment_html(data, labels, lang))):
                    with self.subTest(state=state, lang=lang, output=output):
                        page.goto("about:blank")
                        page.set_content(markup, wait_until="domcontentloaded")
                        summary = page.locator("#three-pass-summary")
                        self.assertTrue(summary.is_visible())
                        content = summary.inner_text()
                        for text in view_texts(view):
                            self.assertIn(text, content)
                        self.assert_safe(content)
                        if output == "dashboard":
                            page.locator(".finding-toggle").click()
                            expected = "fix_now" if state in ("complete", "scope_gap") else "verify_first"
                            self.assertEqual(page.locator(".action-guidance strong").inner_text(), labels[expected])
                        self.assertEqual(page.locator("svg").count(), 0)
                        self.assertIsNone(page.evaluate("window.THREE_PASS_INJECTED"))
                        self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"))
                        self.assertFalse(errors)
                        self.save_browser_artifact(page, lang + "-three-pass-" + state + "-" + output + "-375px")


@unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium three-pass PDF tests")
class ThreePassPDFTests(unittest.TestCase):
    setUp = pdf_helpers.ReportArtifactTests.setUp
    normalized = staticmethod(pdf_helpers.ReportArtifactTests.normalized)
    render_pdf = pdf_helpers.ReportArtifactTests.render_pdf

    @classmethod
    def setUpClass(cls):
        pdf_helpers.ReportArtifactTests.setUpClass.__func__(cls)
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)
        with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1] / "skills/security-scan/scripts")] + sys.path):
            importlib.import_module("render")
        cls.workflow = sys.modules["verification_workflow"]

    def check_pdf(self, lang):
        source = fixture(self.workflow, hostile=True, missing_scope=True)
        path = self.root / "synthetic-three-pass.json"
        path.write_text(json.dumps(source, ensure_ascii=False), encoding="utf-8")
        data = self.renderer.load(path)
        text, pages = self.render_pdf(path, lang, lang + "-three-pass-evidence")
        self.assertGreaterEqual(pages, 2)
        extracted = self.normalized(text)
        for value in view_texts(self.renderer.three_pass_view(data, lang)):
            self.assertIn(self.normalized(value), extracted)
        for value in ("DISCOVERY_PROOF", "DISCOVERY_CELL", "ZERO_CANDIDATE_PROOF", "NA_PROOF", "synthetic-discoverer", "source-before"):
            self.assertIn(self.normalized(value), extracted)
        for secret in ("THREE_PASS_SECRET", "THREE_PASS_URL_SECRET", "THREE_PASS_QUERY_SECRET", "THREE_PASS_FRAGMENT_SECRET"):
            self.assertNotIn(secret, text)

    def test_english_three_pass_pdf(self):
        self.check_pdf("en")

    def test_japanese_three_pass_pdf(self):
        self.check_pdf("ja")


if __name__ == "__main__":
    unittest.main()
