"""Synthetic manual-workflow reports: safe projection, readiness, browser and PDF.

The fixture submits recorded stage outputs. It runs no agents, commands from the
record, application tests, advisory services, or network requests.
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


SCRIPTS = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts"
BROWSER_TESTS = os.environ.get("SECURITY_SCAN_BROWSER_TEST") == "1"
HOSTILE = "</script><svg onload='window.WORKFLOW_INJECTED=1'>日本語 & \"handoff\"</svg>"
SECRET = (" password=WORKFLOW_SECRET https://workflow-user:WORKFLOW_URL_SECRET@example.invalid/lineage"
          "?token=WORKFLOW_QUERY_SECRET#WORKFLOW_FRAGMENT_SECRET")


def fixture(workflow, *, stop_after="decision", interrupted=False, hostile=False, finding_id="F-001", opaque=False):
    """Build outputs from an Unverified candidate using the real transition API."""
    data = verification_helpers.fixture()
    finding = data["findings"][0]
    finding["id"] = finding_id
    proof = finding.pop("verification")
    finding.pop("remediation")
    if opaque:
        proof["claims"]["reachability"]["opaque"] = {"private": "WORKFLOW_EXTENSION_MUST_NOT_RENDER"}
        proof["reviews"][0]["opaque"] = {"private": "WORKFLOW_EXTENSION_MUST_NOT_RENDER"}
    finding["status"] = "Open"
    finding["validation"] = {"verdict": "Unverified", "evidence": "Synthetic candidate awaiting manual review."}
    suffix = " " + HOSTILE + SECRET if hostile else ""
    # Secret-bearing evidence identifiers must also be safe in lineage/history.
    if hostile:
        old_id, new_id = "source-before", "source-before" + SECRET
        for evidence in data["evidence"]:
            if evidence["id"] == old_id:
                evidence["id"] = new_id
        for claim in proof["claims"].values():
            claim["evidence_ids"] = [new_id if item == old_id else item for item in claim["evidence_ids"]]
        for check in proof["falsification"]:
            check["evidence_ids"] = [new_id if item == old_id else item for item in check["evidence_ids"]]
        for review in proof["reviews"]:
            review["evidence_ids"] = [new_id if item == old_id else item for item in review["evidence_ids"]]
    evidence_id = data["evidence"][0]["id"]
    workflow.initialize(data, finding["id"], "synthetic-coordinator" + suffix,
                        "Synthetic workflow initialized. 検証の開始" + suffix)
    outputs = [
        {"stage": "conditions", "actor": proof["reviewer"] + suffix, "status": "complete",
         "summary": "CONDITIONS_PROOF: synthetic condition trace. 成立条件の記録" + suffix,
         "evidence_ids": [evidence_id], "claims": proof["claims"], "environment": proof["environment"]},
        {"stage": "falsification", "actor": proof["reviews"][0]["reviewer"] + suffix, "status": "complete",
         "summary": "FALSIFICATION_PROOF: synthetic independent countercheck. 独立した反証の記録" + suffix,
         "evidence_ids": [evidence_id], "checks": proof["falsification"], "reviews": proof["reviews"]},
        {"stage": "decision", "actor": "synthetic-decider" + suffix, "status": "complete",
         "summary": "DECISION_PROOF: synthetic evidence-based conclusion. 証拠による判定の記録" + suffix,
         "evidence_ids": [evidence_id, "test-before"], "run_ids": proof["run_ids"],
         "validation": {"verdict": "Valid", "method": "synthetic manual sequence",
                        "evidence": "Synthetic current evidence supports the scoped finding."}},
    ]
    if hostile:
        # The falsification actor matches its explicitly named independent review.
        outputs[1]["reviews"][0]["reviewer"] = outputs[1]["actor"]
        outputs[0]["summary"] += " " + "UNBROKEN_WORKFLOW_TEXT" * 45
    if stop_after == "initialize":
        return data
    for output in outputs:
        if interrupted and output["stage"] == "falsification":
            held = {"stage": "falsification", "actor": output["actor"], "status": "held",
                    "summary": "HELD_HISTORY: synthetic missing counterevidence. 根拠不足で保留" + suffix,
                    "evidence_ids": [evidence_id], "input_digest": workflow.derive_workflow(data, finding)["input_digest"]}
            workflow.submit(data, finding["id"], held)
            workflow.resume(data, finding["id"], "synthetic-coordinator" + suffix,
                            "RESUMED_HISTORY: synthetic missing evidence supplied. 根拠を補い再開" + suffix)
        output["input_digest"] = workflow.derive_workflow(data, finding)["input_digest"]
        workflow.submit(data, finding["id"], output)
        if output["stage"] == stop_after:
            break
    return data



def held_fixture(workflow, *, status="held", hostile=False, finding_id="F-001"):
    """A new held round must not borrow readiness from an older complete proof."""
    data = fixture(workflow, hostile=hostile, finding_id=finding_id)
    finding = data["findings"][0]
    finding.pop("verification_workflow")
    suffix = " " + HOSTILE + SECRET if hostile else ""
    workflow.initialize(data, finding_id, "synthetic-coordinator" + suffix,
                        "Synthetic additional verification round." + suffix)
    output = {"stage": "conditions", "actor": "synthetic-author" + suffix, "status": status,
              "summary": "NEW_ROUND_HOLD: earlier evidence needs a fresh manual check." + suffix,
              "evidence_ids": [data["evidence"][0]["id"]],
              "input_digest": workflow.derive_workflow(data, finding)["input_digest"]}
    workflow.submit(data, finding_id, output)
    return data


def view_texts(view):
    yield view["status"]
    yield view["next_stage"]
    yield from view["gaps"]
    for section in view["sections"]:
        yield section["title"]
        yield from section["items"]


class WorkflowReportTests(unittest.TestCase):
    setUp = report_helpers.ReportOutputTests.setUp
    output = report_helpers.ReportOutputTests.output
    payload = report_helpers.ReportOutputTests.payload
    start_browser = report_helpers.ReportOutputTests.start_browser
    save_browser_artifact = report_helpers.ReportOutputTests.save_browser_artifact

    @classmethod
    def setUpClass(cls):
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)
        with patch.object(sys, "path", [str(SCRIPTS)] + sys.path):
            importlib.import_module("render")
        cls.workflow = sys.modules["verification_workflow"]

    def load_data(self, source):
        path = self.root / "workflow.json"
        path.write_text(json.dumps(source, ensure_ascii=False), encoding="utf-8")
        return self.renderer.load(path)

    def assert_safe(self, text):
        for secret in ("WORKFLOW_SECRET", "workflow-user", "WORKFLOW_URL_SECRET",
                       "WORKFLOW_QUERY_SECRET", "WORKFLOW_FRAGMENT_SECRET"):
            self.assertNotIn(secret, text)
        self.assertIn("********", text)
        self.assertIn("https://example.invalid/lineage", text)

    def test_handoffs_are_visible_in_both_languages_and_complete_only_at_decision(self):
        for stage, next_stage in (("initialize", "conditions"), ("conditions", "falsification"),
                                  ("falsification", "decision"), ("decision", None)):
            with self.subTest(stage=stage):
                data = self.load_data(fixture(self.workflow, stop_after=stage))
                model = self.renderer.report_model(data)
                self.assertEqual(model["workflows"]["F-001"]["next_stage"], next_stage)
                self.assertEqual(model["queue"][0]["action"], "fix_now" if stage == "decision" else "verify_first")
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    payload = self.payload(dashboard)
                    view = payload["workflow_views"]["F-001"]
                    record = assessment.find(**{"class": "workflow-record"})
                    for text in view_texts(view):
                        self.assertIn(text, record.text())
                    for label in ("w_note", "w_safety", "w_conditions", "w_falsification", "w_decision"):
                        self.assertIn(self.renderer.LABELS[lang][label], record.text())
                    if next_stage:
                        self.assertEqual(view["next_stage"], self.renderer.LABELS[lang]["w_" + next_stage])
                    self.assertEqual(payload["report"], model)

    def test_noncomplete_workflows_never_borrow_old_verification_readiness(self):
        finding = verification_helpers.fixture()["findings"][0]
        finding.update(status="Open", verdict="Valid", verification_workflow={"version": 1})
        for state in (None, "not_started", "ready", "held", "error", "unknown", "conflict", "stale"):
            with self.subTest(state=state):
                workflow = None if state is None else {"status": state}
                self.assertEqual(self.renderer.action_kind(finding, {"level": "runtime_supported"}, workflow), "verify_first")
        self.assertEqual(self.renderer.action_kind(finding, {"level": "runtime_supported"}, {"status": "complete"}), "fix_now")

    def test_held_failed_unknown_and_conflicting_rounds_override_previous_ready_proof(self):
        for status in ("held", "error", "unknown", "conflict"):
            with self.subTest(status=status):
                data = self.load_data(held_fixture(self.workflow, status=status))
                model = self.renderer.report_model(data)
                self.assertEqual(model["verification"]["F-001"]["level"], "runtime_supported")
                self.assertEqual(model["workflows"]["F-001"]["status"], status)
                self.assertEqual(model["fix_now"], 0)
                self.assertEqual(model["queue"][0]["action"], "verify_first")
                for lang in ("en", "ja"):
                    dashboard, assessment = self.output(data, lang)
                    view = self.payload(dashboard)["workflow_views"]["F-001"]
                    self.assertTrue(view["gaps"])
                    self.assertEqual(view["status"], self.renderer.LABELS[lang]["w_" + status])
                    self.assertIn(view["status"], assessment.text())

    def test_stale_complete_workflow_stays_visible_but_is_not_fix_ready(self):
        source = fixture(self.workflow)
        source["findings"][0]["impact"] = "Synthetic changed impact after the recorded decision."
        data = self.load_data(source)
        model = self.renderer.report_model(data)
        self.assertEqual(model["verification"]["F-001"]["level"], "runtime_supported")
        self.assertEqual(model["workflows"]["F-001"]["status"], "stale")
        self.assertEqual(model["queue"][0]["action"], "verify_first")
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            view = self.payload(dashboard)["workflow_views"]["F-001"]
            self.assertEqual(view["status"], self.renderer.LABELS[lang]["w_stale"])
            self.assertTrue(view["gaps"])
            self.assertIn(view["status"], assessment.text())

    def test_interrupted_history_and_lineage_survive_without_raw_outputs(self):
        data = self.load_data(fixture(self.workflow, interrupted=True))
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            view = payload["workflow_views"]["F-001"]
            text = "\n".join(view_texts(view))
            for proof in ("CONDITIONS_PROOF", "FALSIFICATION_PROOF", "DECISION_PROOF",
                          "HELD_HISTORY", "RESUMED_HISTORY", "source-before", "test-before"):
                self.assertIn(proof, text)
                self.assertIn(proof, assessment.text())
            for finding in payload["findings"] + [item["finding"] for item in payload["report"]["queue"]]:
                self.assertNotIn("verification_workflow", finding)
                self.assertNotIn("_workflow", finding)
            self.assertEqual(set(payload["report"]["workflows"]["F-001"]), {"status", "next_stage"})

    def test_workflow_extensions_and_injected_flags_are_not_public(self):
        source = fixture(self.workflow, opaque=True)
        clean = self.load_data(copy.deepcopy(source))
        finding = source["findings"][0]
        invalid = copy.deepcopy(source)
        invalid["findings"][0]["verification_workflow"]["opaque"] = {"private": "WORKFLOW_EXTENSION_MUST_NOT_RENDER"}
        with self.assertRaises(self.renderer.SchemaError):
            self.load_data(invalid)
        invalid_event = copy.deepcopy(source)
        invalid_event["findings"][0]["verification_workflow"]["history"][0]["opaque"] = "WORKFLOW_EXTENSION_MUST_NOT_RENDER"
        with self.assertRaises(self.renderer.SchemaError):
            self.load_data(invalid_event)
        finding["_workflow"] = {"status": "complete", "secret": "WORKFLOW_EXTENSION_MUST_NOT_RENDER"}
        data = self.load_data(source)
        self.assertEqual(self.renderer.report_model(data), self.renderer.report_model(clean))
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            self.assertNotIn("WORKFLOW_EXTENSION_MUST_NOT_RENDER", json.dumps(self.payload(dashboard)))
            self.assertNotIn("WORKFLOW_EXTENSION_MUST_NOT_RENDER", assessment.text())

    def test_workflow_ids_actors_summaries_and_history_are_redacted_and_inert(self):
        data = self.load_data(fixture(self.workflow, interrupted=True, hostile=True))
        for lang in ("en", "ja"):
            dashboard, assessment = self.output(data, lang)
            payload = self.payload(dashboard)
            self.assert_safe(json.dumps(payload, ensure_ascii=False))
            self.assert_safe(assessment.text())
            self.assertIn(HOSTILE, "\n".join(view_texts(payload["workflow_views"]["F-001"])))
            for document in (dashboard, assessment):
                self.assertFalse(document.find_all("svg"))
                self.assertFalse(any(key.lower().startswith("on") for node in document.find_all() for key in node.attrs))
            self.assertEqual(len(dashboard.find_all("script")), 2)
            self.assertFalse(assessment.find_all("script"))

    def test_legacy_and_schema_two_without_workflow_keep_the_existing_action_model(self):
        for source in (verification_helpers.fixture(), verification_helpers.mixed_fixture()):
            data = self.load_data(source)
            self.assertNotIn("workflows", self.renderer.report_model(data))
            for lang in ("en", "ja"):
                dashboard, assessment = self.output(data, lang)
                self.assertEqual(self.payload(dashboard)["workflow_views"], {})
                self.assertFalse(assessment.find_all(**{"class": "workflow-record"}))

    @unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium workflow interaction test")
    def test_browser_workflow_handoffs_both_languages_mobile(self):
        page = self.start_browser()
        page.set_viewport_size({"width": 375, "height": 812})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        for state in ("complete", "stale", "pending", "held"):
            source = fixture(self.workflow, stop_after="conditions" if state == "pending" else "decision",
                             interrupted=True, hostile=True)
            if state == "held":
                source = held_fixture(self.workflow, hostile=True)
            if state == "stale":
                source["findings"][0]["impact"] = "Synthetic changed impact."
            data = self.load_data(source)
            for lang in ("en", "ja"):
                labels = self.renderer.LABELS[lang]
                dashboard, _ = self.output(data, lang)
                view = self.payload(dashboard)["workflow_views"]["F-001"]
                for output, markup in (("dashboard", self.renderer.render_dashboard(data, labels, lang)),
                                       ("assessment", self.renderer.render_assessment_html(data, labels, lang))):
                    with self.subTest(state=state, lang=lang, output=output):
                        page.goto("about:blank")
                        page.set_content(markup, wait_until="domcontentloaded")
                        if output == "dashboard":
                            page.locator(".finding-toggle").click()
                            action = page.locator(".action-guidance strong").inner_text()
                            self.assertEqual(action, labels["fix_now" if state == "complete" else "verify_first"])
                        record = page.locator(".workflow-record")
                        self.assertTrue(record.is_visible())
                        content = record.inner_text()
                        for proof in view_texts(view):
                            self.assertIn(proof, content)
                        self.assert_safe(content)
                        self.assertIn(HOSTILE, content)
                        self.assertEqual(page.locator("svg").count(), 0)
                        self.assertIsNone(page.evaluate("window.WORKFLOW_INJECTED"))
                        self.assertTrue(page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"))
                        self.assertFalse(errors)
                        self.save_browser_artifact(page, lang + "-workflow-" + state + "-" + output + "-375px")


@unittest.skipUnless(BROWSER_TESTS, "opt-in real Chromium workflow PDF tests")
class WorkflowPDFTests(unittest.TestCase):
    setUp = pdf_helpers.ReportArtifactTests.setUp
    normalized = staticmethod(pdf_helpers.ReportArtifactTests.normalized)
    render_pdf = pdf_helpers.ReportArtifactTests.render_pdf

    @classmethod
    def setUpClass(cls):
        pdf_helpers.ReportArtifactTests.setUpClass.__func__(cls)
        report_helpers.ReportOutputTests.setUpClass.__func__(cls)
        with patch.object(sys, "path", [str(SCRIPTS)] + sys.path):
            importlib.import_module("render")
        cls.workflow = sys.modules["verification_workflow"]

    def check_workflow_pdf(self, lang):
        source = fixture(self.workflow, interrupted=True)
        held = held_fixture(self.workflow, finding_id="F-held")
        stale = fixture(self.workflow, finding_id="F-stale")
        stale["findings"][0]["impact"] = "Synthetic changed impact after the recorded decision."
        source["findings"].extend(held["findings"] + stale["findings"])
        path = self.root / "synthetic-workflow.json"
        path.write_text(json.dumps(source, ensure_ascii=False), encoding="utf-8")
        data = self.renderer.load(path)
        labels = self.renderer.LABELS[lang]
        dashboard = report_helpers.ReportHTML(self.renderer.render_dashboard(data, labels, lang)).root
        payload = json.loads(dashboard.find("script", id="data").text())
        text, pages = self.render_pdf(path, lang, lang + "-workflow-evidence")
        self.assertGreaterEqual(pages, 2, "The workflow evidence should cross real PDF pages")
        extracted = self.normalized(text)
        for view in payload["workflow_views"].values():
            for value in view_texts(view):
                self.assertIn(self.normalized(value), extracted)
        for value in ("CONDITIONS_PROOF", "FALSIFICATION_PROOF", "DECISION_PROOF", "HELD_HISTORY",
                      "RESUMED_HISTORY", "synthetic-author", "synthetic-independent-reviewer", "synthetic-decider",
                      "source-before", "test-before", "NEW_ROUND_HOLD", labels["w_held"], labels["w_stale"],
                      labels["w_note"], labels["w_safety"]):
            self.assertIn(self.normalized(value), extracted)
        for view in payload["verification_views"].values():
            for value in verification_helpers.view_texts(view):
                self.assertIn(self.normalized(value), extracted)

    def test_english_workflow_evidence_pdf(self):
        self.check_workflow_pdf("en")

    def test_japanese_workflow_evidence_pdf(self):
        self.check_workflow_pdf("ja")


if __name__ == "__main__":
    unittest.main()
