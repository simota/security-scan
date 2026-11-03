"""Bound report work while keeping every render and evidence selection fresh."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import evidence_integrity as integrity  # noqa: E402
import render  # noqa: E402
import verification_workflow as workflow  # noqa: E402


class ReportComputationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "examples/findings.verification.sample.json").read_text(encoding="utf-8"))
        finding = self.data["findings"][0]
        finding["status"] = "Open"
        finding.pop("remediation")
        render.validate_data(self.data)

    def payload(self, markup):
        return json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>',
                                    markup, re.DOTALL).group(1))

    def test_each_output_derives_report_states_once(self):
        workflow.initialize(self.data, "F-001", "synthetic-coordinator")
        original = copy.deepcopy(self.data)
        expected = render.report_model(self.data)
        for lang in ("en", "ja"):
            for renderer in (render.render_dashboard, render.render_assessment_html):
                with self.subTest(lang=lang, renderer=renderer.__name__):
                    with patch.object(render, "derive_verification", wraps=render.derive_verification) as derive, \
                            patch.object(render, "workflow_states", wraps=render.workflow_states) as workflows:
                        markup = renderer(self.data, render.LABELS[lang], lang)
                    self.assertEqual(derive.call_count, 1)
                    self.assertEqual(workflows.call_count, 1)
                    self.assertEqual(self.data, original)
                    if renderer is render.render_dashboard:
                        self.assertEqual(self.payload(markup)["report"], expected)

    def test_later_renders_rederive_changed_policy_and_evidence(self):
        for lang in ("en", "ja"):
            for renderer in (render.render_dashboard, render.render_assessment_html):
                with self.subTest(lang=lang, renderer=renderer.__name__):
                    data = copy.deepcopy(self.data)
                    before = renderer(data, render.LABELS[lang], lang)
                    data["evidence_integrity"] = {"required": True}
                    marker = "Changed synthetic evidence observation."
                    data["evidence"][0]["summary"] = marker
                    # Derived fields from the earlier validation are now stale.
                    self.assertEqual(data["findings"][0]["_verification"]["level"], "runtime_supported")
                    after = renderer(data, render.LABELS[lang], lang)
                    self.assertNotIn(marker, before)
                    self.assertIn(marker, after)
                    self.assertNotEqual(before, after)
                    if renderer is render.render_dashboard:
                        old, new = self.payload(before)["report"], self.payload(after)["report"]
                        self.assertEqual(old["fix_now"], 1)
                        self.assertEqual(new["fix_now"], 0)
                        self.assertEqual(new["verification"]["F-001"]["level"], "incomplete")
                    else:
                        self.assertIn(render.LABELS[lang]["v_gap_evidence_integrity_unchecked"], after)

    def test_later_renders_rederive_stale_workflows(self):
        workflow.initialize(self.data, "F-001", "synthetic-coordinator")
        labels = render.LABELS["en"]
        before = self.payload(render.render_dashboard(self.data, labels, "en"))
        self.assertEqual(before["report"]["workflows"]["F-001"]["status"], "ready")
        self.data["evidence"][0]["summary"] = "Changed workflow input."
        after = self.payload(render.render_dashboard(self.data, labels, "en"))
        self.assertEqual(after["report"]["workflows"]["F-001"]["status"], "stale")
        self.assertEqual(after["report"], render.report_model(self.data))

    def test_shared_states_still_project_only_public_fields(self):
        marker = "PRIVATE_PROOF_EXTENSION_MUST_NOT_RENDER"
        self.data["findings"][0]["verification"]["opaque"] = {"secret": marker}
        self.data["evidence"][0]["opaque"] = {"secret": marker}
        for lang in ("en", "ja"):
            labels = render.LABELS[lang]
            dashboard = render.render_dashboard(self.data, labels, lang)
            assessment = render.render_assessment_html(self.data, labels, lang)
            payload = self.payload(dashboard)
            self.assertNotIn(marker, dashboard)
            self.assertNotIn(marker, assessment)
            self.assertEqual(set(payload["report"]["verification"]["F-001"]), {"level", "retest", "gaps"})
            self.assertEqual(set(payload["report"]["queue"][0]["finding"]["_verification"]),
                             {"level", "retest", "gaps"})


@unittest.skipUnless(os.name == "posix", "POSIX safe evidence reader required")
class EvidenceSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-scan-selected-evidence-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        content = b"synthetic runtime observation\n"
        (self.root / "runtime.txt").write_bytes(content)
        commit = "1" * 40
        self.data = {
            "schema_version": 2,
            "assessment": {"repository": "synthetic-local", "commit": commit, "worktree": "clean"},
            "evidence": [{"id": "runtime-%03d" % i, "kind": "runtime", "commit": commit,
                          "location": "runtime.txt", "sha256": hashlib.sha256(content).hexdigest(),
                          "summary": "Synthetic runtime observation"} for i in range(80)],
            "test_runs": [], "findings": [],
        }

    def verify(self, selection=None):
        return integrity.verify_evidence(self.data, self.root, evidence_ids=selection)

    def test_selection_copies_only_requested_receipt_items(self):
        result = self.verify()
        selection = ["runtime-007", "runtime-001"]
        copied = []
        deepcopy = copy.deepcopy

        def observed_copy(value):
            pending = [value]
            while pending:
                item = pending.pop()
                if isinstance(item, dict):
                    if "evidence_id" in item:
                        copied.append(item["evidence_id"])
                    pending.extend(item.values())
                elif isinstance(item, (list, tuple)):
                    pending.extend(item)
            return deepcopy(value)

        with patch.object(integrity.copy, "deepcopy", side_effect=observed_copy):
            state = integrity.provenance_state(self.data, selection, result)
        self.assertCountEqual(copied, selection)
        self.assertEqual([item["evidence_id"] for item in state["records"]], sorted(selection))
        self.assertEqual(state["status"], "checked")

    def test_partial_and_empty_selections_preserve_unchecked_status(self):
        result = self.verify(["runtime-001"])
        checked = result.receipt["items"][0]
        self.assertEqual(integrity.provenance_state(self.data, ["runtime-001"], result),
                         {"status": "checked", "reasons": [], "records": [checked]})
        missing = {"evidence_id": "runtime-007", "bytes": "unavailable", "source": "not_checked",
                   "reason": "evidence_not_checked"}
        self.assertEqual(integrity.provenance_state(self.data, ["runtime-007", "runtime-001"], result),
                         {"status": "incomplete", "reasons": ["evidence_not_checked"],
                          "records": [checked, missing]})
        self.assertEqual(integrity.provenance_state(self.data, [], result),
                         {"status": "incomplete", "reasons": ["no_evidence_selected"], "records": []})

    def test_returned_records_and_receipts_cannot_mutate_later_selections(self):
        result = self.verify()
        receipt = result.receipt
        expected = integrity.provenance_state(self.data, ["runtime-001"], result)
        changed = integrity.provenance_state(self.data, ["runtime-001"], result)
        changed["records"][0].update(bytes="mismatch", source="fake", reason="tampered", observed_size=-1)
        changed["records"].append({"evidence_id": "injected"})
        exported = result.receipt
        exported["items"][1]["bytes"] = "mismatch"
        exported["items"].clear()
        self.assertEqual(result.receipt, receipt)
        self.assertEqual(integrity.provenance_state(self.data, ["runtime-001"], result), expected)
        self.assertEqual(integrity.provenance_state(self.data, ["runtime-007"], result)["status"], "checked")

    def test_changed_declarations_and_saved_receipts_remain_untrusted(self):
        result = self.verify()
        selection = ["runtime-001"]
        for supplied, reason, status in ((None, "not_checked", "declared"),
                                          (result.receipt, "recorded_receipt_only", "declared")):
            state = integrity.provenance_state(self.data, selection, supplied)
            self.assertEqual(state["status"], status)
            self.assertEqual(state["reasons"], [reason])
            self.assertEqual(state["records"][0]["bytes"], "declared")
        # Even a change to an unselected declaration must stale the live result.
        self.data["evidence"][0]["summary"] = "Changed synthetic declaration."
        state = integrity.provenance_state(self.data, selection, result)
        self.assertFalse(result.matches(self.data))
        self.assertEqual(state["status"], "incomplete")
        self.assertEqual(state["reasons"], ["context_stale"])
        self.assertEqual(state["records"][0]["bytes"], "declared")
        self.assertEqual(integrity.provenance_state(self.data, selection, self.verify())["status"], "checked")


if __name__ == "__main__":
    unittest.main()
