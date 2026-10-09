"""Second-round render regressions: translations, payload scope, empty states, strict IDs."""
import copy
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import render  # noqa: E402
from test_expert import complete_data  # noqa: E402
from test_invariant_ledger import sample as ledger_sample  # noqa: E402


def load(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "findings.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return render.load(path)


def legacy():
    return {"meta": {"project": "Synthetic", "date": "2026-10-09"},
            "findings": [{"id": "F-001", "title": "Synthetic", "severity": "High", "confidence": "Confirmed",
                          "location": "app.py:1"}]}


class ExpertTranslationTests(unittest.TestCase):
    def test_gate_codes_and_qa_result_are_translated(self):
        data = complete_data()
        data["expert"].pop("qa")
        data["expert"]["panels"] = []
        view = render.expert_view(render.validate_data(data), "ja")
        text = "\n".join(view["lines"] + view["gaps"])
        self.assertIn("未記録", text)
        self.assertIn("反証パネルがありません: F-001", text)
        self.assertNotIn("qa_missing", text)
        self.assertFalse(re.search(r"\b[a-z]+_[a-z_]+\b", "\n".join(view["gaps"])), view["gaps"])

    def test_every_expert_gate_code_has_both_labels(self):
        source = (ROOT / "skills/security-scan/scripts/expert.py").read_text(encoding="utf-8")
        codes = set(re.findall(r'gap\(f?"([a-z_]+)', source))
        codes |= {stage + "_actor_not_spawned" for stage in ("conditions", "falsification", "decision")}
        for lang in ("en", "ja"):
            missing = sorted(code for code in codes if "e_gap_" + code not in render.LABELS[lang])
            self.assertEqual(missing, [], lang)


class VerificationTranslationTests(unittest.TestCase):
    def test_recorded_codes_are_labelled_in_japanese(self):
        data = load(json.loads((ROOT / "examples/findings.verification.sample.json").read_text()))
        page = render.render_assessment_html(data, render.LABELS["ja"], "ja")
        for raw in ("作業ツリー: clean", "失敗の種類: none", "before_run_id:", "· source", "· runtime"):
            self.assertNotIn(raw, page)
        self.assertIn("未変更（クリーン）", page)
        self.assertIn("修正前の実行 ID", page)


class ReportScopeTests(unittest.TestCase):
    def test_perspective_extension_fields_stay_out_of_the_payload(self):
        data = legacy()
        data["perspectives"] = [{"name": "Actor and tenant", "result": "x", "internal_notes": "SYNTHETIC_NOTE"}]
        html = render.render_dashboard(load(data), render.LABELS["en"], "en")
        self.assertNotIn("SYNTHETIC_NOTE", html)

    def test_empty_decisions_and_next_steps_are_shown_as_none(self):
        page = render.render_assessment_html(load(legacy()), render.LABELS["en"], "en")
        self.assertIn("No decisions were recorded.", page)
        self.assertIn("No additional next steps were recorded.", page)

    def test_running_footer_is_localized(self):
        page = render.render_assessment_html(load(legacy()), render.LABELS["ja"], "ja")
        self.assertIn('content:"セキュリティ診断"', page)
        self.assertNotIn('"SECURITY ASSESSMENT"', page)

    def test_legacy_findings_have_no_integrity_summary(self):
        data = load(legacy())
        states = render.derive_verification(data, render.SchemaError)
        self.assertIsNone(render.integrity_summary_view(states, data["findings"], render.LABELS["en"]))
        render.render_dashboard(data, render.LABELS["en"], "en")

    def test_snippets_wrap_in_print_and_narrow_detail_lists(self):
        html = render.render_dashboard(load(legacy()), render.LABELS["en"], "en")
        self.assertIn(".snippet{white-space:pre-wrap;overflow:visible}", html)
        self.assertIn("tr.detail dl{grid-template-columns:minmax(0,1fr);gap:3px}", html)

    def test_headline_when_nothing_is_unverified(self):
        html = render.render_dashboard(load(legacy()), render.LABELS["en"], "en")
        self.assertIn("R.unverified?fmt(L.unverified_line", html)


class StrictIdTests(unittest.TestCase):
    def test_opted_in_gates_refuse_ids_they_cannot_see(self):
        for fid in ("F-1000", "APP-1", "F-001\n"):
            with self.subTest(fid=fid):
                data = complete_data()
                data["findings"].append(dict(copy.deepcopy(data["findings"][0]), id=fid))
                with self.assertRaises(render.SchemaError):
                    render.validate_data(data)


class LedgerReferenceTests(unittest.TestCase):
    def test_violated_needs_an_included_finding_and_holds_cites_none(self):
        data = ledger_sample()
        data["findings"][0]["validation"] = dict(data["findings"][0].get("validation") or {}, verdict="FalsePositive",
                                                 evidence="ruled out", method="review")
        with self.assertRaisesRegex(render.SchemaError, "included"):
            render.validate_data(copy.deepcopy(data))
        data = ledger_sample()
        data["invariant_ledger"]["entries"][0].update(status="holds", paths_read=3, paths_total=3)
        with self.assertRaisesRegex(render.SchemaError, "holds cites no findings"):
            render.validate_data(data)


if __name__ == "__main__":
    unittest.main()
