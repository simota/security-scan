"""Regressions for expert gates, the run-file audit and the ledger close state."""
import copy
from pathlib import Path
import shutil
import tempfile
import unittest

from test_expert import complete_data, expert, expert_audit, render
from test_invariant_ledger import sample as ledger_sample


class ExpertReviewTests(unittest.TestCase):
    def setUp(self):
        self.data = complete_data()
        self.assertEqual(expert.derive_expert(self.data)["gaps"], [])

    def gaps(self):
        return expert.derive_expert(self.data)["gaps"]

    def test_failed_rater_cannot_be_rescored(self):
        failing = {"rater": "rater-1", "scores": dict(expert.ANCHOR_KEY, A1="Low")}
        failing["scores"]["A1"] = "Info" if expert.ANCHOR_KEY["A1"] == "High" else "High"
        self.data["expert"]["calibration"].insert(0, failing)
        self.assertIn("rater_recalibrated:rater-1", self.gaps())

    def test_variant_dispositions_need_a_target_and_safe_takes_none(self):
        for result in ("finding", "same", "same:", "safe:F-001"):
            with self.subTest(result=result):
                data = copy.deepcopy(self.data)
                data["expert"]["variants"][0]["dispositions"][0]["result"] = result
                with self.assertRaises(ValueError):
                    expert.derive_expert(data)

    def test_ratings_for_unknown_findings_and_repeats_hold(self):
        ratings = self.data["expert"]["ratings"]
        ratings.append(dict(ratings[0]))
        ratings.append(dict(ratings[0], finding="F-999"))
        gaps = self.gaps()
        self.assertTrue(any(g.startswith("rating_duplicate:") for g in gaps))
        self.assertIn("rating_unknown_finding:F-999", gaps)

    def test_non_object_validation_is_a_schema_matter_not_a_crash(self):
        self.data["findings"][0]["validation"] = "Confirmed"
        expert.derive_expert(self.data)

    def test_symlinked_run_directory_is_not_inside_out_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, outside = Path(tmp) / "out", Path(tmp) / "outside"
            out.mkdir()
            outside.mkdir()
            (outside / "gate.md").write_text("synthetic")
            (out / "run").symlink_to(outside)
            self.assertFalse(expert_audit.run_file(out, "run/gate.md"))
            shutil.rmtree(outside)


class LedgerCloseStateTests(unittest.TestCase):
    def test_open_unit_with_matching_counts_renders_open(self):
        data = ledger_sample()
        data["invariant_ledger"]["units"][0]["closed"] = False
        page = render.render_assessment_html(render.validate_data(data), render.LABELS["en"], "en")
        self.assertIn("<td>open</td>", page)
        self.assertNotIn("<td>closed</td>", page)


if __name__ == "__main__":
    unittest.main()
