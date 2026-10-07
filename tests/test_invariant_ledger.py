"""Opt-in invariant ledger: static-reproduction gate, ledger validation and rendering."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/security-scan"
sys.path.insert(0, str(SKILL / "scripts"))
import render  # noqa: E402

SAMPLE = ROOT / "examples/findings.three-pass.sample.json"
REQUEST = ("Preconditions: 1. tenant B has an order\nSteps: 1. GET /orders/<order id of tenant B>\n"
           "Contrast: GET /orders lists only the caller's tenant at src/orders.py:9")
IMPACT = ("Expected: not-found, as the list route scopes by tenant (violates INV-01). "
          "Actual: tenant B's order is returned by src/orders.py:20")
FIX = "Orders are loaded only inside the caller's tenant. Test: tenant A reading tenant B's order receives not-found"
ENTRY = {"id": "INV-01", "family": "OWN", "invariant": "An order is read only within its tenant",
         "source": "src/models.py:4", "status": "violated", "paths_read": 2, "paths_total": 3,
         "finding_ids": ["F-001"]}


def sample(ledger=True):
    data = json.loads(SAMPLE.read_text(encoding="utf-8"))
    data["findings"][0].update(request=REQUEST, fix=FIX, impact=IMPACT)
    if ledger:
        data["invariant_ledger"] = {"version": 1, "entries": [dict(ENTRY)],
                                    "units": [{"unit": "orders", "record_inputs": 2, "trace_rows": 2,
                                                "blank_cells": 0, "closed": True}]}
    return data


def validate(data):
    return render.validate_data(copy.deepcopy(data))


class InvariantLedgerTests(unittest.TestCase):
    def assertRejected(self, data, fragment):
        with self.assertRaises(render.SchemaError) as raised:
            validate(data)
        self.assertIn(fragment, str(raised.exception))

    def test_opted_in_report_with_full_steps_validates_and_renders(self):
        data = validate(sample())
        page = render.render_assessment_html(data, render.LABELS["en"], "en")
        self.assertIn("id='invariant-ledger'", page)
        self.assertIn("violated (F-001); 2/3 paths read", page)
        self.assertIn("data-ledger-status='violated'", page)
        self.assertIn("<td>closed</td>", page)

    def test_default_report_is_unchanged_without_steps(self):
        data = sample(ledger=False)
        data["findings"][0].update(request="GET /orders/{id}", fix="scope by tenant")
        validated = validate(data)
        self.assertNotIn("invariant-ledger", render.render_assessment_html(validated, render.LABELS["en"], "en"))

    def test_ledger_ignored_before_schema_version_2(self):
        data = sample()
        data.pop("schema_version")
        data.pop("assessment")
        data.pop("evidence")
        data.pop("three_pass")
        data["findings"][0]["request"] = "GET /orders/{id}"
        validate(data)

    def test_missing_reproduction_markers_rejected(self):
        for key, marker in (("request", "Preconditions:"), ("request", "Steps:"),
                            ("request", "Contrast:"), ("fix", "Test:")):
            data = sample()
            data["findings"][0][key] = data["findings"][0][key].replace(marker, "")
            self.assertRejected(data, marker)

    def test_excluded_finding_needs_no_steps(self):
        data = sample()
        data["invariant_ledger"]["entries"][0].update(status="partial", finding_ids=[])
        data["findings"][0].update(request="", fix="", validation={
            "verdict": "FalsePositive", "evidence": "tenant scope applied at src/orders.py:9"})
        validate(data)

    def test_status_vocabulary_and_path_counts(self):
        cases = (
            ({"status": "unknown"}, "status: one of"),
            ({"status": "holds"}, "holds requires every path read"),
            ({"status": "holds", "paths_read": 0, "paths_total": 0}, "holds requires every path read"),
            ({"status": "partial", "paths_read": 3}, "partial requires"),
            ({"finding_ids": []}, "violated requires"),
            ({"finding_ids": ["F-999"]}, "finding_ids"),
            ({"paths_read": 4}, "cannot exceed"),
            ({"paths_read": -1}, "non-negative"),
            ({"paths_total": True}, "non-negative"),
            ({"status": "not_checked", "finding_ids": []}, "reason"),
            ({"id": "INV-1"}, "INV-<nn>"),
            ({"family": "MONEY"}, "family"),
            ({"invariant": " "}, "invariant"),
            ({"extra": 1}, "requires"),
        )
        for change, fragment in cases:
            with self.subTest(change=change):
                data = sample()
                data["invariant_ledger"]["entries"][0].update(change)
                self.assertRejected(data, fragment)
        data = sample()
        data["invariant_ledger"]["entries"][0].update(status="holds", paths_read=3, finding_ids=[])
        validate(data)

    def test_duplicate_ids_units_and_envelope_rejected(self):
        data = sample()
        data["invariant_ledger"]["entries"].append(dict(ENTRY))
        self.assertRejected(data, "unique")
        data = sample()
        data["invariant_ledger"]["units"][0]["trace_rows"] = "2"
        self.assertRejected(data, "trace_rows")
        for ledger in ({"version": 2, "entries": [ENTRY]}, {"version": 1, "entries": []}, {"entries": [ENTRY]}):
            data = sample()
            data["invariant_ledger"] = ledger
            self.assertRejected(data, "invariant_ledger")

    def test_unit_marked_closed_must_match_its_close_check(self):
        for change in ({"trace_rows": 1}, {"record_inputs": 3}, {"blank_cells": 1}):
            with self.subTest(change=change):
                data = sample()
                data["invariant_ledger"]["units"][0].update(change)
                self.assertRejected(data, "closed unit requires")
        data = sample()
        data["invariant_ledger"]["units"][0]["closed"] = "yes"
        self.assertRejected(data, "closed: must be true or false")
        for unit in ({"trace_rows": 1, "closed": False}, {"blank_cells": 2}):
            with self.subTest(open_unit=unit):
                data = sample()
                data["invariant_ledger"]["units"][0].update(unit)
                if "closed" not in unit:
                    data["invariant_ledger"]["units"][0].pop("closed")
                validate(data)

    def test_impact_requires_expected_then_actual(self):
        for impact in ("", "Actual: data returned", "Expected: not-found",
                       "Actual: data returned; expected: not-found", "unexpected factual drift"):
            with self.subTest(impact=impact):
                data = sample()
                data["findings"][0]["impact"] = impact
                self.assertRejected(data, "expected vs actual")
        data = sample()
        data["findings"][0]["impact"] = "期待: 404（INV-01 違反）。実際: 他テナントの注文が返る src/orders.py:20"
        validate(data)

    def test_excluded_finding_needs_no_impact_pair(self):
        data = sample()
        data["invariant_ledger"]["entries"][0].update(status="partial", finding_ids=[])
        data["findings"][0].update(impact="", validation={
            "verdict": "NotApplicable", "evidence": "route not registered at src/routes.py:3"})
        validate(data)

    def test_open_unit_and_japanese_render(self):
        data = sample()
        data["invariant_ledger"]["units"][0].update(trace_rows=1, closed=False)
        page = render.render_assessment_html(validate(data), render.LABELS["ja"], "ja")
        self.assertIn("不変条件台帳", page)
        self.assertIn("<td>未完了</td>", page)


if __name__ == "__main__":
    unittest.main()
