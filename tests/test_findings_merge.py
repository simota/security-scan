"""findings.py: fragment merging, the payload refusal and the schema gate."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from test_security_scan import import_module

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts"

META = {"project": "demo", "date": "2026-10-07", "assessor": "Claude Code (test)"}
FINDING = {"id": "F-001", "title": "Order detail lacks a tenant check", "severity": "High",
           "confidence": "Confirmed", "category": "Actor and tenant", "location": "src/orders.py:2",
           "actor": "any signed-in user", "request": "GET /orders/{id} with <other tenant's order id>",
           "impact": "reads another tenant's order", "fix": "scope the query by tenant", "status": "Open"}


class FindingsMergeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = import_module(SCRIPTS / "findings.py", "tested_findings_merge")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-merge-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.out = self.tmp / "findings.json"

    def fragment(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def merge(self, *fragments):
        with self.assertRaises(SystemExit) as raised:
            raise SystemExit(self.tool.main(["merge", str(self.out), *fragments]))
        return raised.exception.code

    def test_creates_then_updates_by_id_and_dedupes_lists(self):
        first = self.fragment("a.json", {"meta": META, "findings": [FINDING], "limitations": ["no deploy config"]})
        self.assertEqual(self.merge(first), 0)
        second = self.fragment("b.json", {"findings": [{"id": "F-001", "fix": "filter by tenant_id"}],
                                          "limitations": ["no deploy config"]})
        self.assertEqual(self.merge(second), 0)
        data = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["fix"], "filter by tenant_id")
        self.assertEqual(data["findings"][0]["actor"], "any signed-in user")
        self.assertEqual(data["limitations"], ["no deploy config"])

    def test_literal_attack_string_is_refused_and_nothing_written(self):
        bad = dict(FINDING, request="GET /search?q=' OR '1'='1")
        self.assertEqual(self.merge(self.fragment("a.json", {"meta": META, "findings": [bad]})), 1)
        self.assertFalse(self.out.exists())

    def test_pin_fields_come_only_from_evidence_capture(self):
        frag = self.fragment("a.json", {"meta": META, "schema_version": 2, "findings": []})
        self.assertEqual(self.merge(frag), 1)

    def test_schema_failure_writes_nothing(self):
        self.assertEqual(self.merge(self.fragment("a.json", {"findings": [FINDING]})), 2)
        self.assertFalse(self.out.exists())

    def test_malformed_existing_container_is_a_schema_error(self):
        fragment = self.fragment("update.json", {"findings": [{"id": "F-001", "fix": "scope by tenant"}]})
        for data in ([], {"meta": META, "findings": {}},
                     {"meta": META, "findings": [{"id": []}]}):
            with self.subTest(data=data):
                self.out.write_text(json.dumps(data))
                before = self.out.read_bytes()
                self.assertEqual(self.merge(fragment), 2)
                self.assertEqual(self.out.read_bytes(), before)

    def renumber(self):
        with self.assertRaises(SystemExit) as raised:
            raise SystemExit(self.tool.main(["renumber", str(self.out)]))
        return raised.exception.code

    def test_renumber_orders_by_severity_then_location_and_follows_references(self):
        excluded = {"verdict": "FalsePositive", "evidence": "the query is scoped", "method": "static"}
        findings = [dict(FINDING, id="F-001", severity="Low", location="b.py:9"),
                    dict(FINDING, id="F-002", location="z.py:1", impact="same root as F-004"),
                    dict(FINDING, id="F-003", location="a.py:5", validation=excluded),
                    dict(FINDING, id="F-004", severity="Low", location="b.py:2")]
        self.assertEqual(self.merge(self.fragment("a.json", {
            "meta": META, "findings": findings, "next_steps": ["fix F-002 first, then F-001"]})), 0)
        self.assertEqual(self.renumber(), 0)
        data = json.loads(self.out.read_text(encoding="utf-8"))
        # High z.py, then Low b.py:2 before b.py:9; the excluded High goes last.
        self.assertEqual([(f["id"], f["location"]) for f in data["findings"]],
                         [("F-001", "z.py:1"), ("F-002", "b.py:2"), ("F-003", "b.py:9"), ("F-004", "a.py:5")])
        self.assertEqual(data["findings"][0]["impact"], "same root as F-002")
        self.assertEqual(data["next_steps"], ["fix F-001 first, then F-003"])
        before = self.out.read_bytes()
        self.assertEqual(self.renumber(), 0)
        self.assertEqual(self.out.read_bytes(), before)

    def test_renumber_follows_references_that_touch_japanese_text(self):
        findings = [dict(FINDING, id="F-001", severity="Low"), dict(FINDING, id="F-002")]
        self.assertEqual(self.merge(self.fragment("a.json", {
            "meta": META, "findings": findings, "next_steps": ["F-002を先に修正し、次にF-001を確認する"]})), 0)
        self.assertEqual(self.renumber(), 0)
        data = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(data["next_steps"], ["F-001を先に修正し、次にF-002を確認する"])

    def test_renumber_refuses_ids_outside_the_f_nnn_form(self):
        self.out.write_text(json.dumps({"meta": META, "findings": [
            dict(FINDING, id="F-01"), dict(FINDING, id="F-002", severity="Low")]}), encoding="utf-8")
        before = self.out.read_bytes()
        self.assertEqual(self.renumber(), 1)
        self.assertEqual(self.out.read_bytes(), before)

    def test_renumber_refuses_when_digests_pin_the_ids(self):
        mapping = {"F-001": "F-002", "F-002": "F-001"}
        data = {"findings": [dict(FINDING, id="F-001"), dict(FINDING, id="F-002", verification_workflow={})]}
        self.assertIn("verification_workflow", self.tool.renumber_problems(data, data)[0])
        data = {"findings": [dict(FINDING, id="F-001"), dict(FINDING, id="F-002")],
                "evidence": [{"id": "E-001", "summary": "shows F-001"}]}
        moved = self.tool.renumber(json.loads(json.dumps(data)), mapping)
        self.assertEqual(self.tool.renumber_problems(data, moved),
                         ["evidence: renumbering would change captured records whose digests pin the current IDs"])


if __name__ == "__main__":
    unittest.main()
