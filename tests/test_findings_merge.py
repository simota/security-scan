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
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-merge-"))
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


if __name__ == "__main__":
    unittest.main()
