"""Contract diagnostics and bounded classification work for large registers."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import contract_check  # noqa: E402


class ContractPerformanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-scan-contract-performance-")
        self.addCleanup(temporary.cleanup)
        self.out = Path(temporary.name)
        (self.out / "evidence").mkdir()
        (self.out / "deps.json").write_text('{}\n', encoding="utf-8")

    @staticmethod
    def finding(identifier, **fields):
        return {
            "id": identifier, "title": "Synthetic finding", "severity": "High",
            "category": "Actor and tenant", "location": "app.py:1",
            "actor": "synthetic actor", "request": "synthetic request",
            "impact": "synthetic impact", "fix": "synthetic fix",
            "validation": {"verdict": "Likely"},
            "verification": {"claims": {key: {} for key in contract_check.CLAIMS}, "falsification": [{}]},
            **fields,
        }

    @staticmethod
    def document(findings, dependencies=0):
        return {
            "schema_version": 2,
            "meta": {"project": "Synthetic contract fixture", "date": "2026-11-04",
                     "assessor": "Synthetic fixture", "commit": "a" * 40},
            "assessment": {"repository": "synthetic", "commit": "a" * 40, "worktree": "clean"},
            "findings": findings,
            "perspectives": [{"name": name, "result": "N/A - synthetic fixture"}
                             for name in contract_check.perspective_names()],
            "dependency_scan": {"tool": "deps_scan.py", "audit": True, "findings": dependencies, "not_run": 0},
            "limitations": ["assessment.pdf not produced: no PDF engine",
                            "invariant ledger and close-check not machine-checked (no invariant_ledger opt-in)"],
        }

    def check(self, document):
        # Only the source marker is relevant to this contract test; no browser
        # or application execution is represented by these synthetic pages.
        raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
        (self.out / "findings.json").write_bytes(raw)
        stamp = '<meta name="security-scan-source" content="sha256:%s">' % hashlib.sha256(raw).hexdigest()
        for name in ("dashboard.html", "assessment.html"):
            (self.out / name).write_text(stamp, encoding="utf-8")
        return contract_check.check(document, self.out, pdf=False)

    def test_mixed_register_preserves_finding_order_and_input(self):
        document = self.document([
            self.finding("D-002"), self.finding("F-002", location="z.py:2"),
            self.finding("D-001"), self.finding("F-001", location="a.py:1"),
        ], dependencies=2)
        before = copy.deepcopy(document)
        self.assertEqual(self.check(document), [])
        self.assertEqual(document, before)

    def test_duplicate_diagnostics_are_sorted_unique_and_precede_invalid_ids(self):
        repeated = self.finding("D-002")
        document = self.document([
            repeated, self.finding("zzz"), self.finding("F-001"),
            self.finding("F-001", title="Different finding with the same ID"),
            repeated, repeated, self.finding("aaa"), self.finding("zzz"), self.finding("aaa"),
        ], dependencies=3)
        self.assertEqual(self.check(document), [
            "D-002: duplicate id", "F-001: duplicate id", "aaa: duplicate id", "zzz: duplicate id",
            "zzz: ids are F-NNN (code findings) or D-NNN (deps_scan.py only)",
            "aaa: ids are F-NNN (code findings) or D-NNN (deps_scan.py only)",
            "zzz: ids are F-NNN (code findings) or D-NNN (deps_scan.py only)",
            "aaa: ids are F-NNN (code findings) or D-NNN (deps_scan.py only)",
            "F-*: number code findings F-001..F-002 without gaps",
        ])

    def test_nonstring_and_noncanonical_ids_keep_their_diagnostics(self):
        identifiers = [None, [], {}, 12, True, "", "F-１２３", "F-001\n", "F-1000", "D-1000", "F-01"]
        findings = [self.finding(identifier) for identifier in identifiers]
        missing = self.finding("unused")
        missing.pop("id")
        findings.extend([missing, None, [], "ignored non-object"])
        document = self.document(findings)
        expected = [": duplicate id"]
        expected += [f"{identifier}: ids are F-NNN (code findings) or D-NNN (deps_scan.py only)"
                     for identifier in identifiers + [None]]
        self.assertEqual(self.check(document), expected)

    def test_excluded_code_and_repeated_dependency_objects_remain_classified(self):
        dependency = self.finding("D-001")
        document = self.document([
            self.finding("F-001", severity="Low", location="z.py:3"),
            dependency,
            self.finding("F-002", validation={"verdict": "FalsePositive"}),
            dependency,
        ], dependencies=2)
        self.assertEqual(self.check(document), ["D-001: duplicate id"])

    def test_equal_dictionaries_are_not_merged_or_removed(self):
        finding = self.finding("F-001")
        document = self.document([finding, copy.deepcopy(finding), finding])
        self.assertEqual(self.check(document), [
            "F-001: duplicate id",
            "F-*: number code findings F-001..F-003 without gaps",
        ])
        self.assertEqual(len(document["findings"]), 3)

    def test_large_register_does_not_compare_whole_finding_dictionaries(self):
        class ObservedFinding(dict):
            comparisons = 0

            def __eq__(self, other):
                type(self).comparisons += 1
                return super().__eq__(other)

        findings = [ObservedFinding(self.finding(prefix + "%03d" % index))
                    for prefix in ("F-", "D-") for index in range(1, 501)]
        document = self.document(findings, dependencies=500)
        self.assertEqual(self.check(document), [])
        self.assertEqual(ObservedFinding.comparisons, 0)


if __name__ == "__main__":
    unittest.main()
