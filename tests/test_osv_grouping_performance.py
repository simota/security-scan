"""OSV grouping preserves evidence and validation with linear record visits."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import deps_scan  # noqa: E402


class CountedRecords(list):
    """Count records visited, independently of machine speed or parser internals."""
    visits = 0

    def __iter__(self):
        for record in super().__iter__():
            self.visits += 1
            yield record


class OsvGroupingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="security-scan-osv-groups-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.lock = self.root / "poetry.lock"
        self.lock.write_text("", encoding="utf-8")

    def payload(self, records, groups, lock=None, name="fixture"):
        return {"results": [{"source": {"path": str(lock or self.lock)}, "packages": [
            {"package": {"name": name, "version": "1.0"},
             "vulnerabilities": records, "groups": groups}]}]}

    def parse(self, records, groups):
        collector = deps_scan.Collector(self.root)
        deps_scan.parse_osv(collector, self.payload(records, groups), self.root, self.lock)
        return collector.findings

    def test_group_order_aliases_fix_versions_and_references_are_preserved(self):
        records = [
            {"id": "GHSA-primary", "summary": "representative summary", "aliases": ["CVE-2026-0003"],
             "affected": [{"package": {"name": "fixture"}, "ranges": [
                 {"type": "ECOSYSTEM", "events": [{"fixed": "2.0.0"}]}]}]},
            {"id": "UNGROUPED", "summary": "ungrouped summary"},
            {"id": "PYSEC-secondary", "summary": "secondary summary",
             "aliases": ["CVE-2026-0002", "CVE-2026-0001", "MAL-2026-1"],
             "affected": [{"package": {"name": "fixture"}, "ranges": [
                 {"type": "GIT", "events": [{"fixed": "a" * 40}]},
                 {"type": "ECOSYSTEM", "events": [{"fixed": "2.1.0"}, {"fixed": "2.0.0"}]}]}],
             "references": [{"type": "FIX", "url": "https://github.com/example/repo/commit/fix"}]},
            {"id": "OTHER", "summary": "other group"},
        ]
        # Group order differs from record order, and membership can come from aliases.
        groups = [{"ids": ["OTHER"], "max_severity": "2.0"},
                  {"ids": ["GHSA-primary"], "aliases": ["PYSEC-secondary"], "max_severity": "5.0"}]
        findings = self.parse(records, groups)
        self.assertEqual([f["impact"] for f in findings],
                         ["representative summary", "ungrouped summary", "other group"])
        self.assertEqual([f["severity"] for f in findings], ["High", "Medium", "Low"])
        self.assertTrue(findings[0]["malicious"])
        self.assertEqual(findings[0]["advisory_ids"],
                         ["CVE-2026-0001", "CVE-2026-0002", "GHSA-primary", "MAL-2026-1"])
        self.assertEqual(findings[0]["fix"], "Upgrade to 2.0.0, 2.1.0")
        self.assertEqual([r["url"] for r in findings[0]["references"]], [
            "https://osv.dev/vulnerability/GHSA-primary",
            "https://osv.dev/vulnerability/PYSEC-secondary",
            "https://github.com/example/repo/commit/fix",
        ])

    def test_ungrouped_records_remain_independent_including_duplicate_ids(self):
        first = {"id": "GHSA-same", "summary": "first"}
        findings = self.parse([first, first, dict(first, summary="second")], [])
        self.assertEqual([f["impact"] for f in findings], ["first", "first", "second"])
        self.assertEqual([f["id"] for f in findings], ["D-001", "D-002", "D-003"])

    def test_group_members_keep_identity_and_input_order(self):
        first = {"id": "GHSA-first"}
        alias = {"id": "PYSEC-alias"}
        same_id = dict(first)
        records = [first, first, alias, alias, same_id]
        with patch.object(deps_scan, "osv_fixed", wraps=deps_scan.osv_fixed) as fixed:
            findings = self.parse(records, [{"ids": ["GHSA-first", "PYSEC-alias"]}])
        self.assertEqual(len(findings), 1)
        # Repeated references to the representative are excluded; other entries
        # keep their order, even when they have the same ID or object identity.
        self.assertEqual([id(call.args[0]) for call in fixed.call_args_list],
                         [id(first), id(alias), id(alias), id(same_id)])

    def test_last_group_assignment_wins_for_overlapping_ids_and_aliases(self):
        records = [{"id": name, "summary": name} for name in ("A", "B", "C")]
        findings = self.parse(records, [
            {"ids": ["A", "B"], "max_severity": "2.0"},
            {"ids": ["C"], "aliases": ["B"], "max_severity": "8.0"},
        ])
        self.assertEqual([f["impact"] for f in findings], ["A", "B"])
        self.assertEqual([f["severity"] for f in findings], ["Low", "High"])
        self.assertEqual([r["title"] for r in findings[0]["references"]], ["A"])
        self.assertEqual([r["title"] for r in findings[1]["references"]], ["B", "C"])

    def test_groups_do_not_leak_between_packages(self):
        data = self.payload([{"id": "A", "summary": "first package"}], [{"ids": ["A"]}])
        data["results"][0]["packages"] += self.payload(
            [{"id": "B", "summary": "second package"}], [{"ids": ["B"]}], name="other"
        )["results"][0]["packages"]
        collector = deps_scan.Collector(self.root)
        deps_scan.parse_osv(collector, data, self.root, self.lock)
        self.assertEqual([f["package"] for f in collector.findings], ["fixture", "other"])
        self.assertEqual([r["title"] for r in collector.findings[1]["references"]], ["B"])

    def test_record_visits_are_linear_for_grouped_and_ungrouped_results(self):
        count = 256
        for group_size in (0, 1, 2):
            with self.subTest(group_size=group_size):
                records = CountedRecords({"id": f"GHSA-{i}"} for i in range(count))
                groups = ([{"ids": [f"GHSA-{i + j}" for j in range(group_size)]}
                           for i in range(0, count, group_size)] if group_size else [])
                findings = self.parse(records, groups)
                self.assertEqual(len(findings), count // group_size if group_size else count)
                self.assertGreaterEqual(records.visits, count)
                self.assertLessEqual(records.visits, count * 4)

    def test_malformed_secondary_records_roll_back_only_the_failed_audit(self):
        good_lock = self.root / "other" / "poetry.lock"
        good_lock.parent.mkdir()
        good_lock.write_text("", encoding="utf-8")
        malformed = [
            None, [], {"id": []}, {"id": {}}, {"id": ""},
            {"id": "PYSEC-secondary", "summary": 7},
            {"id": "PYSEC-secondary", "aliases": "CVE-invalid"},
            {"id": "PYSEC-secondary", "aliases": [None]},
            {"id": "GHSA-primary", "summary": 7},
            {"id": "GHSA-primary", "aliases": None},
            {"id": "GHSA-primary", "aliases": [7]},
        ]
        for record in malformed:
            with self.subTest(record=record):
                bad = self.payload([{"id": "GHSA-primary"}, record],
                                   [{"ids": ["GHSA-primary", "PYSEC-secondary"]}])
                good = self.payload([{"id": "GHSA-good", "summary": "valid finding"}], [], good_lock)
                collector = deps_scan.Collector(self.root)
                collector.add("Info", "existing finding", self.lock)
                original = list(collector.findings)
                with patch.object(deps_scan.shutil, "which", return_value="/tools/osv-scanner"), \
                     patch.object(deps_scan, "run", side_effect=[
                         (1, json.dumps(bad), ""), (1, json.dumps(good), "")]):
                    covered = deps_scan.audit_osv(collector, self.root, [self.lock, good_lock])
                self.assertEqual(covered, {good_lock})
                self.assertEqual(collector.findings[:-1], original)
                self.assertEqual(collector.findings[-1]["impact"], "valid finding")
                self.assertEqual(collector.not_run, [{
                    "tool": "osv-scanner",
                    "reason": "poetry.lock: invalid or inconsistent result schema",
                }])


if __name__ == "__main__":
    unittest.main()
